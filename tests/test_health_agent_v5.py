"""V5-D4: the Health Agent flow (debounce, early evidence, fail closed, follow-ups, watch, concurrency).

Offline: fake Kubernetes API, Redis, Prometheus window and inference service (tests/health_helpers.py). The
feature code, the posture code and the failure_reasons code are the real ones."""
import asyncio
import json

import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from health_helpers import KEY, Env, FakeAutoscaling, dep, failing_pod, full_window, prediction
from agents.health_agent import agent as ha
from agents.health_agent import baseline
from kubeheal.features.health import METRIC_FEATURES
from kubeheal.posture import PostureError


def run(coro):
    return asyncio.run(coro)


def scenario(fn):
    def wrapper():
        async def go():
            env = Env()
            try:
                await fn(env)
            finally:
                await env.agent.stop()
        run(go())
    wrapper.__name__ = fn.__name__
    return wrapper


# ---- change detection ---------------------------------------------------------------------------------------
@scenario
async def test_first_sight_records_the_golden_baseline_and_assesses_nothing(env):
    await env.send("ADDED", dep())
    assert baseline.baseline_key(*KEY) in env.redis.store
    assert KEY not in env.agent.pending
    await env.tick(120)
    assert env.events == [] and env.predictions == []


@scenario
async def test_only_a_changed_hash_counts_as_a_change(env):
    await env.send("ADDED", dep())
    # status-only update (rollout progress), metadata-only update (annotation, resourceVersion, generation)
    await env.send("MODIFIED", dep(rolled_out=False))
    await env.send("MODIFIED", dep(annotations={"note": "x"}, generation=1))
    # a replicas change is scaling, not drift: the drift view leaves it out
    await env.send("MODIFIED", dep(replicas=5))
    assert env.agent.pending == {}
    await env.tick(300)
    assert env.events == [] and env.windows == []


@scenario
async def test_a_changed_spec_goes_on_the_debounce_and_status_updates_do_not_move_it(env):
    await env.baseline_then_change(image="img:2")
    assert KEY in env.agent.pending
    deadline = env.agent.pending[KEY].deadline
    await env.send("MODIFIED", dep(image="img:2", rolled_out=False, generation=2))
    assert env.agent.pending[KEY].deadline == deadline


@scenario
async def test_a_noop_change_back_to_the_baseline_publishes_nothing(env):
    await env.baseline_then_change(image="img:2")
    await env.send("MODIFIED", dep())                # back to the golden spec before the deadline
    await env.tick(60)
    assert env.events == [] and env.predictions == [] and env.windows == []
    assert KEY not in env.agent._drifted


# ---- debounce -----------------------------------------------------------------------------------------------
@scenario
async def test_assessment_waits_for_the_delay_and_later_changes_never_postpone_it(env):
    await env.baseline_then_change(image="img:2")
    t0_wall = env.clock.wall()
    await env.tick(30)
    assert env.events == []
    await env.send("MODIFIED", dep(image="img:3"))     # a second change inside the window
    await env.tick(29)                                 # t = 59 s
    assert env.events == []
    await env.tick(1)                                  # t = 60 s: the first deadline, not 60 s after img:3
    [event] = env.events
    # the pending spec of the second change is the one assessed
    assert json.loads(event["changed_fields_json"]) == ["template.spec.containers[0].image"]
    # the window starts at the FIRST change and ends at the assessment time
    assert env.windows == [("prod", "victim-app", t0_wall, t0_wall + 60)]
    assert KEY not in env.agent.pending


@scenario
async def test_a_second_assessment_window_starts_at_the_next_change(env):
    await env.baseline_then_change(image="img:2")
    await env.tick(60)
    assert len(env.events) == 1
    t1 = env.clock.wall()
    await env.send("MODIFIED", dep(image="img:3"))
    assert env.agent.pending[KEY].t0_wall == t1
    await env.tick(60)
    assert len(env.events) == 2 and env.windows[1][2] == t1


# ---- early evidence -----------------------------------------------------------------------------------------
@scenario
async def test_a_posture_violation_is_assessed_without_waiting(env):
    await env.send("ADDED", dep())
    await env.send("MODIFIED", dep(cpu="50m"))         # 500m to 50m: the 10x cut rule (inclusive, D1)
    await env.tick(0)                                  # the first poll is immediate
    [event] = env.events
    assert "policy:cpu_cut_10x" in json.loads(event["failure_reasons_json"])
    assert env.clock.t == 1000.0                       # no time passed: no waiting for the 60 s deadline


@scenario
async def test_a_failed_rollout_is_assessed_early_once_confirmed_on_two_polls(env):
    await env.baseline_then_change(image="img:bad", rolled_out=False)
    env.core.pods = [failing_pod(env.clock.wall())]
    await env.tick(0)                                  # poll 1: seen once, a transient waits
    assert env.events == []
    await env.tick(2)                                  # poll 2: seen again, assess now
    [event] = env.events
    assert json.loads(event["failure_reasons_json"]) == ["ImagePullBackOff"]
    assert env.clock.t == 1002.0
    assert env.core.pod_calls[0][0] == "prod"          # pods are listed per namespace
    assert env.core.pod_calls[0][1]["label_selector"] == "app=victim-app"


@scenario
async def test_a_transient_failure_that_disappears_waits_for_the_deadline(env):
    await env.baseline_then_change(image="img:2", rolled_out=False)
    env.core.pods = [failing_pod(env.clock.wall())]
    await env.tick(0)
    env.core.pods = []
    await env.tick(2)
    assert env.events == []
    await env.tick(58)
    assert len(env.events) == 1 and json.loads(env.events[0]["failure_reasons_json"]) == []


@scenario
async def test_a_pod_listing_error_loses_only_the_pod_evidence(env):
    await env.baseline_then_change(image="img:2", rolled_out=False)
    env.core.fail = ApiException(status=403, reason="Forbidden")
    await env.tick(60)
    [event] = env.events
    assert json.loads(event["failure_reasons_json"]) == []     # not a failure reason, not a crash


@scenario
async def test_progress_deadline_exceeded_is_a_failure_reason_from_the_status(env):
    await env.baseline_then_change(image="img:2", rolled_out=False, extra_status={
        "observedGeneration": 1, "conditions": [{"type": "Progressing", "status": "False",
                                                 "reason": "ProgressDeadlineExceeded"}]})
    await env.tick(60)
    assert json.loads(env.events[0]["failure_reasons_json"]) == ["ProgressDeadlineExceeded"]


# ---- fail closed on the model -------------------------------------------------------------------------------
@scenario
async def test_inference_down_publishes_the_model_unavailable_notice_once_and_retries(env):
    env.result = None
    await env.baseline_then_change(image="img:2")
    await env.tick(60)
    [notice] = env.events
    assert notice["model_unavailable"] == "true" and notice["model_scored"] == "false"
    assert notice["health_label"] == "model_unavailable" and notice["health_prediction_set"] == "[]"
    assert "health_risk" not in notice and "failure_reasons_json" not in notice     # nothing is invented
    assert env.redis.store.get(env.agent._assessed_key(KEY)) is None                # not stored as assessed
    assert env.agent.pending[KEY].deadline == env.clock.t + ha.RETRY_DELAY_S       # tried again later
    await env.tick(60)
    assert len(env.events) == 1                        # the retry does not repeat the notice
    env.result = prediction()                          # the service is back
    await env.tick(60)
    scored = env.events[-1]
    assert scored["model_scored"] == "true" and "model_unavailable" not in scored


@scenario
async def test_inference_down_with_failure_reasons_still_publishes_the_rule_evidence(env):
    env.result = None
    await env.send("ADDED", dep())
    await env.send("MODIFIED", dep(cpu="50m"))
    await env.tick(0)
    [event] = env.events
    assert event["model_unavailable"] == "true" and event["model_scored"] == "false"
    assert json.loads(event["failure_reasons_json"]) == ["policy:cpu_cut_10x"]
    assert event["spec_changed"] == "true" and event["has_baseline"] == "true"
    assert json.loads(event["changed_fields_json"]) == ["template.spec.containers[0].resources.limits.cpu"]
    assert "health_risk" not in event
    assert KEY not in env.agent.pending                # rule evidence is a decision input, no retry loop


@scenario
async def test_a_posture_error_is_a_failed_assessment_never_a_verdict(env, monkeypatch=None):
    await env.baseline_then_change(image="img:2")

    def boom(base, spec):
        raise PostureError("unreadable")

    original = ha.policy_violations
    ha.policy_violations = boom
    try:
        await env.tick(60)
    finally:
        ha.policy_violations = original
    assert env.events == [] and env.predictions == []        # no event, no model call, nothing to roll back
    assert KEY not in env.agent.pending


@scenario
async def test_a_metric_query_for_a_non_dns_name_is_a_failed_assessment(env):
    env.window_error = ValueError("invalid deployment name for a PromQL selector")
    await env.baseline_then_change(image="img:2")
    await env.tick(60)
    assert env.events == [] and env.predictions == []


@scenario
async def test_missing_metrics_are_null_features_never_zeros(env):
    win = full_window()
    win["latency_p99_s"] = None
    win["error_rate_rps"] = []
    env.window = win
    await env.baseline_then_change(image="img:2")
    await env.tick(60)
    [features] = env.predictions
    assert features["latency_p99_mean_s"] is None and features["latency_p99_max_s"] is None
    assert features["latency_trend"] is None and features["error_ratio"] is None
    assert features["cpu_util_mean"] is not None
    assert json.loads(env.events[0]["metrics_missing_json"]) == ["error_rate_rps", "latency_p99_s"]
    assert env.events[0]["health_uncertain"] == "false"      # the service's own answer stays


@scenario
async def test_no_metric_at_all_is_published_uncertain(env):
    env.window = {k: None for k in full_window()}
    await env.baseline_then_change(image="img:2")
    await env.tick(60)
    [features] = env.predictions
    assert all(features[k] is None for k in METRIC_FEATURES)
    assert env.events[0]["health_uncertain"] == "true"


@scenario
async def test_features_are_computed_against_the_golden_baseline(env):
    await env.send("ADDED", dep(cpu="500m"))
    await env.send("MODIFIED", dep(cpu="400m"))
    await env.tick(60)
    assert env.predictions[0]["cpu_limit_ratio"] == pytest.approx(0.8)
    assert env.predictions[0]["replicas_ratio"] == 1.0         # replicas never count (S-HA-3)
    # the next change is still diffed against the GOLDEN spec, not against the previous change
    await env.send("MODIFIED", dep(cpu="300m"))
    await env.tick(60)
    assert env.predictions[1]["cpu_limit_ratio"] == pytest.approx(0.6)


# ---- follow-up events ---------------------------------------------------------------------------------------
@scenario
async def test_failure_reasons_that_appear_late_get_a_follow_up_event(env):
    await env.baseline_then_change(image="img:2", rolled_out=False)
    await env.tick(60)
    [first] = env.events
    assert json.loads(first["failure_reasons_json"]) == []
    assert KEY in env.agent.tracking
    env.core.pods = [failing_pod(env.clock.wall() - 30)]
    await env.tick(2)                                  # seen once
    assert len(env.events) == 1
    await env.tick(2)                                  # confirmed twice: one follow-up
    assert len(env.events) == 2
    follow = env.events[1]
    assert follow["event_id"] != first["event_id"]
    assert json.loads(follow["failure_reasons_json"]) == ["ImagePullBackOff"]
    assert follow["changed_fields_json"] == first["changed_fields_json"]
    await env.tick(2)
    await env.tick(2)
    assert len(env.events) == 2                        # the same reason is not reported twice


@scenario
async def test_follow_up_ends_when_the_rollout_completes(env):
    await env.baseline_then_change(image="img:2", rolled_out=False)
    await env.tick(60)
    assert KEY in env.agent.tracking
    await env.send("MODIFIED", dep(image="img:2", rolled_out=True))      # status-only: rollout done
    await env.tick(2)
    assert KEY not in env.agent.tracking


@scenario
async def test_follow_up_is_bounded_by_the_window_and_a_newer_spec_supersedes_it(env):
    await env.baseline_then_change(image="img:2", rolled_out=False)
    await env.tick(60)
    window = (600 + ha.FOLLOWUP_MARGIN_S)
    assert env.agent.tracking[KEY].end == env.clock.t + window
    await env.tick(window)
    assert KEY not in env.agent.tracking
    await env.send("MODIFIED", dep(image="img:3", rolled_out=False))
    await env.tick(60)
    assert KEY in env.agent.tracking
    await env.send("MODIFIED", dep(image="img:4", rolled_out=False))
    assert KEY not in env.agent.tracking               # superseded by the newer pending spec


def test_followup_window_is_configurable(monkeypatch):
    monkeypatch.setenv("FOLLOWUP_WINDOW_S", "120")
    assert ha.HealthAgent(redis_url="redis://unused").followup_window_s == 120.0
    monkeypatch.setenv("ASSESS_DELAY_S", "15")
    monkeypatch.setenv("MAX_CONCURRENT_ASSESSMENTS", "3")
    a = ha.HealthAgent(redis_url="redis://unused")
    assert a.delay_s == 15.0 and a.max_concurrent == 3
    monkeypatch.setenv("ASSESS_DELAY_S", "0")
    with pytest.raises(ValueError):
        ha.HealthAgent(redis_url="redis://unused")


# ---- concurrency cap ----------------------------------------------------------------------------------------
@scenario
async def test_at_most_eight_assessments_run_at_the_same_time(env):
    n = 20
    for i in range(n):
        await env.send("ADDED", dep(name=f"app{i}"))
    for i in range(n):
        await env.send("MODIFIED", dep(name=f"app{i}", image="img:2"))
    env.gate = asyncio.Event()
    env.clock.advance(60)
    await env.agent.tick()
    for _ in range(60):
        await asyncio.sleep(0)
    assert env.max_active == 8 and env.active == 8
    env.gate.set()
    await env.agent.drain()
    assert len(env.events) == n and env.max_active == 8


# ---- watch loop ---------------------------------------------------------------------------------------------
class FakeWatch:
    script: list = []
    calls: list = []

    def __init__(self):
        self.resource_version = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stop(self):
        pass

    def stream(self, fn, *args, **kw):
        FakeWatch.calls.append((args, kw))
        return FakeWatch.script.pop(0)(self)


@scenario
async def test_410_gone_re_lists_and_watches_from_the_new_resource_version(env, monkeypatch=None):
    FakeWatch.script, FakeWatch.calls = [], []
    env.apps.items = [dep()]
    env.agent.running = True

    async def gone(w):
        raise ApiException(status=410, reason="Gone")
        yield

    async def one_event_then_stop(w):
        w.resource_version = "25"
        yield {"type": "MODIFIED", "raw_object": dep(image="img:2")}
        env.agent.running = False

    FakeWatch.script = [gone, one_event_then_stop]
    original = ha.watch.Watch
    ha.watch.Watch = FakeWatch
    try:
        await asyncio.wait_for(env.agent.watch_loop("prod"), 5)
    finally:
        ha.watch.Watch = original
    assert [kw["resource_version"] for _, kw in FakeWatch.calls] == ["10", "20"]      # re-listed after the 410
    assert len(env.apps.list_calls) == 2
    assert all(kw["label_selector"] == "kubeheal.io/watch=true" for _, kw in FakeWatch.calls)
    assert all(kw["label_selector"] == "kubeheal.io/watch=true" for _, kw in env.apps.list_calls)
    assert FakeWatch.calls[0][0] == ("prod",)
    assert KEY in env.agent.pending                    # the event of the second watch was processed


@scenario
async def test_re_list_replays_added_idempotently_and_forgets_deleted_deployments(env):
    env.apps.items = [dep(), dep(name="other")]
    await env.agent.relist("prod")
    assert set(env.agent.seen_hash) == {KEY, ("prod", "other")}
    env.apps.items = [dep()]                           # "other" was deleted while no watch was open
    rv = await env.agent.relist("prod")
    assert set(env.agent.seen_hash) == {KEY} and rv == "20"
    assert env.agent.pending == {}                     # replaying the same specs is no change
    assert baseline.baseline_key("prod", "other") in env.redis.store      # golden baselines are never deleted


@scenario
async def test_a_watch_error_re_lists_instead_of_exiting(env):
    FakeWatch.script, FakeWatch.calls = [], []
    env.agent.running = True
    slept = []

    async def boom(w):
        raise RuntimeError("connection reset")
        yield

    async def stop(w):
        env.agent.running = False
        return
        yield

    FakeWatch.script = [boom, stop]
    original_watch, original_sleep = ha.watch.Watch, ha.asyncio.sleep
    ha.watch.Watch = FakeWatch

    async def fast_sleep(s):
        slept.append(s)

    ha.asyncio.sleep = fast_sleep
    try:
        await env.agent.watch_loop("prod")
    finally:
        ha.watch.Watch, ha.asyncio.sleep = original_watch, original_sleep
    assert len(env.apps.list_calls) == 2 and slept == [1.0]


def test_watch_namespaces_default_and_override(monkeypatch):
    monkeypatch.delenv("WATCH_NAMESPACES", raising=False)
    assert ha.watch_namespaces_from_env() == ["prod", "staging", "dev"]
    monkeypatch.setenv("WATCH_NAMESPACES", " prod , shop ")
    assert ha.watch_namespaces_from_env() == ["prod", "shop"]
    monkeypatch.setenv("WATCH_NAMESPACES", "*")
    assert ha.watch_namespaces_from_env() == [None]


# ---- HPAs ---------------------------------------------------------------------------------------------------
@scenario
async def test_hpas_are_listed_per_namespace_and_a_failure_keeps_the_last_set(env):
    env.agent.autoscaling_api = FakeAutoscaling([("prod", "victim-app"), ("dev", "other")])
    await env.agent.refresh_hpas("prod")
    await env.agent.refresh_hpas("dev")
    assert env.agent.autoscaling_api.calls == ["prod", "dev"]       # never a cluster-wide list
    assert env.agent.hpa == {"prod": {("prod", "victim-app")}, "dev": {("dev", "other")}}
    assert env.agent.hpa_owned(("prod", "victim-app")) and not env.agent.hpa_owned(("prod", "nope"))
    env.agent.autoscaling_api.error = ApiException(status=403, reason="Forbidden")
    await env.agent.refresh_hpas("prod")
    assert env.agent.hpa["prod"] == {("prod", "victim-app")}


# ---- restarts and deletes -----------------------------------------------------------------------------------
@scenario
async def test_a_restart_does_not_assess_a_drifted_spec_that_was_already_assessed(env):
    await env.baseline_then_change(image="img:2")
    await env.tick(60)
    assert len(env.events) == 1
    # a new agent process on the same Redis replays the drifted Deployment as ADDED
    again = Env()
    again.redis.store.update(env.redis.store)
    again.agent.redis = again.redis
    await again.send("ADDED", dep(image="img:2"))
    assert again.agent.pending == {}
    assert KEY in again.agent._drifted                 # but it is tracked for OBSERVE
    await again.send("MODIFIED", dep(image="img:3"))   # a real change is assessed
    assert KEY in again.agent.pending
    await again.agent.stop()


@scenario
async def test_a_restart_assesses_a_drifted_spec_nobody_has_assessed(env):
    await env.send("ADDED", dep())
    again = Env()
    again.redis.store.update(env.redis.store)
    await again.send("ADDED", dep(image="img:2"))
    assert KEY in again.agent.pending
    await again.agent.stop()


@scenario
async def test_deleted_forgets_the_workload_but_keeps_the_golden_baseline(env):
    await env.baseline_then_change(image="img:2")
    await env.send("DELETED", dep(image="img:2"))
    assert env.agent.pending == {} and KEY not in env.agent.seen_hash
    assert baseline.baseline_key(*KEY) in env.redis.store
    await env.tick(120)
    assert env.events == []


# ---- the agent writes nothing to Kubernetes -----------------------------------------------------------------
def test_the_agent_package_makes_no_kubernetes_write_call():
    import re
    from pathlib import Path
    pattern = re.compile(r"\b(create|patch|delete|replace)_(namespaced_\w+|namespace\b|node\b|cluster_\w+)")
    for path in (Path(ha.__file__).parent).glob("*.py"):
        assert not pattern.search(path.read_text(encoding="utf-8")), path.name
