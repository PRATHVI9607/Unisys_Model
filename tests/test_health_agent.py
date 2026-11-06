"""Health agent: change detection, debounce, Prometheus parsing, publish / first-sight / inference-down."""

import asyncio
import copy
import json
import logging
from datetime import datetime
from types import SimpleNamespace

import aiohttp
import fakeredis
import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from agents.health_agent import agent as ha
from agents.health_agent import prometheus as prom
from kubeheal.contracts import STREAM_HEALTH, HealthEvent, Prediction, key_baseline, key_event, key_spec
from kubeheal.features.health import canonical_spec


def deployment(cpu="500m", replicas=2, ns="shop", name="web", status=None):
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns, "resourceVersion": "1"},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "app", "image": "nginx:1.27",
                                         "resources": {"limits": {"cpu": cpu, "memory": "256Mi"}}}]},
            },
        },
        "status": status or {"readyReplicas": replicas},
    }


def rolled_out(dep):
    dep["metadata"]["generation"] = 2
    dep["status"] = {"observedGeneration": 2, "updatedReplicas": dep["spec"]["replicas"],
                     "availableReplicas": dep["spec"]["replicas"]}
    return dep


def prediction(label="benign", risk=0.05, uncertain=False):
    return Prediction(model_version="health-test", label=label, risk=risk,
                      probabilities={label: 0.9}, prediction_set=[label], uncertain=uncertain,
                      top_factors=[{"feature": "cpu_limit_ratio", "value": 0.2, "contribution": 1.3}])


@pytest.fixture
async def redis():
    r = fakeredis.FakeAsyncRedis(decode_responses=True)
    yield r
    await r.aclose()


@pytest.fixture
def agent(redis):
    return ha.HealthAgent(redis, session=None, delay_s=0.05, protected=frozenset({"kube-system"}))


@pytest.fixture
def no_prometheus(monkeypatch):
    async def fake_window(*_):
        return {"cpu_usage_cores": [0.1, 0.2]}
    monkeypatch.setattr(ha, "fetch_window", fake_window)


def stub_predict(monkeypatch, result):
    calls = []

    async def fake(session, task, features):
        calls.append((task, features))
        return result
    monkeypatch.setattr(ha, "predict", fake)
    return calls


# ── change detection + debounce ──────────────────────────────────────────────
async def test_status_only_update_is_ignored_and_spec_change_debounced(agent, monkeypatch):
    fired = []

    async def fake_assess(key):
        fired.append((key, agent.latest[key]))
    monkeypatch.setattr(agent, "assess", fake_assess)

    agent.on_event("ADDED", deployment())
    agent.on_event("MODIFIED", deployment(status={"readyReplicas": 1}))   # status noise only
    agent.on_event("MODIFIED", deployment(cpu="100m"))
    agent.on_event("MODIFIED", deployment(cpu="50m"))                     # last change wins
    await asyncio.sleep(0.15)
    assert len(fired) == 1
    key, spec = fired[0]
    assert key == ("shop", "web")
    assert spec == canonical_spec(deployment(cpu="50m"))


async def test_protected_namespace_skipped(agent):
    agent.on_event("ADDED", deployment(ns="kube-system"))
    assert not agent.timers and not agent.latest


async def test_deleted_cleans_up(agent, redis):
    await redis.set(key_spec("shop", "web"), "{}")
    await redis.set(key_baseline("shop", "web"), "{}")
    agent.on_event("ADDED", deployment())
    agent.on_event("DELETED", deployment())
    await asyncio.sleep(0.01)
    assert not agent.timers and ("shop", "web") not in agent.latest
    assert await redis.exists(key_spec("shop", "web"), key_baseline("shop", "web")) == 0


# ── assessment ───────────────────────────────────────────────────────────────
async def test_first_sight_stores_spec_and_baseline_without_assessing(agent, redis, monkeypatch, no_prometheus):
    calls = stub_predict(monkeypatch, prediction())
    agent.latest[("shop", "web")] = canonical_spec(deployment())
    await agent.assess(("shop", "web"))
    assert calls == []
    assert await redis.xlen(STREAM_HEALTH) == 0
    stored = json.loads(await redis.get(key_spec("shop", "web")))
    assert stored == canonical_spec(deployment())
    assert await redis.get(key_baseline("shop", "web")) == await redis.get(key_spec("shop", "web"))


async def test_change_publishes_event_that_round_trips(agent, redis, monkeypatch, no_prometheus):
    old = canonical_spec(deployment())
    await redis.set(key_spec("shop", "web"), json.dumps(old))
    await redis.set(key_baseline("shop", "web"), json.dumps(old))
    calls = stub_predict(monkeypatch, prediction("degradation", 0.7))
    new = canonical_spec(deployment(cpu="50m"))
    agent.latest[("shop", "web")] = new

    await agent.assess(("shop", "web"))

    assert calls and calls[0][0] == "health"
    entries = await redis.xrange(STREAM_HEALTH)
    assert len(entries) == 1
    ev = HealthEvent.from_fields(entries[0][1])
    assert (ev.namespace, ev.workload, ev.label, ev.risk) == ("shop", "web", "degradation", 0.7)
    assert ev.has_baseline and ev.spec_changed
    assert any("resources.limits.cpu" in p for p in ev.changed_fields)
    assert ev.features == calls[0][1]
    assert ev.top_factors[0].feature == "cpu_limit_ratio"
    # hash copy with TTL, spec saved, baseline untouched (not benign)
    assert HealthEvent.from_fields(await redis.hgetall(key_event("health", ev.event_id))) == ev
    assert 0 < await redis.ttl(key_event("health", ev.event_id)) <= 86400
    assert json.loads(await redis.get(key_spec("shop", "web"))) == new
    assert json.loads(await redis.get(key_baseline("shop", "web"))) == old


async def test_window_starts_at_change_and_spans_the_assess_delay(agent, redis, monkeypatch):
    """Train/serve parity: the scored window is [change seen, change seen + delay], as drift_lab collects."""
    spans = []

    async def fake_window(session, url, ns, name, start, end):
        spans.append((start, end))
        return {}
    monkeypatch.setattr(ha, "fetch_window", fake_window)
    stub_predict(monkeypatch, prediction())
    await redis.set(key_spec("shop", "web"), json.dumps(canonical_spec(deployment())))
    monkeypatch.setattr(ha.time, "time", lambda: 5000.0)
    agent.on_event("MODIFIED", deployment(cpu="50m"))
    monkeypatch.setattr(ha.time, "time", lambda: 9999.0)      # assessed late (e.g. a retry): same window
    await agent.assess(("shop", "web"))
    agent.timers.pop(("shop", "web")).cancel()
    assert spans == [(5000.0, 5000.0 + agent.delay_s)]


async def test_benign_certain_updates_baseline_uncertain_does_not(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    old = canonical_spec(deployment())
    await redis.set(key_spec(*key), json.dumps(old))
    stub_predict(monkeypatch, prediction("benign", 0.05, uncertain=True))
    agent.latest[key] = canonical_spec(deployment(replicas=3))
    await agent.assess(key)
    assert await redis.get(key_baseline(*key)) is None

    stub_predict(monkeypatch, prediction("benign", 0.05))
    agent.on_event("MODIFIED", deployment(replicas=4))              # rollout not complete yet
    await agent.assess(key)
    assert await redis.get(key_baseline(*key)) is None               # benign + certain is not enough
    agent.on_event("MODIFIED", rolled_out(deployment(replicas=5)))
    await agent.assess(key)
    agent.timers.pop(key).cancel()
    assert json.loads(await redis.get(key_baseline(*key))) == canonical_spec(deployment(replicas=5))
    assert await redis.xlen(STREAM_HEALTH) == 3


async def test_benign_change_on_top_of_drift_is_not_promoted(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    good, drifted = canonical_spec(deployment()), canonical_spec(deployment(cpu="50m"))
    await redis.set(key_baseline(*key), json.dumps(good))
    await redis.set(key_spec(*key), json.dumps(drifted))         # drift left in place (observe mode)
    answers = iter([prediction("benign"), prediction("degradation", 0.7)])   # vs previous, vs baseline

    async def fake(session, task, features):
        return next(answers)
    monkeypatch.setattr(ha, "predict", fake)
    agent.latest[key] = canonical_spec(deployment(cpu="50m", replicas=3))   # e.g. an autoscaler
    agent.rolled_out[key] = True
    await agent.assess(key)
    assert json.loads(await redis.get(key_baseline(*key))) == good
    assert next(answers, None) is None                                       # both predictions were used


async def test_return_to_baseline_is_not_assessed(agent, redis, monkeypatch, no_prometheus):
    """An AUTO_PATCH restore (or manual rollback) must not be scored as a new drift."""
    key = ("shop", "web")
    good, drifted = canonical_spec(deployment()), canonical_spec(deployment(cpu="20m"))
    await redis.set(key_baseline(*key), json.dumps(good))
    await redis.set(key_spec(*key), json.dumps(drifted))
    calls = stub_predict(monkeypatch, prediction("degradation", 0.6))
    agent.latest[key] = copy.deepcopy(good)
    await agent.assess(key)
    assert calls == [] and await redis.xlen(STREAM_HEALTH) == 0
    assert json.loads(await redis.get(key_spec(*key))) == good


async def test_unchanged_spec_is_not_assessed(agent, redis, monkeypatch, no_prometheus):
    spec = canonical_spec(deployment())
    await redis.set(key_spec("shop", "web"), json.dumps(spec))
    calls = stub_predict(monkeypatch, prediction())
    agent.latest[("shop", "web")] = copy.deepcopy(spec)
    await agent.assess(("shop", "web"))
    assert calls == [] and await redis.xlen(STREAM_HEALTH) == 0


async def test_inference_down_publishes_nothing_and_retries(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    old = canonical_spec(deployment())
    await redis.set(key_spec(*key), json.dumps(old))
    stub_predict(monkeypatch, None)
    agent.latest[key] = canonical_spec(deployment(cpu="50m"))
    await agent.assess(key)
    assert await redis.xlen(STREAM_HEALTH) == 0
    assert json.loads(await redis.get(key_spec(*key))) == old      # change still pending
    assert key in agent.timers                                      # re-assessment scheduled
    agent.timers.pop(key).cancel()


# ── posture policy rule ──────────────────────────────────────────────────────
def posture(dep, **pod):
    dep = copy.deepcopy(dep)
    tpl = dep["spec"]["template"]["spec"]
    sc = pod.pop("container_sc", None)
    if sc:
        tpl["containers"][0]["securityContext"] = sc
    tpl.update(pod)
    return dep


@pytest.mark.parametrize("change,expected", [
    ({}, []),
    ({"container_sc": {"privileged": True}}, ["policy:privileged_added"]),
    ({"container_sc": {"runAsUser": 0}}, ["policy:root_user_added"]),
    ({"container_sc": {"capabilities": {"add": ["SYS_ADMIN"]}}}, ["policy:capabilities_added"]),
    ({"hostPID": True}, ["policy:host_namespace_added"]),
    ({"volumes": [{"name": "h", "hostPath": {"path": "/"}}]}, ["policy:host_path_added"]),
    ({"hostNetwork": True, "container_sc": {"privileged": True}},
     ["policy:privileged_added", "policy:host_namespace_added"]),
])
def test_policy_violations_one_reason_per_posture_feature(change, expected):
    base = canonical_spec(deployment())
    assert ha.policy_violations(base, canonical_spec(posture(deployment(), **change))) == expected


def test_policy_violation_is_relative_to_the_baseline():
    priv = canonical_spec(posture(deployment(), container_sc={"privileged": True}))
    assert ha.policy_violations(priv, priv) == []                          # baseline already privileged


async def test_posture_violation_is_reported_and_never_promoted(agent, redis, monkeypatch, no_prometheus):
    """A model that rates `privileged: true` benign must not make it the AUTO_PATCH restore target."""
    key = ("shop", "web")
    good = canonical_spec(deployment())
    await redis.set(key_baseline(*key), json.dumps(good))
    await redis.set(key_spec(*key), json.dumps(good))
    calls = stub_predict(monkeypatch, prediction("benign", 0.02))
    priv = posture(deployment(), container_sc={"privileged": True})
    agent.on_event("MODIFIED", rolled_out(priv))
    agent.timers.pop(key).cancel()
    await agent.assess(key)
    ev = HealthEvent.from_fields((await redis.xrange(STREAM_HEALTH))[0][1])
    assert ev.failure_reasons == ["policy:privileged_added"] and ev.has_baseline
    assert json.loads(await redis.get(key_baseline(*key))) == good
    assert len(calls) == 1                                                 # no promotion inference

    # Left in place (observe mode), a later benign change on top still carries the violation.
    priv["spec"]["replicas"] = 3
    agent.on_event("MODIFIED", rolled_out(priv))
    agent.timers.pop(key).cancel()
    await agent.assess(key)
    ev = HealthEvent.from_fields((await redis.xrange(STREAM_HEALTH))[-1][1])
    assert ev.failure_reasons == ["policy:privileged_added"]
    assert json.loads(await redis.get(key_baseline(*key))) == good


# ── Prometheus ───────────────────────────────────────────────────────────────
def test_parse_range_matrix_and_missing():
    body = {"status": "success", "data": {"resultType": "matrix", "result": [
        {"metric": {}, "values": [[1, "0.5"], [2, "NaN"], [3, "+Inf"], [4, "0.25"]]}]}}
    assert prom.parse_range(body) == [0.5, 0.25]
    assert prom.parse_range({"status": "success", "data": {"result": []}}) is None
    assert prom.parse_range({"status": "error", "error": "bad"}) is None
    nan_only = {"status": "success", "data": {"result": [{"values": [[1, "NaN"]]}]}}
    assert prom.parse_range(nan_only) is None


def test_queries_scope_to_this_deployment():
    import re
    q = prom.build_queries("shop", "web")
    assert set(q) == {"cpu_usage_cores", "cpu_limit_cores", "cpu_throttled_ratio", "memory_working_set_bytes",
                      "memory_limit_bytes", "request_rate_rps", "error_rate_rps", "latency_p99_s",
                      "restarts_total", "replicas_desired", "replicas_ready"}
    rx = re.compile(prom.pod_regex("web").replace("\\\\", "\\"))
    assert rx.fullmatch("web-7d9f8b6c5-x2x7q")
    assert not rx.fullmatch("web-api-7d9f8b6c5-x2x7q")       # another Deployment sharing the prefix
    assert "*100" not in q["cpu_throttled_ratio"].replace(" ", "")
    assert 'deployment="web"' in q["replicas_desired"]


class FakeResp:
    def __init__(self, body, status=200):
        self.body, self.status = body, status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self.body

    async def text(self):
        return json.dumps(self.body)


class FakeSession:
    """Answers per-metric by matching a PromQL substring; raises for 'boom'."""

    def __init__(self, answers):
        self.answers, self.urls, self.params = answers, [], []

    def get(self, url, params, timeout):
        self.urls.append(url)
        self.params.append(params)
        for needle, ans in self.answers.items():
            if needle in params["query"]:
                if ans == "boom":
                    raise aiohttp.ClientConnectionError("refused")
                return FakeResp(ans)
        return FakeResp({"status": "success", "data": {"resultType": "matrix", "result": []}})


async def test_fetch_window_missing_never_zero(caplog):
    series = {"status": "success", "data": {"resultType": "matrix",
                                            "result": [{"metric": {}, "values": [[1, "0.2"], [2, "0.4"]]}]}}
    session = FakeSession({"container_cpu_usage_seconds_total": series,
                           "container_memory_working_set_bytes": "boom"})
    with caplog.at_level(logging.WARNING):
        w = await prom.fetch_window(session, "http://prom:9090", "shop", "web", 1000.0, 1120.0)
    assert w == {"cpu_usage_cores": [0.2, 0.4]}            # failed / empty metrics are absent, not 0.0
    assert len(session.urls) == len(prom.build_queries("shop", "web"))
    assert all(u == "http://prom:9090/api/v1/query_range" for u in session.urls)
    assert {(p["start"], p["end"], p["step"]) for p in session.params} == {("1000.000", "1120.000", "15")}
    assert any("queries failed" in r.message for r in caplog.records)


# ── watch loop ───────────────────────────────────────────────────────────────
async def test_watch_resumes_with_resource_version_and_relists_after_410(agent, monkeypatch):
    seen_rv, sleeps = [], []
    script = [
        [{"type": "ADDED", "raw_object": deployment()}, {"type": "BOOKMARK", "raw_object": {}}],
        ApiException(status=410, reason="Gone"),
        RuntimeError("apiserver down"),
        asyncio.CancelledError(),
    ]

    class FakeWatch:
        resource_version = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, fn, *args, resource_version=None, **kw):
            seen_rv.append(resource_version)
            step = script.pop(0)
            if isinstance(step, BaseException):
                raise step

            async def gen():
                for ev in step:
                    self.resource_version = "42"
                    yield ev
            return gen()

    real_sleep = asyncio.sleep

    async def fast_sleep(s):
        sleeps.append(s)
        await real_sleep(0)

    monkeypatch.setattr(ha.watch, "Watch", FakeWatch)
    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    apps = SimpleNamespace(list_deployment_for_all_namespaces=None)
    with pytest.raises(asyncio.CancelledError):
        await agent.watch_loop(apps, None)
    assert seen_rv == [None, "42", None, None]             # resume, then full re-list after 410
    assert sleeps == [1.0, 2.0]                            # backoff, never a tight loop
    assert ("shop", "web") in agent.timers
    assert agent.healthy()
    agent.timers.pop(("shop", "web")).cancel()


def test_rollout_complete():
    assert ha.rollout_complete(rolled_out(deployment()))
    assert not ha.rollout_complete(deployment())                                   # no rollout status yet
    stuck = rolled_out(deployment())
    stuck["status"]["availableReplicas"] = 1                                       # e.g. ImagePullBackOff
    assert not ha.rollout_complete(stuck)
    stale = rolled_out(deployment())
    stale["metadata"]["generation"] = 3                                            # controller not caught up
    assert not ha.rollout_complete(stale)
    zero = rolled_out(deployment(replicas=0))
    zero["status"] = {"observedGeneration": 2}                                     # API omits zero counts
    assert not ha.rollout_complete(zero)                       # scaled to zero: no evidence it is good


# ── failed-rollout evidence (fusion's rule-based rollback; not a model feature) ─
def pod(created, waiting=None, last_terminated=None, init=False):
    cs = {"name": "app", "state": {"waiting": {"reason": waiting}} if waiting else {"running": {}},
          "lastState": {"terminated": {"reason": last_terminated}} if last_terminated else {}}
    return {"metadata": {"creationTimestamp": created},
            "status": {("initContainerStatuses" if init else "containerStatuses"): [cs]}}


def test_pod_failure_reasons_only_counts_pods_created_after_the_change():
    since = datetime.fromisoformat("2026-10-17T10:00:00Z").timestamp()
    pods = [pod("2026-10-17T09:00:00Z", waiting="CrashLoopBackOff"),               # old revision: ignored
            pod("2026-10-17T09:59:57Z", waiting="ImagePullBackOff"),               # within clock slack
            pod("2026-10-17T10:00:30Z", last_terminated="OOMKilled"),
            pod("2026-10-17T10:00:31Z", waiting="ContainerCreating"),              # normal start-up
            pod("2026-10-17T10:00:32Z", waiting="CreateContainerConfigError", init=True),
            pod("2026-10-17T10:00:33Z", last_terminated="Completed"),
            {"metadata": {}, "status": {}}]
    assert ha.pod_failure_reasons(pods, since) == {"ImagePullBackOff", "OOMKilled", "CreateContainerConfigError"}


def test_progress_deadline_exceeded_only_for_the_current_generation():
    dep = rolled_out(deployment())
    dep["status"]["conditions"] = [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]
    assert ha.progress_deadline_exceeded(dep)
    dep["metadata"]["generation"] = 3                                              # condition is about the old spec
    assert not ha.progress_deadline_exceeded(dep)
    assert not ha.progress_deadline_exceeded(rolled_out(deployment()))


class FakeCore:
    def __init__(self, items=None, error=None):
        self.items, self.error, self.selectors = items or [], error, []

    async def list_namespaced_pod(self, ns, label_selector, **_):
        self.selectors.append((ns, label_selector))
        if self.error:
            raise self.error
        body = json.dumps({"items": self.items}).encode()

        class Resp:
            async def read(self):
                return body
        return Resp()


async def test_failed_rollout_reasons_are_published(redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    core = FakeCore([pod("2999-01-01T00:00:00Z", waiting="ImagePullBackOff")])
    agent = ha.HealthAgent(redis, session=None, delay_s=0.05, protected=frozenset(), core=core)
    await redis.set(key_spec(*key), json.dumps(canonical_spec(deployment())))
    await redis.set(key_baseline(*key), json.dumps(canonical_spec(deployment())))
    stub_predict(monkeypatch, prediction("benign", 0.05, uncertain=True))
    dep = deployment(cpu="50m")
    dep["status"] = {"conditions": [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]}
    dep["metadata"]["generation"], dep["status"]["observedGeneration"] = 2, 2
    agent.on_event("MODIFIED", dep)
    agent.timers.pop(key).cancel()
    await agent.assess(key)
    ev = HealthEvent.from_fields((await redis.xrange(STREAM_HEALTH))[0][1])
    assert ev.failure_reasons == ["ImagePullBackOff", "ProgressDeadlineExceeded"]
    assert core.selectors == [("shop", "app=web")]


async def test_pod_listing_error_loses_only_pod_evidence(redis):
    agent = ha.HealthAgent(redis, session=None, protected=frozenset(), core=FakeCore(error=ApiException(status=403)))
    assert await agent.failure_reasons(("shop", "web"), canonical_spec(deployment()), 0.0) == []
    agent.core = None                                                            # no core API: no listing at all
    assert await agent.failure_reasons(("shop", "web"), canonical_spec(deployment()), 0.0) == []
