"""Health agent: change detection, debounce, Prometheus parsing, publish / first-sight / inference-down."""

import asyncio
import copy
import json
import logging
import time
from datetime import UTC, datetime
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
    n = dep["spec"]["replicas"]
    dep["status"] = {"observedGeneration": 2, "replicas": n, "updatedReplicas": n, "availableReplicas": n}
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
        return {"cpu_usage_cores": [0.1, 0.2], "replicas_desired": [2.0], "replicas_ready": [2.0]}
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
    assert spec == deployment(cpu="50m")["spec"]                          # API-shaped: the restore target


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
    agent.pollers.pop(("shop", "web")).cancel()
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
    agent.pollers.pop(key).cancel()
    assert json.loads(await redis.get(key_baseline(*key))) == deployment(replicas=5)["spec"]
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
    agent.pollers.pop(key).cancel()
    await agent.assess(key)
    ev = HealthEvent.from_fields((await redis.xrange(STREAM_HEALTH))[0][1])
    assert ev.failure_reasons == ["policy:privileged_added"] and ev.has_baseline
    assert json.loads(await redis.get(key_baseline(*key))) == good
    assert len(calls) == 1                                                 # no promotion inference

    # Left in place (observe mode), a later benign change on top still carries the violation.
    priv["spec"]["replicas"] = 3
    agent.on_event("MODIFIED", rolled_out(priv))
    agent.timers.pop(key).cancel()
    agent.pollers.pop(key).cancel()
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
                      "restarts_total", "replicas_desired", "replicas_ready", "replicas_updated",
                      "replicas_unavailable"}
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
async def test_watch_resumes_with_resource_version_and_relists_after_410(agent, redis, monkeypatch):
    seen_rv, sleeps, lists = [], [], []
    for k in (key_spec("shop", "gone"), key_baseline("shop", "gone"), key_spec("shop", "web")):
        await redis.set(k, "{}")                       # "gone" was deleted while no watch was open
    agent.seen_hash[("shop", "gone")] = "h"
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
    async def list_all(**kw):
        lists.append(kw)
        body = json.dumps({"metadata": {"resourceVersion": "7"}, "items": [deployment()]}).encode()

        class Resp:
            async def read(self):
                return body
        return Resp()
    apps = SimpleNamespace(list_deployment_for_all_namespaces=list_all)
    with pytest.raises(asyncio.CancelledError):
        await agent.watch_loop(apps, None)
    assert seen_rv == ["7", "42", "7", "7"]                # list, resume, then a full re-list after 410
    assert len(lists) == 2
    assert sleeps == [1.0, 2.0]                            # backoff, never a tight loop
    assert await redis.exists(key_spec("shop", "gone"), key_baseline("shop", "gone")) == 0
    assert await redis.exists(key_spec("shop", "web")) == 1 and ("shop", "gone") not in agent.seen_hash
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
OWNED = {"labels": {"app": "web", "pod-template-hash": "5d4f9c"},
         "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d4f9c", "controller": True}]}


def pod(created, waiting=None, last_terminated=None, init=False):
    cs = {"name": "app", "state": {"waiting": {"reason": waiting}} if waiting else {"running": {}},
          "lastState": {"terminated": {"reason": last_terminated}} if last_terminated else {}}
    return {"metadata": {"creationTimestamp": created, **OWNED},
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
    agent.pollers.pop(key).cancel()
    await agent.assess(key)
    ev = HealthEvent.from_fields((await redis.xrange(STREAM_HEALTH))[0][1])
    assert ev.failure_reasons == ["ImagePullBackOff", "ProgressDeadlineExceeded"]
    assert core.selectors == [("shop", "app=web")]


async def test_pod_listing_error_loses_only_pod_evidence(redis):
    agent = ha.HealthAgent(redis, session=None, protected=frozenset(), core=FakeCore(error=ApiException(status=403)))
    assert await agent.failure_reasons(("shop", "web"), canonical_spec(deployment()), 0.0) == []
    agent.core = None                                                            # no core API: no listing at all
    assert await agent.failure_reasons(("shop", "web"), canonical_spec(deployment()), 0.0) == []


# ── early assessment ─────────────────────────────────────────────────────────
async def pending_agent(redis, monkeypatch, core=None, delay=0.5, poll=0.02, **dep):
    """Agent with a stored good spec and a recorded assess() trigger time; change applied now."""
    monkeypatch.setattr(ha, "POLL_S", poll)
    agent = ha.HealthAgent(redis, session=None, delay_s=delay, protected=frozenset(), core=core)
    good = json.dumps(canonical_spec(deployment()))
    await redis.set(key_spec("shop", "web"), good)
    await redis.set(key_baseline("shop", "web"), good)
    fired = []

    async def fake_assess(key):
        fired.append(time.monotonic() - start)
    monkeypatch.setattr(agent, "assess", fake_assess)
    start = time.monotonic()
    agent.on_event("MODIFIED", dep.get("dep") or deployment(cpu="50m"))
    return agent, fired


async def until(cond, limit_s=5.0):
    """Wait for cond() without asserting on wall-clock durations (loaded CI machines stretch them)."""
    async with asyncio.timeout(limit_s):
        while not cond():  # noqa: ASYNC110 - cond() reads plain lists the fakes append to; no event exists
            await asyncio.sleep(0.01)


async def test_posture_violation_is_assessed_immediately(redis, monkeypatch):
    priv = posture(deployment(cpu="50m"), container_sc={"privileged": True})
    agent, fired = await pending_agent(redis, monkeypatch, dep=priv, delay=30)
    await until(lambda: fired)
    assert len(fired) == 1 and fired[0] < 30                           # well before the 30 s deadline
    assert ("shop", "web") not in agent.timers                       # the deadline timer is cancelled


async def test_failed_rollout_appearing_mid_wait_is_assessed_then(redis, monkeypatch):
    core = FakeCore()
    agent, fired = await pending_agent(redis, monkeypatch, core=core, delay=30)
    await until(lambda: core.selectors)
    assert fired == []                                                     # polling, nothing yet
    core.items = [pod("2999-01-01T00:00:00Z", waiting="ContainerCreating")]  # normal start-up: not a failure
    n = len(core.selectors)
    await until(lambda: len(core.selectors) >= n + 3)
    assert fired == []
    core.items = [pod("2999-01-01T00:00:00Z", waiting="ImagePullBackOff")]
    await until(lambda: fired)
    assert len(fired) == 1 and fired[0] < 30


async def test_healthy_rollout_is_assessed_at_the_deadline_and_polling_stops(redis, monkeypatch):
    core = FakeCore([pod("2999-01-01T00:00:00Z", waiting="ContainerCreating")])
    agent, fired = await pending_agent(redis, monkeypatch, core=core, delay=0.3)
    await until(lambda: fired)
    assert len(fired) == 1 and fired[0] >= 0.25                          # the deadline, not early evidence
    n = len(core.selectors)
    assert n >= 1
    await asyncio.sleep(0.1)
    assert len(core.selectors) == n                                      # polling stopped with the assessment


async def test_delete_stops_polling(redis, monkeypatch):
    core = FakeCore()
    agent, fired = await pending_agent(redis, monkeypatch, core=core, delay=5)
    await asyncio.sleep(0.1)
    agent.on_event("DELETED", deployment(cpu="50m"))
    await asyncio.sleep(0.05)
    n = len(core.selectors)
    core.items = [pod("2999-01-01T00:00:00Z", waiting="ImagePullBackOff")]
    await asyncio.sleep(0.1)
    assert len(core.selectors) == n and fired == [] and not agent.pollers


async def test_early_window_ends_at_assess_time(agent, redis, monkeypatch):
    spans = []

    async def fake_window(session, url, ns, name, start, end):
        spans.append((start, end))
        return {}
    monkeypatch.setattr(ha, "fetch_window", fake_window)
    stub_predict(monkeypatch, prediction())
    await redis.set(key_spec("shop", "web"), json.dumps(canonical_spec(deployment())))
    agent.delay_s = 60
    monkeypatch.setattr(ha.time, "time", lambda: 5000.0)
    agent.on_event("MODIFIED", deployment(cpu="50m"))
    monkeypatch.setattr(ha.time, "time", lambda: 5004.0)
    await agent.assess(("shop", "web"))
    agent.timers.pop(("shop", "web")).cancel()
    agent.pollers.pop(("shop", "web")).cancel()
    assert spans == [(5000.0, 5004.0)]


# ── review fixes ─────────────────────────────────────────────────────────────
class SlowCore(FakeCore):
    async def list_namespaced_pod(self, ns, label_selector, **kw):
        await asyncio.sleep(0.4)
        return await super().list_namespaced_pod(ns, label_selector, **kw)


async def test_deadline_timer_cancels_a_slow_poller_so_one_event_is_published(redis, monkeypatch, no_prometheus):
    monkeypatch.setattr(ha, "POLL_S", 0.02)
    core = SlowCore([pod("2999-01-01T00:00:00Z", waiting="ImagePullBackOff")])
    agent = ha.HealthAgent(redis, session=None, delay_s=0.2, protected=frozenset(), core=core)
    good = json.dumps(canonical_spec(deployment()))
    await redis.mset({key_spec("shop", "web"): good, key_baseline("shop", "web"): good})
    stub_predict(monkeypatch, prediction("degradation", 0.7))
    agent.on_event("MODIFIED", deployment(cpu="50m"))
    await asyncio.sleep(1.2)
    assert await redis.xlen(STREAM_HEALTH) == 1 and not agent.pollers


async def test_same_spec_is_not_assessed_twice_concurrently(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    good = json.dumps(canonical_spec(deployment()))
    await redis.mset({key_spec(*key): good, key_baseline(*key): good})
    stub_predict(monkeypatch, prediction("degradation", 0.7))
    agent.latest[key] = canonical_spec(deployment(cpu="50m"))
    await asyncio.gather(agent.assess(key), agent.assess(key))
    assert await redis.xlen(STREAM_HEALTH) == 1


async def test_replayed_unchanged_spec_neither_polls_nor_keeps_a_timer(redis, monkeypatch):
    core = FakeCore()
    agent = ha.HealthAgent(redis, session=None, delay_s=5, protected=frozenset(), core=core)
    await redis.set(key_spec("shop", "web"), json.dumps(canonical_spec(deployment())))
    agent.on_event("ADDED", deployment())
    await asyncio.sleep(0.1)
    assert core.selectors == [] and not agent.timers


class ScriptedCore(FakeCore):
    def __init__(self, script):
        super().__init__()
        self.script = list(script)

    async def list_namespaced_pod(self, ns, label_selector, **kw):
        self.items = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        return await super().list_namespaced_pod(ns, label_selector, **kw)


async def test_transient_failure_needs_two_consecutive_polls(redis, monkeypatch):
    bad = [pod("2999-01-01T00:00:00Z", waiting="ErrImagePull")]
    core = ScriptedCore([bad, [], bad, [], []])
    agent, fired = await pending_agent(redis, monkeypatch, core=core, delay=5)
    await asyncio.sleep(0.25)
    assert fired == []                                          # never two in a row
    core.script = [bad]
    await until(lambda: fired)
    assert len(fired) == 1


async def test_slow_rollout_is_promoted_when_it_completes(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    good = json.dumps(canonical_spec(deployment()))
    await redis.mset({key_spec(*key): good, key_baseline(*key): good})
    stub_predict(monkeypatch, prediction("benign", 0.05))
    agent.on_event("MODIFIED", deployment(cpu="50m"))            # rollout still in progress
    await asyncio.sleep(0.2)
    assert await redis.xlen(STREAM_HEALTH) == 1 and await redis.get(key_baseline(*key)) == good
    agent.on_event("MODIFIED", rolled_out(deployment(cpu="50m")))
    await asyncio.sleep(0.1)
    assert json.loads(await redis.get(key_baseline(*key))) == canonical_spec(deployment(cpu="50m"))


async def test_no_metrics_makes_the_model_verdict_uncertain_and_blocks_promotion(agent, redis, monkeypatch):
    async def empty(*_):
        return {}
    monkeypatch.setattr(ha, "fetch_window", empty)
    key = ("shop", "web")
    good = json.dumps(canonical_spec(deployment()))
    await redis.mset({key_spec(*key): good, key_baseline(*key): good})
    stub_predict(monkeypatch, prediction("benign", 0.05))
    agent.latest[key] = canonical_spec(deployment(cpu="50m"))
    agent.rolled_out[key] = True
    await agent.assess(key)
    (_, fields), = await redis.xrange(STREAM_HEALTH)
    assert HealthEvent.from_fields(fields).uncertain is True
    assert await redis.get(key_baseline(*key)) == good and key not in agent.pending_promo


# ── readiness never passed, follow-up events, unit-typo rule ─────────────────
T0 = datetime.fromisoformat("2026-10-17T10:00:00Z").timestamp()


def rpod(age_s, probe=None, ready=False, deleting=False, created_off=1, extra=None):
    """Pod whose app container started `age_s` before NOW (= T0 + 1000); probe None = no readiness probe."""
    started = datetime.fromtimestamp(T0 + 1000 - age_s, UTC).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    c = {"name": "app", **({"readinessProbe": probe} if probe is not None else {})}
    meta = {"creationTimestamp": datetime.fromtimestamp(T0 + created_off, UTC).strftime("%Y-%m-%dT%H:%M:%S") + "Z",
            **OWNED}
    if deleting:
        meta["deletionTimestamp"] = "2026-10-17T10:05:00Z"
    return {"metadata": meta, "spec": {"containers": [c]}, "status": {
        "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        "containerStatuses": [{"name": "app", "ready": ready, "state": {"running": {"startedAt": started}}}] + (extra or [])}}


def never_ready(pods):
    return "ReadinessNeverPassed" in ha.pod_failure_reasons(pods, T0, now=T0 + 1000)


@pytest.mark.parametrize("probe,age,expected", [
    ({}, 59, False), ({}, 61, True),                                    # defaults 0 + 10x3 + 30 margin = 60 s (= floor)
    ({"periodSeconds": 5, "failureThreshold": 2}, 61, True),            # 10 + 30 = 40 s, floored to 60 s
    ({"initialDelaySeconds": 120, "periodSeconds": 10, "failureThreshold": 3}, 100, False),   # 120+30+30 = 180 s
    ({"initialDelaySeconds": 120, "periodSeconds": 10, "failureThreshold": 3}, 181, True),
    (None, 500, False),                                                 # no probe: never the culprit
])
def test_readiness_budget(probe, age, expected):
    assert never_ready([rpod(age, probe)]) is expected


def test_readiness_ignores_ready_terminating_old_and_not_running_pods():
    assert not never_ready([rpod(500, {}, ready=True)])
    assert not never_ready([rpod(500, {}, deleting=True)])
    assert not never_ready([rpod(500, {}, created_off=-3600)])           # previous ReplicaSet
    waiting = rpod(500, {})
    waiting["status"]["containerStatuses"][0]["state"] = {"waiting": {"reason": "ContainerCreating"}}
    assert not never_ready([waiting])
    # init containers are not app containers; a second probed container that is ready doesn't hide the first
    other = {"name": "side", "ready": True, "state": {"running": {"startedAt": "2026-10-17T10:00:00"}}}
    assert never_ready([rpod(500, {}, extra=[other])])
    p = rpod(500, {})
    p["status"]["initContainerStatuses"] = [{"name": "init", "state": {"terminated": {"exitCode": 0}}}]
    assert never_ready([p])


@pytest.mark.parametrize("old,new,expected", [
    ("500m", "5m", ["policy:cpu_cut_10x"]),
    ("500m", "100m", []),            # 5x rightsizing
    ("500m", "125m", []),            # 4x
    ("2", "100m", []),               # 20x but still a sane value
    ("500m", "50m", []),             # 10x, not below 50m
    ("500m", "49m", ["policy:cpu_cut_10x"]),
])
def test_cpu_cut_rule_limits(old, new, expected):
    assert ha.policy_violations(canonical_spec(deployment(cpu=old)), canonical_spec(deployment(cpu=new))) == expected


def test_cut_rule_covers_requests_and_memory_and_ignores_removal():
    def dep(res):
        d = deployment()
        d["spec"]["template"]["spec"]["containers"][0]["resources"] = res
        return canonical_spec(d)
    base = dep({"requests": {"cpu": "500m", "memory": "512Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}})
    assert ha.policy_violations(base, dep({"requests": {"cpu": "5m", "memory": "512Mi"}})) == ["policy:cpu_cut_10x"]
    assert ha.policy_violations(base, dep({"limits": {"memory": "10Mi"}})) == ["policy:memory_cut_10x"]
    assert ha.policy_violations(base, dep({"limits": {"memory": "128Mi"}})) == []     # 8x
    assert ha.policy_violations(base, dep({})) == []                                   # removed, not cut


async def tracking_agent(redis, monkeypatch, core, predict_result=None):
    monkeypatch.setattr(ha, "POLL_S", 0.02)

    async def window(*_):
        return {"cpu_usage_cores": [0.1, 0.2], "replicas_desired": [2.0], "replicas_ready": [2.0]}
    monkeypatch.setattr(ha, "fetch_window", window)
    stub_predict(monkeypatch, predict_result or prediction("benign", 0.05))
    agent = ha.HealthAgent(redis, session=None, delay_s=0.05, protected=frozenset(), core=core)
    good = json.dumps(canonical_spec(deployment()))
    await redis.mset({key_spec("shop", "web"): good, key_baseline("shop", "web"): good})
    return agent


async def events(redis):
    return [HealthEvent.from_fields(f) for _, f in await redis.xrange(STREAM_HEALTH)]


async def test_late_failure_publishes_one_follow_up_and_blocks_promotion(redis, monkeypatch):
    key = ("shop", "web")
    core = FakeCore()
    agent = await tracking_agent(redis, monkeypatch, core)
    agent.on_event("MODIFIED", deployment(cpu="400m"))                   # rollout unfinished
    await asyncio.sleep(0.2)
    first, = await events(redis)
    assert first.failure_reasons == [] and key in agent.trackers and key in agent.pending_promo
    core.items = [pod("2999-01-01T00:00:00Z", waiting="ImagePullBackOff")]
    await asyncio.sleep(0.3)                                             # many polls: still only one follow-up
    evs = await events(redis)
    assert len(evs) == 2
    assert evs[1].failure_reasons == ["ImagePullBackOff"] and evs[1].spec_changed and evs[1].has_baseline
    assert evs[1].changed_fields == first.changed_fields and evs[1].event_id != first.event_id
    assert key not in agent.pending_promo
    agent.on_event("MODIFIED", rolled_out(deployment(cpu="400m")))        # late completion must not promote either
    await asyncio.sleep(0.05)
    assert json.loads(await redis.get(key_baseline(*key))) == canonical_spec(deployment())


async def test_progress_deadline_after_first_event_reaches_fusion(redis, monkeypatch):
    agent = await tracking_agent(redis, monkeypatch, FakeCore())
    agent.on_event("MODIFIED", deployment(cpu="400m"))
    await asyncio.sleep(0.2)
    stalled = deployment(cpu="400m")
    stalled["metadata"]["generation"] = 2
    stalled["status"] = {"observedGeneration": 2, "conditions": [
        {"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]}
    agent.on_event("MODIFIED", stalled)                                  # same spec: status only
    await asyncio.sleep(0.2)
    evs = await events(redis)
    assert [e.failure_reasons for e in evs] == [[], ["ProgressDeadlineExceeded"]]


async def test_readiness_before_first_assessment_fires_it_early(redis, monkeypatch):
    core = FakeCore([rpod(0, {})])
    core.items[0]["status"]["containerStatuses"][0]["state"]["running"]["startedAt"] = "2000-01-01T00:00:00Z"
    core.items[0]["metadata"]["creationTimestamp"] = "2999-01-01T00:00:00Z"
    agent = await tracking_agent(redis, monkeypatch, core)
    agent.delay_s = 5
    agent.on_event("MODIFIED", deployment(cpu="400m"))
    await asyncio.sleep(0.3)
    evs = await events(redis)
    assert len(evs) == 1 and evs[0].failure_reasons == ["ReadinessNeverPassed"]


async def test_supersede_completion_and_delete_stop_tracking(redis, monkeypatch):
    key = ("shop", "web")
    agent = await tracking_agent(redis, monkeypatch, FakeCore())
    agent.on_event("MODIFIED", deployment(cpu="400m"))
    await asyncio.sleep(0.2)
    first = agent.trackers[key]
    agent.on_event("MODIFIED", deployment(cpu="300m"))                   # superseded
    await asyncio.sleep(0.01)
    assert first.cancelled() or first.done()
    await asyncio.sleep(0.2)
    second = agent.trackers[key]
    agent.on_event("MODIFIED", rolled_out(deployment(cpu="300m")))       # rollout done
    await asyncio.sleep(0.1)
    assert second.done() and key not in agent.trackers
    agent.on_event("MODIFIED", deployment(cpu="200m"))
    await asyncio.sleep(0.2)
    assert key in agent.trackers
    agent.on_event("DELETED", deployment(cpu="200m"))
    await asyncio.sleep(0.01)
    assert key not in agent.trackers


async def test_tracking_ends_at_the_cap(redis, monkeypatch):
    monkeypatch.setattr(ha, "TRACK_MARGIN_S", 0)
    agent = await tracking_agent(redis, monkeypatch, FakeCore())
    d = deployment(cpu="400m")
    d["spec"]["progressDeadlineSeconds"] = 0.3
    agent.on_event("MODIFIED", d)
    await asyncio.sleep(0.2)
    assert ("shop", "web") in agent.trackers
    await asyncio.sleep(0.4)
    assert ("shop", "web") not in agent.trackers


# ── review round 2 ───────────────────────────────────────────────────────────
def test_rollout_complete_counts_no_old_replicaset_pod():
    # replicas 1, maxSurge 1 / maxUnavailable 0: the new pod exists (updated 1) but the available one is the OLD pod
    surging = rolled_out(deployment(replicas=1))
    surging["status"] |= {"replicas": 2, "updatedReplicas": 1, "availableReplicas": 1}
    assert not ha.rollout_complete(surging)
    surging["status"] |= {"replicas": 1}                                           # old pod gone, new one available
    assert ha.rollout_complete(surging)
    surging["status"] |= {"availableReplicas": 0}
    assert not ha.rollout_complete(surging)


def test_pod_regex_excludes_sibling_workloads():
    import re
    rx = re.compile(prom.pod_regex("web").replace("\\\\", "\\"))
    assert rx.fullmatch("web-7d9f8b6c5-x2x7q") and rx.fullmatch("web-5b-x2x7q")
    for sibling in ("web-migrate-abcde", "web-db-0", "web-agent-k8s2z", "web-7d9f8b6c5-x2x7", "web-api-7d9f8b6c5-x2x7q"):
        assert not rx.fullmatch(sibling), sibling


async def test_failure_reasons_ignore_pods_of_an_overlapping_deployment(redis):
    canary = pod("2999-01-01T00:00:00Z", waiting="CrashLoopBackOff")
    canary["metadata"] = {**canary["metadata"], "labels": {"app": "web", "track": "canary", "pod-template-hash": "6c8"},
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "web-canary-6c8"}]}
    unowned = pod("2999-01-01T00:00:00Z", waiting="ImagePullBackOff")
    unowned["metadata"] = {"creationTimestamp": "2999-01-01T00:00:00Z"}
    agent = ha.HealthAgent(redis, session=None, protected=frozenset(), core=FakeCore([canary, unowned]))
    assert await agent.failure_reasons(("shop", "web"), deployment()["spec"], 0.0) == []
    agent.core.items.append(pod("2999-01-01T00:00:00Z", waiting="ErrImagePull"))   # this Deployment's own pod
    assert await agent.failure_reasons(("shop", "web"), deployment()["spec"], 0.0) == ["ErrImagePull"]


async def test_churn_cannot_postpone_the_assessment_past_the_first_change(agent, monkeypatch):
    key, now = ("shop", "web"), [1000.0]
    monkeypatch.setattr(ha.time, "time", lambda: now[0])
    agent.delay_s = 60
    loop = asyncio.get_running_loop()
    for i, t in enumerate((1000.0, 1050.0, 1059.0)):                    # annotation churn every few seconds
        now[0] = t
        d = deployment()
        d["spec"]["template"]["metadata"]["annotations"] = {"rev": str(i)}
        agent.on_event("MODIFIED", d)
    assert agent.changed_at[key] == 1000.0                               # the window starts at the first change
    assert agent.timers[key].when() - loop.time() <= 1.0                 # due at 1060, not 1059 + 60
    agent._forget(key)


async def test_hpa_scaling_is_not_drift_and_never_in_changed_fields(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    calls = stub_predict(monkeypatch, prediction("benign", 0.05))
    agent.hpa["*"] = {key}
    good = json.dumps(deployment(replicas=2)["spec"])
    await redis.mset({key_spec(*key): good, key_baseline(*key): good})
    agent.on_event("ADDED", deployment(replicas=2))
    h = agent.seen_hash[key]
    agent.on_event("MODIFIED", deployment(replicas=7))                    # the HPA scaled it
    assert agent.seen_hash[key] == h
    agent.on_event("MODIFIED", deployment(replicas=9, cpu="300m"))       # a real change on top
    agent.timers.pop(key).cancel()
    agent.pollers.pop(key).cancel()
    await agent.assess(key)
    ev, = [HealthEvent.from_fields(f) for _, f in await redis.xrange(STREAM_HEALTH)]
    assert "replicas" not in ev.changed_fields and calls[0][1]["replicas_ratio"] == 1.0


async def test_hpa_listing_and_failure(agent):
    class Auto:
        error = None

        async def list_horizontal_pod_autoscaler_for_all_namespaces(self, **_):
            if self.error:
                raise self.error
            body = json.dumps({"items": [
                {"metadata": {"namespace": "shop"}, "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "web"}}},
                {"metadata": {"namespace": "shop"}, "spec": {"scaleTargetRef": {"kind": "StatefulSet", "name": "db"}}},
            ]}).encode()

            class Resp:
                async def read(self):
                    return body
            return Resp()
    auto = Auto()
    await agent.refresh_hpas(auto, None)
    assert agent.hpa == {"*": {("shop", "web")}}
    auto.error = ApiException(status=403)                                 # missing RBAC: keep the last known set
    await agent.refresh_hpas(auto, None)
    assert agent.hpa == {"*": {("shop", "web")}}


async def test_baseline_keeps_user_data_keys_for_restore(agent, redis, monkeypatch, no_prometheus):
    key = ("shop", "web")
    d = deployment()
    d["spec"]["template"]["spec"]["volumes"] = [{"name": "blob", "csi": {
        "driver": "blob.csi.azure.com", "volumeAttributes": {"storage_account": "acct", "container_name": "c"}}}]
    agent.on_event("ADDED", d)
    agent.timers.pop(key).cancel()
    agent.pollers.pop(key).cancel()
    await agent.assess(key)                                              # first sight
    attrs = json.loads(await redis.get(key_baseline(*key)))["template"]["spec"]["volumes"][0]["csi"]["volumeAttributes"]
    assert attrs == {"storage_account": "acct", "container_name": "c"}
    # a baseline stored by an older agent (canonical form) still matches the same spec: no spurious assessment
    await redis.set(key_spec(*key), json.dumps(canonical_spec(d)))
    agent.latest[key] = d["spec"]
    calls = stub_predict(monkeypatch, prediction())
    await agent.assess(key)
    assert calls == [] and await redis.xlen(STREAM_HEALTH) == 0


async def test_window_start_is_read_with_the_spec(agent, redis, monkeypatch):
    key, spans = ("shop", "web"), []

    async def fake_window(session, url, ns, name, start, end):
        spans.append(start)
        return {}
    monkeypatch.setattr(ha, "fetch_window", fake_window)
    stub_predict(monkeypatch, prediction())
    await redis.set(key_spec(*key), json.dumps(deployment()["spec"]))
    agent.latest[key], agent.changed_at[key] = deployment(cpu="50m")["spec"], 1000.0
    real_get = redis.get

    async def get(k):
        agent.changed_at[key] = 2000.0                                   # a newer change lands during the await
        return await real_get(k)
    monkeypatch.setattr(redis, "get", get)
    await agent.assess(key)
    assert spans == [1000.0]
