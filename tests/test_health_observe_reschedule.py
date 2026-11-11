"""P6-D2 re-applied on the V5-D4 Health Agent (owner decision D7): the OBSERVE lifecycle.

An OBSERVE request from Fusion (a bounded Redis key) triples the sampling of a DRIFTED workload. No periodic
assessment runs without a request. Every sample does a LIVE read of the Deployment and scores that current spec
(the stale-object fix). The cooldown and the per-workload lock of the old agent are gone: the per-workload
debounce and the in-flight guard replace them."""
import asyncio
import json

import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from health_helpers import KEY, Env, dep
from agents.health_agent import agent as ha
from agents.health_agent.agent import HealthAgent, observe_base_s_from_env

SAMPLING_KEY = "kubeheal:sampling:prod:workload:victim-app"


def run(coro):
    return asyncio.run(coro)


def request(factor=3, until_ms=9_999_999_999_999):
    return json.dumps({"factor": factor, "until_ms": until_ms})


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


async def drifted(env, **change):
    """Golden baseline, one drifted change, assessed at its deadline: the workload is now tracked."""
    await env.baseline_then_change(**(change or {"image": "img:2"}))
    await env.tick(60)
    assert KEY in env.agent._drifted
    return len(env.events)


def test_observe_base_interval_has_documented_default_and_env_override(monkeypatch):
    monkeypatch.delenv("HEALTH_OBSERVE_BASE_S", raising=False)
    assert observe_base_s_from_env() == 60.0
    monkeypatch.setenv("HEALTH_OBSERVE_BASE_S", "45")
    assert observe_base_s_from_env() == 45.0


def test_observe_base_interval_rejects_invalid_values(monkeypatch):
    for raw in ("0", "-1", "NaN", "inf", "not-a-number"):
        monkeypatch.setenv("HEALTH_OBSERVE_BASE_S", raw)
        with pytest.raises(ValueError):
            observe_base_s_from_env()


@scenario
async def test_rescheduler_only_samples_drift_with_an_active_observe_request(env):
    env.apps.live[KEY] = dep(image="img:2")
    await drifted(env)
    base = len(env.events)
    # no request: no periodic assessment, however much time passes
    await env.tick(600)
    assert len(env.apps.reads) == 0 and len(env.events) == base
    # with a request the interval is the base interval divided by the factor (60 / 3 = 20 s); the last
    # assessment is long ago, so the first sample is due at once
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(0)
    assert len(env.apps.reads) == 1 and len(env.events) == base + 1
    await env.tick(19)
    assert len(env.apps.reads) == 1
    await env.tick(1)
    assert len(env.apps.reads) == 2 and len(env.events) == base + 2


@scenario
async def test_an_expired_request_stops_the_sampling(env):
    env.apps.live[KEY] = dep(image="img:2")
    await drifted(env)
    env.redis.store[SAMPLING_KEY] = request(until_ms=1)
    await env.tick(600)
    assert env.apps.reads == []


@scenario
async def test_a_workload_at_its_baseline_is_not_sampled(env):
    await env.send("ADDED", dep())
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(600)
    assert env.apps.reads == [] and env.events == []


@scenario
async def test_every_sample_does_a_live_read_and_scores_the_current_spec(env):
    # The watch delivered cpu 250m; by the time of the sample the live Deployment says 300m.
    await env.send("ADDED", dep(cpu="500m"))
    await env.send("MODIFIED", dep(cpu="250m"))
    await env.tick(60)
    assert env.predictions[-1]["cpu_limit_ratio"] == pytest.approx(0.5)
    env.apps.live[KEY] = dep(cpu="300m")
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(20)
    assert env.predictions[-1]["cpu_limit_ratio"] == pytest.approx(0.6)      # the live spec, not the event's
    assert len(env.apps.reads) == 1
    env.apps.live[KEY] = dep(cpu="350m")
    await env.tick(20)
    assert len(env.apps.reads) == 2                                          # one live read PER sample
    assert env.predictions[-1]["cpu_limit_ratio"] == pytest.approx(0.7)
    ns, name, kw = env.apps.reads[0]
    assert (ns, name) == KEY and kw["_preload_content"] is False
    # the watch event for that same live spec arriving later is not a new change
    await env.send("MODIFIED", dep(cpu="350m"))
    assert env.agent.pending == {}


@scenario
async def test_a_sample_window_is_the_trailing_assess_delay(env):
    env.apps.live[KEY] = dep(image="img:2")
    await drifted(env)
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(20)
    ns, name, start, end = env.windows[-1]
    assert end == env.clock.wall() and start == end - 60


@scenario
async def test_a_deleted_workload_is_dropped_from_tracking_on_404(env):
    await drifted(env)
    env.apps.read_error = ApiException(status=404, reason="Not Found")
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(20)
    assert KEY not in env.agent._drifted and KEY not in env.agent.seen_hash


@scenario
async def test_another_read_error_skips_the_sample_and_keeps_tracking(env):
    base = await drifted(env)
    env.apps.read_error = ApiException(status=500, reason="boom")
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(20)
    assert KEY in env.agent._drifted and len(env.events) == base


@scenario
async def test_a_sample_that_finds_the_workload_back_at_baseline_untracks_it(env):
    base = await drifted(env)
    env.apps.live[KEY] = dep()                         # restored to the golden spec in the meantime
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(20)
    assert KEY not in env.agent._drifted and len(env.events) == base       # nothing is scored


@scenario
async def test_a_sample_skips_while_an_assessment_of_the_workload_is_in_flight(env):
    env.apps.live[KEY] = dep(image="img:2")
    await env.baseline_then_change(image="img:2")
    env.gate = asyncio.Event()
    env.clock.advance(60)
    await env.agent.tick()
    for _ in range(20):
        await asyncio.sleep(0)
    assert env.active == 1                             # the debounce assessment is mid-scoring
    env.agent._drifted[KEY] = {"hash": "x", "t0_wall": 0.0, "last_assessed": -1e9}
    env.redis.store[SAMPLING_KEY] = request()
    await env.agent.observe_tick()
    await asyncio.sleep(0)
    for _ in range(20):
        await asyncio.sleep(0)
    assert env.apps.reads == []                        # the sample yielded
    env.gate.set()
    await env.agent.drain()
    assert env.max_active == 1


@scenario
async def test_a_debounce_assessment_waits_for_a_sample_that_is_scoring(env):
    env.apps.live[KEY] = dep(image="img:2")
    await drifted(env)
    env.gate = asyncio.Event()
    env.redis.store[SAMPLING_KEY] = request()
    env.clock.advance(20)
    await env.agent.tick()
    for _ in range(20):
        await asyncio.sleep(0)
    assert env.active == 1
    await env.send("MODIFIED", dep(image="img:3"))
    env.clock.advance(60)
    env.agent.pending[KEY].deadline = env.clock.t       # due now
    await env.agent.tick()
    for _ in range(20):
        await asyncio.sleep(0)
    assert env.active == 1                              # not scoring alongside the sample
    env.gate.set()
    await env.agent.drain()
    for _ in range(3):
        await env.tick(ha.POLL_S)                       # the waiting assessment is retried
    assert env.max_active == 1
    # The sample for image:2 became stale when image:3 arrived while scoring was in
    # flight. Only the original image:2 assessment and the current image:3 assessment
    # should be published.
    assert len(env.events) == 2
    assert env.redis.store[env.agent._assessed_key(KEY)] == env.agent.seen_hash[KEY]


@scenario
async def test_a_failed_sample_does_not_publish_a_fabricated_score(env):
    base = await drifted(env)
    env.result = None
    env.apps.live[KEY] = dep(image="img:2")
    env.redis.store[SAMPLING_KEY] = request()
    await env.tick(20)
    new = env.events[base:]
    assert len(new) == 1 and new[0]["model_unavailable"] == "true" and "health_risk" not in new[0]
    await env.agent.observe_sample(KEY)                 # another sample of the same spec is deduplicated
    assert len(env.events) == base + 1


# ---- lifecycle ----------------------------------------------------------------------------------------------
def test_spec_json_uses_one_shared_client_and_stop_closes_it(monkeypatch):
    from types import SimpleNamespace
    created, closed = [], []

    class FakeApiClient:
        def __init__(self):
            created.append(self)

        def sanitize_for_serialization(self, obj):
            return {"fake": True}

        async def close(self):
            closed.append(self)

    monkeypatch.setattr(ha.client, "ApiClient", FakeApiClient)

    async def scenario_():
        agent = HealthAgent(redis_url="redis://unused")
        d = SimpleNamespace(spec=object())
        for _ in range(5):
            assert agent._spec_json(d) == {"fake": True}
            assert agent._dep_json(d) == {"fake": True}
        assert len(created) == 1 and closed == []
        await agent.stop()
        assert closed == created and agent._serializer is None

    run(scenario_())


def test_dep_json_output_is_camel_case_with_the_shared_client():
    from kubernetes_asyncio import client as k8s

    async def scenario_():
        agent = HealthAgent(redis_url="redis://unused")
        spec = k8s.V1DeploymentSpec(
            replicas=1, selector=k8s.V1LabelSelector(match_labels={"app": "x"}),
            template=k8s.V1PodTemplateSpec(spec=k8s.V1PodSpec(containers=[k8s.V1Container(
                name="app", image="img:1", resources=k8s.V1ResourceRequirements(limits={"cpu": "50m"}))])))
        out = agent._dep_json(k8s.V1Deployment(metadata=k8s.V1ObjectMeta(name="x", namespace="prod"), spec=spec))
        assert out["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"] == {"cpu": "50m"}
        assert out["spec"]["selector"]["matchLabels"] == {"app": "x"}
        assert agent._spec_json(k8s.V1Deployment(spec=spec))["selector"]["matchLabels"] == {"app": "x"}
        await agent.stop()

    run(scenario_())


def test_stop_cancels_the_scheduler_task():
    async def scenario_():
        agent = HealthAgent(redis_url="redis://unused")
        agent.running = True
        agent._scheduler_task = asyncio.create_task(agent.scheduler_loop())
        task = agent._scheduler_task
        await asyncio.sleep(0)
        await agent.stop()
        assert task.cancelled() and agent._scheduler_task is None and agent.running is False

    run(scenario_())


def test_stop_does_not_swallow_an_outer_cancellation():
    async def scenario_():
        agent = HealthAgent(redis_url="redis://unused")

        async def slow_to_exit():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)     # slow cleanup keeps stop() suspended on the task
                raise

        agent._scheduler_task = asyncio.create_task(slow_to_exit())
        await asyncio.sleep(0)
        stop_task = asyncio.create_task(agent.stop())
        await asyncio.sleep(0.01)
        stop_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stop_task
        assert stop_task.cancelled()

    run(scenario_())


def test_start_sets_running_before_creating_the_scheduler_and_shares_one_api_client(monkeypatch):
    seen = {}

    async def scenario_():
        env = Env()
        agent = env.agent
        monkeypatch.setattr(ha, "load_incluster_config", lambda: None)
        built = []

        class FakeApiClient:
            async def close(self):
                pass

        monkeypatch.setattr(ha.client, "ApiClient", FakeApiClient)
        for api in ("CoreV1Api", "AppsV1Api", "NetworkingV1Api", "AutoscalingV2Api"):
            monkeypatch.setattr(ha.client, api, lambda c, api=api: built.append((api, c)) or object())
        monkeypatch.setattr(ha.aioredis, "from_url", lambda *a, **k: env.redis)

        class FakeSession:
            async def close(self):
                pass

        monkeypatch.setattr(ha.aiohttp, "ClientSession", lambda *a, **k: FakeSession())
        monkeypatch.setenv("WATCH_NAMESPACES", "prod,dev")
        scopes = []

        async def fake_watch(scope):
            seen["running"] = agent.running
            seen["task"] = agent._scheduler_task
            scopes.append(scope)

        async def fake_refresh(scope):
            seen.setdefault("refreshed", []).append(scope)

        async def fake_hpa(scope):
            pass

        monkeypatch.setattr(agent, "watch_loop", fake_watch)
        monkeypatch.setattr(agent, "hpa_loop", fake_hpa)
        monkeypatch.setattr(agent, "refresh_hpas", fake_refresh)
        await agent.start()
        task = seen["task"]
        assert seen["running"] is True and isinstance(task, asyncio.Task)
        assert scopes == ["prod", "dev"] and seen["refreshed"] == ["prod", "dev"]
        assert len({id(c) for _, c in built}) == 1 and len(built) == 4        # one shared ApiClient
        await asyncio.sleep(0)
        assert not task.done()
        await agent.stop()
        assert task.cancelled()

    run(scenario_())
