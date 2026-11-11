import asyncio
import json
from types import SimpleNamespace

import numpy as np
import pytest
from kubernetes_asyncio import client as k8s_client

from agents.health_agent import agent as ha
from agents.health_agent import prometheus_client
from agents.health_agent.agent import HealthAgent, observe_base_s_from_env


class FakeRedis:
    def __init__(self, value=None):
        self.value = value

    async def get(self, key):
        return self.value


def deployment(name="victim-app", namespace="prod"):
    return SimpleNamespace(metadata=SimpleNamespace(name=name, namespace=namespace))


def request(factor=3, until_ms=9_999_999_999_999):
    return json.dumps({"factor": factor, "until_ms": until_ms})


def test_observe_base_interval_has_documented_default_and_env_override(monkeypatch):
    monkeypatch.delenv("HEALTH_OBSERVE_BASE_S", raising=False)
    assert observe_base_s_from_env() == 60.0
    monkeypatch.setenv("HEALTH_OBSERVE_BASE_S", "45")
    assert observe_base_s_from_env() == 45.0


def test_observe_base_interval_rejects_invalid_values(monkeypatch):
    for raw in ("0", "-1", "NaN", "inf", "not-a-number"):
        monkeypatch.setenv("HEALTH_OBSERVE_BASE_S", raw)
        try:
            observe_base_s_from_env()
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid HEALTH_OBSERVE_BASE_S={raw!r}")


def test_health_rescheduler_only_rescores_drift_with_active_observe(monkeypatch):
    now = [0.0]
    agent = HealthAgent(observe_base_s=60, clock=lambda: now[0])
    agent.redis = FakeRedis(request())
    dep = deployment()
    agent._drifted[("prod", "victim-app")] = {
        "deployment": dep,
        "last_assessed": 0.0,
    }
    calls = []

    async def handle(event_type, item):
        calls.append((event_type, item))

    monkeypatch.setattr(agent, "handle_deployment_event", handle)

    async def scenario():
        now[0] = 19.9
        await agent.observe_tick()
        assert calls == []
        now[0] = 20.0
        await agent.observe_tick()
        assert calls == [("OBSERVE_SAMPLE", dep)]
        await agent.observe_tick()
        assert len(calls) == 1

    asyncio.run(scenario())


def test_health_rescheduler_does_not_sample_without_observe_request(monkeypatch):
    now = [120.0]
    agent = HealthAgent(observe_base_s=60, clock=lambda: now[0])
    agent.redis = FakeRedis()
    agent._drifted[("prod", "victim-app")] = {
        "deployment": deployment(),
        "last_assessed": 0.0,
    }
    calls = []

    async def handle(*args):
        calls.append(args)

    monkeypatch.setattr(agent, "handle_deployment_event", handle)
    asyncio.run(agent.observe_tick())
    assert calls == []


# ---------------------------------------------------------------------------
# P6-D2 review fixes. The handler tests below run the REAL handle_deployment_event;
# only Redis, Prometheus, the Health Model HTTP call and the Kubernetes API are faked.
# ---------------------------------------------------------------------------


class StoreRedis:
    """Small in-memory Redis: enough for sampling, baseline, cooldown and publishing."""

    def __init__(self):
        self.kv = {}
        self.streams = []

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def setex(self, key, ttl, value):
        self.kv[key] = value

    async def exists(self, key):
        return 1 if key in self.kv else 0

    async def xadd(self, stream, payload):
        self.streams.append((stream, dict(payload)))

    async def hset(self, *a, **k):
        pass

    async def expire(self, *a, **k):
        pass

    async def aclose(self):
        pass


def real_deployment(cpu="500m", name="victim-app", namespace="prod"):
    container = k8s_client.V1Container(
        name="app", image="img:1",
        resources=k8s_client.V1ResourceRequirements(limits={"cpu": cpu}),
    )
    spec = k8s_client.V1DeploymentSpec(
        replicas=1,
        selector=k8s_client.V1LabelSelector(match_labels={"app": name}),
        template=k8s_client.V1PodTemplateSpec(spec=k8s_client.V1PodSpec(containers=[container])),
    )
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace, generation=1, resource_version="1"),
        status=SimpleNamespace(observed_generation=1),
        spec=spec,
    )


class ModelHarness:
    """Fakes for the Prometheus window and the Health Model HTTP call, with call counters."""

    def __init__(self, monkeypatch):
        import aiohttp
        self.window_calls = 0
        self.active = 0
        self.max_active = 0
        self.gate = None          # optional asyncio.Event the Prometheus fake waits on
        self.started = None       # optional asyncio.Event set when the Prometheus fake is entered
        self.model_calls = 0
        harness = self

        async def fake_window(namespace, name, url, *a, **k):
            harness.window_calls += 1
            harness.active += 1
            harness.max_active = max(harness.max_active, harness.active)
            try:
                if harness.started:
                    harness.started.set()
                if harness.gate:
                    await harness.gate.wait()
                return np.zeros((60, 15))
            finally:
                harness.active -= 1

        class Resp:
            status = 200

            async def json(self):
                return {"risk_score": 0.7, "label": "drift", "ci_width": 0.1, "top_field": "limits.cpu"}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def post(self, *a, **k):
                harness.model_calls += 1
                return Resp()

            async def close(self):
                pass            # the real kubernetes ApiClient also builds its session through this fake

        monkeypatch.setattr(prometheus_client, "wait_for_fresh_metric_window", fake_window)
        monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: Session())


def new_agent(**kw):
    agent = HealthAgent(observe_base_s=60, **kw)
    agent.redis = StoreRedis()
    return agent


COOLDOWN_KEY = "kubeheal:cooldown:prod:victim-app"
KEY = ("prod", "victim-app")


async def seed_drift(agent):
    """First sight records the golden baseline; a drifted spec is then tracked and scored."""
    await agent.handle_deployment_event("ADDED", real_deployment("500m"))
    assert KEY not in agent._drifted
    await agent.handle_deployment_event("MODIFIED", real_deployment("50m"))
    assert KEY in agent._drifted


def test_spec_json_uses_one_shared_client_and_stop_closes_it(monkeypatch):
    created, closed = [], []

    class FakeApiClient:
        def __init__(self):
            created.append(self)

        def sanitize_for_serialization(self, obj):
            return {"fake": True}

        async def close(self):
            closed.append(self)

    monkeypatch.setattr(ha.client, "ApiClient", FakeApiClient)

    async def scenario():
        agent = new_agent()
        dep = real_deployment()
        for _ in range(5):
            assert agent._spec_json(dep) == {"fake": True}
        assert len(created) == 1
        assert closed == []
        await agent.stop()
        assert closed == created
        assert agent._serializer is None

    asyncio.run(scenario())


def test_spec_json_output_is_camel_case_with_the_shared_client():
    async def scenario():
        agent = new_agent()
        spec = agent._spec_json(real_deployment("50m"))
        assert spec["template"]["spec"]["containers"][0]["resources"]["limits"] == {"cpu": "50m"}
        assert spec["selector"]["matchLabels"] == {"app": "victim-app"}
        await agent.stop()

    asyncio.run(scenario())


def test_deleted_event_removes_workload_from_tracking(monkeypatch):
    ModelHarness(monkeypatch)

    async def scenario():
        agent = new_agent()
        await seed_drift(agent)
        await agent.handle_deployment_event("DELETED", real_deployment("50m"))
        assert KEY not in agent._drifted
        await agent.stop()

    asyncio.run(scenario())


def test_return_to_baseline_removes_workload_from_tracking(monkeypatch):
    harness = ModelHarness(monkeypatch)

    async def scenario():
        agent = new_agent()
        await seed_drift(agent)
        assert harness.model_calls == 1
        agent.redis.kv.pop(COOLDOWN_KEY)          # cooldown over: the normal (non-cooldown) path
        await agent.handle_deployment_event("MODIFIED", real_deployment("500m"))
        assert KEY not in agent._drifted
        assert harness.model_calls == 1            # a baseline-equal spec is not scored
        await agent.stop()

    asyncio.run(scenario())


def test_cooldown_refreshes_tracked_deployment_and_does_not_rescore(monkeypatch):
    harness = ModelHarness(monkeypatch)

    async def scenario():
        agent = new_agent()
        await seed_drift(agent)
        assert COOLDOWN_KEY in agent.redis.kv
        newer = real_deployment("40m")
        await agent.handle_deployment_event("MODIFIED", newer)
        assert agent._drifted[KEY]["deployment"] is newer
        assert harness.model_calls == 1
        published = len(agent.redis.streams)

        # Still cooling down, but the workload went back to baseline: stop scheduling it.
        await agent.handle_deployment_event("MODIFIED", real_deployment("500m"))
        assert KEY not in agent._drifted
        assert harness.model_calls == 1
        assert len(agent.redis.streams) == published
        await agent.stop()

    asyncio.run(scenario())


def test_observe_sample_skips_while_a_watch_event_is_scoring_the_same_workload(monkeypatch):
    harness = ModelHarness(monkeypatch)

    async def scenario():
        agent = new_agent()
        await agent.handle_deployment_event("ADDED", real_deployment("500m"))
        harness.gate, harness.started = asyncio.Event(), asyncio.Event()
        drifted = real_deployment("50m")
        watch_task = asyncio.create_task(agent.handle_deployment_event("MODIFIED", drifted))
        await harness.started.wait()
        assert harness.window_calls == 1

        # The sample arrives while the watch event is mid-scoring: it must skip, not score.
        await agent.handle_deployment_event("OBSERVE_SAMPLE", drifted)
        assert harness.window_calls == 1

        # A second watch event waits its turn instead of scoring concurrently.
        second = asyncio.create_task(agent.handle_deployment_event("MODIFIED", drifted))
        await asyncio.sleep(0)
        harness.gate.set()
        await asyncio.gather(watch_task, second)
        assert harness.max_active == 1
        await agent.stop()

    asyncio.run(scenario())


def test_watch_event_waits_for_a_sample_that_is_scoring(monkeypatch):
    harness = ModelHarness(monkeypatch)

    async def scenario():
        agent = new_agent()
        await seed_drift(agent)
        agent.redis.kv.pop(COOLDOWN_KEY)
        harness.gate, harness.started = asyncio.Event(), asyncio.Event()
        sample = asyncio.create_task(
            agent.handle_deployment_event("OBSERVE_SAMPLE", real_deployment("50m")))
        await harness.started.wait()
        event = asyncio.create_task(agent.handle_deployment_event("MODIFIED", real_deployment("40m")))
        await asyncio.sleep(0)
        assert not event.done()                   # waiting on the guard, not scoring alongside
        harness.gate.set()
        await asyncio.gather(sample, event)
        assert harness.max_active == 1
        await agent.stop()

    asyncio.run(scenario())


def test_stop_cancels_the_observe_task():
    async def scenario():
        agent = new_agent()
        agent.running = True
        task = asyncio.create_task(agent.observe_loop())
        agent._observe_task = task
        await asyncio.sleep(0)
        await agent.stop()
        assert task.cancelled()
        assert agent._observe_task is None
        assert agent.running is False

    asyncio.run(scenario())


def test_stop_does_not_swallow_an_outer_cancellation():
    async def scenario():
        agent = new_agent()

        async def slow_to_exit():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)     # slow cleanup keeps stop() suspended on the task
                raise

        agent._observe_task = asyncio.create_task(slow_to_exit())
        await asyncio.sleep(0)
        stop_task = asyncio.create_task(agent.stop())
        await asyncio.sleep(0.01)
        stop_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stop_task
        assert stop_task.cancelled()

    asyncio.run(scenario())


def test_start_sets_running_before_creating_the_observe_task(monkeypatch):
    seen = {}

    async def scenario():
        agent = new_agent()
        monkeypatch.setattr(ha, "load_incluster_config", lambda: None)
        for api in ("CoreV1Api", "AppsV1Api", "CustomObjectsApi", "NetworkingV1Api"):
            monkeypatch.setattr(ha.client, api, lambda: object())
        monkeypatch.setattr(ha.aioredis, "from_url", lambda *a, **k: agent.redis)

        async def fake_watch():
            seen["running"] = agent.running
            seen["task"] = agent._observe_task

        monkeypatch.setattr(agent, "watch_deployments", fake_watch)
        await agent.start()
        task = seen["task"]
        assert seen["running"] is True
        assert isinstance(task, asyncio.Task)
        await asyncio.sleep(0)
        assert not task.done()                    # the loop sees running=True and keeps going
        await agent.stop()
        assert task.cancelled()

    asyncio.run(scenario())
