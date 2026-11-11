import asyncio
import json
from types import SimpleNamespace

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
