"""F2: golden baseline written once with SET NX; drift diff is live vs golden."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.health_agent import baseline as bl


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.store:
            return None
        self.store[k] = v
        return True

    async def get(self, k):
        return self.store.get(k)


def spec(cpu="500m", replicas=3):
    return {"replicas": replicas, "template": {"spec": {"containers": [
        {"name": "app", "resources": {"limits": {"cpu": cpu}}}]}}}


def run(coro):
    return asyncio.run(coro)


def test_first_sight_creates_baseline():
    r = FakeRedis()
    golden, created = run(bl.get_or_set_baseline(r, "prod", "web", spec()))
    assert created is True
    assert "kubeheal:baseline:prod:web" in r.store
    assert golden["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"


def test_persistent_drift_never_overwrites_baseline():
    r = FakeRedis()
    run(bl.get_or_set_baseline(r, "prod", "web", spec("500m")))
    golden, created = run(bl.get_or_set_baseline(r, "prod", "web", spec("50m")))
    assert created is False
    assert golden["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"
    run(bl.get_or_set_baseline(r, "prod", "web", spec("50m")))      # still golden after repeats
    stored = json.loads(r.store["kubeheal:baseline:prod:web"])
    assert stored["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"


def test_drift_is_live_vs_golden():
    r = FakeRedis()
    golden, _ = run(bl.get_or_set_baseline(r, "prod", "web", spec("500m")))
    assert bl.is_drifted(golden, spec("500m")) is False
    assert bl.is_drifted(golden, spec("50m")) is True


def test_scaling_is_not_drift():
    r = FakeRedis()
    golden, _ = run(bl.get_or_set_baseline(r, "prod", "web", spec(replicas=3)))
    assert bl.is_drifted(golden, spec(replicas=8)) is False


def test_baselines_are_per_workload():
    r = FakeRedis()
    run(bl.get_or_set_baseline(r, "prod", "web", spec("500m")))
    _, created = run(bl.get_or_set_baseline(r, "prod", "api", spec("100m")))
    assert created is True
    assert run(bl.load_baseline(r, "prod", "missing")) is None
