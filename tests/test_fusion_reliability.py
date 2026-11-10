"""F3 (explicit workload), F4 (ack only on success), F5 (unique lock token), F8 (CONTAIN naming)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.fusion_agent import agent as fusion
from agents.fusion_agent import decision_policy as dp
from agents.fusion_agent.incident_lock import acquire_incident_lock, LOCK_PREFIX


class FakeRedis:
    def __init__(self):
        self.acked, self.added, self.store = [], [], {}

    async def xack(self, stream, group, msg_id):
        self.acked.append((stream, msg_id))

    async def xadd(self, stream, fields):
        self.added.append((stream, fields))

    async def get(self, k):
        return self.store.get(k)

    async def incr(self, k):
        self.store[k] = int(self.store.get(k, 0)) + 1
        return self.store[k]

    async def expire(self, k, ttl):
        return True

    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.store:
            return None
        self.store[k] = v
        return True

    async def eval(self, script, n, key, token, *extra):
        if self.store.get(key) != token:
            return 0
        if "expire" in script:
            return 1
        del self.store[key]
        return 1


def run(c):
    return asyncio.run(c)


def agent_with_fake_redis():
    a = fusion.FusionAgentV4()
    a.redis = FakeRedis()
    return a


def test_key_uses_explicit_deployment_not_pod_suffix():
    a = fusion.FusionAgentV4()
    ev = {"namespace": "prod", "deployment": "payment-api-svc", "pod_name": "payment-api-svc-7d9f-xk2"}
    assert a._key(ev) == "prod:payment-api-svc"
    # health and security events for the same workload pair up under the same key
    assert a._key({"namespace": "prod", "deployment": "payment-api-svc", "pod_name": "other-pod"}) == a._key(ev)


def test_ack_only_after_success():
    a = agent_with_fake_redis()
    ok = run(a._handle_entry(fusion.SEC_STREAM, "1-0", {
        "namespace": "dev", "deployment": "web", "pod_name": "web-abc-1", "sec_risk": "0.1"}))
    assert ok is True and a.redis.acked == [(fusion.SEC_STREAM, "1-0")]


def test_failed_handler_is_not_acked():
    a = agent_with_fake_redis()

    async def boom(_):
        raise RuntimeError("downstream failure")

    a._on_security = boom
    ok = run(a._handle_entry(fusion.SEC_STREAM, "2-0", {"namespace": "dev"}))
    assert ok is False and a.redis.acked == []


def test_lock_token_is_unique_and_owner_checked():
    async def go():
        r = FakeRedis()
        key = f"{LOCK_PREFIX}:prod:web"
        async with acquire_incident_lock(r, "prod", "web") as got:
            assert got is True
            token_a = r.store[key]
            assert token_a != "1" and len(token_a) >= 16
            # another replica trying to release with its own token must not remove ours
            assert await r.eval("", 1, key, "some-other-token") == 0
            assert key in r.store
        assert key not in r.store
        async with acquire_incident_lock(r, "prod", "web") as got:
            assert r.store[key] != token_a      # fresh token for the next incident
    run(go())


def test_contain_naming_everywhere():
    assert hasattr(dp.Decision, "AUTO_CONTAIN") and hasattr(dp.Decision, "HUMAN_CONTAIN")
    assert not hasattr(dp.Decision, "AUTO_KILL")
    assert not hasattr(dp.Thresholds, "RANSOMWARE_DIRECT_KILL")
    assert hasattr(dp, "CB_CONTAIN_LIMIT_PER_HOUR")


# ---- P1 review fixes: circuit breaker accounting and pod target ----
from types import SimpleNamespace


def _out(decision, dry_run):
    return SimpleNamespace(decision=decision, dry_run=dry_run, adjusted_score=0.9, rationale="t",
                           action_params={})


def _inp():
    return SimpleNamespace(health_field_top="", namespace_tier="prod")


def test_dry_run_does_not_use_circuit_breaker_budget():
    a = agent_with_fake_redis()
    run(a._execute("prod", "web", "web-abc-1", _out(dp.Decision.AUTO_CONTAIN, True), _inp(), []))
    run(a._execute("prod", "web", "", _out(dp.Decision.AUTO_PATCH, True), _inp(), []))
    assert a.redis.store.get("kubeheal:cb:contain:prod") is None
    assert a.redis.store.get("kubeheal:cb:patch:prod:web") is None


def test_enforced_actions_count_after_queueing():
    a = agent_with_fake_redis()
    run(a._execute("prod", "web", "web-abc-1", _out(dp.Decision.AUTO_CONTAIN, False), _inp(), []))
    run(a._execute("prod", "web", "", _out(dp.Decision.AUTO_PATCH, False), _inp(), []))
    assert int(a.redis.store["kubeheal:cb:contain:prod"]) == 1
    assert int(a.redis.store["kubeheal:cb:patch:prod:web"]) == 1


def test_contain_without_pod_is_not_queued():
    a = agent_with_fake_redis()
    run(a._execute("prod", "web", "", _out(dp.Decision.AUTO_CONTAIN, False), _inp(), []))
    assert a.redis.store.get("kubeheal:cb:contain:prod") is None
    assert not any(s == fusion.EXEC_STREAM for s, _ in getattr(a.redis, "added", []))
