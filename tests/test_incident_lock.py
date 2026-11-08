"""Incident lock ownership + circuit breaker.

fakeredis has no Lua without `lupa`, so the lock runs against a minimal fake whose
eval() mirrors the two owner-checked scripts; the circuit breaker uses fakeredis.
"""

import asyncio

import fakeredis

from agents.fusion_agent import incident_lock as il

KEY = "kubeheal:lock:prod:web"


class LockRedis:
    def __init__(self):
        self.store, self.extends, self.tokens = {}, 0, []
        self.extended_twice, self.rejected = asyncio.Event(), asyncio.Event()

    async def set(self, key, value, nx=False, px=None):
        self.tokens.append(value)
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def eval(self, script, numkeys, key, token, *args):
        if self.store.get(key) != token:
            if script == il.EXTEND_IF_OWNER:
                self.rejected.set()
            return 0
        if script == il.EXTEND_IF_OWNER:
            self.extends += 1
            if self.extends >= 2:
                self.extended_twice.set()
        else:
            assert script == il.RELEASE_IF_OWNER
            del self.store[key]
        return 1


async def test_acquire_release_and_contention():
    r = LockRedis()
    async with il.incident_lock(r, KEY) as held:
        assert held
        async with il.incident_lock(r, KEY) as other:
            assert not other
    assert KEY not in r.store
    async with il.incident_lock(r, KEY) as held:
        assert held
    assert len(set(r.tokens)) == len(r.tokens)        # unique token per holder


async def test_release_never_deletes_someone_elses_lock():
    r = LockRedis()
    async with il.incident_lock(r, KEY):
        r.store[KEY] = "other-holder"                 # ours expired, someone else took it
    assert r.store[KEY] == "other-holder"


async def test_heartbeat_extends_only_while_owner(monkeypatch):
    """Event-driven, no wall-clock assumptions: wait for the extends, then for the rejected one."""
    monkeypatch.setattr(il, "HEARTBEAT_S", 0)
    r = LockRedis()
    async with il.incident_lock(r, KEY):
        await asyncio.wait_for(r.extended_twice.wait(), 5)
        r.store[KEY] = "other-holder"                 # ours expired, someone else took it
        await asyncio.wait_for(r.rejected.wait(), 5)  # the heartbeat returns right after this
        frozen = r.extends
        for _ in range(10):
            await asyncio.sleep(0)
        assert r.extends == frozen
    assert r.store[KEY] == "other-holder"


async def test_lock_released_on_exception():
    r = LockRedis()
    try:
        async with il.incident_lock(r, KEY):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert KEY not in r.store


async def test_circuit_breaker_counts_successes_in_a_fixed_window():
    r = fakeredis.FakeAsyncRedis(decode_responses=True)
    key = "kubeheal:cb:kill:prod:Deployment/web"
    assert not await il.circuit_open(r, key, limit=2)
    assert not await il.circuit_open(r, key, limit=2)    # checking never spends budget
    await il.circuit_count(r, key)
    await il.circuit_count(r, key)
    assert await il.circuit_open(r, key, limit=2)
    await r.expire(key, 100)
    await il.circuit_count(r, key)
    assert 0 < await r.ttl(key) <= 100                # later counts don't extend the window


async def test_circuit_count_never_raises():
    class Down:
        def pipeline(self, transaction):
            raise ConnectionError("redis down")
    await il.circuit_count(Down(), "k")
