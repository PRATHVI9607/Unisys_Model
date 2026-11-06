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

    async def set(self, key, value, nx=False, px=None):
        self.tokens.append(value)
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def eval(self, script, numkeys, key, token, *args):
        if self.store.get(key) != token:
            return 0
        if script == il.EXTEND_IF_OWNER:
            self.extends += 1
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
    monkeypatch.setattr(il, "HEARTBEAT_S", 0.01)
    r = LockRedis()
    async with il.incident_lock(r, KEY):
        await asyncio.sleep(0.05)
        assert r.extends >= 2
        r.store[KEY] = "other-holder"
        await asyncio.sleep(0.03)                     # heartbeat notices and stops
        frozen = r.extends
        await asyncio.sleep(0.05)
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


async def test_circuit_breaker_limit_and_fixed_window():
    r = fakeredis.FakeAsyncRedis(decode_responses=True)
    key = "kubeheal:cb:kill:prod:web"
    assert await il.circuit_allows(r, key, limit=2)
    assert await il.circuit_allows(r, key, limit=2)
    await r.expire(key, 100)
    assert not await il.circuit_allows(r, key, limit=2)
    assert 0 < await r.ttl(key) <= 100                # later calls don't extend the window
