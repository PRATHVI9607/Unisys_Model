import sys, asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.fusion_agent.incident_lock import acquire_incident_lock, LOCK_TTL_SECONDS

class FakeRedis:
    def __init__(self): self.store={}
    async def set(self,k,v,nx=False,ex=None):
        if nx and k in self.store: return None
        self.store[k]=v; return True
    async def expire(self,k,ttl): return k in self.store
    async def eval(self,script,n,key,token):
        if self.store.get(key)==token: del self.store[key]; return 1
        return 0

def test_lock_acquire_release():
    async def run():
        r=FakeRedis()
        async with acquire_incident_lock(r,"prod","podA") as got:
            assert got is True
            assert "kubeheal:incident-lock:prod:podA" in r.store
        # released after context
        assert "kubeheal:incident-lock:prod:podA" not in r.store
    asyncio.run(run())

def test_lock_contended():
    async def run():
        r=FakeRedis()
        async with acquire_incident_lock(r,"prod","podB") as a:
            assert a is True
            async with acquire_incident_lock(r,"prod","podB") as b:
                assert b is False   # held
    asyncio.run(run())

def test_lock_released_on_exception():
    async def run():
        r=FakeRedis()
        try:
            async with acquire_incident_lock(r,"prod","podC") as got:
                assert got
                raise ValueError("boom")
        except ValueError:
            pass
        assert "kubeheal:incident-lock:prod:podC" not in r.store
    asyncio.run(run())
