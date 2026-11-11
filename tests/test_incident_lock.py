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
    async def eval(self,script,n,key,token,*extra):
        if self.store.get(key)!=token: return 0
        if "expire" in script: return 1      # extend-if-owner
        del self.store[key]; return 1        # delete-if-owner

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


def test_heartbeat_extends_only_own_lock(monkeypatch):
    import agents.fusion_agent.incident_lock as il
    monkeypatch.setattr(il, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    async def run():
        r=FakeRedis()
        calls=[]
        orig=r.eval
        async def spy(script,n,key,token,*extra):
            calls.append(("expire" in script, token)); return await orig(script,n,key,token,*extra)
        r.eval=spy
        r.store["k"]="mine"
        t=asyncio.create_task(il._heartbeat(r,"k","mine"))
        await asyncio.sleep(0.05)
        assert any(c[0] for c in calls)          # extended while we own it
        r.store["k"]="other"                      # TTL expired, another replica took the lock
        await asyncio.wait_for(t, timeout=1)      # heartbeat stops instead of extending theirs
        assert r.store["k"]=="other"
    asyncio.run(run())


# ---- review fix E: a transient Redis error must not end the heartbeat -------------------------------------
def test_one_transient_extend_error_does_not_stop_the_heartbeat(monkeypatch):
    import agents.fusion_agent.incident_lock as il
    monkeypatch.setattr(il, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    async def run():
        r = FakeRedis()
        r.store["k"] = "mine"
        orig, state_calls = r.eval, {"n": 0}
        async def flaky(script, n, key, token, *extra):
            state_calls["n"] += 1
            if state_calls["n"] == 1:
                raise ConnectionError("one-off")
            return await orig(script, n, key, token, *extra)
        r.eval = flaky
        state = il.LockState()
        t = asyncio.create_task(il._heartbeat(r, "k", "mine", state))
        await asyncio.sleep(0.1)
        assert state_calls["n"] >= 3 and not t.done() and state.lost is False   # kept extending after the error
        t.cancel()
    asyncio.run(run())


def test_persistent_errors_mark_the_lock_lost_once_the_ttl_has_passed(monkeypatch):
    import agents.fusion_agent.incident_lock as il
    monkeypatch.setattr(il, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(il, "LOCK_TTL_SECONDS", 0.05)
    async def run():
        r = FakeRedis()
        async def broken(*a, **k):
            raise ConnectionError("down")
        r.eval = broken
        state = il.LockState()
        await asyncio.wait_for(il._heartbeat(r, "k", "mine", state), timeout=2)
        assert state.lost is True and "no successful extend" in state.reason
    asyncio.run(run())


def test_a_changed_owner_marks_the_lock_lost():
    import agents.fusion_agent.incident_lock as il
    async def run():
        r = FakeRedis()
        r.store["k"] = "other"
        state = il.LockState()
        il.HEARTBEAT_INTERVAL_SECONDS, saved = 0.01, il.HEARTBEAT_INTERVAL_SECONDS
        try:
            await asyncio.wait_for(il._heartbeat(r, "k", "mine", state), timeout=1)
        finally:
            il.HEARTBEAT_INTERVAL_SECONDS = saved
        assert state.lost is True
    asyncio.run(run())


def test_the_context_manager_fills_the_state_passed_in(monkeypatch):
    import agents.fusion_agent.incident_lock as il
    monkeypatch.setattr(il, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    async def run():
        r = FakeRedis()
        state = il.LockState()
        async with acquire_incident_lock(r, "prod", "podZ", state=state) as got:
            assert got is True and state.lost is False
            r.store["kubeheal:incident-lock:prod:podZ"] = "stolen"       # another replica owns the key now
            await asyncio.sleep(0.1)
            assert state.lost is True
    asyncio.run(run())
