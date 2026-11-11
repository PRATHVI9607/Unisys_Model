"""P6-R1 for the Fusion Agent: a replica dies holding a pending entry, the other reclaims and handles it once;
repeated failures are dead-lettered and escalated; the lease and the consume loop are wired."""
import asyncio
import inspect
import json

from fusion_helpers import NOW_MS, StubInterp, make_agent, run, sec_event, stream
from agents.common.stream_reliability import DEADLETTER_STREAM, ReliabilityConfig, StreamReliability
from agents.fusion_agent import agent as fusion

IDLE_MS = 30_000


def small(a, consumer):
    a.consumer = consumer
    a.reliability = StreamReliability(lambda: a.redis, fusion.GROUP, consumer,
                                      ReliabilityConfig(min_idle_ms=IDLE_MS, max_deliveries=3, batch=5),
                                      clock=lambda: a.redis.now)
    return a


async def groups(r):
    for s, start in ((fusion.HEALTH_STREAM, "0"), (fusion.SEC_STREAM, "0"), (fusion.ACTIONS_STREAM, "0")):
        await r.xgroup_create(s, fusion.GROUP, id=start, mkstream=True)


def test_dead_replica_security_entry_is_reclaimed_and_handled_exactly_once():
    async def go():
        a = small(make_agent(), "fusion-A")
        b = small(make_agent(redis=a.redis), "fusion-B")
        r = a.redis
        await groups(r)
        await r.xadd(fusion.SEC_STREAM, sec_event())
        got = await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"})     # A takes it, dies
        assert got and r.pending_ids(fusion.SEC_STREAM, fusion.GROUP)
        await b._reclaim_pending()                                                         # too early
        assert stream(r, fusion.EXEC_STREAM) == []
        r.advance(IDLE_MS / 1000 + 1)
        await b._reclaim_pending()
        assert len(stream(r, fusion.EXEC_STREAM)) == 1
        assert r.pending_ids(fusion.SEC_STREAM, fusion.GROUP) == []
        assert len(r.zsets["kubeheal:cbw:contain:prod"]) == 1                              # counted once
        r.advance(IDLE_MS / 1000 + 1)
        await b._reclaim_pending()
        await a._reclaim_pending()
        assert len(stream(r, fusion.EXEC_STREAM)) == 1
    run(go())


def test_reclaimed_entry_that_was_half_handled_does_not_double_count_or_double_queue():
    """A dies after queueing the request and counting the breaker but before the ack: B handles the same entry."""
    async def go():
        a = small(make_agent(), "fusion-A")
        b = small(make_agent(redis=a.redis), "fusion-B")
        b.ledger = a.ledger
        r = a.redis
        await groups(r)
        ev = sec_event()
        await r.xadd(fusion.SEC_STREAM, ev)
        got = await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"})
        _, fields = got[0][1][0]
        await a._on_security(fields)                       # everything but the ack
        assert len(stream(r, fusion.EXEC_STREAM)) == 1
        r.advance(IDLE_MS / 1000 + 1)
        await b._reclaim_pending()
        assert len(stream(r, fusion.EXEC_STREAM)) == 1
        assert len(r.zsets["kubeheal:cbw:contain:prod"]) == 1
        assert r.pending_ids(fusion.SEC_STREAM, fusion.GROUP) == []
    run(go())


def test_dead_replica_containment_result_is_reclaimed_and_triggers_one_restore():
    async def go():
        a = small(make_agent(), "fusion-A")
        b = small(make_agent(redis=a.redis), "fusion-B")
        b.ledger = a.ledger
        r = a.redis
        await groups(r)
        ev = sec_event(t0_ms=str(NOW_MS - 10_000))
        await a._on_security(ev)
        iid = fusion.derive_incident_id(ev)
        await r.xadd(fusion.ACTIONS_STREAM, {"incident_id": iid, "action_type": "executed_contain",
                                             "outcome": "contained", "approved_by": "auto"})
        await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.ACTIONS_STREAM: ">"})     # A dies holding it
        r.advance(IDLE_MS / 1000 + 1)
        await b._reclaim_pending()
        restores = [f for f in stream(r, fusion.EXEC_STREAM) if f["action"] == "restore"]
        assert len(restores) == 1 and restores[0]["t0_ms"] == str(NOW_MS - 10_000)
        r.advance(IDLE_MS / 1000 + 1)
        await b._reclaim_pending()
        assert len([f for f in stream(r, fusion.EXEC_STREAM) if f["action"] == "restore"]) == 1
    run(go())


def test_entry_that_keeps_failing_is_dead_lettered_and_escalated():
    async def go():
        a = small(make_agent(), "fusion-A")
        b = small(make_agent(redis=a.redis), "fusion-B")
        r = a.redis
        await groups(r)
        await r.xadd(fusion.SEC_STREAM, sec_event())
        await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"})
        calls = []

        async def boom(fields):
            calls.append(1)
            raise RuntimeError("downstream failure")
        b._on_security = boom
        for _ in range(8):
            r.advance(IDLE_MS / 1000 + 1)
            await b._reclaim_pending()
        assert len(calls) == 2                                   # delivery 1 was A's; 3 allowed in total
        assert r.pending_ids(fusion.SEC_STREAM, fusion.GROUP) == []
        assert len(r.streams[DEADLETTER_STREAM]) == 1
        esc = stream(r, fusion.ESCALATIONS_STREAM)
        assert len(esc) == 1 and esc[0]["reason"].startswith("dead_lettered") and esc[0]["required"] == "human"
        assert esc[0]["source"] == "fusion" and esc[0]["incident_id"].startswith("inc-")
    run(go())


def test_consume_loop_reads_all_three_streams_and_sweeps_pending():
    src = inspect.getsource(fusion.FusionAgentV4._consume)
    assert "_reclaim_pending" in src and "ACTIONS_STREAM" in src and "SEC_STREAM" in src


def test_handle_entry_runs_under_a_lease():
    src = inspect.getsource(fusion.FusionAgentV4._handle_entry)
    assert "reliability.lease" in src
    assert "xack" in inspect.getsource(fusion.FusionAgentV4._handle_entry_body)


def test_the_ack_comes_only_after_success_for_every_stream():
    async def go():
        a = make_agent()
        for stream_name, fields in ((fusion.HEALTH_STREAM, {"namespace": "dev", "deployment": "w",
                                                             "health_risk": "0.1", "event_id": "h"}),
                                    (fusion.SEC_STREAM, sec_event(sec_risk="0.1")),
                                    (fusion.ACTIONS_STREAM, {"action_type": "auto_contain"})):
            assert await a._handle_entry(stream_name, "1-0", fields) is True
        assert len(a.redis.acked) == 3

        async def boom(*_):
            raise RuntimeError("x")
        a.redis.acked.clear()
        a._on_action_result = boom
        assert await a._handle_entry(fusion.ACTIONS_STREAM, "2-0", {}) is False and a.redis.acked == []
    run(go())
