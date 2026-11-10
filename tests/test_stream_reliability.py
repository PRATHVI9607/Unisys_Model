"""P6-R1: pending reclaim with two consumers, delivery counting, dead letter, lease, and the Executor's
idempotent consume path (S-MQ-2, S-MQ-3)."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

import pytest

import remediation_fakes as fk
from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.common.stream_reliability import (
    DEADLETTER_STREAM, DEFAULT_MAX_DELIVERIES, ReliabilityConfig, StreamReliability,
)
from agents.executor import main as exec_main
from agents.executor.main import ESCALATIONS_STREAM, EXEC_STREAM, GROUP, ExecutorService
from fake_redis import FakeRedis

STREAM, G = "kubeheal.test", "grp"
IDLE_MS = 30_000


def run(coro):
    return asyncio.run(coro)


def cfg(**kw):
    base = dict(min_idle_ms=IDLE_MS, max_deliveries=3, reclaim_interval_s=1.0, batch=2)
    return ReliabilityConfig(**{**base, **kw})


def rel(redis, consumer, **kw):
    return StreamReliability(lambda: redis, G, consumer, cfg(**kw), clock=lambda: redis.now)


async def prepared(redis, n=1):
    await redis.xgroup_create(STREAM, G, id="0", mkstream=True)
    for i in range(n):
        await redis.xadd(STREAM, {"n": str(i)})


# ---- the helper with two consumers --------------------------------------------------------------
def test_config_defaults_are_labelled_chosen_and_env_overridable():
    c = ReliabilityConfig.from_env({})
    assert (c.min_idle_ms, c.max_deliveries) == (60_000, DEFAULT_MAX_DELIVERIES)
    c = ReliabilityConfig.from_env({"KUBEHEAL_PENDING_IDLE_MS": "5000", "KUBEHEAL_MAX_DELIVERIES": "2",
                                    "KUBEHEAL_RECLAIM_INTERVAL_S": "x"})
    assert c.min_idle_ms == 5000 and c.max_deliveries == 2 and c.reclaim_interval_s == 15.0
    assert ReliabilityConfig.from_env({"KUBEHEAL_MAX_DELIVERIES": "0"}).max_deliveries == DEFAULT_MAX_DELIVERIES
    src = Path(sys.modules[ReliabilityConfig.__module__].__file__).read_text(encoding="utf-8")
    assert src.count("chosen, not measured") >= 1


def test_dead_consumer_entry_is_reclaimed_and_handled_exactly_once_by_the_other():
    async def go():
        r = FakeRedis()
        await prepared(r)
        # consumer A takes the entry and dies before it acknowledges
        got = await r.xreadgroup(G, "A", {STREAM: ">"}, count=10)
        assert got[0][1][0][1] == {"n": "0"}
        assert r.pending_ids(STREAM, G)

        handled = []

        async def handle(stream, msg_id, fields):
            handled.append((stream, msg_id, dict(fields)))
            await r.xack(stream, G, msg_id)
            return True

        async def dead(*a):
            raise AssertionError("must not be dead-lettered")

        b = rel(r, "B")
        res = await b.reclaim(STREAM, handle, dead)          # not idle long enough yet
        assert res.claimed == 0 and handled == []
        r.advance(IDLE_MS / 1000 + 1)
        res = await b.reclaim(STREAM, handle, dead)
        assert res.claimed == 1 and res.handled == 1 and len(handled) == 1
        assert r.pending_ids(STREAM, G) == []
        # a later sweep (by either consumer) finds nothing: handled once
        r.advance(IDLE_MS / 1000 + 1)
        assert (await b.reclaim(STREAM, handle, dead)).claimed == 0
        assert (await rel(r, "A").reclaim(STREAM, handle, dead)).claimed == 0
        assert len(handled) == 1
    run(go())


def test_failed_handler_stays_pending_and_is_retried_until_the_limit_then_dead_lettered():
    async def go():
        r = FakeRedis()
        await prepared(r)
        await r.xreadgroup(G, "A", {STREAM: ">"})            # delivery 1 by A, never acknowledged
        attempts, escalated = [], []

        async def handle(stream, msg_id, fields):
            attempts.append(msg_id)
            raise RuntimeError("boom")

        async def dead(stream, msg_id, fields, deliveries, reason):
            escalated.append((stream, msg_id, dict(fields), deliveries, reason))

        b = rel(r, "B")
        for _ in range(10):
            r.advance(IDLE_MS / 1000 + 1)
            await b.reclaim(STREAM, handle, dead)
        # max_deliveries=3: delivery 1 was A's, B handled deliveries 2 and 3, the next claim dead-letters
        assert len(attempts) == 2
        assert len(escalated) == 1
        stream, msg_id, fields, deliveries, reason = escalated[0]
        assert fields == {"n": "0"} and deliveries == 3 and "dead_lettered" in reason
        assert r.pending_ids(STREAM, G) == []                # acknowledged after the dead letter
        dl = r.streams[DEADLETTER_STREAM]
        assert len(dl) == 1
        assert dl[0][1]["source_stream"] == STREAM and dl[0][1]["original_id"] == msg_id
        assert json.loads(dl[0][1]["fields_json"]) == {"n": "0"}
    run(go())


def test_dead_letter_is_not_acknowledged_when_the_escalation_fails():
    async def go():
        r = FakeRedis()
        await prepared(r)
        await r.xreadgroup(G, "A", {STREAM: ">"})
        calls = []

        async def handle(*a):
            return False

        async def dead(*a):
            calls.append(1)
            raise RuntimeError("redis down")

        b = rel(r, "B", max_deliveries=1)
        r.advance(IDLE_MS / 1000 + 1)
        res = await b.reclaim(STREAM, handle, dead)
        assert res.dead_lettered == 0 and res.failed == 1 and calls
        assert r.pending_ids(STREAM, G)                      # still pending, tried again next sweep
    run(go())


def test_lease_keeps_a_long_running_entry_from_being_reclaimed():
    async def go():
        r = FakeRedis()
        await prepared(r)
        await r.xreadgroup(G, "A", {STREAM: ">"})
        a = rel(r, "A", min_idle_ms=30)                       # heartbeat every 10 ms
        async with a.lease(STREAM, r.pending_ids(STREAM, G)[0]):
            r.advance(100)                                    # idle far beyond the threshold
            await asyncio.sleep(0.05)                         # at least one heartbeat
            res = await rel(r, "B", min_idle_ms=30).reclaim(STREAM, _never, _never_dead)
            assert res.claimed == 0
        meta = r.groups[(STREAM, G)]["pending"][r.pending_ids(STREAM, G)[0]]
        assert meta["times"] == 1                             # JUSTID heartbeat does not count as a delivery
    run(go())


async def _never(*a):
    raise AssertionError("handler must not run")


async def _never_dead(*a):
    raise AssertionError("dead letter must not run")


def test_trimmed_entry_is_dropped_from_the_pending_list():
    async def go():
        r = FakeRedis()
        await prepared(r)
        await r.xreadgroup(G, "A", {STREAM: ">"})
        r.streams[STREAM].clear()                              # trimmed away
        r.advance(IDLE_MS / 1000 + 1)
        res = await rel(r, "B").reclaim(STREAM, _never, _never_dead)
        assert res.skipped == 1 and r.pending_ids(STREAM, G) == []
    run(go())


def test_reclaim_pages_through_a_backlog():
    async def go():
        r = FakeRedis()
        await prepared(r, n=5)
        await r.xreadgroup(G, "A", {STREAM: ">"}, count=10)
        seen = []

        async def handle(stream, msg_id, fields):
            seen.append(fields["n"])
            await r.xack(stream, G, msg_id)
            return True

        r.advance(IDLE_MS / 1000 + 1)
        res = await rel(r, "B").reclaim(STREAM, handle, _never_dead)     # batch=2: three XAUTOCLAIM calls
        assert res.handled == 5 and sorted(seen) == ["0", "1", "2", "3", "4"]
    run(go())


# ---- the Executor consume path -----------------------------------------------------------------------
INC = "inc-reclaim-1"


def req(**kw):
    base = {"action": "contain", "namespace": "prod", "deployment": "web", "pod": "web-abc-1",
            "incident_id": INC, "approved_by": "auto", "dry_run": "false"}
    base.update(kw)
    return base


def make_executor(redis, consumer, calls=None, outcome="contained", fail=False):
    ledger = Ledger(InMemoryLedgerStore())
    ex = ExecutorService(redis=redis, mode=fk.Mode(), ledger=ledger, cfg=None)
    ex.consumer = consumer
    ex.reliability = StreamReliability(lambda: redis, GROUP, consumer, cfg(), clock=lambda: redis.now)

    async def execute(f):
        if calls is not None:
            calls.append(dict(f))
        if fail:
            raise RuntimeError("cluster unreachable")
        return outcome
    ex.execute = execute
    return ex, ledger


async def drain(ex):
    while ex._tasks:
        await asyncio.gather(*list(ex._tasks), return_exceptions=True)


def test_executor_pending_entry_of_a_dead_executor_is_reclaimed_and_run_once():
    async def go():
        r = FakeRedis()
        await r.xgroup_create(EXEC_STREAM, GROUP, id="0", mkstream=True)
        await r.xadd(EXEC_STREAM, req())
        await r.xreadgroup(GROUP, "exec-A", {EXEC_STREAM: ">"})        # A dies holding it
        calls = []
        b, ledger = make_executor(r, "exec-B", calls)
        await b.reclaim_pending()
        await drain(b)
        assert calls == []                                              # not stale yet
        r.advance(IDLE_MS / 1000 + 1)
        await b.reclaim_pending()
        await drain(b)
        assert len(calls) == 1
        assert r.pending_ids(EXEC_STREAM, GROUP) == []
        # a second executor sweeping later does not run it again
        c, _ = make_executor(r, "exec-C", calls)
        r.advance(IDLE_MS / 1000 + 1)
        await c.reclaim_pending()
        await drain(c)
        assert len(calls) == 1
        results = [json.loads(v) for v in ledger.store.objects.values()]
        assert [x["step"] for x in results] == ["executor_result"]
    run(go())


def test_executor_dead_letters_a_request_that_keeps_failing_and_escalates():
    async def go():
        r = FakeRedis()
        await r.xgroup_create(EXEC_STREAM, GROUP, id="0", mkstream=True)
        await r.xadd(EXEC_STREAM, req(action="patch", patch_field="spec.x"))
        await r.xreadgroup(GROUP, "exec-A", {EXEC_STREAM: ">"})
        calls = []
        b, ledger = make_executor(r, "exec-B", calls, fail=True)
        for _ in range(8):
            r.advance(IDLE_MS / 1000 + 1)
            await b.reclaim_pending()
            await drain(b)
        assert len(calls) == 2                                          # max_deliveries 3: A had the first
        assert r.pending_ids(EXEC_STREAM, GROUP) == []
        assert len(r.streams[DEADLETTER_STREAM]) == 1
        esc = [f for s, f in r.added if s == ESCALATIONS_STREAM]
        assert len(esc) == 1 and esc[0]["reason"].startswith("dead_lettered") and esc[0]["required"] == "human"
        assert esc[0]["incident_id"] == INC
        steps = [json.loads(v)["step"] for v in ledger.store.objects.values()]
        assert "executor_escalation" in steps
    run(go())


def test_executor_does_not_rerun_an_incident_that_already_has_a_result():
    async def go():
        r = FakeRedis()
        calls = []
        ex, ledger = make_executor(r, "exec-A", calls)
        assert await ex.handle_entry(EXEC_STREAM, "1-0", req()) is True
        assert len(calls) == 1
        # the same request again (lost ack, or a duplicate approval): acknowledged, not executed
        assert await ex.handle_entry(EXEC_STREAM, "2-0", req()) is True
        assert len(calls) == 1
        assert (EXEC_STREAM, "2-0") in r.acked
        steps = [json.loads(v)["step"] for v in ledger.store.objects.values()]
        assert steps.count("executor_result") == 1
    run(go())


def test_executor_marker_is_per_action_and_dry_run_flag():
    async def go():
        r = FakeRedis()
        calls = []
        ex, _ = make_executor(r, "exec-A", calls)
        await ex.handle_entry(EXEC_STREAM, "1-0", req(action="contain"))
        await ex.handle_entry(EXEC_STREAM, "2-0", req(action="restore", t0_ms="1700000000000"))
        await ex.handle_entry(EXEC_STREAM, "3-0", req(action="contain", dry_run="true"))
        assert [c["action"] for c in calls] == ["contain", "restore", "contain"]
    run(go())


@pytest.mark.parametrize("outcome", ["DRY RUN: would have CONTAIN x", "stopped_mode_test: switched",
                                     "refused:bad", "escalated:t0_missing: x", "no_baseline_escalated"])
def test_executor_outcomes_that_did_nothing_do_not_block_a_later_run(outcome):
    async def go():
        r = FakeRedis()
        calls = []
        ex, _ = make_executor(r, "exec-A", calls, outcome=outcome)
        await ex.handle_entry(EXEC_STREAM, "1-0", req())
        await ex.handle_entry(EXEC_STREAM, "2-0", req())
        assert len(calls) == 2
    run(go())


def test_executor_result_marker_is_written_before_the_record_and_the_ack():
    async def go():
        r = FakeRedis()
        calls = []
        ex, ledger = make_executor(r, "exec-A", calls)
        real = ex._record
        state = {"fail": True}

        async def flaky(f, outcome):
            if state["fail"]:
                raise RuntimeError("ledger down")
            return await real(f, outcome)
        ex._record = flaky
        await r.xgroup_create(EXEC_STREAM, GROUP, id="0", mkstream=True)
        await r.xadd(EXEC_STREAM, req())
        got = await r.xreadgroup(GROUP, "exec-A", {EXEC_STREAM: ">"})
        msg_id, fields = got[0][1][0]
        assert await ex.handle_entry(EXEC_STREAM, msg_id, fields) is False   # not acknowledged
        assert r.pending_ids(EXEC_STREAM, GROUP) == [msg_id]
        marker = json.loads(next(v for k, v in r.store.items() if k.startswith("kubeheal:exec:done:")))
        assert marker == {"outcome": "contained", "recorded": False}         # result stored before the ack
        state["fail"] = False
        # redelivery: the action is not run again, the record is finished from the stored outcome
        assert await ex.handle_entry(EXEC_STREAM, msg_id, fields) is True
        assert len(calls) == 1 and r.pending_ids(EXEC_STREAM, GROUP) == []
        assert json.loads(next(v for k, v in r.store.items() if k.startswith("kubeheal:exec:done:")))["recorded"]
        assert any(f["action_type"] == "executed_contain" and f["outcome"] == "contained"
                   for s, f in r.added if s == exec_main.ACTIONS_STREAM)
    run(go())


def test_executor_consume_loop_sweeps_pending_entries():
    import inspect
    src = inspect.getsource(ExecutorService._consume)
    assert "reclaim_pending" in src and "create_task(self.handle_entry" in src
