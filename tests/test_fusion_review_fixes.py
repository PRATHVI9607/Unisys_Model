"""Review fixes A to F for the Fusion Agent: a busy lock never drops an automatic action, an unknown tier never
acts automatically, the exec request and the restore request are queued once (SET NX), every entry of a read
batch is leased, a lost lock is noticed, a missing health model_scored counts as not scored, and a Health Model
outage reaches a human."""
import asyncio
import contextlib
import json

import pytest

from fusion_helpers import (NOW_MS, StubInterp, emb, health_event, ledger_steps, make_agent, run, sec_event,
                            stream)
from agents.common.stream_reliability import ReliabilityConfig, StreamReliability
from agents.fusion_agent import agent as fusion
from agents.fusion_agent.incident_lock import LOCK_PREFIX

LOCK_KEY = f"{LOCK_PREFIX}:prod:payments"


def decisions(a):
    return [r["payload"]["decision"] for r in ledger_steps(a) if r["step"] == "decision"]


def exec_requests(a):
    return stream(a.redis, fusion.EXEC_STREAM)


def small(a, consumer, idle_ms=30_000, max_deliveries=3):
    a.consumer = consumer
    a.reliability = StreamReliability(lambda: a.redis, fusion.GROUP, consumer,
                                      ReliabilityConfig(min_idle_ms=idle_ms, max_deliveries=max_deliveries,
                                                        batch=5), clock=lambda: a.redis.now)
    return a


async def groups(r):
    for s in (fusion.HEALTH_STREAM, fusion.SEC_STREAM, fusion.ACTIONS_STREAM):
        await r.xgroup_create(s, fusion.GROUP, id="0", mkstream=True)


def test_stream_groups_retry_when_redis_is_unavailable_during_fusion_startup():
    async def go():
        a = make_agent(enforce=False)
        redis = a.redis
        original = redis.xgroup_create
        attempts = 0
        queued_id = await redis.xadd(fusion.HEALTH_STREAM, {"event_id": "queued-before-groups"})

        async def fail_once(stream_name, group, id="$", mkstream=False):
            nonlocal attempts
            if attempts == 0:
                attempts += 1
                raise ConnectionError("temporary Redis startup race")
            return await original(stream_name, group, id=id, mkstream=mkstream)

        redis.xgroup_create = fail_once
        await a._ensure_stream_groups(retry_delay_s=0)

        assert attempts == 1
        assert all((name, fusion.GROUP) in redis.groups for name in
                   (fusion.HEALTH_STREAM, fusion.SEC_STREAM, fusion.ACTIONS_STREAM))
        queued = await redis.xreadgroup(fusion.GROUP, "fusion-after-retry", {fusion.HEALTH_STREAM: ">"})
        assert queued[0][1][0] == (queued_id, {"event_id": "queued-before-groups"})

    run(go())


# ---- A: a busy lock does not drop the automatic action --------------------------------------------------
def test_busy_lock_leaves_the_entry_pending_writes_a_ledger_line_and_retries_after_release():
    async def go():
        a = small(make_agent(), "fusion-A")
        r = a.redis
        await groups(r)
        await r.xadd(fusion.SEC_STREAM, sec_event())
        await r.set(LOCK_KEY, "someone-else", nx=True, ex=10)
        await a._handle_batch(await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"}))
        assert r.pending_ids(fusion.SEC_STREAM, fusion.GROUP) and r.acked == []        # not acked
        assert exec_requests(a) == []
        assert "action_deferred" in [x["step"] for x in ledger_steps(a)]
        await r.delete(LOCK_KEY)
        r.advance(31)
        await a._reclaim_pending()                                                    # redelivery
        assert len(exec_requests(a)) == 1 and r.pending_ids(fusion.SEC_STREAM, fusion.GROUP) == []
    run(go())


def test_a_lock_that_stays_busy_ends_in_a_dead_letter_and_an_escalation_not_silence():
    async def go():
        a = small(make_agent(), "fusion-A", max_deliveries=2)
        r = a.redis
        await groups(r)
        await r.xadd(fusion.SEC_STREAM, sec_event())
        await r.set(LOCK_KEY, "someone-else", ex=100_000)                # still held at every delivery
        await a._handle_batch(await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"}))
        for _ in range(6):
            r.advance(31)
            await a._reclaim_pending()
        assert exec_requests(a) == []
        assert r.pending_ids(fusion.SEC_STREAM, fusion.GROUP) == []     # dead-lettered and acked
        esc = stream(r, fusion.ESCALATIONS_STREAM)
        assert len(esc) == 1 and "dead_lettered" in esc[0]["reason"] and esc[0]["required"] == "human"
    run(go())


def test_a_second_infected_pod_of_the_same_deployment_is_retried_not_lost():
    async def go():
        a = small(make_agent(), "fusion-A")
        r = a.redis
        await groups(r)
        await r.xadd(fusion.SEC_STREAM, sec_event(event_id="sec-2", pod_name="payments-abc-2", pid_target="43"))
        await r.set(LOCK_KEY, "patch-in-progress", ex=10)             # e.g. a patch of the Deployment
        await a._handle_batch(await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"}))
        assert exec_requests(a) == []
        await r.delete(LOCK_KEY)
        r.advance(31)
        await a._reclaim_pending()
        assert [q["pod"] for q in exec_requests(a)] == ["payments-abc-2"]
    run(go())


# ---- B: an unknown tier never acts automatically ---------------------------------------------------------
@pytest.mark.parametrize("tier", ["", "production", "unknown", "weird"])
def test_an_unknown_or_missing_tier_is_human_through_fusion(tier):
    a = make_agent()
    ev = sec_event(namespace_tier=tier)
    if not tier:
        del ev["namespace_tier"]
    run(a._decide("prod:payments", None, ev))
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["namespace_tier"] == "unknown" and "tier is unknown" in payload["rationale"]


def test_conflicting_tiers_from_the_two_agents_count_as_unknown():
    assert fusion.tier_of({"namespace_tier": "dev"}, {"namespace_tier": "prod"}) == "unknown"
    assert fusion.tier_of({"namespace_tier": "prod"}, {"namespace_tier": "prod"}) == "prod"
    assert fusion.tier_of({}, {"namespace_tier": "Staging"}) == "staging"
    assert fusion.tier_of({}, {}) == "unknown"


def test_known_tier_still_acts_automatically():
    a = make_agent()
    run(a._decide("prod:payments", None, sec_event()))
    assert decisions(a) == ["auto_contain"] and len(exec_requests(a)) == 1


# ---- C: one exec request per incident and action ----------------------------------------------------------
def test_second_replica_with_a_stale_state_does_not_queue_a_second_request():
    a = make_agent()
    b = make_agent(redis=a.redis)
    b.ledger = a.ledger
    run(a._decide("prod:payments", None, sec_event(event_id="sec-1")))
    assert len(exec_requests(a)) == 1
    iid = fusion.derive_incident_id(sec_event(event_id="sec-1"))
    # B read the incident before A wrote the state: its copy has no action_state
    original = b._incident_for

    async def stale(namespace, pod, health, sec):
        incident_id, ctx = await original(namespace, pod, health, sec)
        return incident_id, {k: v for k, v in ctx.items() if k != "action_state"}
    b._incident_for = stale
    # 1) the state is re-read after the lock: B backs off even without the marker
    run(a.redis.delete(f"{fusion.EXEC_REQ_PREFIX}:{iid}:contain"))
    run(b._decide("prod:payments", None, sec_event(event_id="sec-2", entropy_phase="complete")))
    assert len(exec_requests(a)) == 1
    # 2) and when the state key is empty as well, the SET NX marker stops the second request
    run(a.redis.hset(fusion.INCIDENT_PREFIX + ":" + iid, mapping={"action_state": ""}))
    run(a.redis.set(f"{fusion.EXEC_REQ_PREFIX}:{iid}:contain", "1", nx=True))
    run(b._decide("prod:payments", None, sec_event(event_id="sec-3", entropy_phase="complete")))
    assert len(exec_requests(a)) == 1
    assert len(a.redis.zsets["kubeheal:cbw:contain:prod"]) == 1


def test_a_failed_enqueue_releases_the_marker_so_a_retry_can_queue():
    a = make_agent()
    a.redis.fail["xadd"] = RuntimeError("redis down")
    with pytest.raises(RuntimeError):
        run(a._decide("prod:payments", None, sec_event()))
    a.redis.fail.clear()
    assert not [k for k in a.redis.store if k.startswith(fusion.EXEC_REQ_PREFIX)]
    run(a._decide("prod:payments", None, sec_event()))
    assert len(exec_requests(a)) == 1


def test_restore_marker_is_set_nx_before_the_request_is_queued():
    a = make_agent()
    ev = sec_event(t0_ms=str(NOW_MS - 20_000))
    run(a._decide("prod:payments", None, ev))
    iid = fusion.derive_incident_id(ev)
    run(a.redis.hset(fusion.INCIDENT_PREFIX + ":" + iid, mapping={"contained": "1"}))
    # another replica already took the marker: nothing is queued
    run(a.redis.set(f"{fusion.RESTORE_PREFIX}:{iid}", "1", nx=True))
    run(a._maybe_request_restore(iid))
    assert [q for q in exec_requests(a) if q["action"] == "restore"] == []
    # a failed xadd gives the marker back so the redelivery can queue the restore
    run(a.redis.delete(f"{fusion.RESTORE_PREFIX}:{iid}"))
    a.redis.fail["xadd"] = RuntimeError("redis down")
    with pytest.raises(RuntimeError):
        run(a._maybe_request_restore(iid))
    a.redis.fail.clear()
    assert f"{fusion.RESTORE_PREFIX}:{iid}" not in a.redis.store
    run(a._maybe_request_restore(iid))
    run(a._maybe_request_restore(iid))
    assert len([q for q in exec_requests(a) if q["action"] == "restore"]) == 1


# ---- D: every entry of a batch is leased ------------------------------------------------------------------
def test_entries_two_and_three_are_not_reclaimable_while_the_first_is_slow():
    async def go():
        a = small(make_agent(), "fusion-A", idle_ms=30)
        b = small(make_agent(redis=a.redis), "fusion-B", idle_ms=30)
        r = a.redis
        await groups(r)
        for i in range(3):
            await r.xadd(fusion.SEC_STREAM, sec_event(event_id=f"sec-{i}", pid_target=str(40 + i)))
        gate = {"stolen": None}

        async def slow(fields):
            if fields["event_id"] == "sec-0":
                for _ in range(4):
                    r.advance(0.02)                       # the two entries behind it would turn stale
                    await asyncio.sleep(0.03)             # real time for the lease heartbeats
                gate["stolen"] = await r.xautoclaim(fusion.SEC_STREAM, fusion.GROUP, "fusion-B",
                                                    min_idle_time=30, start_id="0-0", count=10)
                await b._reclaim_pending()
        a._on_security = slow
        await a._handle_batch(await r.xreadgroup(fusion.GROUP, "fusion-A", {fusion.SEC_STREAM: ">"}, count=10))
        assert gate["stolen"][1] == [] and exec_requests(b) == []     # B found nothing to take over
        assert len(r.acked) == 3
    run(go())


# ---- E: the action path checks the lost-lock flag ---------------------------------------------------------
def test_a_lost_lock_before_the_enqueue_retries_instead_of_acting(monkeypatch):
    real = fusion.acquire_incident_lock

    @contextlib.asynccontextmanager
    async def losing(redis, namespace, name, token=None, state=None):
        async with real(redis, namespace, name, token, state) as got:
            state.lost = True                              # the heartbeat gave up during the decision
            yield got
    monkeypatch.setattr(fusion, "acquire_incident_lock", losing)
    a = make_agent()
    with pytest.raises(fusion.RetryLater):
        run(a._decide("prod:payments", None, sec_event()))
    assert exec_requests(a) == []


# ---- F: model_scored of the health event, model outage ----------------------------------------------------
def test_a_health_event_without_model_scored_is_not_trusted():
    a = make_agent()
    ev = health_event(sec_risk="0")
    del ev["model_scored"]
    run(a._decide("prod:payments", ev, None))
    assert decisions(a) == ["human_patch"] and exec_requests(a) == []


def test_a_health_event_marked_scored_can_still_patch_automatically():
    a = make_agent()
    run(a._decide("prod:payments", health_event(), None))
    assert decisions(a) == ["auto_patch"]


def test_model_unavailable_escalates_once_and_makes_no_decision():
    a = make_agent()
    ev = {"event_id": "health-9", "namespace": "prod", "deployment": "payments", "pod_name": "payments",
          "namespace_tier": "prod", "health_risk": "0.0000", "health_label": "model_unavailable",
          "health_ci_width": "1.0000", "model_scored": "false", "model_unavailable": "true",
          "timestamp_ms": str(NOW_MS)}
    assert run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", ev)) is True
    ev2 = dict(ev, event_id="health-10")
    assert run(a._handle_entry(fusion.HEALTH_STREAM, "2-0", ev2)) is True
    esc = stream(a.redis, fusion.ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human" and "health_model_unavailable" in esc[0]["reason"]
    assert decisions(a) == [] and exec_requests(a) == [] and a.pending_health == {}
    assert a.redis.sets.get(fusion.BurnInCounter.__module__) is None       # not counted as a metric sample
    a.redis.advance(a.cfg.model_unavailable_dedup_ttl_s + 1)
    run(a._handle_entry(fusion.HEALTH_STREAM, "3-0", dict(ev, event_id="health-11")))
    assert len(stream(a.redis, fusion.ESCALATIONS_STREAM)) == 2


def test_a_failed_escalation_of_a_model_outage_is_retried():
    a = make_agent()
    ev = {"event_id": "health-9", "namespace": "prod", "deployment": "payments", "model_unavailable": "true",
          "model_scored": "false"}
    a.redis.fail["xadd"] = RuntimeError("redis down")
    assert run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", ev)) is False
    a.redis.fail.clear()
    assert run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", ev)) is True
    assert len(stream(a.redis, fusion.ESCALATIONS_STREAM)) == 1
