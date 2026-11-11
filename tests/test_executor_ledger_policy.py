"""P7-RR-10 owner decision on ledger write failures, through the real Executor paths.

protective steps (quarantine, label, forensic snapshot, scale to zero) go on when MinIO fails and the record
goes to `kubeheal.ledger.pending`; corrective steps (drift patch, restore, lifting quarantine) need a MinIO
write first, else no automatic action and a human is paged; MinIO and fallback both down: nothing runs.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
sys.path.insert(0, str(ROOT / "tests"))

import remediation_fakes as fk
from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.executor.config import ExecConfig
from agents.executor.ledger_guard import FALLBACK_STREAM
from agents.executor.main import ACTIONS_STREAM, ESCALATIONS_STREAM, METRICS, ExecutorService
from test_remediation_drift import CPU, ENV as DRIFT_ENV, Scenario
from test_remediation_ransomware import ENV as RR_ENV, INC, T0, R, make_executor


def run(c):
    return asyncio.run(c)


class FlakyLedger:
    """Ledger that fails on demand, either for everything or only for the listed steps."""

    def __init__(self):
        self.ledger = Ledger(InMemoryLedgerStore())
        self.down = False
        self.down_steps = set()

    @property
    def store(self):
        return self.ledger.store

    def append(self, incident_id, step, payload):
        if self.down or step in self.down_steps:
            raise OSError("minio down")
        return self.ledger.append(incident_id, step, payload)

    def steps(self):
        return [json.loads(v)["step"] for _k, v in sorted(self.store.objects.items())]


def fallback(redis):
    return redis.stream(FALLBACK_STREAM)


def metric(name):
    return [l for l in METRICS.render().decode().splitlines() if l.startswith(name) and not l.startswith("#")]


# ---- protective: containment goes on without MinIO ---------------------------------------------------

def test_contain_proceeds_when_minio_is_down_and_the_record_goes_to_the_fallback_stream():
    r = R(freeze_old=False)
    led = FlakyLedger()
    led.down = True
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    ok = run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "contain", "namespace": "prod", "deployment": "db", "pod": "db-abc-1", "incident_id": INC}))
    assert ok
    assert "create_policy" in [e[1] for e in r.c.log]                      # the quarantine really happened
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"
    assert r.redis.stream(ESCALATIONS_STREAM) == []
    steps = [f["step"] for f in fallback(r.redis)]
    assert "intent_create_quarantine_policy" in steps and "intent_label_pod" in steps
    assert "executor_result" in steps                                        # nothing was lost
    assert led.store.objects == {}
    assert any('kind="protective_intent"' in l for l in metric("kubeheal_ledger_fallback_writes_total"))
    assert r.redis.acked == ["1-0"]


def test_contain_does_nothing_when_minio_and_the_fallback_are_both_down():
    r = R(freeze_old=False)
    led = FlakyLedger()
    led.down = True
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led

    async def broken_xadd(stream, fields, *a, **k):
        if stream == FALLBACK_STREAM:
            raise ConnectionError("redis down for this stream")
        return await original(stream, fields, *a, **k)

    original = r.redis.xadd
    r.redis.xadd = broken_xadd
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "contain", "namespace": "prod", "deployment": "db", "pod": "db-abc-1", "incident_id": INC}))
    assert [e[1] for e in r.c.log] == []                                     # no Kubernetes write at all
    out = r.redis.stream(ACTIONS_STREAM)
    esc = r.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human"
    assert "ledger_unavailable" in esc[0]["reason"]
    assert any('reason="ledger_and_fallback_down"' in l for l in metric("kubeheal_ledger_unavailable_total"))


# ---- corrective: needs MinIO ----------------------------------------------------------------------------

def test_drift_patch_needs_a_successful_ledger_write_first():
    s = Scenario()
    s.redis.store["kubeheal:baseline:prod:web"] = json.dumps(s.golden)
    led = FlakyLedger()
    led.down_steps = {"intent_patch_deployment"}
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(), metric_source=s.source,
                         cfg=ExecConfig(DRIFT_ENV), sleep=s.clock.sleep, clock=s.clock, ledger=led)
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "patch", "namespace": "prod", "deployment": "web", "pod": "", "patch_field": CPU,
        "incident_id": "inc-led"}))
    assert s.c.writes() == []                                               # the live spec was never touched
    assert fallback(s.redis) == [] or all(f["step"] != "intent_patch_deployment" for f in fallback(s.redis))
    esc = s.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human" and "ledger_unavailable" in esc[0]["reason"]
    assert any('reason="corrective_needs_ledger"' in l for l in metric("kubeheal_ledger_unavailable_total"))
    # The refused patch must not leave a pending rollback point: it would block every later patch of this
    # Deployment ("rollback_recovery_required") or turn a retry of the same incident into a blind rollback.
    saved = json.loads(s.redis.store["kubeheal:rollback:prod:web"]) if "kubeheal:rollback:prod:web" in s.redis.store else None
    assert saved is None or saved.get("state") != "pending", saved


def test_a_later_patch_runs_after_a_ledger_refused_one():
    s = Scenario()
    s.redis.store["kubeheal:baseline:prod:web"] = json.dumps(s.golden)
    led = FlakyLedger()
    led.down_steps = {"intent_patch_deployment"}
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(), metric_source=s.source,
                         cfg=ExecConfig(DRIFT_ENV), sleep=s.clock.sleep, clock=s.clock, ledger=led)
    req = {"action": "patch", "namespace": "prod", "deployment": "web", "pod": "", "patch_field": CPU}
    run(ex.handle_entry("kubeheal.exec", "1-0", dict(req, incident_id="inc-a")))
    assert s.c.writes() == []
    led.down_steps = set()                                   # MinIO is back; another incident, same Deployment
    run(ex.handle_entry("kubeheal.exec", "2-0", dict(req, incident_id="inc-b")))
    assert s.c.writes() != []                                # it patched: not blocked by a stale pending record
    assert "rollback_recovery_required" not in json.dumps(s.redis.stream(ESCALATIONS_STREAM))


def test_drift_rollback_is_protective_and_goes_on_without_minio():
    """The patch got its ledger entry, then MinIO failed: the canary must still be able to roll back."""
    s = Scenario(metrics_after=[{"http_p99_latency_ms": 999.0, "cpu_throttle_percent": 99.0}])
    s.redis.store["kubeheal:baseline:prod:web"] = json.dumps(s.golden)
    led = FlakyLedger()
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(), metric_source=s.source,
                         cfg=ExecConfig(DRIFT_ENV), sleep=s.clock.sleep, clock=s.clock, ledger=led)
    real = led.append
    seen = []

    def append(incident_id, step, payload):
        failing = "intent_patch_deployment" in seen
        seen.append(step)
        if failing:                                     # MinIO fails right after the patch was authorised
            raise OSError("minio down")
        return real(incident_id, step, payload)

    led.append = append
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "patch", "namespace": "prod", "deployment": "web", "pod": "", "patch_field": CPU,
        "incident_id": "inc-rb"}))
    assert len(s.c.writes()) >= 2                                           # patch and rollback both ran
    assert s.redis.stream(ACTIONS_STREAM)[-1]["outcome"].startswith("rolled_back")
    assert any(f["step"] == "intent_rollback_deployment" for f in fallback(s.redis))


def test_restore_scale_to_zero_is_protective_but_the_restored_volume_is_corrective():
    """MinIO dies after scale to zero: the PVC creation (corrective) must not happen, the human is told, and the
    workload stays isolated at zero replicas."""
    r = R()
    led = FlakyLedger()
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    real = led.append
    seen = []

    def append(incident_id, step, payload):
        failing = "intent_scale_to_zero" in seen
        seen.append(step)
        if failing:                                     # MinIO fails right after scale to zero was authorised
            raise OSError("minio down")
        return real(incident_id, step, payload)

    led.append = append
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "restore", "namespace": "prod", "deployment": "db", "pod": "db-abc-1",
        "incident_id": INC, "t0_ms": str(T0 * 1000)}))
    methods = [e[1] for e in r.c.log]
    assert "create_pvc" not in methods and methods.count("delete_policy") == 0
    assert methods[:3] == ["create_policy", "patch_Deployment", "scale_Deployment"]     # protective steps ran
    esc = r.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and "ledger_unavailable" in esc[0]["reason"]


def test_lifting_quarantine_needs_a_ledger_write_and_otherwise_stays_isolated():
    r = R()
    led = FlakyLedger()
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    led.down_steps = {"intent_remove_original_replicas_annotation", "intent_lift_quarantine",
                      "intent_delete_quarantine_policy"}
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "restore", "namespace": "prod", "deployment": "db", "pod": "db-abc-1",
        "incident_id": INC, "t0_ms": str(T0 * 1000)}))
    methods = [e[1] for e in r.c.log]
    assert "delete_policy" not in methods                                    # quarantine policy still in place
    labels = r.wl()["spec"]["template"].get("metadata", {}).get("labels", {})
    assert labels.get("kubeheal/quarantine") == "true"                       # pods still carry the quarantine label
    esc = r.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human"


def test_healthy_ledger_changes_nothing_in_the_normal_flow():
    r = R(freeze_old=False)
    led = FlakyLedger()
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    base = {"namespace": "prod", "deployment": "db", "pod": "db-abc-1", "incident_id": INC}
    assert run(ex.handle_entry("kubeheal.exec", "1-0", dict(base, action="contain")))
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"
    assert fallback(r.redis) == []
    steps = led.steps()
    assert "intent_create_quarantine_policy" in steps and "intent_label_pod" in steps


def test_escalation_reaches_the_human_stream_even_when_the_ledger_is_down():
    """The page goes out BEFORE the ledger write, and the ledger write falls back to the stream."""
    r = R(entropy=False)
    led = FlakyLedger()
    led.down = True
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "restore", "namespace": "prod", "deployment": "db", "pod": "db-abc-1",
        "incident_id": INC, "t0_ms": str(T0 * 1000)}))
    # restore needs corrective ledger writes, so it stops early; either way a human was paged
    assert len(r.redis.stream(ESCALATIONS_STREAM)) == 1


# ---- duplicate requests never run at the same time (P6/P8 review) -----------------------------------------

def test_a_duplicate_entry_for_the_same_incident_and_action_does_not_run_concurrently():
    r = R(freeze_old=False)
    ex = make_executor(r, r.entropy)
    base = {"namespace": "prod", "deployment": "db", "pod": "db-abc-1", "incident_id": INC, "action": "contain"}
    key = ex._done_key(base, "1-0")
    r.redis.store[f"{key}:inflight"] = "another-executor"          # the first request is still running
    assert run(ex.handle_entry("kubeheal.exec", "2-0", dict(base))) is False
    assert r.c.log == [] and r.redis.acked == []                    # nothing ran, left pending for a later skip
    del r.redis.store[f"{key}:inflight"]
    assert run(ex.handle_entry("kubeheal.exec", "2-0", dict(base))) is True
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"
    assert f"{key}:inflight" not in r.redis.store                   # cleared afterwards


# ---- in-progress marker: short TTL, refreshed by the live run, owner-checked (review fix 1) ------------------

def contain_fields(**extra):
    return dict({"action": "contain", "namespace": "prod", "deployment": "db", "pod": "db-abc-1",
                 "incident_id": INC}, **extra)


def test_inflight_ttl_is_a_short_chosen_default():
    from agents.executor.main import INFLIGHT_TTL_S
    assert INFLIGHT_TTL_S <= 120          # chosen default (90 s), not measured; the old 1800 s blocked reclaims


def test_marker_of_a_dead_executor_expires_and_the_reclaimed_entry_runs():
    r = R(freeze_old=False)
    ex = make_executor(r, r.entropy)
    key = ex._done_key(contain_fields(), "1-0")
    # an Executor that died mid-request left its marker, set with the real TTL
    run(r.redis.set(f"{key}:inflight", "dead-executor", nx=True, ex=ex.inflight_ttl_s))
    assert run(ex.handle_entry("kubeheal.exec", "1-0", contain_fields())) is False     # still looks alive
    assert r.c.log == [] and r.redis.acked == []
    assert run(r.redis.get(f"{key}:inflight")) == "dead-executor"                      # not deleted by a non-owner
    r.redis.advance(ex.inflight_ttl_s + 1)                                             # nobody refreshed it
    assert run(ex.handle_entry("kubeheal.exec", "1-0", contain_fields())) is True
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"
    assert r.redis.acked == ["1-0"] and f"{key}:inflight" not in r.redis.store


def test_a_live_run_keeps_refreshing_its_marker_and_only_the_owner_deletes_it():
    r = R(freeze_old=False)
    ex = make_executor(r, r.entropy)
    ex.inflight_refresh_s = 0.01
    key = ex._done_key(contain_fields(), "1-0")
    inflight = f"{key}:inflight"
    sets = []
    real_set = r.redis.set

    async def spy(k, v, nx=False, ex=None):
        sets.append((k, v, nx, ex))
        return await real_set(k, v, nx=nx, ex=ex)

    r.redis.set = spy

    async def slow_execute(fields):
        await asyncio.sleep(0.15)                               # a long action, several refresh intervals
        return "contained"

    ex.execute = slow_execute
    assert run(ex.handle_entry("kubeheal.exec", "1-0", contain_fields())) is True
    refreshes = [s for s in sets if s[0] == inflight and not s[2]]
    assert len(refreshes) >= 2 and all(s[1] == ex.consumer and s[3] == ex.inflight_ttl_s for s in refreshes)
    assert inflight not in r.redis.store

    # lost ownership: another consumer holds the marker when this run ends, it must stay
    r2 = R(freeze_old=False)
    ex2 = make_executor(r2, r2.entropy)
    inflight2 = f"{ex2._done_key(contain_fields(), '1-0')}:inflight"

    async def stolen(fields):
        r2.redis.store[inflight2] = "someone-else"
        return "contained"

    ex2.execute = stolen
    assert run(ex2.handle_entry("kubeheal.exec", "1-0", contain_fields())) is True
    assert r2.redis.store[inflight2] == "someone-else"


def test_marker_refresh_and_delete_use_compare_scripts_when_the_client_has_eval():
    class EvalRedis(fk.Redis):
        def __init__(self):
            super().__init__()
            self.scripts = []

        async def eval(self, script, n, key, token, *extra):
            self.scripts.append(("refresh" if "expire" in script else "delete", key, token, extra))
            if self.store.get(key) != token:
                return 0
            if "expire" not in script:
                self.store.pop(key, None)
            return 1

    r = R(freeze_old=False)
    r.redis = EvalRedis()
    ex = make_executor(r, r.entropy)
    ex.inflight_refresh_s = 0.01

    async def slow_execute(fields):
        await asyncio.sleep(0.08)
        return "contained"

    ex.execute = slow_execute
    assert run(ex.handle_entry("kubeheal.exec", "1-0", contain_fields())) is True
    kinds = [s[0] for s in r.redis.scripts]
    assert kinds.count("refresh") >= 2 and kinds[-1] == "delete"
    assert all(s[2] == ex.consumer for s in r.redis.scripts)
    assert not any(k.endswith(":inflight") for k in r.redis.store)


def test_start_clears_stale_markers_owned_by_this_consumer_name_only():
    r = R(freeze_old=False)
    ex = make_executor(r, r.entropy)
    mine = "kubeheal:exec:done:inc-a:contain:live:inflight"
    theirs = "kubeheal:exec:done:inc-b:contain:live:inflight"
    done = "kubeheal:exec:done:inc-c:contain:live"
    r.redis.store.update({mine: ex.consumer, theirs: "another-executor", done: "{}"})
    assert run(ex._clear_own_inflight()) == 1
    assert mine not in r.redis.store and theirs in r.redis.store and done in r.redis.store


# ---- a healthy long run is not dead-lettered by its duplicates (review fix 2a) --------------------------------

def test_duplicate_entry_is_not_dead_lettered_while_a_healthy_run_holds_the_marker():
    from fake_redis import FakeRedis
    from agents.common.stream_reliability import ReliabilityConfig, StreamReliability
    from agents.executor.main import EXEC_STREAM, GROUP
    r = R(freeze_old=False)
    redis = FakeRedis()
    r.redis = redis
    ex = make_executor(r, r.entropy)
    ex.reliability = StreamReliability(lambda: redis, GROUP, ex.consumer,
                                       ReliabilityConfig(min_idle_ms=1000, max_deliveries=2),
                                       clock=lambda: redis.now)

    async def go():
        await redis.xgroup_create(EXEC_STREAM, GROUP, id="0", mkstream=True)
        msg_id = await redis.xadd(EXEC_STREAM, contain_fields())
        await redis.xreadgroup(GROUP, "first-run-executor", {EXEC_STREAM: ">"}, count=5)    # delivery 1
        key = ex._done_key(contain_fields(), msg_id)
        await redis.set(f"{key}:inflight", "first-run-executor", nx=True, ex=3600)           # the run is healthy
        for _ in range(5):                                                                    # deliveries 2..6
            redis.advance(2)
            await ex.reclaim_pending()
            await asyncio.gather(*list(ex._tasks))
        return msg_id, key

    msg_id, key = run(go())
    assert [f for s, f in redis.added if s == ESCALATIONS_STREAM] == []
    assert redis.streams.get("kubeheal.deadletter") is None
    assert (EXEC_STREAM, msg_id) not in redis.acked                                          # left pending
    assert r.c.log == []                                                                     # nothing ran twice

    # the run died (marker gone): the same entry is now dead-lettered and escalated as before
    async def after():
        del redis.store[f"{key}:inflight"]

        async def failing(*a):
            return False

        ex.handle_entry = failing                                                            # keeps failing
        for _ in range(4):
            redis.advance(2)
            await ex.reclaim_pending()
            await asyncio.gather(*list(ex._tasks))

    run(after())
    assert len([f for s, f in redis.added if s == ESCALATIONS_STREAM]) == 1
    assert (EXEC_STREAM, msg_id) in redis.acked


# ---- a ledger-refused request is retryable under the same incident id (review fix 4) --------------------------

def test_ledger_refused_patch_is_escalated_not_final_and_a_retry_runs_after_minio_recovers():
    s = Scenario()
    s.redis.store["kubeheal:baseline:prod:web"] = json.dumps(s.golden)
    led = FlakyLedger()
    led.down_steps = {"intent_patch_deployment"}
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(), metric_source=s.source,
                         cfg=ExecConfig(DRIFT_ENV), sleep=s.clock.sleep, clock=s.clock, ledger=led)
    req = {"action": "patch", "namespace": "prod", "deployment": "web", "pod": "", "patch_field": CPU,
           "incident_id": "inc-same"}
    run(ex.handle_entry("kubeheal.exec", "1-0", dict(req)))
    first = s.redis.stream(ACTIONS_STREAM)[-1]["outcome"]
    assert first.startswith("escalated:ledger_unavailable") and s.c.writes() == []
    assert not any(k.startswith("kubeheal:exec:done") for k in s.redis.store)        # no 7-day marker
    assert len(s.redis.stream(ESCALATIONS_STREAM)) == 1                              # a human was told
    led.down_steps = set()                                                           # MinIO is back
    s.calls.clear()                                                                  # fresh metric history
    assert run(ex.handle_entry("kubeheal.exec", "2-0", dict(req))) is True           # re-approval, same incident
    assert s.c.writes() != []                                                        # it really patched
    assert s.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "patched_kept"


def test_ledger_refused_contain_is_not_final_and_a_retry_runs_after_minio_recovers():
    r = R(freeze_old=False)
    led = FlakyLedger()
    led.down_steps = {"intent_create_quarantine_policy"}     # MinIO and the fallback both refuse that one entry
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    real_xadd = r.redis.xadd
    broken = {"on": True}

    async def xadd(stream, fields, *a, **k):
        if broken["on"] and stream == FALLBACK_STREAM and fields.get("step") == "intent_create_quarantine_policy":
            raise ConnectionError("fallback down")
        return await real_xadd(stream, fields, *a, **k)

    r.redis.xadd = xadd
    run(ex.handle_entry("kubeheal.exec", "1-0", contain_fields()))
    assert r.c.log == []
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"].startswith("contain_failed:ledger_unavailable")
    assert not any(k.startswith("kubeheal:exec:done") for k in r.redis.store)
    led.down_steps, broken["on"] = set(), False
    assert run(ex.handle_entry("kubeheal.exec", "2-0", contain_fields())) is True
    assert "create_policy" in [e[1] for e in r.c.log]
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"


# ---- restore: the corrective ledger entry comes BEFORE the first write (review fix 7) -------------------------

def restore_fields():
    return {"action": "restore", "namespace": "prod", "deployment": "db", "pod": "db-abc-1",
            "incident_id": INC, "t0_ms": str(T0 * 1000)}


def test_restore_writes_nothing_when_minio_is_down_even_though_the_fallback_is_up():
    r = R()
    led = FlakyLedger()
    led.down_steps = {"intent_restore_begin"}          # MinIO refuses the corrective entry; Redis fallback is up
    ex = make_executor(r, r.entropy)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    run(ex.handle_entry("kubeheal.exec", "1-0", restore_fields()))
    assert r.c.log == []                                                  # no policy, no annotation, no scale
    assert r.c.workloads[("Deployment", "db")]["spec"]["replicas"] == 1
    out = r.redis.stream(ACTIONS_STREAM)[-1]["outcome"]
    assert out.startswith("escalated:ledger_unavailable") and "restore_begin" in out
    esc = r.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human"
    assert all(f["step"] != "intent_restore_begin" for f in fallback(r.redis))    # the fallback does not count
    assert not any(k.startswith("kubeheal:exec:done") for k in r.redis.store)
    led.down_steps = set()                                                # MinIO recovers: the same incident runs
    assert run(ex.handle_entry("kubeheal.exec", "2-0", restore_fields())) is True
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "restored"
    assert "intent_restore_begin" in led.steps()


def test_restore_begin_is_a_corrective_step_and_is_skipped_in_a_dry_run():
    from agents.executor.ledger_guard import step_class
    assert step_class("restore_begin") == "corrective"
    r = R()
    led = FlakyLedger()
    ex = make_executor(r, r.entropy)
    ex.mode = fk.Mode(dry=True)
    ex.ledger = led
    ex.ledger_guard.ledger = led
    run(ex.handle_entry("kubeheal.exec", "1-0", restore_fields()))
    assert r.c.log == [] and "intent_restore_begin" not in led.steps()
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"].startswith("DRY RUN:")


# ---- LedgerUnavailable is never read as "already exists" (review fix 9) ---------------------------------------

class RefusingGate:
    """Opens every write but refuses the "about to do" entry of `step` with a text that contains 'conflict'."""

    def __init__(self, step):
        self.step = step

    def allow_write(self, namespace):
        return True

    async def record_intent(self, namespace, step):
        from agents.executor.ledger_guard import LedgerUnavailable
        if step == self.step:
            raise LedgerUnavailable(step, "corrective", "ledger write failed (409 Conflict: already exists)")


def test_contain_does_not_treat_a_ledger_refusal_as_an_existing_policy():
    from agents.executor import quarantine
    from agents.executor.support import Recorder
    from agents.executor.validation import Request
    r = R(freeze_old=False)
    req = Request(action="contain", namespace="prod", incident_id=INC, deployment="db", pod="db-abc-1")
    out = run(quarantine.contain(RefusingGate("create_quarantine_policy"), r.c.core, r.c.net, r.c.apps,
                                 r.c.custom, req, Recorder(None, INC), ExecConfig(RR_ENV)))
    assert out.startswith("contain_failed:") and "ledger_unavailable" in out
    assert r.c.log == []                                      # the label and the snapshot did not follow


def test_restore_does_not_treat_a_ledger_refusal_as_an_existing_pvc():
    from agents.executor import restore, snapshots
    from agents.executor.support import Recorder
    from test_remediation_ransomware import req
    r = R()
    out = run(restore.restore(RefusingGate("create_restored_pvc"), r.c.core, r.c.apps, r.c.net, r.c.custom,
                              req("restore"), Recorder(None, INC), ExecConfig(RR_ENV),
                              snapshots.SnapshotFreeze(r.redis), r.entropy, r.clock.sleep, r.clock))
    assert out.startswith("restore_failed:") and "ledger_unavailable" in out
    assert "create_pvc" not in r.methods()
    assert r.methods().count("patch_Deployment") == 1         # only the replica annotation: repoint never ran
