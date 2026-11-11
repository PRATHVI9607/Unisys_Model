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
