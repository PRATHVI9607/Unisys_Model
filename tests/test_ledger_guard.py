"""P7-RR-10 owner decision on ledger write failures (agents/executor/ledger_guard.py).

protective steps proceed when MinIO fails, the record goes to the fallback stream plus a metric;
corrective steps need a MinIO write first; both down means nothing runs and a human is told.
"""
import asyncio

import pytest

from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.common.metrics import KubeHealMetrics
from agents.executor.ledger_guard import (FALLBACK_STREAM, PROTECTIVE_STEPS, LedgerGuard, LedgerUnavailable,
                                          step_class)


def run(c):
    return asyncio.run(c)


class Stream:
    """Just the stream commands the guard uses."""

    def __init__(self):
        self.entries, self.n, self.fail_xadd = [], 0, False

    async def xadd(self, stream, fields):
        if self.fail_xadd:
            raise ConnectionError("redis down")
        assert stream == FALLBACK_STREAM
        self.n += 1
        eid = f"{self.n}-0"
        self.entries.append((eid, dict(fields)))
        return eid

    async def xrange(self, stream, min="-", max="+", count=None):
        return list(self.entries[:count])

    async def xdel(self, stream, *ids):
        self.entries = [e for e in self.entries if e[0] not in ids]

    async def xlen(self, stream):
        return len(self.entries)


class FlakyLedger:
    def __init__(self):
        self.ledger = Ledger(InMemoryLedgerStore())
        self.down = False

    @property
    def store(self):
        return self.ledger.store

    def append(self, incident_id, step, payload):
        if self.down:
            raise OSError("minio down")
        return self.ledger.append(incident_id, step, payload)


def build(redis_present=True):
    ledger, stream, metrics = FlakyLedger(), Stream(), KubeHealMetrics()
    guard = LedgerGuard(ledger, (lambda: stream) if redis_present else (lambda: None), metrics)
    return guard, ledger, stream, metrics


def counter(metrics, text):
    return [l for l in metrics.render().decode().splitlines() if l.startswith(text) and not l.startswith("#")]


def test_classification_lists_the_owner_named_steps_and_defaults_to_corrective():
    for s in ("create_quarantine_policy", "label_pod", "forensic_snapshot", "scale_to_zero",
              "create_rolling_snapshot"):
        assert step_class(s) == "protective"
    for s in ("patch_deployment", "create_restored_pvc", "repoint_and_pin", "scale_back", "lift_quarantine",
              "delete_quarantine_policy", "remove_original_replicas_annotation", "delete_old_rolling_snapshot",
              "create_restore_entropy_job", "something_new"):
        assert step_class(s) == "corrective"
    assert "patch_deployment" not in PROTECTIVE_STEPS and "lift_quarantine" not in PROTECTIVE_STEPS


def test_healthy_ledger_takes_the_intent_and_never_touches_the_fallback():
    guard, ledger, stream, _ = build()
    assert run(guard.intent("inc-1", "label_pod", {"namespace": "prod"})) == "ledger"
    assert run(guard.intent("inc-1", "patch_deployment")) == "ledger"
    assert stream.entries == []
    assert len(list(ledger.store.keys("incidents/inc-1/"))) == 2


@pytest.mark.parametrize("step", ["create_quarantine_policy", "label_pod", "forensic_snapshot", "scale_to_zero"])
def test_protective_step_proceeds_on_ledger_failure_with_fallback_record_and_metric(step):
    guard, ledger, stream, metrics = build()
    ledger.down = True
    assert run(guard.intent("inc-1", step, {"namespace": "prod"})) == "fallback"
    (eid, fields), = stream.entries
    assert fields["incident_id"] == "inc-1" and fields["step"] == f"intent_{step}"
    assert counter(metrics, "kubeheal_ledger_fallback_writes_total") == [
        'kubeheal_ledger_fallback_writes_total{kind="protective_intent"} 1.0']


@pytest.mark.parametrize("step", ["patch_deployment", "create_restored_pvc", "repoint_and_pin", "scale_back",
                                  "lift_quarantine", "delete_quarantine_policy"])
def test_corrective_step_needs_a_ledger_write_and_the_fallback_does_not_count(step):
    guard, ledger, stream, metrics = build()
    ledger.down = True
    with pytest.raises(LedgerUnavailable) as e:
        run(guard.intent("inc-1", step))
    assert e.value.klass == "corrective" and "no automatic action" in str(e.value)
    assert stream.entries == []                       # nothing was parked as if it had been recorded
    assert counter(metrics, "kubeheal_ledger_unavailable_total") == [
        'kubeheal_ledger_unavailable_total{reason="corrective_needs_ledger"} 1.0']


@pytest.mark.parametrize("step", ["label_pod", "scale_to_zero", "patch_deployment"])
def test_both_down_means_no_automatic_action_even_for_protective_steps(step):
    guard, ledger, stream, metrics = build()
    ledger.down, stream.fail_xadd = True, True
    with pytest.raises(LedgerUnavailable):
        run(guard.intent("inc-1", step))
    guard2, ledger2, _, metrics2 = build(redis_present=False)
    ledger2.down = True
    with pytest.raises(LedgerUnavailable):
        run(guard2.intent("inc-1", step))


def test_record_goes_to_the_fallback_and_only_raises_when_both_fail():
    guard, ledger, stream, _ = build()
    ledger.down = True
    assert run(guard.record("inc-1", "result", {"outcome": "x"})) == "fallback"
    stream.fail_xadd = True
    with pytest.raises(RuntimeError):
        run(guard.record("inc-1", "result", {"outcome": "y"}))


def test_flush_moves_entries_to_the_ledger_in_order_then_deletes_them():
    guard, ledger, stream, metrics = build()
    ledger.down = True
    run(guard.record("inc-1", "a", {"n": 1}))
    run(guard.intent("inc-1", "label_pod"))
    assert run(guard.flush()) == 0 and len(stream.entries) == 2     # still down: nothing lost, nothing deleted
    ledger.down = False
    assert run(guard.flush()) == 2
    assert stream.entries == []
    keys = sorted(ledger.store.keys("incidents/inc-1/"))
    assert [k.rsplit("/", 1)[1].split("-", 1)[1] for k in keys] == ["a.json", "intent_label_pod.json"]
    import json
    first = json.loads(ledger.store.objects[keys[0]])["payload"]
    assert first["deferred_from_fallback"] is True and first["recorded_at"] and first["fallback_stream_id"] == "1-0"
    assert counter(metrics, "kubeheal_ledger_pending_entries") == ["kubeheal_ledger_pending_entries 0.0"]


def test_flush_stops_at_the_first_failure_and_keeps_the_rest():
    guard, ledger, stream, _ = build()
    ledger.down = True
    run(guard.record("inc-1", "a", {}))
    run(guard.record("inc-1", "b", {}))
    ledger.down = False
    real = ledger.append
    calls = []

    def flaky(incident_id, step, payload):
        calls.append(step)
        if len(calls) == 2:
            raise OSError("minio down again")
        return real(incident_id, step, payload)

    ledger.append = flaky
    assert run(guard.flush()) == 1
    assert [e[1]["step"] for e in stream.entries] == ["b"]


def test_malformed_fallback_entry_is_left_in_place():
    guard, ledger, stream, _ = build()
    stream.entries.append(("9-0", {"incident_id": "inc-1"}))
    assert run(guard.flush()) == 0 and len(stream.entries) == 1


def test_gated_write_is_blocked_by_a_corrective_ledger_failure_and_runs_for_a_protective_one():
    """End to end through actions._write, the single choke point for Kubernetes writes."""
    from agents.executor.actions import _write
    guard, ledger, stream, _ = build()
    ledger.down = True

    class Gate:
        def allow_write(self, ns):
            return True

        async def record_intent(self, ns, step):
            await guard.intent("inc-1", step, {"namespace": ns})

    calls = []

    async def write(*a):
        calls.append(a)
        return "ok"

    assert run(_write(Gate(), "prod", "label_pod", write, 1)) == "ok" and calls == [(1,)]
    with pytest.raises(LedgerUnavailable):
        run(_write(Gate(), "prod", "patch_deployment", write, 2))
    assert calls == [(1,)]                                  # the corrective write never reached Kubernetes


def test_gate_is_checked_again_after_the_intent_write():
    """The intent write takes time. If the mode flips to test meanwhile, the write must not happen."""
    from agents.executor.actions import ModeBlocked, _write
    state = {"allow": True}

    class Gate:
        def allow_write(self, ns):
            return state["allow"]

        async def record_intent(self, ns, step):
            state["allow"] = False                          # the kill switch flips during the ledger write

    calls = []

    async def write():
        calls.append(1)

    with pytest.raises(ModeBlocked):
        run(_write(Gate(), "prod", "label_pod", write))
    assert calls == []
