"""P7-RR-10 owner decision on ledger write failures (agents/executor/ledger_guard.py).

protective steps proceed when MinIO fails, the record goes to the fallback stream plus a metric;
corrective steps need a MinIO write first; both down means nothing runs and a human is told.
"""
import asyncio

import pytest

from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.common.metrics import KubeHealMetrics
from agents.executor.ledger_guard import (DEAD_STREAM, FALLBACK_STREAM, PROTECTIVE_STEPS, LedgerGuard, LedgerUnavailable,
                                          step_class)


def run(c):
    return asyncio.run(c)


class Stream:
    """Just the stream commands the guard uses."""

    def __init__(self):
        self.entries, self.n, self.fail_xadd, self.dead = [], 0, False, []

    async def xadd(self, stream, fields):
        if stream == DEAD_STREAM:
            self.dead.append(dict(fields))
            return f"d{len(self.dead)}-0"
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


def test_malformed_fallback_entry_goes_to_the_dead_stream_and_does_not_block_the_queue():
    guard, ledger, stream, _ = build()
    stream.entries.append(("9-0", {"incident_id": "inc-1"}))                       # no step, no payload
    stream.entries.append(("10-0", {"incident_id": "inc-1", "step": "a", "payload": "{not json"}))
    stream.entries.append(("11-0", {"incident_id": "a/b", "step": "a", "payload": "{}"}))   # ledger refuses the id
    run(guard.record("inc-2", "good", {"n": 1}))
    ledger.down = True
    run(guard.record("inc-2", "later", {"n": 2}))
    ledger.down = False
    assert run(guard.flush()) == 1                                        # the entry behind them still moved
    assert stream.entries == []
    assert [d["original_id"] for d in stream.dead] == ["9-0", "10-0", "11-0"]
    assert all(d["reason"] and d["fields_json"] for d in stream.dead)


def test_flush_loops_over_batches_until_empty():
    guard, ledger, stream, _ = build()
    ledger.down = True
    for i in range(7):
        run(guard.record("inc-1", f"s{i}", {}))
    ledger.down = False
    assert run(guard.flush(batch=3)) == 7 and stream.entries == []


def test_flush_batch_loop_is_capped_and_stops_at_the_first_failure():
    import agents.executor.ledger_guard as lg
    guard, ledger, stream, _ = build()
    ledger.down = True
    for i in range(6):
        run(guard.record("inc-1", f"s{i}", {}))
    ledger.down = False
    old = lg.FLUSH_MAX_BATCHES
    lg.FLUSH_MAX_BATCHES = 2
    try:
        assert run(guard.flush(batch=2)) == 4 and len(stream.entries) == 2      # cap: 2 batches of 2
    finally:
        lg.FLUSH_MAX_BATCHES = old
    real = ledger.append

    def down(*a):
        raise OSError("down")

    ledger.append = down
    assert run(guard.flush(batch=2)) == 0 and len(stream.entries) == 2
    ledger.append = real


# ---- write timeout (a hung MinIO must not delay the protective steps by minutes) ---------------------------

class SlowLedger:
    """append blocks `delay_s` in its worker thread (like a hung MinIO call), holding the Ledger lock."""

    def __init__(self, delay_s):
        self.ledger = Ledger(InMemoryLedgerStore())
        self.delay_s = delay_s

    def append(self, incident_id, step, payload):
        import time
        time.sleep(self.delay_s)
        return self.ledger.append(incident_id, step, payload)


def slow_guard(delay_s, timeout_s):
    stream, metrics = Stream(), KubeHealMetrics()
    return LedgerGuard(SlowLedger(delay_s), lambda: stream, metrics, timeout_s=timeout_s), stream


def test_a_hung_ledger_write_times_out_and_a_protective_intent_goes_to_the_fallback():
    import time
    guard, stream = slow_guard(delay_s=0.6, timeout_s=0.05)
    started = time.monotonic()
    assert run(guard.intent("inc-1", "scale_to_zero", {"namespace": "prod"})) == "fallback"
    assert time.monotonic() - started < 0.4                      # did not wait for the hung write
    assert [e[1]["step"] for e in stream.entries] == ["intent_scale_to_zero"]


def test_a_hung_ledger_write_stops_a_corrective_step_and_a_record_falls_back():
    guard, stream = slow_guard(delay_s=0.6, timeout_s=0.05)
    with pytest.raises(LedgerUnavailable) as e:
        run(guard.intent("inc-1", "patch_deployment"))
    assert "TimeoutError" in str(e.value) and e.value.klass == "corrective"
    assert stream.entries == []
    assert run(guard.record("inc-1", "result", {"outcome": "x"})) == "fallback"


def test_later_calls_do_not_block_forever_behind_a_timed_out_one():
    """The hung worker still holds the Ledger lock: the next call also times out (fast), and once the hung call
    returns, writes work again. Neither the event loop nor the caller waits for it."""
    import time
    guard, stream = slow_guard(delay_s=0.4, timeout_s=0.05)

    async def go():
        t = time.monotonic()
        first = await guard.record("inc-1", "a", {})
        second = await guard.record("inc-1", "b", {})
        fast = time.monotonic() - t
        await asyncio.sleep(1.0)                                  # the hung calls finish
        guard.ledger.delay_s = 0.0
        third = await guard.record("inc-1", "c", {})
        return first, second, third, fast

    first, second, third, fast = run(go())
    assert (first, second, third) == ("fallback", "fallback", "ledger")
    assert fast < 0.3


def test_write_timeout_default_and_env_override(monkeypatch):
    from agents.executor.ledger_guard import DEFAULT_WRITE_TIMEOUT_S, write_timeout_s
    assert write_timeout_s({}) == DEFAULT_WRITE_TIMEOUT_S == 5.0
    assert write_timeout_s({"LEDGER_WRITE_TIMEOUT_S": "2.5"}) == 2.5
    assert write_timeout_s({"LEDGER_WRITE_TIMEOUT_S": "junk"}) == DEFAULT_WRITE_TIMEOUT_S
    assert write_timeout_s({"LEDGER_WRITE_TIMEOUT_S": "-1"}) == DEFAULT_WRITE_TIMEOUT_S
    monkeypatch.setenv("LEDGER_WRITE_TIMEOUT_S", "7")
    assert LedgerGuard(FlakyLedger(), lambda: None).timeout_s == 7.0


# ---- sequence collisions with another writer ------------------------------------------------------------------

class TakenOnceStore(InMemoryLedgerStore):
    """Another writer takes the key we computed: put_if_absent raises FileExistsError `times` times, each time
    after the other writer's object appeared at that key."""

    def __init__(self, times=1):
        super().__init__()
        self.times = times

    def put_if_absent(self, key, data):
        if self.times:
            self.times -= 1
            super().put_if_absent(key, b"{}")
            raise FileExistsError(key)
        super().put_if_absent(key, data)


def test_corrective_intent_survives_a_sequence_collision_on_a_healthy_store():
    ledger = Ledger(TakenOnceStore(times=1))
    guard = LedgerGuard(ledger, lambda: None, timeout_s=2)
    assert run(guard.intent("inc-1", "patch_deployment")) == "ledger"
    assert len(list(ledger.store.keys("incidents/inc-1/"))) == 2


def test_ledger_append_retries_a_taken_sequence_number_but_not_forever():
    ledger = Ledger(TakenOnceStore(times=2))
    assert ledger.append("inc-1", "a", {}).sequence == 3
    ledger = Ledger(TakenOnceStore(times=5))
    with pytest.raises(FileExistsError):
        ledger.append("inc-1", "a", {})


def test_guard_retries_a_fake_ledger_that_raises_file_exists_once():
    guard, ledger, stream, _ = build()
    real, state = ledger.append, {"n": 0}

    def once(incident_id, step, payload):
        state["n"] += 1
        if state["n"] == 1:
            raise FileExistsError("taken")
        return real(incident_id, step, payload)

    ledger.append = once
    assert run(guard.intent("inc-1", "patch_deployment")) == "ledger" and state["n"] == 2


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
