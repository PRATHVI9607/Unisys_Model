"""
Ledger failure policy for the Executor (owner decision, P7-RR-10).
================================================================
Every Kubernetes write is preceded by an "about to do" ledger entry (see `actions._write`). What
happens when that entry cannot be written to MinIO depends on the kind of step:

  protective  quarantine, forensic snapshot, scale to zero (and the steps that serve them), plus rolling
              snapshots and the rollback of our own patch. They are reversible or only add safety, so
              they proceed. The record goes to a durable Redis stream (`kubeheal.ledger.pending`) and the
              counter `kubeheal_ledger_fallback_writes_total` rises. `flush()` moves it to MinIO later.
  corrective  drift patch, restore (PVC, repoint, scale back), lifting quarantine, and every step this
              module does not know by name. They need a successful MinIO write first. If it fails there
              is no automatic action: `LedgerUnavailable` stops the step and the Executor escalates to a
              human. The fallback stream does NOT count for these.

If MinIO and the fallback stream are both unavailable, no step runs at all (protective included).

`record()` is for the records written after a step (results, errors): it tries MinIO, then the fallback,
and raises only when both fail. The steps themselves are protected by the `intent()` barrier.

Time limit: one ledger write waits at most `LEDGER_WRITE_TIMEOUT_S` (chosen default 5 s, not measured). A
timeout counts as a failed write, so a hung MinIO delays the protective steps (quarantine, snapshot, scale to
zero) by that long, not by minutes. Limit that cannot be fully removed: `asyncio.to_thread` cannot cancel a
thread that is already blocked in the MinIO client. The timed-out call keeps running on its own worker and
keeps holding the `Ledger` append lock until the client call returns, so later appends on the same `Ledger`
queue behind it and time out too (they fall back to the stream) until MinIO answers. The workers are a
dedicated small pool, so hung ledger calls cannot starve the other threads of the process. A timed-out write
may still land in MinIO later: the same record can then also sit in the fallback stream, and a reader sees
it twice (the flushed copy carries `deferred_from_fallback`).

Entries flushed later get a later sequence number than the entries written meanwhile; the flushed
payload carries `deferred_from_fallback`, the original `recorded_at` time and the fallback stream id, so
a reader can order them and detect a duplicate (a crash between the MinIO write and the stream delete
re-sends that one entry on the next flush).
"""

import asyncio
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

FALLBACK_STREAM = "kubeheal.ledger.pending"
DEAD_STREAM = "kubeheal.ledger.dead"     # malformed fallback entries, moved out of the way for a human
DEFAULT_WRITE_TIMEOUT_S = 5.0            # chosen default, not measured; env LEDGER_WRITE_TIMEOUT_S
APPEND_ATTEMPTS = 3                      # chosen default, not measured: tries on FileExistsError
FLUSH_MAX_BATCHES = 20                   # chosen default, not measured: batches per flush call
LEDGER_WORKERS = 4                       # chosen default, not measured: threads reserved for ledger writes


def write_timeout_s(env=None) -> float:
    raw = (os.environ if env is None else env).get("LEDGER_WRITE_TIMEOUT_S")
    if raw in (None, ""):
        return DEFAULT_WRITE_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        value = 0.0
    if value <= 0:
        logger.warning("LEDGER_WRITE_TIMEOUT_S=%r must be a positive number; using %s", raw,
                       DEFAULT_WRITE_TIMEOUT_S)
        return DEFAULT_WRITE_TIMEOUT_S
    return value

# Steps that proceed when only the fallback is available. Anything not listed is corrective.
# `rollback_deployment`, `restore_strategy` and `recover_rollback_after_restart` return a Deployment to
# the state saved before our own patch. The owner's list did not name them; they are treated as
# protective because refusing them would leave a failed canary in place. Revisit if the owner disagrees.
PROTECTIVE_STEPS = frozenset({
    "create_quarantine_policy", "label_pod", "forensic_snapshot",
    "ensure_quarantine_policy", "remember_replicas", "scale_to_zero",
    "create_rolling_snapshot", "request_freeze",
    "rollback_deployment", "restore_strategy", "recover_rollback_after_restart",
})


def step_class(step: str) -> str:
    return "protective" if step in PROTECTIVE_STEPS else "corrective"


class LedgerUnavailable(Exception):
    """The ledger write required before a step failed, so the step must not run automatically."""

    def __init__(self, step: str, klass: str, detail: str):
        super().__init__(f"ledger_unavailable: no automatic action for {klass} step '{step}': {detail}")
        self.step, self.klass, self.detail = step, klass, detail


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LedgerGuard:
    def __init__(self, ledger, get_redis: Callable[[], Any], metrics=None,
                 timeout_s: Optional[float] = None):
        self.ledger = ledger
        self.get_redis = get_redis
        self.metrics = metrics
        self.timeout_s = write_timeout_s() if timeout_s is None else timeout_s
        self._pool = ThreadPoolExecutor(max_workers=LEDGER_WORKERS, thread_name_prefix="ledger-write")

    # ---- low level

    def _append_blocking(self, incident_id: str, step: str, payload: Dict) -> None:
        """Runs in a worker thread. Another writer on the same incident can take the next sequence number
        (FileExistsError); the listing is read again on the next try."""
        for attempt in range(APPEND_ATTEMPTS):
            try:
                self.ledger.append(incident_id, step, payload)
                return
            except FileExistsError:
                if attempt == APPEND_ATTEMPTS - 1:
                    raise

    async def _to_ledger(self, incident_id: str, step: str, payload: Dict) -> None:
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(self._pool, self._append_blocking, incident_id, step, payload)
        try:
            await asyncio.wait_for(future, self.timeout_s)
        except asyncio.TimeoutError as exc:
            # The worker thread cannot be stopped (see the module docstring); we stop waiting for it.
            raise TimeoutError(f"ledger write timed out after {self.timeout_s:g} s") from exc

    async def _to_fallback(self, incident_id: str, step: str, payload: Dict, error: Exception, kind: str) -> None:
        redis = self.get_redis()
        if redis is None:
            raise RuntimeError("fallback stream unavailable: Redis is not connected")
        await redis.xadd(FALLBACK_STREAM, {
            "incident_id": incident_id, "step": step, "payload": json.dumps(payload, default=str),
            "recorded_at": _now(), "ledger_error": type(error).__name__,
        })
        if self.metrics is not None:
            self.metrics.record_ledger_fallback(kind)
        logger.error("ledger write %s/%s failed (%s); kept in %s", incident_id, step,
                     type(error).__name__, FALLBACK_STREAM)

    # ---- public

    async def record(self, incident_id: str, step: str, payload: Dict) -> str:
        """Ledger, else fallback. Returns where the record went; raises if both failed."""
        try:
            await self._to_ledger(incident_id, step, payload)
            return "ledger"
        except Exception as first:
            try:
                await self._to_fallback(incident_id, step, payload, first, "record")
                return "fallback"
            except Exception as second:
                if self.metrics is not None:
                    self.metrics.record_ledger_unavailable("record_lost")
                raise RuntimeError(f"ledger and fallback both failed for {step}: "
                                   f"{type(first).__name__}, {type(second).__name__}") from second

    async def intent(self, incident_id: str, step: str, payload: Optional[Dict] = None) -> str:
        """The "about to do" entry. Returns "ledger" or "fallback", or raises LedgerUnavailable."""
        klass = step_class(step)
        body = {"phase": "about_to_do", "step": step, "class": klass, **(payload or {})}
        try:
            await self._to_ledger(incident_id, f"intent_{step}", body)
            return "ledger"
        except Exception as first:
            if klass == "corrective":
                if self.metrics is not None:
                    self.metrics.record_ledger_unavailable("corrective_needs_ledger")
                raise LedgerUnavailable(step, klass, f"ledger write failed ({type(first).__name__})") from first
            try:
                await self._to_fallback(incident_id, f"intent_{step}", body, first, "protective_intent")
                return "fallback"
            except Exception as second:
                if self.metrics is not None:
                    self.metrics.record_ledger_unavailable("ledger_and_fallback_down")
                raise LedgerUnavailable(
                    step, klass, f"ledger ({type(first).__name__}) and fallback stream "
                                 f"({type(second).__name__}) both unavailable") from second

    async def pending_depth(self) -> int:
        redis = self.get_redis()
        if redis is None:
            return 0
        depth = int(await redis.xlen(FALLBACK_STREAM))
        if self.metrics is not None:
            self.metrics.set_ledger_pending(depth)
        return depth

    async def flush(self, batch: int = 50) -> int:
        """Move fallback entries to the ledger, oldest first, batch after batch until the stream is empty or
        the first ledger failure (MinIO is still down), at most FLUSH_MAX_BATCHES batches per call. An entry
        is deleted from the stream only after its ledger write succeeded. A malformed entry (it can never be
        written) is copied to DEAD_STREAM and removed, so it cannot block the head of the queue forever."""
        redis = self.get_redis()
        if redis is None:
            return 0
        flushed = 0
        for _batch in range(FLUSH_MAX_BATCHES):
            entries = await redis.xrange(FALLBACK_STREAM, min="-", max="+", count=batch)
            if not entries:
                break
            removed, stop = 0, False
            for entry_id, fields in entries:
                f = {_s(k): _s(v) for k, v in (fields or {}).items()}
                try:
                    payload = json.loads(f.get("payload") or "{}")
                    if not isinstance(payload, dict):
                        payload = {"value": payload}
                    incident_id, step = f["incident_id"], f["step"]
                except (ValueError, KeyError):
                    await self._to_dead(redis, entry_id, f, "malformed fallback entry")
                    removed += 1
                    continue
                payload.update({"deferred_from_fallback": True, "recorded_at": f.get("recorded_at"),
                                "fallback_stream_id": _s(entry_id)})
                try:
                    await self._to_ledger(incident_id, step, payload)
                except (ValueError, TypeError) as exc:
                    # the ledger refuses the id or step itself (for example a "/" in it): never writable
                    await self._to_dead(redis, entry_id, f, f"ledger refused the entry: {exc}")
                    removed += 1
                    continue
                except Exception as exc:     # MinIO still failing (or a timeout): retry on the next run
                    logger.warning("fallback flush stopped, ledger still failing: %s", type(exc).__name__)
                    stop = True
                    break
                await redis.xdel(FALLBACK_STREAM, entry_id)
                flushed += 1
                removed += 1
            if stop or removed == 0 or len(entries) < batch:
                break
        await self.pending_depth()
        return flushed

    async def _to_dead(self, redis, entry_id, fields: Dict, reason: str) -> None:
        """Dead-letter one fallback entry. The copy is written before the original is deleted."""
        logger.error("%s %s moved to %s", reason, _s(entry_id), DEAD_STREAM)
        await redis.xadd(DEAD_STREAM, {
            "original_id": _s(entry_id), "reason": reason,
            "fields_json": json.dumps(fields, sort_keys=True, default=str), "moved_at": _now()})
        await redis.xdel(FALLBACK_STREAM, entry_id)
        if self.metrics is not None and hasattr(self.metrics, "record_ledger_unavailable"):
            self.metrics.record_ledger_unavailable("fallback_entry_dead")

    async def run_flusher(self, interval_s: float = 30.0, sleep: Callable = asyncio.sleep,
                          running: Callable[[], bool] = lambda: True) -> None:
        """Background loop. `interval_s` is a chosen default, not a measurement."""
        while running():
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("fallback flush failed: %s", type(exc).__name__)
            await sleep(interval_s)


def _s(v):
    return v.decode() if isinstance(v, bytes) else v
