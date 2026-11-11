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

Entries flushed later get a later sequence number than the entries written meanwhile; the flushed
payload carries `deferred_from_fallback`, the original `recorded_at` time and the fallback stream id, so
a reader can order them and detect a duplicate (a crash between the MinIO write and the stream delete
re-sends that one entry on the next flush).
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

FALLBACK_STREAM = "kubeheal.ledger.pending"

# Steps that proceed when only the fallback is available. Anything not listed is corrective.
# `rollback_deployment`, `restore_strategy` and `recover_rollback_after_restart` return a Deployment to
# the state saved before our own patch. The owner's list did not name them; they are treated as
# protective because refusing them would leave a failed canary in place. Revisit if the owner disagrees.
PROTECTIVE_STEPS = frozenset({
    "create_quarantine_policy", "label_pod", "forensic_snapshot",
    "ensure_quarantine_policy", "remember_replicas", "scale_to_zero",
    "create_rolling_snapshot",
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
    def __init__(self, ledger, get_redis: Callable[[], Any], metrics=None):
        self.ledger = ledger
        self.get_redis = get_redis
        self.metrics = metrics

    # ---- low level

    async def _to_ledger(self, incident_id: str, step: str, payload: Dict) -> None:
        await asyncio.to_thread(self.ledger.append, incident_id, step, payload)

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
        """Move fallback entries to the ledger, oldest first. An entry is deleted from the stream only
        after its ledger write succeeded; the first failure stops the run (MinIO is still down)."""
        redis = self.get_redis()
        if redis is None:
            return 0
        flushed = 0
        entries = await redis.xrange(FALLBACK_STREAM, min="-", max="+", count=batch)
        for entry_id, fields in entries or []:
            f = {_s(k): _s(v) for k, v in fields.items()}
            try:
                payload = json.loads(f.get("payload") or "{}")
                if not isinstance(payload, dict):
                    payload = {"value": payload}
                incident_id, step = f["incident_id"], f["step"]
            except (ValueError, KeyError):
                logger.error("malformed fallback entry %s left in place", _s(entry_id))
                continue
            payload.update({"deferred_from_fallback": True, "recorded_at": f.get("recorded_at"),
                            "fallback_stream_id": _s(entry_id)})
            try:
                await self._to_ledger(incident_id, step, payload)
            except Exception as exc:     # includes FileExistsError (sequence key taken): retry next run
                logger.warning("fallback flush stopped, ledger still failing: %s", type(exc).__name__)
                break
            await redis.xdel(FALLBACK_STREAM, entry_id)
            flushed += 1
        await self.pending_depth()
        return flushed

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
