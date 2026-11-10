"""
Redis Streams reliability shared by the Fusion Agent and the Executor (S-MQ-2, S-MQ-3, P6-R1).
=============================================================================================
A consumer group delivers each entry to one consumer. If that consumer dies (or fails) before it
acknowledges, the entry stays in the group's pending list (PEL). Without a reader of the PEL it would
stay there forever. This helper adds the missing parts, once, for every consumer loop:

  reclaim   XAUTOCLAIM of entries that were idle for `min_idle_ms`, handed to the owner's handler.
            Redis increments the delivery counter on every claim; it is read back with XPENDING.
  dead      an entry that was already delivered `max_deliveries` times without a successful ack is not
            handled again: it is copied to the dead-letter stream (`kubeheal.deadletter`), the owner's
            `dead_letter` callback runs (the owners write an escalation for a human), and only then is the
            original acknowledged. A poison entry therefore cannot loop forever.
  lease     while an entry is being handled, its idle time is reset with XCLAIM ... JUSTID (no delivery
            count change) so that a long action (a canary watch lasts several windows) is not reclaimed
            and run a second time by another consumer or by the same one.

Ack only on success stays with the owner's handler (it acks after the work). The helper never acks an
entry whose handler failed.

Redelivery means at-least-once: owners must be idempotent (Fusion keys circuit breakers and incidents by
incident id, the Executor records a result marker per incident, action and dry-run flag).

Numbers below are chosen, not measured; every one is configurable through the environment.
"""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DEADLETTER_STREAM = "kubeheal.deadletter"

# chosen, not measured (documented defaults; override with the environment variables named below)
DEFAULT_MIN_IDLE_MS = 60_000        # KUBEHEAL_PENDING_IDLE_MS: how long an entry may sit unacknowledged
DEFAULT_MAX_DELIVERIES = 5          # KUBEHEAL_MAX_DELIVERIES: deliveries allowed before dead-lettering
DEFAULT_RECLAIM_INTERVAL_S = 15.0   # KUBEHEAL_RECLAIM_INTERVAL_S: pause between reclaim sweeps
DEFAULT_RECLAIM_BATCH = 10          # KUBEHEAL_RECLAIM_BATCH: COUNT of one XAUTOCLAIM call
DEFAULT_DEADLETTER_MAXLEN = 10_000  # KUBEHEAL_DEADLETTER_MAXLEN: approximate cap of the dead-letter stream


@dataclass(frozen=True)
class ReliabilityConfig:
    min_idle_ms: int = DEFAULT_MIN_IDLE_MS
    max_deliveries: int = DEFAULT_MAX_DELIVERIES
    reclaim_interval_s: float = DEFAULT_RECLAIM_INTERVAL_S
    batch: int = DEFAULT_RECLAIM_BATCH
    deadletter_stream: str = DEADLETTER_STREAM
    deadletter_maxlen: int = DEFAULT_DEADLETTER_MAXLEN

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "ReliabilityConfig":
        env = os.environ if env is None else env

        def num(name, default, cast):
            raw = env.get(name)
            if raw in (None, ""):
                return default
            try:
                value = cast(raw)
            except ValueError:
                logger.warning(f"{name}={raw!r} is not a number; using {default}")
                return default
            if value <= 0:
                logger.warning(f"{name}={raw!r} must be positive; using {default}")
                return default
            return value

        return cls(
            min_idle_ms=num("KUBEHEAL_PENDING_IDLE_MS", DEFAULT_MIN_IDLE_MS, int),
            max_deliveries=num("KUBEHEAL_MAX_DELIVERIES", DEFAULT_MAX_DELIVERIES, int),
            reclaim_interval_s=num("KUBEHEAL_RECLAIM_INTERVAL_S", DEFAULT_RECLAIM_INTERVAL_S, float),
            batch=num("KUBEHEAL_RECLAIM_BATCH", DEFAULT_RECLAIM_BATCH, int),
            deadletter_maxlen=num("KUBEHEAL_DEADLETTER_MAXLEN", DEFAULT_DEADLETTER_MAXLEN, int),
        )


Handler = Callable[[str, str, Dict], Awaitable[bool]]
DeadLetterHook = Callable[[str, str, Dict, int, str], Awaitable[None]]


@dataclass
class SweepResult:
    claimed: int = 0
    handled: int = 0
    failed: int = 0
    dead_lettered: int = 0
    skipped: int = 0


def _split_claim(reply) -> Tuple[str, List[Tuple[str, Optional[Dict]]]]:
    """XAUTOCLAIM answers [next_id, entries] (Redis 6.2) or [next_id, entries, deleted_ids] (Redis 7)."""
    if not reply or len(reply) < 2:
        return "0-0", []
    return str(reply[0]), list(reply[1] or [])


class StreamReliability:
    def __init__(self, get_redis: Callable[[], object], group: str, consumer: str,
                 cfg: Optional[ReliabilityConfig] = None, clock: Callable[[], float] = time.time):
        self._get_redis = get_redis
        self.group, self.consumer = group, consumer
        self.cfg = cfg or ReliabilityConfig.from_env()
        self.clock = clock
        self._inflight: Set[Tuple[str, str]] = set()

    @property
    def redis(self):
        return self._get_redis()

    # ---- lease while handling ---------------------------------------------------------------
    @asynccontextmanager
    async def lease(self, stream: str, msg_id: str):
        """Hold an entry while it is handled: mark it in flight and keep its idle time near zero."""
        key = (stream, msg_id)
        self._inflight.add(key)
        interval = max(self.cfg.min_idle_ms / 1000.0 / 3.0, 0.001)
        task = asyncio.create_task(self._heartbeat(stream, msg_id, interval))
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self._inflight.discard(key)

    async def _heartbeat(self, stream: str, msg_id: str, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await self.redis.xclaim(stream, self.group, self.consumer, min_idle_time=0,
                                        message_ids=[msg_id], justid=True)
            except Exception as e:
                logger.warning(f"lease heartbeat for {stream}/{msg_id} failed: {e}")

    # ---- reclaim sweep ----------------------------------------------------------------------
    async def reclaim(self, stream: str, handle: Handler, dead_letter: DeadLetterHook) -> SweepResult:
        """One sweep over the stale pending entries of `stream`. `handle(stream, id, fields)` returns True
        when the entry was handled and acknowledged. Never raises for one bad entry."""
        result = SweepResult()
        cursor = "0-0"
        while True:
            reply = await self.redis.xautoclaim(stream, self.group, self.consumer,
                                                min_idle_time=self.cfg.min_idle_ms, start_id=cursor,
                                                count=self.cfg.batch)
            cursor, entries = _split_claim(reply)
            for msg_id, fields in entries:
                result.claimed += 1
                await self._one(stream, msg_id, fields, handle, dead_letter, result)
            if cursor in ("0-0", "0"):
                return result

    async def _one(self, stream, msg_id, fields, handle, dead_letter, result: SweepResult) -> None:
        if (stream, msg_id) in self._inflight:
            result.skipped += 1          # our own running entry: the lease keeps it ours
            return
        if fields is None:
            # the entry was trimmed from the stream; nothing to run, drop it from the pending list
            await self.redis.xack(stream, self.group, msg_id)
            result.skipped += 1
            return
        try:
            deliveries = await self.deliveries(stream, msg_id)
        except Exception as e:
            logger.error(f"cannot read the delivery count of {stream}/{msg_id}: {e}; retry next sweep")
            result.skipped += 1
            return
        if deliveries > self.cfg.max_deliveries:
            await self._dead(stream, msg_id, fields, deliveries, dead_letter, result)
            return
        try:
            ok = await handle(stream, msg_id, fields)
        except Exception as e:
            logger.error(f"reclaimed {stream}/{msg_id} failed again: {e}", exc_info=True)
            ok = False
        if ok:
            result.handled += 1
        else:
            result.failed += 1

    async def deliveries(self, stream: str, msg_id: str) -> int:
        rows = await self.redis.xpending_range(stream, self.group, min=msg_id, max=msg_id, count=1)
        for row in rows or []:
            return int(row["times_delivered"])
        raise LookupError("entry is not pending")

    async def _dead(self, stream, msg_id, fields, deliveries, dead_letter, result: SweepResult) -> None:
        reason = (f"dead_lettered: {deliveries - 1} deliveries without a successful ack "
                  f"(limit {self.cfg.max_deliveries})")
        logger.error(f"DEAD LETTER {stream}/{msg_id}: {reason}")
        try:
            await self.redis.xadd(self.cfg.deadletter_stream, {
                "source_stream": stream, "group": self.group, "original_id": msg_id,
                "deliveries": str(deliveries - 1), "reason": reason,
                "fields_json": json.dumps(fields, sort_keys=True),
                "timestamp_ms": str(int(self.clock() * 1000)),
            }, maxlen=self.cfg.deadletter_maxlen, approximate=True)
            await dead_letter(stream, msg_id, fields, deliveries - 1, reason)
            await self.redis.xack(stream, self.group, msg_id)
        except Exception as e:
            # not acknowledged: it stays pending and the next sweep tries again
            logger.error(f"dead-lettering {stream}/{msg_id} failed: {e}", exc_info=True)
            result.failed += 1
            return
        result.dead_lettered += 1
