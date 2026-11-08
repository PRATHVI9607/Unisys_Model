"""Concurrency guards for remediation: per-workload incident lock + circuit breaker.

Order in the agent: take the lock, check the breaker, act, count a success. The lock and the breaker are
keyed on the same target, so check → act → count runs serialised per target even across fusion replicas
and the count cannot overshoot (no Lua needed); only a lock lost mid-action (Redis unreachable > 10 s)
could let one extra action through.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

log = logging.getLogger(__name__)

LOCK_TTL_MS = 10_000
HEARTBEAT_S = 3.0
CIRCUIT_WINDOW_S = 3600

# Owner-checked: a holder whose lock expired and was re-taken must not extend or delete it.
EXTEND_IF_OWNER = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) end
return 0
"""
RELEASE_IF_OWNER = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end
return 0
"""


@asynccontextmanager
async def incident_lock(redis, key: str) -> AsyncIterator[bool]:
    """`async with incident_lock(r, key) as held:` — held is False if another holder has it."""
    token = uuid.uuid4().hex
    if not await redis.set(key, token, nx=True, px=LOCK_TTL_MS):
        yield False
        return
    hb = asyncio.create_task(_heartbeat(redis, key, token))
    try:
        yield True
    finally:
        hb.cancel()
        await asyncio.gather(hb, return_exceptions=True)
        try:
            await redis.eval(RELEASE_IF_OWNER, 1, key, token)
        except Exception:
            log.warning("could not release lock %s; it expires in %d ms", key, LOCK_TTL_MS, exc_info=True)


async def _heartbeat(redis, key: str, token: str) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_S)
        try:
            if not await redis.eval(EXTEND_IF_OWNER, 1, key, token, LOCK_TTL_MS):
                log.warning("lost incident lock %s", key)
                return
        except Exception:
            log.warning("lock heartbeat failed for %s", key, exc_info=True)
            return


async def circuit_open(redis, key: str, limit: int) -> bool:
    """True once `limit` successful actions were counted in the current window."""
    return int(await redis.get(key) or 0) >= limit


async def circuit_count(redis, key: str, window_s: int = CIRCUIT_WINDOW_S) -> None:
    """Count one successful action; the fixed window starts at the first (EXPIRE NX). Never raises:
    the action already happened, and failing now would only re-run it."""
    try:
        async with redis.pipeline(transaction=True) as p:
            p.incr(key)
            p.expire(key, window_s, nx=True)
            await p.execute()
    except Exception:
        log.error("could not count a success in circuit breaker %s", key, exc_info=True)
