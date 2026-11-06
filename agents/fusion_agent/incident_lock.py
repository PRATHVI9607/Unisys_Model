"""Concurrency guards for remediation: per-workload incident lock + circuit breaker.

Order in the agent: take the lock first, then consume circuit-breaker budget.
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


async def circuit_allows(redis, key: str, limit: int, window_s: int = CIRCUIT_WINDOW_S) -> bool:
    """Atomically count one action in a fixed window; False once `limit` is exceeded."""
    async with redis.pipeline(transaction=True) as p:
        p.incr(key)
        p.expire(key, window_s, nx=True)
        count, _ = await p.execute()
    return count <= limit
