"""
Redis incident lock with heartbeat — KubeHeal v4 (PRD Section 07.2)
===================================================================
v3 used SETNX + 30s TTL: a crash mid-incident left the pod unprotected for
30s. v4 uses a 10s TTL refreshed every 3s by a background task, released via
an atomic Lua check-and-delete. Max gap after a crash = 10s.
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

LOCK_PREFIX = "kubeheal:incident-lock"
LOCK_TTL_SECONDS = 10
HEARTBEAT_INTERVAL_SECONDS = 3

_DELETE_IF_OWNER = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


_EXTEND_IF_OWNER = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("expire", KEYS[1], ARGV[2])
else
    return 0
end
"""


class LockState:
    """Filled in by the heartbeat. `lost` becomes True when the lock is really gone: another owner holds the
    key, or the TTL has passed without a successful extend (so another replica may now own it)."""

    def __init__(self):
        self.lost = False
        self.reason = ""


@asynccontextmanager
async def acquire_incident_lock(redis, namespace: str, pod_name: str, token: str = None,
                                state: "LockState" = None):
    """
    async with acquire_incident_lock(redis, ns, pod, state=state) as acquired:
        if not acquired:
            return  # held by another worker
        if state.lost: ...  # check right before a side effect
        ...  # decision + action
    Lock is released even on exception. Pass a LockState to learn whether the lock was lost mid-action.
    """
    # Unique token per replica and incident: the Lua check-and-delete only releases our own lock.
    token = token or uuid.uuid4().hex
    lock_key = f"{LOCK_PREFIX}:{namespace}:{pod_name}"
    acquired = await redis.set(lock_key, token, nx=True, ex=LOCK_TTL_SECONDS)
    if not acquired:
        yield False
        return

    hb = asyncio.create_task(_heartbeat(redis, lock_key, token, state))
    try:
        yield True
    finally:
        hb.cancel()
        try:
            await hb
        except asyncio.CancelledError:
            pass
        try:
            await redis.eval(_DELETE_IF_OWNER, 1, lock_key, token)
        except Exception:
            pass


async def _heartbeat(redis, lock_key: str, token: str, state: "LockState" = None, clock=time.monotonic):
    """Extend the lock every HEARTBEAT_INTERVAL_SECONDS. One transient Redis error does not end the
    heartbeat: it keeps retrying until the lock is truly lost, which means the ownership check failed (another
    owner) or LOCK_TTL_SECONDS passed since the last successful extend (the key may have expired)."""
    last_ok = clock()

    def lose(reason: str):
        if state is not None:
            state.lost, state.reason = True, reason
        logger.error(f"incident lock {lock_key} lost: {reason}")

    delay = HEARTBEAT_INTERVAL_SECONDS
    while True:
        await asyncio.sleep(delay)
        delay = HEARTBEAT_INTERVAL_SECONDS
        try:
            # Extend only our own lock: after a TTL expiry another replica may own the key.
            if not await redis.eval(_EXTEND_IF_OWNER, 1, lock_key, token, LOCK_TTL_SECONDS):
                return lose("another owner holds the key or it expired")
            last_ok = clock()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"incident lock {lock_key}: extend failed ({e}); retrying")
            remaining = LOCK_TTL_SECONDS - (clock() - last_ok)
            if remaining <= 0:
                return lose(f"no successful extend for {LOCK_TTL_SECONDS} s")
            delay = min(delay, remaining)       # wake no later than the moment the TTL passes
