"""
Redis incident lock with heartbeat — KubeHeal v4 (PRD Section 07.2)
===================================================================
v3 used SETNX + 30s TTL: a crash mid-incident left the pod unprotected for
30s. v4 uses a 10s TTL refreshed every 3s by a background task, released via
an atomic Lua check-and-delete. Max gap after a crash = 10s.
"""

import asyncio
from contextlib import asynccontextmanager

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


@asynccontextmanager
async def acquire_incident_lock(redis, namespace: str, pod_name: str, token: str = "1"):
    """
    async with acquire_incident_lock(redis, ns, pod) as acquired:
        if not acquired:
            return  # held by another worker
        ...  # decision + action
    Lock is released even on exception.
    """
    lock_key = f"{LOCK_PREFIX}:{namespace}:{pod_name}"
    acquired = await redis.set(lock_key, token, nx=True, ex=LOCK_TTL_SECONDS)
    if not acquired:
        yield False
        return

    hb = asyncio.create_task(_heartbeat(redis, lock_key))
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


async def _heartbeat(redis, lock_key: str):
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
        try:
            await redis.expire(lock_key, LOCK_TTL_SECONDS)
        except Exception:
            return
