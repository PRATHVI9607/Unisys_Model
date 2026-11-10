"""
Circuit breakers as true sliding windows, and the burn-in sample counter (S-POL-6, S-POL-7, P6-D4, P6-D5).
=========================================================================================================
State lives in Redis, so both Fusion replicas see the same counts. The policy itself stays pure: these
classes only produce the numbers that go into `DecisionInput`.

Sliding window: a sorted set per breaker, member = incident id, score = the time of the enforced action.
`count` removes members older than the window and returns the cardinality, so an action stops counting
exactly one window after it happened (a fixed-TTL counter restarts the hour at the first action and lets
twice the limit through around the boundary). The member is the INCIDENT ID: counting the same incident
twice (a redelivered stream entry) adds nothing.

Only enforced actions are recorded (never dry runs) and only after the request was queued.

Burn-in counter: the number of distinct metric samples Fusion has seen, shared across replicas. One sample is
one health assessment event (one metric window). Each event id is counted once (SADD): a redelivered
event does not count again, because double counting would end burn-in too early, the unsafe direction.
"""

import logging
import time
from typing import Callable, Optional

from agents.fusion_agent.decision_policy import BURN_IN_SAMPLES

logger = logging.getLogger(__name__)

WINDOW_S = 3600                      # "per hour" in S-POL-6
CONTAIN_KEY = "kubeheal:cbw:contain:{namespace}"
PATCH_KEY = "kubeheal:cbw:patch:{namespace}:{workload}"
BURN_IN_SEEN_KEY = "kubeheal:burnin:seen"


class SlidingWindowBreaker:
    def __init__(self, redis, key: str, window_s: int = WINDOW_S, clock: Callable[[], float] = time.time):
        self.redis, self.key, self.window_s, self.clock = redis, key, window_s, clock

    async def count(self) -> int:
        now = self.clock()
        await self.redis.zremrangebyscore(self.key, "-inf", now - self.window_s)
        return int(await self.redis.zcard(self.key))

    async def record(self, incident_id: str) -> None:
        """Count one enforced action. Idempotent per incident id."""
        await self.redis.zadd(self.key, {incident_id: self.clock()})
        await self.redis.expire(self.key, self.window_s + 60)   # housekeeping only, the score decides


def contain_breaker(redis, namespace: str, clock=time.time) -> SlidingWindowBreaker:
    return SlidingWindowBreaker(redis, CONTAIN_KEY.format(namespace=namespace), clock=clock)


def patch_breaker(redis, namespace: str, workload: str, clock=time.time) -> SlidingWindowBreaker:
    return SlidingWindowBreaker(redis, PATCH_KEY.format(namespace=namespace, workload=workload), clock=clock)


class BurnInCounter:
    def __init__(self, redis, key: str = BURN_IN_SEEN_KEY, limit: int = BURN_IN_SAMPLES):
        self.redis, self.key, self.limit = redis, key, limit

    async def observe(self, event_id: Optional[str]) -> None:
        """Count one metric sample. An event without an id cannot be de-duplicated and is not counted."""
        if not event_id:
            return
        # Burn-in ends at `limit`: past it the set stops growing (the count only has to reach the limit).
        if int(await self.redis.scard(self.key)) >= self.limit:
            return
        await self.redis.sadd(self.key, event_id)

    async def seen(self) -> Optional[int]:
        """Samples seen so far, or None when Redis cannot say (the policy then treats it as burn-in)."""
        try:
            return int(await self.redis.scard(self.key))
        except Exception as e:
            logger.warning(f"burn-in counter unreadable ({e}); treating as burn-in")
            return None
