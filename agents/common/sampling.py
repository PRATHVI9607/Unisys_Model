"""
Sampling request contract: OBSERVE triples the sampling of one pod for a bounded period (S-POL-5, P6-D2).
=========================================================================================================
The decision policy returns OBSERVE ("3x sampling") for a low but non-zero signal. Fusion turns that into a
request that the Health Agent and the Security Agent read. Contract:

  Writer  Fusion, on every OBSERVE decision:
            SET kubeheal:sampling:<namespace>:workload:<deployment>   (always)
            SET kubeheal:sampling:<namespace>:pod:<pod>               (when a security event named a pod)
          value  JSON {"factor": 3, "until_ms": <epoch ms>, "incident_id": "<id>", "requested_by": "fusion"}
          SET ... NX EX <period>. NX: while a request is active a repeated OBSERVE does not extend it, so
          the period is bounded (it cannot keep itself alive); after it expired a new OBSERVE may ask again.
          The period is OBSERVE_PERIOD_S (chosen, not measured; see FusionConfig).

  Reader  Health Agent (per workload) and Security Agent (per pod) call `sampling_factor(...)` before they
          schedule the next sample and divide their base interval by the returned factor
          (`scaled_interval`). The factor is 1 when no valid request exists. Any read problem gives 1:
          sampling is monitoring, so a broken read must never stop sensing, and the key also expires on
          its own (Redis TTL), which is the real bound.

The factor 3 is the spec value (S-POL-5). This module has no other number.
"""

import json
import logging
import time
from typing import Iterable, List, Optional

logger = logging.getLogger(__name__)

SAMPLING_PREFIX = "kubeheal:sampling"
OBSERVE_FACTOR = 3


def workload_key(namespace: str, workload: str) -> str:
    return f"{SAMPLING_PREFIX}:{namespace}:workload:{workload}"


def pod_key(namespace: str, pod: str) -> str:
    return f"{SAMPLING_PREFIX}:{namespace}:pod:{pod}"


def keys_for(namespace: str, workload: Optional[str], pod: Optional[str]) -> List[str]:
    keys = []
    if workload:
        keys.append(workload_key(namespace, workload))
    if pod:
        keys.append(pod_key(namespace, pod))
    return keys


async def request_observe(redis, namespace: str, workload: Optional[str], pod: Optional[str],
                          incident_id: str, period_s: int, now_ms: Optional[int] = None) -> List[str]:
    """Write the sampling request (Fusion side). Returns the keys that were newly written."""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    value = json.dumps({"factor": OBSERVE_FACTOR, "until_ms": now_ms + int(period_s) * 1000,
                        "incident_id": incident_id, "requested_by": "fusion"})
    written = []
    for key in keys_for(namespace, workload, pod):
        if await redis.set(key, value, nx=True, ex=int(period_s)):
            written.append(key)
    return written


async def sampling_factor(redis, namespace: str, workload: Optional[str] = None,
                          pod: Optional[str] = None, now_ms: Optional[int] = None) -> int:
    """Reader side (Health and Security Agents): the sampling multiplier for this target, 1 if none."""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    factor = 1
    for key in keys_for(namespace, workload, pod):
        try:
            raw = await redis.get(key)
            if not raw:
                continue
            data = json.loads(raw)
            if int(data["until_ms"]) > now_ms:
                factor = max(factor, int(data["factor"]))
        except Exception as e:
            logger.debug(f"sampling request {key} unreadable ({e}); ignored")
    return max(factor, 1)


def scaled_interval(base_interval_s: float, factor: int) -> float:
    """Sampling interval under a request: the base interval divided by the factor."""
    return base_interval_s / max(int(factor), 1)
