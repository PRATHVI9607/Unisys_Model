"""Cgroup freeze REQUEST (V5-S5, owner decisions D5 and Q2).
=========================================================

The Executor never writes a cgroup file. For an automatic containment of a ransomware or exfiltration pod it
publishes a freeze request on the stream of the pod's node and waits a bounded time for the result that the
node-local Security Agent writes after it has validated the request, re-checked the kill-switch mode, frozen the
pod's cgroup and read the state back (`agents/security_agent/containment.py`).

Protocol (fixed; the Security Agent implements the other side):
  request  stream  kubeheal.contain.req:<node>     fields request_id, incident_id, namespace, pod, pod_uid, node,
                                                   action (freeze), label, requested_by (executor), timestamp_ms
  result   hash    kubeheal:contain:result:<request_id>   status, reason, request_id, incident_id, namespace, pod,
                                                   pod_uid, node, action, frozen, mode_seen, cgroup, ts_ms

A freeze counts as CONFIRMED only when the result hash says status `frozen` and frozen `1` AND its request id,
incident id, pod UID and node equal what was requested. Anything else (no answer in time, `dry_run`, `refused`,
`failed`, a mismatch) is NOT confirmed. The caller then goes on with the remaining protective steps and reports
the gap (`contained_with_gaps:freeze_unconfirmed`), so Fusion requests no restore and a human is told.

The request itself is a gated step (`request_freeze`, a protective step in ledger_guard): in mode test it is not
sent at all, and the ledger gets its "about to do" entry first. It is a Redis write, not a Kubernetes write.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from agents.executor.actions import ModeBlocked, _write
from agents.executor.ledger_guard import LedgerUnavailable
from agents.executor.support import gate_open, poll_until

STREAM_PREFIX = "kubeheal.contain.req"
RESULT_PREFIX = "kubeheal:contain:result"
FREEZE_LABELS = frozenset({"ransomware", "exfiltration"})    # Q2: the only labels that contain automatically
FREEZE_POLL_S = 1.0                                          # chosen, not measured


@dataclass
class FreezeOutcome:
    confirmed: bool
    reason: str = ""
    request_id: str = ""
    node: str = ""
    result: Dict[str, str] = field(default_factory=dict)


def request_stream(node: str) -> str:
    return f"{STREAM_PREFIX}:{node}"


def result_key(request_id: str) -> str:
    return f"{RESULT_PREFIX}:{request_id}"


def _text(v: Any) -> str:
    return v.decode() if isinstance(v, (bytes, bytearray)) else ("" if v is None else str(v))


def _fields(raw: Any) -> Dict[str, str]:
    return {_text(k): _text(v) for k, v in (raw or {}).items()}


def verify_result(result: Dict[str, str], expected: Dict[str, str]) -> str:
    """"" when the result confirms the freeze, otherwise the reason it does not."""
    if not result:
        return "no_result"
    status, frozen = result.get("status", ""), result.get("frozen", "")
    if status != "frozen" or frozen != "1":
        why = result.get("reason", "")
        return f"status_{status or 'missing'}" + (f": {why}" if why else "")
    for key, want in expected.items():
        if result.get(key, "") != want:
            return f"result_mismatch:{key}"
    return ""


async def request_freeze(gate, redis, namespace: str, incident_id: str, pod: Dict, label: str,
                         timeout_s: float, sleep: Callable = asyncio.sleep,
                         clock: Callable[[], float] = time.monotonic,
                         poll_s: float = FREEZE_POLL_S) -> FreezeOutcome:
    """Ask the pod's node-local Security Agent to freeze the pod and wait for the verified answer.

    Raises ModeBlocked (gate closed) and LedgerUnavailable like every gated step; never raises for a missing
    answer: that is `FreezeOutcome(confirmed=False, ...)`."""
    meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
    node, uid, pod_name = spec.get("nodeName") or "", meta.get("uid") or "", meta.get("name") or ""
    if not (node and uid and pod_name):
        # Nothing can be requested. In a dry run the answer is still the usual blocked step, not a gap.
        if not gate_open(gate, namespace):
            if gate is not None and hasattr(gate, "record_step"):
                await gate.record_step(namespace, "request_freeze", "blocked_by_kill_switch")
            raise ModeBlocked("request_freeze")
        return FreezeOutcome(False, "pod_node_or_uid_unknown")
    request_id = uuid.uuid4().hex
    fields = {
        "request_id": request_id, "incident_id": incident_id, "namespace": namespace, "pod": pod_name,
        "pod_uid": uid, "node": node, "action": "freeze", "label": label, "requested_by": "executor",
        "timestamp_ms": str(int(time.time() * 1000)),
    }
    stream = request_stream(node)
    try:
        await _write(gate, namespace, "request_freeze", redis.xadd, stream, fields)
    except (ModeBlocked, LedgerUnavailable):
        raise
    except Exception as e:           # a Redis error is a gap, not a reason to skip the other protective steps
        return FreezeOutcome(False, f"redis_error:{e}", request_id, node)
    key = result_key(request_id)
    expected = {"request_id": request_id, "incident_id": incident_id, "pod_uid": uid, "node": node,
                "namespace": namespace, "pod": pod_name, "action": "freeze"}
    seen: Dict[str, str] = {}

    async def answered() -> bool:
        nonlocal seen
        seen = _fields(await redis.hgetall(key))
        return bool(seen)

    try:
        got = await poll_until(answered, timeout_s, poll_s, sleep, clock)
    except Exception as e:
        return FreezeOutcome(False, f"redis_error:{e}", request_id, node)
    if not got:
        return FreezeOutcome(False, "no_result_in_time", request_id, node)
    why = verify_result(seen, expected)
    return FreezeOutcome(not why, why, request_id, node, seen)
