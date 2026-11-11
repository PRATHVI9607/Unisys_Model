"""
Kubernetes write actions - the ONLY module in KubeHeal that may call a Kubernetes write API.
=============================================================================================
Every write goes through `_write(gate, ...)`, which asks the kill-switch gate immediately before the
call (S-KS-3). A blocked write raises ModeBlocked; the action function turns that into:

  * "DRY RUN: would have ..."  when nothing was written yet (mode `test` the whole time), or
  * "stopped_mode_test: ..."   when the mode flipped to `test` mid-action: the next step is not run
    and the caller escalates to a human (S-KS-5).

A gate that has `record_intent` also writes an "about to do" ledger entry before each write; if that
write fails the rules in ledger_guard.py apply (protective steps go on through the fallback stream,
corrective steps stop with LedgerUnavailable, and the Executor escalates).

tests/test_no_writes_outside_executor.py proves that no write call exists outside this package and
that inside it every write method is only ever passed to `_write`, never called directly.
The write paths live next to this module and use the same `_write` choke point: drift.py (canary patch),
quarantine.py (labelled-pod quarantine and forensic snapshot), restore.py, snapshots.py (rolling
snapshots). The P2 interim `contain` (which deleted the pod) and `patch_to_baseline` were removed in the
P7 integration: the RBAC role no longer grants `delete pods` and the plan's design is quarantine, not delete.
"""

import logging
from typing import Awaitable, Callable, List

logger = logging.getLogger(__name__)

class ModeBlocked(Exception):
    """The kill-switch gate refused a write."""

    def __init__(self, step: str):
        super().__init__(step)
        self.step = step


async def _write(gate, namespace: str, step: str, fn: Callable[..., Awaitable], *args, **kwargs):
    """The single choke point for Kubernetes writes. `gate.allow_write(namespace)` is evaluated
    right before the call, so a mode switch between two steps stops the second one. A missing
    gate blocks (fail safe)."""
    if gate is None or not gate.allow_write(namespace):
        if gate is not None and hasattr(gate, "record_step"):
            await gate.record_step(namespace, step, "blocked_by_kill_switch")
        raise ModeBlocked(step)
    if hasattr(gate, "record_intent"):
        # "About to do" ledger entry (ledger_guard.py). It may raise LedgerUnavailable: then the step
        # does not run. The write can take a while, so the gate is asked AGAIN right before the call.
        await gate.record_intent(namespace, step)
        if not gate.allow_write(namespace):
            if hasattr(gate, "record_step"):
                await gate.record_step(namespace, step, "blocked_by_kill_switch")
            raise ModeBlocked(step)
    try:
        result = await fn(*args, **kwargs)
    except Exception as exc:
        if hasattr(gate, "record_step"):
            await gate.record_step(namespace, step, f"failed: {exc}")
        raise
    if hasattr(gate, "record_step"):
        await gate.record_step(namespace, step, "succeeded")
    return result


def _blocked_outcome(what: str, planned: List[str], done: List[str], blocked: ModeBlocked) -> str:
    if not done:
        return f"DRY RUN: would have {what} ({', '.join(planned)})"
    return (f"stopped_mode_test: mode switched to test before '{blocked.step}'; "
            f"completed {done}; escalated to HUMAN")
