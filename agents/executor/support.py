"""Small shared helpers for the Executor paths: step recording, polling, gate query."""

import asyncio
import inspect
import logging
import time
from typing import Any, Awaitable, Callable, Dict, Optional

logger = logging.getLogger(__name__)

_serializer = None

# Outcome prefixes that must be sent to a human on kubeheal.escalations.
ESCALATE_PREFIXES = (
    "stopped_mode_test", "escalated:", "rolled_back", "kept_unverified", "patch_failed",
    "contain_failed", "contained_with_", "restore_failed", "restored_kept_isolated",
    "no_baseline_escalated",
)


def needs_escalation(outcome: str) -> bool:
    return isinstance(outcome, str) and outcome.startswith(ESCALATE_PREFIXES)


def to_dict(obj: Any) -> Dict:
    """Kubernetes object as camelCase dict. Dicts pass through (custom objects, test fakes)."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    global _serializer
    if _serializer is None:       # ApiClient() opens an aiohttp session: build ONE, not one per call
        from kubernetes_asyncio import client
        _serializer = client.ApiClient()
    return _serializer.sanitize_for_serialization(obj)


async def noop_record(incident_id: str, step: str, payload: dict) -> None:
    return None


class Recorder:
    """Calls the injected `record_step(incident_id, step, payload)` (sync or async). A failing
    callback is logged and never breaks the action (same rule as the mode-change hook)."""

    def __init__(self, callback: Optional[Callable], incident_id: str):
        self.callback, self.incident_id = callback or noop_record, incident_id
        self.steps = []

    async def __call__(self, step: str, payload: Optional[dict] = None) -> None:
        payload = payload or {}
        self.steps.append(step)
        try:
            res = self.callback(self.incident_id, step, payload)
            if inspect.isawaitable(res):
                await res
        except Exception as e:
            logger.error(f"record_step hook failed for {step}: {e}")


def gate_open(gate, namespace: str) -> bool:
    """Query only (used between canary windows). Writes still go through actions._write."""
    return gate is not None and bool(gate.allow_write(namespace))


async def poll_until(pred: Callable[[], Awaitable[bool]], timeout_s: float, poll_s: float,
                     sleep: Callable = asyncio.sleep,
                     clock: Callable[[], float] = time.monotonic) -> bool:
    deadline = clock() + timeout_s
    while True:
        if await pred():
            return True
        if clock() >= deadline:
            return False
        await sleep(poll_s)
