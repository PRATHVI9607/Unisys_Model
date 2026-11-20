"""Fire-and-forget alert webhook (Slack-compatible `{"text": ...}` plus structured fields).

notify() is synchronous and never blocks: it drops the oldest queued alert when full. A single worker task
posts them, so a slow or dead webhook can delay nothing but later alerts.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp
from prometheus_client import Counter

from kubeheal.contracts import ActionEvent

log = logging.getLogger("fusion.alerts")

QUEUE_MAX = 100
TIMEOUT_S = 2.0
ALERTS = Counter("kubeheal_fusion_alerts_total", "Alert webhook deliveries", ["result"])   # sent|failed|dropped


def payload(action: ActionEvent, pending: bool) -> dict:
    """`pending`: a HUMAN decision with an executable candidate waiting for approval in the console."""
    where = f"{action.namespace}/{action.workload}" + (f" pod {action.pod}" if action.pod else "")
    verb = "needs approval" if pending else action.outcome
    return {
        "text": f"[KubeHeal] {action.decision.value} {verb}: {where} (score {action.score:.2f}, {action.mode})",
        "decision": action.decision.value, "outcome": action.outcome, "mode": action.mode,
        "namespace": action.namespace, "workload": action.workload, "pod": action.pod, "score": action.score,
        "action_event_id": action.event_id, "console_path": f"/#/incident/action/{action.event_id}",
    }


class Alerter:
    def __init__(self, url: str, queue_max: int = QUEUE_MAX, timeout_s: float = TIMEOUT_S) -> None:
        self.url, self.timeout = url, aiohttp.ClientTimeout(total=timeout_s)
        self.queue: asyncio.Queue[dict] = asyncio.Queue(queue_max)

    def notify(self, body: dict) -> None:
        if self.queue.full():
            self.queue.get_nowait()
            ALERTS.labels("dropped").inc()
        self.queue.put_nowait(body)

    async def run(self) -> None:
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            while True:
                body = await self.queue.get()
                try:
                    async with session.post(self.url, json=body) as resp:
                        resp.raise_for_status()
                    ALERTS.labels("sent").inc()
                except (aiohttp.ClientError, TimeoutError) as e:
                    ALERTS.labels("failed").inc()
                    log.warning("alert webhook failed: %s", type(e).__name__)   # never log the URL: it is a secret
