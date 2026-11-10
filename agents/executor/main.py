"""
Remediation Executor - the only KubeHeal component with Kubernetes write permissions (S-EX-1).
==============================================================================================
Consumes approved actions from the Redis stream `kubeheal.exec` (consumer group `executor`),
applies the target guard, performs the action through `agents.executor.actions`, and records the
outcome on `kubeheal.actions`. A message is acknowledged only after it was handled.

P3 adds the kill-switch gate in front of every write call, P4 the ledger, P7 the full drift and
ransomware remediation paths.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, Optional

import redis.asyncio as aioredis
from kubernetes_asyncio import client, config

from agents.common.killswitch import ModeWatcher
from agents.executor import actions
from agents.executor.guard import check_target
from agents.health_agent.baseline import load_baseline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EXEC_STREAM = "kubeheal.exec"
ACTIONS_STREAM = "kubeheal.actions"
ESCALATIONS_STREAM = "kubeheal.escalations"
GROUP = "executor"


class RequestGate:
    """Kill-switch gate for one request. The Executor reads the mode itself (it does not trust the
    Fusion Agent), and a request that Fusion already marked as a dry run can only get stricter."""

    def __init__(self, mode, force_dry: bool = False):
        self.mode, self.force_dry = mode, force_dry

    def allow_write(self, namespace: str) -> bool:
        return (not self.force_dry) and (not self.mode.dry_run_for(namespace))


class ExecutorService:
    def __init__(self, redis=None, core_api=None, apps_api=None, networking_api=None, mode=None):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.redis = redis
        self.core_api = core_api
        self.apps_api = apps_api
        self.networking_api = networking_api
        self.consumer = os.environ.get("HOSTNAME") or f"executor-{uuid.uuid4().hex[:6]}"
        self.mode = mode or ModeWatcher(on_change=self._mode_changed)
        self.running = False

    @staticmethod
    def _mode_changed(old, new, source):
        logger.warning(f"executor mode {old} -> {new} ({source})")

    async def start(self):
        try:
            config.load_incluster_config()
        except Exception:
            await config.load_kube_config()
        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.networking_api = client.NetworkingV1Api()
        await self.mode.start(self.core_api)
        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
        try:
            await self.redis.xgroup_create(EXEC_STREAM, GROUP, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                raise
        self.running = True
        logger.info(f"Executor started (consumer={self.consumer})")
        await self._consume()

    async def stop(self):
        self.running = False
        if self.redis:
            await self.redis.aclose()

    async def _consume(self):
        while self.running:
            try:
                msgs = await self.redis.xreadgroup(GROUP, self.consumer, {EXEC_STREAM: ">"},
                                                   count=5, block=1000)
                for stream, entries in msgs or []:
                    for msg_id, fields in entries:
                        await self.handle_entry(stream, msg_id, fields)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"consume error: {e}")
                await asyncio.sleep(1)

    async def handle_entry(self, stream: str, msg_id: str, fields: Dict) -> bool:
        try:
            outcome = await self.execute(fields)
            await self._record(fields, outcome)
            if outcome.startswith("stopped_mode_test"):
                await self._escalate(fields, outcome)
        except Exception as e:
            logger.error(f"executing {msg_id} failed, left pending: {e}", exc_info=True)
            return False
        await self.redis.xack(stream, GROUP, msg_id)
        return True

    async def execute(self, f: Dict) -> str:
        namespace = f.get("namespace", "")
        ok, reason = check_target(namespace)
        if not ok:
            logger.warning(f"REFUSED {f.get('action')} {namespace}/{f.get('deployment')}: {reason}")
            return f"refused:{reason}"
        action = f.get("action")
        gate = RequestGate(self.mode, force_dry=str(f.get("dry_run", "false")).lower() == "true")
        if action == "contain":
            return await actions.contain(gate, self.core_api, self.networking_api, namespace,
                                         f.get("pod", ""))
        if action == "patch":
            baseline = await load_baseline(self.redis, namespace, f.get("deployment", ""))
            return await actions.patch_to_baseline(gate, self.apps_api, namespace,
                                                   f.get("deployment", ""), baseline)
        return f"unknown_action:{action}"

    async def _escalate(self, f: Dict, outcome: str):
        await self.redis.xadd(ESCALATIONS_STREAM, {
            "incident_id": f.get("incident_id", ""),
            "namespace": f.get("namespace", ""),
            "deployment": f.get("deployment", ""),
            "reason": outcome,
            "required": "human",
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _record(self, f: Dict, outcome: str):
        await self.redis.xadd(ACTIONS_STREAM, {
            "incident_id": f.get("incident_id", ""),
            "action_type": f"executed_{f.get('action', 'unknown')}",
            "target": json.dumps({"namespace": f.get("namespace", ""),
                                  "deployment": f.get("deployment", ""),
                                  "pod": f.get("pod", "")}),
            "outcome": outcome,
            "approved_by": f.get("approved_by", ""),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })


async def main():
    svc = ExecutorService()
    try:
        await svc.start()
    finally:
        await svc.stop()


if __name__ == "__main__":
    asyncio.run(main())
