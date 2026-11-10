"""
Remediation Executor - the only KubeHeal component with Kubernetes write permissions (S-EX-1).
==============================================================================================
Consumes approved actions from the Redis stream `kubeheal.exec` (consumer group `executor`),
applies the target guard and request validation, performs the action and records the outcome on
`kubeheal.actions`. A message is acknowledged only after it was handled.

P3 adds the kill-switch gate in front of every write call, P4 the ledger. P7 adds three actions, each
in its own module: `patch` (drift.py, canary), `contain` (quarantine.py) and `restore` (restore.py),
plus the rolling snapshot scheduler (snapshots.py). Requests are validated first (validation.py).
Every step is reported through the injectable `record_step(incident_id, step, payload)`; P4 connects
it to the ledger, the default is a no-op.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Dict

import redis.asyncio as aioredis
from kubernetes_asyncio import client, config

from agents.common.killswitch import ModeWatcher
from agents.executor import drift, quarantine, restore
from agents.executor.config import ExecConfig
from agents.executor.guard import check_target
from agents.executor.metrics_source import PrometheusMetricSource
from agents.executor.snapshots import SnapshotFreeze, SnapshotScheduler
from agents.executor.support import Recorder, needs_escalation
from agents.executor.validation import parse_request
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
    def __init__(self, redis=None, core_api=None, apps_api=None, networking_api=None, mode=None,
                 custom_api=None, record_step=None, metric_source=None, entropy_check=None,
                 cfg=None, sleep=asyncio.sleep, clock=time.monotonic):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.redis = redis
        self.core_api = core_api
        self.apps_api = apps_api
        self.networking_api = networking_api
        self.custom_api = custom_api
        self.record_step = record_step          # (incident_id, step, payload); None = no-op (P4 connects)
        self.metric_source = metric_source      # async (namespace, deployment, window_s) -> dict
        self.entropy_check = entropy_check      # async (namespace, workload, pvcs) -> True/False/None
        self.cfg = cfg or ExecConfig()
        self.sleep, self.clock = sleep, clock
        self.scheduler = None
        self._locks: Dict[str, asyncio.Lock] = {}
        self._tasks = set()
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
        self.custom_api = client.CustomObjectsApi()
        await self.mode.start(self.core_api)
        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
        if self.metric_source is None and self.cfg.prometheus_url:
            self.metric_source = PrometheusMetricSource(self.cfg.prometheus_url)
        self.scheduler = SnapshotScheduler(
            self.core_api, self.custom_api, RequestGate(self.mode), cfg=self.cfg,
            is_frozen=SnapshotFreeze(self.redis).is_frozen, record_step=self.record_step)
        self._tasks.add(asyncio.create_task(self.scheduler.run_forever()))
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
        if self.scheduler:
            self.scheduler.stop()
        for t in list(self._tasks):
            t.cancel()
        if self.redis:
            await self.redis.aclose()

    async def _consume(self):
        while self.running:
            try:
                msgs = await self.redis.xreadgroup(GROUP, self.consumer, {EXEC_STREAM: ">"},
                                                   count=5, block=1000)
                for stream, entries in msgs or []:
                    for msg_id, fields in entries:
                        # One task per entry: a canary watch lasts several windows and must not
                        # hold up a containment request queued behind it.
                        t = asyncio.create_task(self.handle_entry(stream, msg_id, fields))
                        self._tasks.add(t)
                        t.add_done_callback(self._tasks.discard)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"consume error: {e}")
                await asyncio.sleep(1)

    async def handle_entry(self, stream: str, msg_id: str, fields: Dict) -> bool:
        try:
            outcome = await self.execute(fields)
            if needs_escalation(outcome):
                await self._escalate(fields, outcome)
            await self._record(fields, outcome)
        except Exception as e:
            logger.error(f"executing {msg_id} failed, left pending: {e}", exc_info=True)
            return False
        await self.redis.xack(stream, GROUP, msg_id)
        return True

    def _lock(self, namespace: str, workload: str) -> asyncio.Lock:
        return self._locks.setdefault(f"{namespace}/{workload}", asyncio.Lock())

    async def execute(self, f: Dict) -> str:
        rec = Recorder(self.record_step, f.get("incident_id", "") or "")
        namespace = f.get("namespace", "")
        ok, reason = check_target(namespace)
        if not ok:
            logger.warning(f"REFUSED {f.get('action')} {namespace}/{f.get('deployment')}: {reason}")
            await rec("refused", {"reason": reason})
            return f"refused:{reason}"
        status, reason, req = parse_request(f)
        if status == "refused":
            logger.warning(f"REFUSED {f.get('action')} {namespace}: {reason}")
            await rec("refused", {"reason": reason})
            return f"refused:{reason}"
        if status == "escalate":
            if req.action == "patch" and not await load_baseline(self.redis, namespace, req.deployment):
                await rec("no_baseline", {})
                return "no_baseline_escalated"      # the more fundamental gap is reported first
            await rec("escalated", {"reason": reason})
            return f"escalated:{reason}"
        await rec("request_accepted", {"action": req.action, "namespace": req.namespace,
                                       "deployment": req.deployment, "pod": req.pod,
                                       "dry_run_requested": req.dry_run})
        gate = RequestGate(self.mode, force_dry=req.dry_run)
        freeze = SnapshotFreeze(self.redis)
        if req.action == "contain":
            outcome = await quarantine.contain(gate, self.core_api, self.networking_api, self.apps_api,
                                               self.custom_api, req, rec, self.cfg, freeze)
        elif req.action == "patch":
            golden = await load_baseline(self.redis, namespace, req.deployment)
            async with self._lock(namespace, req.deployment):
                outcome = await drift.canary_patch(
                    gate, self.apps_api, req, golden, rec, self.metric_source,
                    drift.RollbackStore(self.redis), self.cfg, self.sleep, self.clock)
        else:
            async with self._lock(namespace, req.deployment):
                outcome = await restore.restore(
                    gate, self.core_api, self.apps_api, self.networking_api, self.custom_api, req, rec,
                    self.cfg, freeze, self.entropy_check, self.sleep, self.clock)
        await rec("result", {"outcome": outcome})
        return outcome

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
