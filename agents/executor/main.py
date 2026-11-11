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
from typing import Dict, Optional

import redis.asyncio as aioredis
from kubernetes_asyncio import client, config

from agents.common.killswitch import ModeWatcher
from agents.common.ledger import Ledger, ledger_from_env
from agents.common.metrics import KubeHealMetrics
from agents.common.stream_reliability import ReliabilityConfig, StreamReliability
from agents.executor import drift, quarantine, restore, restore_entropy
from agents.executor.config import ExecConfig
from agents.executor.guard import check_target
from agents.executor.metrics_source import PrometheusMetricSource
from agents.executor.snapshots import SnapshotFreeze, SnapshotScheduler
from agents.executor.support import Recorder, needs_escalation
from agents.executor.validation import parse_request
from agents.health_agent.baseline import load_baseline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
METRICS = KubeHealMetrics()

EXEC_STREAM = "kubeheal.exec"
ACTIONS_STREAM = "kubeheal.actions"
ESCALATIONS_STREAM = "kubeheal.escalations"
GROUP = "executor"
DONE_PREFIX = "kubeheal:exec:done"       # result marker per incident, action and dry-run flag (P6-R1)
DONE_TTL_S = 7 * 24 * 3600               # chosen, not measured: how long a finished request is remembered
# Outcomes that are not final: a later request for the same incident may legitimately run again.
# Refused and escalated-before-running outcomes wrote nothing; a corrected request must be able to follow.
# `contain_failed`, `restore_failed` and `restored_kept_isolated` still escalate to a human, but a retry under
# the same incident id must not be skipped for DONE_TTL_S. A retry of a partly run restore fails safe:
# restore preflight cannot read the original pod and escalates before it writes anything.
NOT_FINAL_PREFIXES = ("DRY RUN:", "stopped_mode_test", "refused:", "escalated:", "no_baseline_escalated",
                      "contain_failed", "restore_failed", "restored_kept_isolated")


class RequestGate:
    """Kill-switch gate for one request. The Executor reads the mode itself (it does not trust the
    Fusion Agent), and a request that Fusion already marked as a dry run can only get stricter."""

    def __init__(self, mode, force_dry: bool = False, on_step=None):
        self.mode, self.force_dry, self.on_step = mode, force_dry, on_step

    def allow_write(self, namespace: str) -> bool:
        return (not self.force_dry) and (not self.mode.dry_run_for(namespace))

    async def record_step(self, namespace: str, step: str, outcome: str) -> None:
        if self.on_step:
            await self.on_step(namespace, step, outcome)


class ExecutorService:
    def __init__(self, redis=None, core_api=None, apps_api=None, networking_api=None, mode=None,
                 custom_api=None, batch_api=None, record_step=None, metric_source=None, entropy_check=None,
                 cfg=None, sleep=asyncio.sleep, clock=time.monotonic, ledger: Optional[Ledger] = None):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.redis = redis
        self.core_api = core_api
        self.apps_api = apps_api
        self.networking_api = networking_api
        self.ledger = ledger if ledger is not None else ledger_from_env()
        self.custom_api = custom_api
        self.batch_api = batch_api
        self.record_step = record_step or self._append_ledger_step
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
        # P6-R1: reclaim of stale pending entries, dead letter after N deliveries, lease while handling
        self.reliability = StreamReliability(lambda: self.redis, GROUP, self.consumer,
                                             ReliabilityConfig.from_env())

    def _mode_changed(self, old, new, source):
        logger.warning(f"executor mode {old} -> {new} ({source})")
        incident_id = f"mode-{uuid.uuid4().hex}"
        payload = {"from": old, "to": new, "source": source}
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                self.ledger.append(incident_id, "mode_change", payload)
            except Exception as e:
                logger.error(f"mode change ledger write failed: {e}")
        else:
            loop.create_task(self._record_mode_change(incident_id, payload))

    async def _record_mode_change(self, incident_id: str, payload: Dict):
        try:
            await self._append_ledger(incident_id, "mode_change", payload)
        except Exception as e:
            logger.error(f"mode change ledger write failed: {e}")

    async def _append_ledger_step(self, incident_id: str, step: str, payload: Dict):
        await asyncio.to_thread(self.ledger.append, incident_id, step, payload)

    async def start(self):
        try:
            config.load_incluster_config()
        except Exception:
            await config.load_kube_config()
        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.networking_api = client.NetworkingV1Api()
        self.custom_api = client.CustomObjectsApi()
        self.batch_api = client.BatchV1Api()
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
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.mode.stop()
        if self.redis:
            await self.redis.aclose()

    async def _consume(self):
        last_sweep = None
        while self.running:
            try:
                now = self.clock()
                if last_sweep is None or now - last_sweep >= self.reliability.cfg.reclaim_interval_s:
                    last_sweep = now
                    await self.reclaim_pending()
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

    async def reclaim_pending(self):
        """XAUTOCLAIM the entries another executor (or an earlier run of this one) left unacknowledged.
        Reclaimed entries run as tasks like new ones; after N failed deliveries the entry is dead-lettered
        and escalated instead (P6-R1)."""
        async def run(stream, msg_id, fields):
            t = asyncio.create_task(self.handle_entry(stream, msg_id, fields))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)
            return True

        return await self.reliability.reclaim(EXEC_STREAM, run, self._dead_letter)

    async def _dead_letter(self, stream: str, msg_id: str, fields: Dict, deliveries: int, reason: str):
        """The request failed `deliveries` times. It may have run partly, so a human must look at it."""
        await self._escalate(fields, reason)
        await self._record(fields, reason)
        # Count only after both durable writes succeeded (same rule as _finish): a failure leaves the
        # entry pending and it is dead-lettered again.
        METRICS.record_action(fields.get("action", "unknown"), "escalated")
        METRICS.record_escalation("dead_lettered")

    @staticmethod
    def _done_key(f: Dict, msg_id: str) -> str:
        """Marker key. Contain and restore share an incident id, and a dry-run approval is followed by a
        real one under the same id, so action and the dry-run flag are part of the key. A request without
        an incident id (allowed on the drift path) falls back to the stream entry id."""
        incident = f.get("incident_id") or ""
        who = incident if incident else f"msg-{msg_id}"
        dry = "dry" if str(f.get("dry_run", "false")).lower() == "true" else "live"
        return f"{DONE_PREFIX}:{who}:{f.get('action', 'unknown')}:{dry}"

    async def _read_marker(self, key: str) -> Optional[Dict]:
        raw = await self.redis.get(key)
        if not raw:
            return None
        try:
            marker = json.loads(raw)
            return marker if isinstance(marker, dict) else None
        except (TypeError, ValueError):
            return {"outcome": "unknown_marker", "recorded": True}

    async def _write_marker(self, key: str, outcome: str, recorded: bool) -> None:
        await self.redis.set(key, json.dumps({"outcome": outcome, "recorded": recorded}), ex=DONE_TTL_S)

    async def handle_entry(self, stream: str, msg_id: str, fields: Dict) -> bool:
        async with self.reliability.lease(stream, msg_id):
            return await self._handle_entry(stream, msg_id, fields)

    async def _handle_entry(self, stream: str, msg_id: str, fields: Dict) -> bool:
        try:
            key = self._done_key(fields, msg_id)
            marker = await self._read_marker(key)
            if marker is not None:
                # Redelivery of a request that already ran (the ack was lost, or a second request for the
                # same incident and action). Never run it again. If the result was not recorded yet
                # (crash between the action and the record), finish the record from the stored outcome.
                outcome = str(marker.get("outcome", ""))
                if not marker.get("recorded"):
                    await self._finish(fields, outcome, key)
                else:
                    await Recorder(self.record_step, fields.get("incident_id") or f"inc-{uuid.uuid4().hex}")(
                        "redelivery_skipped", {"action": fields.get("action", "unknown"),
                                               "stream_id": msg_id, "recorded_outcome": outcome})
                await self.redis.xack(stream, GROUP, msg_id)
                return True
            outcome = await self.execute(fields)
            # The outcome is stored BEFORE the ledger and the actions entry, and both before the ack.
            final = not outcome.startswith(NOT_FINAL_PREFIXES)
            if final:
                await self._write_marker(key, outcome, recorded=False)
            await self._finish(fields, outcome, key if final else None)
        except Exception as e:
            logger.error(f"executing {msg_id} failed, left pending: {e}", exc_info=True)
            return False
        await self.redis.xack(stream, GROUP, msg_id)
        return True

    async def _finish(self, fields: Dict, outcome: str, marker_key: Optional[str]) -> None:
        action = fields.get("action", "unknown")
        metric_outcome = "success"
        dry_run = False
        if outcome.startswith("DRY RUN:"):
            metric_outcome, dry_run = "dry_run", True
        elif needs_escalation(outcome):
            metric_outcome = "escalated"
        elif outcome.startswith("refused:"):
            metric_outcome = "refused"
        elif ("failed" in outcome or outcome.startswith("unknown_action")
              or outcome == "no_kube_client"):
            metric_outcome = "failure"
        if needs_escalation(outcome):
            await self._escalate(fields, outcome)
        await self._record(fields, outcome)
        # A request may be retried if durable recording fails. Count only after the ledger and
        # actions-stream record succeed, so a failed record does not increment before retry.
        METRICS.record_action(action, metric_outcome)
        if dry_run:
            METRICS.record_dry_run_action(action)
        if needs_escalation(outcome):
            METRICS.record_escalation(outcome.split(":", 1)[0])
        if marker_key:
            await self._write_marker(marker_key, outcome, recorded=True)

    def _lock(self, namespace: str, workload: str) -> asyncio.Lock:
        return self._locks.setdefault(f"{namespace}/{workload}", asyncio.Lock())

    async def execute(self, f: Dict) -> str:
        incident_id = f.get("incident_id") or f.get("_ledger_incident_id") or f"inc-{uuid.uuid4().hex}"
        f.setdefault("_ledger_incident_id", incident_id)
        rec = Recorder(self.record_step, incident_id)
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
                entropy_check = self.entropy_check
                if entropy_check is None:
                    async def entropy_check(ns, workload, pvcs):
                        return await restore_entropy.check_restored_pvcs(
                            self.core_api, self.batch_api, gate, ns, req.incident_id, pvcs,
                            os.environ.get("RESTORE_ENTROPY_IMAGE"), self.cfg.rollout_timeout_s,
                            self.cfg.rollout_poll_s, self.sleep,
                            [x.strip() for x in os.environ.get(
                                "RESTORE_ENTROPY_IMAGE_PULL_SECRETS", "").split(",") if x.strip()])
                outcome = await restore.restore(
                    gate, self.core_api, self.apps_api, self.networking_api, self.custom_api, req, rec,
                    self.cfg, freeze, entropy_check, self.sleep, self.clock)
        await rec("result", {"outcome": outcome})
        return outcome

    async def _escalate(self, f: Dict, outcome: str):
        incident_id = f.get("incident_id") or f.get("_ledger_incident_id") or f"inc-{uuid.uuid4().hex}"
        await self._append_ledger(incident_id, "executor_escalation", {
            "namespace": f.get("namespace", ""),
            "deployment": f.get("deployment", ""),
            "reason": outcome,
            "required": "human",
        })
        await self.redis.xadd(ESCALATIONS_STREAM, {
            "incident_id": incident_id,
            "namespace": f.get("namespace", ""),
            "deployment": f.get("deployment", ""),
            "reason": outcome,
            "required": "human",
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _record(self, f: Dict, outcome: str):
        incident_id = f.get("incident_id") or f.get("_ledger_incident_id") or f"inc-{uuid.uuid4().hex}"
        await self._append_ledger(incident_id, "executor_result", {
            "action": f.get("action", "unknown"),
            "namespace": f.get("namespace", ""),
            "deployment": f.get("deployment", ""),
            "pod": f.get("pod", ""),
            "outcome": outcome,
            "approved_by": f.get("approved_by", ""),
        })
        await self.redis.xadd(ACTIONS_STREAM, {
            "incident_id": incident_id,
            "action_type": f"executed_{f.get('action', 'unknown')}",
            "target": json.dumps({"namespace": f.get("namespace", ""),
                                  "deployment": f.get("deployment", ""),
                                  "pod": f.get("pod", "")}),
            "outcome": outcome,
            "approved_by": f.get("approved_by", ""),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _append_ledger(self, incident_id: str, step: str, payload: Dict):
        await asyncio.to_thread(self.ledger.append, incident_id, step, payload)


async def main():
    METRICS.start_server(int(os.environ.get("METRICS_PORT", "9100")))
    svc = ExecutorService()
    try:
        await svc.start()
    finally:
        await svc.stop()


if __name__ == "__main__":
    asyncio.run(main())
