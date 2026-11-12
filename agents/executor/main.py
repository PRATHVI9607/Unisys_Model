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
from agents.executor.ledger_guard import LedgerGuard
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
FLUSH_INTERVAL_S = 30                    # chosen, not measured: how often the fallback stream is flushed to MinIO
INFLIGHT_TTL_S = 90                      # chosen default, not measured: how long a dead Executor's in-progress marker lives
INFLIGHT_REFRESH_S = INFLIGHT_TTL_S / 3  # chosen default, not measured: a live run extends its marker this often
# Compare-and-delete / compare-and-extend of the in-progress marker: only the owner (value == consumer name)
# may touch it. The word "expire" appears only in the refresh script (the test fake tells them apart by it).
_INFLIGHT_DELETE = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
_INFLIGHT_REFRESH = ("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) "
                     "else return 0 end")
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

    def __init__(self, mode, force_dry: bool = False, on_step=None, intent=None):
        # `intent(namespace, step)` writes the "about to do" ledger entry (ledger_guard.LedgerGuard) and
        # raises LedgerUnavailable when the step must not run. None: no intent entry (older callers, tests).
        self.mode, self.force_dry, self.on_step, self.intent = mode, force_dry, on_step, intent

    def allow_write(self, namespace: str) -> bool:
        return (not self.force_dry) and (not self.mode.dry_run_for(namespace))

    async def record_step(self, namespace: str, step: str, outcome: str) -> None:
        if self.on_step:
            await self.on_step(namespace, step, outcome)

    async def record_intent(self, namespace: str, step: str) -> None:
        if self.intent:
            await self.intent(namespace, step)


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
        # Ledger failure policy (P7-RR-10): every record falls back to a durable Redis stream, and every
        # write is preceded by an "about to do" entry (RequestGate.record_intent).
        self.ledger_guard = LedgerGuard(self.ledger, lambda: self.redis, METRICS)
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
        self.inflight_ttl_s = INFLIGHT_TTL_S
        self.inflight_refresh_s = INFLIGHT_REFRESH_S
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
        await self.ledger_guard.record(incident_id, step, payload)

    def _intent_for(self, incident_id_fn):
        async def intent(namespace: str, step: str) -> None:
            await self.ledger_guard.intent(incident_id_fn(), step, {"namespace": namespace})
        return intent

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
        await self._clear_own_inflight()
        if self.metric_source is None and self.cfg.prometheus_url:
            self.metric_source = PrometheusMetricSource(self.cfg.prometheus_url)
        self.scheduler = SnapshotScheduler(
            self.core_api, self.custom_api,
            RequestGate(self.mode, intent=self._intent_for(lambda: self.scheduler.run_id)), cfg=self.cfg,
            is_frozen=SnapshotFreeze(self.redis).is_frozen, record_step=self.record_step)
        self._tasks.add(asyncio.create_task(self.scheduler.run_forever()))
        self._tasks.add(asyncio.create_task(
            self.ledger_guard.run_flusher(FLUSH_INTERVAL_S, self.sleep)))   # cancelled in stop()
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

        return await self.reliability.reclaim(EXEC_STREAM, run, self._dead_letter, self._run_alive)

    async def _run_alive(self, stream: str, msg_id: str, fields: Dict) -> bool:
        """True while a healthy run holds the in-progress marker of this request. Such a duplicate entry is
        left pending (it is skipped as a redelivery once the run has written the done marker) and must not be
        dead-lettered and escalated as if it had failed `deliveries` times."""
        return bool(await self.redis.get(f"{self._done_key(fields, msg_id)}:inflight"))

    # ---- in-progress marker: short TTL, refreshed by the live run, owner-checked
    async def _inflight_release(self, key: str) -> bool:
        """Delete the marker only if this consumer still owns it."""
        run_script = getattr(self.redis, "eval", None)
        if run_script is not None:
            return bool(await run_script(_INFLIGHT_DELETE, 1, key, self.consumer))
        if await self.redis.get(key) == self.consumer:      # client without EVAL: not atomic, tests only
            await self.redis.delete(key)
            return True
        return False

    async def _inflight_refresh(self, key: str) -> bool:
        """Extend the marker only if this consumer still owns it."""
        run_script = getattr(self.redis, "eval", None)
        if run_script is not None:
            return bool(await run_script(_INFLIGHT_REFRESH, 1, key, self.consumer, int(self.inflight_ttl_s)))
        if await self.redis.get(key) == self.consumer:
            await self.redis.set(key, self.consumer, ex=int(self.inflight_ttl_s))
            return True
        return False

    async def _inflight_keeper(self, key: str) -> None:
        """Runs beside a request: while the Executor is alive the marker never expires, if it dies the marker
        expires after INFLIGHT_TTL_S and the redelivered entry runs. Uses real asyncio.sleep (the injected
        `sleep` is a fake clock in tests)."""
        while True:
            await asyncio.sleep(self.inflight_refresh_s)
            try:
                if not await self._inflight_refresh(key):
                    logger.warning(f"in-progress marker {key} is no longer owned by {self.consumer}")
            except Exception as exc:
                logger.warning(f"could not refresh in-progress marker {key}: {type(exc).__name__}")

    async def _clear_own_inflight(self) -> int:
        """At start: remove in-progress markers left by an earlier run under this consumer name (the pod
        hostname survives a container restart), so the redelivered entry is not blocked until the TTL."""
        scan = getattr(self.redis, "scan_iter", None)
        if scan is None:
            return 0
        cleared = 0
        try:
            async for key in scan(match=f"{DONE_PREFIX}:*:inflight"):
                key = key.decode() if isinstance(key, bytes) else str(key)
                if await self.redis.get(key) == self.consumer and await self._inflight_release(key):
                    cleared += 1
        except Exception as exc:
            logger.warning(f"could not clear stale in-progress markers: {type(exc).__name__}")
        if cleared:
            logger.warning(f"cleared {cleared} stale in-progress marker(s) owned by {self.consumer}")
        return cleared

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
            # Two stream entries for the same incident and action (a duplicate approval, or a reclaim while
            # the first run is still going) must not run at the same time: the done marker above is only
            # written after the action. SET NX an in-progress marker; the loser stays pending and is
            # skipped as a redelivery once the winner has written the done marker.
            inflight = f"{key}:inflight"
            if not await self.redis.set(inflight, self.consumer, nx=True, ex=int(self.inflight_ttl_s)):
                logger.warning(f"{key} is already being executed; entry {msg_id} left pending")
                return False
            keeper = asyncio.create_task(self._inflight_keeper(inflight))
            try:
                outcome = await self.execute(fields)
                # The outcome is stored BEFORE the ledger and the actions entry, and both before the ack.
                final = not outcome.startswith(NOT_FINAL_PREFIXES)
                if final:
                    await self._write_marker(key, outcome, recorded=False)
                await self._finish(fields, outcome, key if final else None)
            finally:
                keeper.cancel()
                await asyncio.gather(keeper, return_exceptions=True)
                try:
                    await self._inflight_release(inflight)
                except Exception as exc:        # the TTL frees it
                    logger.warning(f"could not clear in-progress marker {inflight}: {type(exc).__name__}")
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
                                       "dry_run_requested": req.dry_run,
                                       "patch_fields": req.patch_fields, "rule_path": req.rule_path,
                                       "rule_reasons": req.rule_reasons,
                                       "containment_label": req.containment_label,
                                       "restore_after": req.restore_after,
                                       "human_followup": req.human_followup})
        gate = RequestGate(self.mode, force_dry=req.dry_run, intent=self._intent_for(lambda: incident_id))
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
        # The human is told FIRST: a ledger outage (the reason for many escalations) must never delay the page.
        await self.redis.xadd(ESCALATIONS_STREAM, {
            "incident_id": incident_id,
            "namespace": f.get("namespace", ""),
            "deployment": f.get("deployment", ""),
            "reason": outcome,
            "required": "human",
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })
        await self._append_ledger(incident_id, "executor_escalation", {
            "namespace": f.get("namespace", ""),
            "deployment": f.get("deployment", ""),
            "reason": outcome,
            "required": "human",
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
        await self.ledger_guard.record(incident_id, step, payload)


async def main():
    METRICS.start_server(int(os.environ.get("METRICS_PORT", "9100")))
    svc = ExecutorService()
    try:
        await svc.start()
    finally:
        await svc.stop()


if __name__ == "__main__":
    asyncio.run(main())
