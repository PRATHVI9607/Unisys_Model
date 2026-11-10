"""
Fusion Agent v4 - Three-Signal Decision Engine (PRD Section 07 / 09).
=====================================================================
Consumes kubeheal.health.events + kubeheal.security.events via a Redis
consumer group (each event handled by exactly one replica). Correlates the
two signals through the DCM, runs the pure decision policy, executes under a
heartbeat incident lock, and writes kubeheal.dcm.events + kubeheal.actions.

P1 notes: events are keyed by the explicit workload (Deployment) name, a message is
acknowledged only after it was handled successfully, and every Kubernetes write goes
through the Executor: this agent only publishes requests to kubeheal.exec.
"""

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Dict, Optional

import aiohttp
import numpy as np
import redis.asyncio as aioredis

from agents.common.killswitch import ModeWatcher
from agents.fusion_agent.decision_policy import (
    make_decision, DecisionInput, Decision,
)
from agents.fusion_agent.incident_lock import acquire_incident_lock

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GROUP = "fusion"
HEALTH_STREAM = "kubeheal.health.events"
SEC_STREAM = "kubeheal.security.events"
DCM_STREAM = "kubeheal.dcm.events"
ACTIONS_STREAM = "kubeheal.actions"
EXEC_STREAM = "kubeheal.exec"


def _b64_to_vec(b64: str):
    if not b64:
        return None
    return np.frombuffer(base64.b64decode(b64), dtype=np.float32).tolist()


def workload_of(fields: Dict) -> str:
    """Explicit workload (Deployment/StatefulSet) name carried in the event.
    Falls back to pod_name only for events from older agents."""
    return fields.get("deployment") or fields.get("pod_name") or "unknown"


class FusionAgentV4:
    # Only correlate a health+security pair if both arrived within this window
    # (else they are independent events that happen to share a workload name).
    CORRELATION_WINDOW_S = 30.0

    def __init__(self):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.dcm_url = os.environ.get("DCM_URL", "http://kubeheal-dcm:8003")
        self.burn_in = os.environ.get("BURN_IN_MODE", "false").lower() == "true"
        self.redis: Optional[aioredis.Redis] = None
        self.consumer = os.environ.get("HOSTNAME") or f"fusion-{uuid.uuid4().hex[:6]}"
        self.mode = ModeWatcher()
        self.running = False
        # short-term correlation buffer: "<ns>:<workload>" -> (event_fields, recv_monotonic)
        self.pending_health: Dict[str, tuple] = {}
        self.pending_sec: Dict[str, tuple] = {}

    async def start(self):
        try:
            from kubernetes_asyncio import client, config
            try:
                config.load_incluster_config()
            except Exception:
                await config.load_kube_config()
            await self.mode.start(client.CoreV1Api())   # read-only: kubeheal-mode + namespace labels
        except Exception as e:
            logger.warning(f"kill switch watcher not started ({e}); mode stays 'test'")
        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
        for stream in (HEALTH_STREAM, SEC_STREAM):
            try:
                await self.redis.xgroup_create(stream, GROUP, id="0", mkstream=True)
            except Exception as e:
                if "BUSYGROUP" not in str(e):
                    logger.warning(f"xgroup_create {stream}: {e}")
        logger.info(f"Fusion Agent v4 started (consumer={self.consumer}, burn_in={self.burn_in})")
        self.running = True
        await self._consume()

    async def stop(self):
        self.running = False
        if self.redis:
            await self.redis.aclose()

    async def _consume(self):
        while self.running:
            try:
                msgs = await self.redis.xreadgroup(
                    GROUP, self.consumer,
                    {HEALTH_STREAM: ">", SEC_STREAM: ">"}, count=10, block=1000,
                )
                for stream, entries in msgs or []:
                    for msg_id, fields in entries:
                        await self._handle_entry(stream, msg_id, fields)
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"consume error: {e}")
                await asyncio.sleep(1)

    async def _handle_entry(self, stream: str, msg_id: str, fields: Dict) -> bool:
        """Handle one stream entry. XACK only after success; a failed entry stays in the
        pending list so it can be reclaimed (P6 adds the reclaim and dead-letter logic)."""
        try:
            if stream == HEALTH_STREAM:
                await self._on_health(fields)
            else:
                await self._on_security(fields)
        except Exception as e:
            logger.error(f"handling {stream}/{msg_id} failed, left pending: {e}", exc_info=True)
            return False
        await self.redis.xack(stream, GROUP, msg_id)
        return True

    def _key(self, fields: Dict) -> str:
        return f"{fields.get('namespace', 'default')}:{workload_of(fields)}"

    def _fresh(self, entry) -> Optional[Dict]:
        """Return the paired event only if it arrived within the correlation
        window - otherwise it is an independent event, not a compound one."""
        if not entry:
            return None
        fields, ts = entry
        return fields if (time.monotonic() - ts) <= self.CORRELATION_WINDOW_S else None

    def _prune(self):
        now = time.monotonic()
        for d in (self.pending_health, self.pending_sec):
            for k in [k for k, (_, ts) in d.items() if now - ts > self.CORRELATION_WINDOW_S]:
                d.pop(k, None)

    async def _on_health(self, f: Dict):
        key = self._key(f)
        self.pending_health[key] = (f, time.monotonic())
        sec = self._fresh(self.pending_sec.get(key))
        await self._decide(key, f, sec)
        self._prune()

    async def _on_security(self, f: Dict):
        key = self._key(f)
        self.pending_sec[key] = (f, time.monotonic())
        health = self._fresh(self.pending_health.get(key))
        await self._decide(key, health, f)
        self._prune()

    async def _decide(self, key: str, health: Optional[Dict], sec: Optional[Dict]):
        namespace, workload = key.split(":", 1)
        health = health or {}
        sec = sec or {}
        # Only a security event names a real pod. Health events set pod_name to the Deployment name.
        pod = sec.get("pod_name") or ""

        health_risk = float(health.get("health_risk", 0) or 0)
        sec_risk = float(sec.get("sec_risk", 0) or 0)

        # DCM correlation (only when both signals are present)
        correlation, compound, causal_chain, nl = 0.0, False, [], None
        h_emb = _b64_to_vec(health.get("health_embedding_b64", ""))
        s_emb = _b64_to_vec(sec.get("security_embedding_b64", ""))
        if h_emb and s_emb:
            corr = await self._call_dcm(h_emb, s_emb, health, sec)
            correlation = corr.get("correlation_score", 0.0)
            compound = corr.get("compound_flag", False)
            causal_chain = corr.get("causal_chain", [])
            nl = corr.get("nl_summary")
            await self._publish_dcm(namespace, workload, corr, health, sec)

        inp = DecisionInput(
            health_risk=health_risk,
            health_label=health.get("health_label", "benign"),
            health_ci_width=float(health.get("health_ci_width", 0) or 0),
            health_field_top=health.get("top_field", ""),
            sec_risk=sec_risk,
            sec_label=sec.get("sec_label", "benign"),
            sec_ci_width=float(sec.get("sec_ci_width", 0) or 0),
            sec_syscall_top=sec.get("top_syscall", ""),
            correlation_score=correlation,
            compound_flag=compound,
            namespace_tier=(health.get("namespace_tier") or sec.get("namespace_tier") or "staging"),
            circuit_breaker_containments=await self._cb_count(f"kubeheal:cb:contain:{namespace}"),
            circuit_breaker_patches=await self._cb_count(f"kubeheal:cb:patch:{namespace}:{workload}"),
            burn_in_mode=self.burn_in,
            nl_summary=nl,
            mode=self.mode.mode_for(namespace),
        )
        out = make_decision(inp)

        if out.requires_incident_lock:
            async with acquire_incident_lock(self.redis, namespace, workload) as got:
                if not got:
                    logger.debug(f"lock held for {key}; skipping")
                    return
                await self._execute(namespace, workload, pod, out, inp, causal_chain)
        else:
            await self._execute(namespace, workload, pod, out, inp, causal_chain)
        # Pending entries are kept for the correlation window so a partner event arriving
        # within 30 s can still form a compound incident. _prune() expires them; the incident
        # lock and the circuit breakers prevent duplicate actions on the same workload.

    async def _execute(self, namespace, workload, pod, out, inp, causal_chain):
        logger.info(f"DECISION {out.decision.value} {namespace}/{workload} "
                    f"score={out.adjusted_score:.2f} :: {out.rationale}")
        outcome = "logged"
        incident_id = f"inc-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        # The Fusion Agent never calls the Kubernetes API. Automatic actions are queued for the
        # Executor, the only component with write permissions (S-EX-1).
        # Circuit breakers count real automatic actions only: increment after the request is queued
        # (a failed enqueue or a retry does not double count) and never for dry runs, otherwise
        # test mode would use up the budget before the switch to enforce.
        if out.decision == Decision.AUTO_CONTAIN and not pod:
            logger.error(f"AUTO_CONTAIN for {namespace}/{workload} without a pod from a security event; "
                         "not queued")
            outcome = "not_queued_no_pod"
        elif out.decision == Decision.AUTO_CONTAIN:
            await self._enqueue_exec(incident_id, "contain", namespace, workload, pod, out, inp)
            if not out.dry_run:
                await self._cb_incr(f"kubeheal:cb:contain:{namespace}")
            outcome = "queued_for_executor"
        elif out.decision == Decision.AUTO_PATCH:
            await self._enqueue_exec(incident_id, "patch", namespace, workload, pod, out, inp)
            if not out.dry_run:
                await self._cb_incr(f"kubeheal:cb:patch:{namespace}:{workload}")
            outcome = "queued_for_executor"
        await self.redis.xadd(ACTIONS_STREAM, {
            "incident_id": incident_id,
            "action_type": out.decision.value,
            "target": json.dumps({"namespace": namespace, "deployment": workload, "pod": pod}),
            "confidence": f"{out.adjusted_score:.4f}",
            "rationale": out.rationale,
            "compound": str(out.action_params.get("compound", False)),
            "nl_summary": out.action_params.get("nl_summary") or "",
            "causal_chain": json.dumps(causal_chain),
            "outcome": outcome,
            "dry_run": str(out.dry_run).lower(),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _enqueue_exec(self, incident_id, action, namespace, workload, pod, out, inp):
        await self.redis.xadd(EXEC_STREAM, {
            "incident_id": incident_id,
            "action": action,
            "namespace": namespace,
            "deployment": workload,
            "pod": pod,
            "patch_field": inp.health_field_top if action == "patch" else "",
            "namespace_tier": inp.namespace_tier,
            "approved_by": "auto",
            "dry_run": str(out.dry_run).lower(),
            "source": "fusion",
            "rationale": out.rationale,
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _call_dcm(self, h_emb, s_emb, health, sec) -> Dict:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(f"{self.dcm_url}/dcm/correlate", json={
                    "health_embedding": h_emb, "security_embedding": s_emb,
                    "health_assessment": health, "security_event": sec,
                    "want_nl_summary": True,
                }, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        return await r.json()
        except Exception as e:
            logger.debug(f"DCM call failed: {e}")
        return {"correlation_score": 0.0, "compound_flag": False, "causal_chain": []}

    async def _publish_dcm(self, namespace, workload, corr, health, sec):
        await self.redis.xadd(DCM_STREAM, {
            "namespace": namespace, "pod_name": workload, "deployment": workload,
            "correlation_score": f"{corr.get('correlation_score', 0):.4f}",
            "compound_flag": str(corr.get("compound_flag", False)),
            "causal_chain_json": json.dumps(corr.get("causal_chain", [])),
            "correlation_confidence": f"{corr.get('correlation_confidence', 0):.4f}",
            "nl_summary": corr.get("nl_summary") or "",
            "health_event_id": health.get("event_id", ""),
            "security_event_id": sec.get("event_id", ""),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _cb_count(self, key: str) -> int:
        v = await self.redis.get(key)
        return int(v) if v else 0

    async def _cb_incr(self, key: str):
        c = await self.redis.incr(key)
        if c == 1:
            await self.redis.expire(key, 3600)


async def main():
    agent = FusionAgentV4()
    try:
        await agent.start()
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
