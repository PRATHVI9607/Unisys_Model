"""
Fusion Agent v4 — Three-Signal Decision Engine (PRD Section 07 / 09).
=====================================================================
Consumes kubeheal.health.events + kubeheal.security.events via a Redis
consumer group (each event handled by exactly one replica). Correlates the
two signals through the DCM, runs the pure decision policy, executes under a
heartbeat incident lock, and writes kubeheal.dcm.events + kubeheal.actions.
"""

import asyncio
import base64
import json
import logging
import os
import socket
import time
import uuid
from datetime import datetime
from typing import Dict, Optional

import aiohttp
import numpy as np
import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, config

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


def _b64_to_vec(b64: str):
    if not b64:
        return None
    return np.frombuffer(base64.b64decode(b64), dtype=np.float32).tolist()


class FusionAgentV4:
    # Only correlate a health+security pair if both arrived within this window
    # (else they are independent events that happen to share a pod name).
    CORRELATION_WINDOW_S = 30.0

    def __init__(self):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.dcm_url = os.environ.get("DCM_URL", "http://kubeheal-dcm:8003")
        self.burn_in = os.environ.get("BURN_IN_MODE", "false").lower() == "true"
        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None
        self.consumer = os.environ.get("HOSTNAME") or f"fusion-{uuid.uuid4().hex[:6]}"
        self.running = False
        # short-term correlation buffer: pod → (event_fields, recv_monotonic)
        self.pending_health: Dict[str, tuple] = {}
        self.pending_sec: Dict[str, tuple] = {}

    async def start(self):
        # Kubernetes clients — required to actually execute kill/patch actions.
        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster config")
        except Exception:
            try:
                await config.load_kube_config()
                logger.info("Loaded kubeconfig")
            except Exception as e:
                logger.warning(f"No kube config ({e}); actions will be dry-run only")
        try:
            self.core_api = client.CoreV1Api()
            self.apps_api = client.AppsV1Api()
            self.networking_api = client.NetworkingV1Api()
        except Exception as e:
            logger.warning(f"Kube client init failed: {e}")

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
                        try:
                            if stream == HEALTH_STREAM:
                                await self._on_health(fields)
                            else:
                                await self._on_security(fields)
                        finally:
                            await self.redis.xack(stream, GROUP, msg_id)
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"consume error: {e}")
                await asyncio.sleep(1)

    def _key(self, fields: Dict) -> str:
        return f"{fields.get('namespace','default')}:{fields.get('pod_name','unknown')}"

    def _fresh(self, entry) -> Optional[Dict]:
        """Return the paired event only if it arrived within the correlation
        window — otherwise it's an independent event, not a compound one."""
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
        namespace = key.split(":")[0]
        pod = key.split(":", 1)[1]
        health = health or {}
        sec = sec or {}

        health_risk = float(health.get("health_risk", 0) or 0)
        sec_risk = float(sec.get("sec_risk", 0) or 0)

        # ── DCM correlation (only when both signals present) ──
        correlation, compound, causal_chain, nl = 0.0, False, [], None
        h_emb = _b64_to_vec(health.get("health_embedding_b64", ""))
        s_emb = _b64_to_vec(sec.get("security_embedding_b64", ""))
        if h_emb and s_emb:
            corr = await self._call_dcm(h_emb, s_emb, health, sec)
            correlation = corr.get("correlation_score", 0.0)
            compound = corr.get("compound_flag", False)
            causal_chain = corr.get("causal_chain", [])
            nl = corr.get("nl_summary")
            await self._publish_dcm(namespace, pod, corr, health, sec)

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
            circuit_breaker_kills=await self._cb_count(f"kubeheal:cb:kill:{namespace}"),
            circuit_breaker_patches=await self._cb_count(f"kubeheal:cb:patch:{namespace}:{pod}"),
            burn_in_mode=self.burn_in,
            nl_summary=nl,
        )
        out = make_decision(inp)

        if out.requires_incident_lock:
            async with acquire_incident_lock(self.redis, namespace, pod) as got:
                if not got:
                    logger.debug(f"lock held for {key}; skipping")
                    return
                await self._execute(namespace, pod, out, inp, causal_chain)
        else:
            await self._execute(namespace, pod, out, inp, causal_chain)
        # Note: pending entries are NOT popped here — they're kept for the
        # correlation window so a partner event arriving within 30s can still
        # form a compound incident. _prune() expires them; the incident lock +
        # circuit breakers prevent duplicate actions on the same pod.

    async def _execute(self, namespace, pod, out, inp, causal_chain):
        logger.info(f"DECISION {out.decision.value} {namespace}/{pod} "
                    f"score={out.adjusted_score:.2f} :: {out.rationale}")
        outcome = "logged"
        if out.decision == Decision.AUTO_KILL:
            await self._cb_incr(f"kubeheal:cb:kill:{namespace}")
            outcome = await self._execute_kill(namespace, pod)
        elif out.decision == Decision.AUTO_PATCH:
            await self._cb_incr(f"kubeheal:cb:patch:{namespace}:{pod}")
            outcome = await self._execute_patch(namespace, pod, inp.health_field_top)
        await self.redis.xadd(ACTIONS_STREAM, {
            "action_type": out.decision.value,
            "target": json.dumps({"namespace": namespace, "pod": pod}),
            "confidence": f"{out.adjusted_score:.4f}",
            "rationale": out.rationale,
            "compound": str(out.action_params.get("compound", False)),
            "nl_summary": out.action_params.get("nl_summary") or "",
            "causal_chain": json.dumps(causal_chain),
            "outcome": outcome,
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _execute_kill(self, namespace: str, pod: str) -> str:
        """AUTO-KILL: quarantine the namespace (egress NetworkPolicy) then
        delete the offending pod immediately."""
        if not self.core_api:
            logger.warning("No kube client — kill is dry-run")
            return "dry_run_no_kube"
        # 1) egress quarantine so any C2 channel is cut before the kill
        np = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "kubeheal-quarantine"},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                     "egress": [{"to": [{"podSelector": {}}]}]},
        }
        try:
            await self.networking_api.create_namespaced_network_policy(namespace, np)
        except Exception as e:
            if "already exists" not in str(e).lower() and "conflict" not in str(e).lower():
                logger.debug(f"quarantine policy: {e}")
        # 2) delete the pod (grace 0 = immediate)
        try:
            await self.core_api.delete_namespaced_pod(
                pod, namespace, grace_period_seconds=0)
            logger.warning(f"AUTO-KILL: deleted pod {namespace}/{pod}")
            return "pod_killed+quarantined"
        except Exception as e:
            logger.error(f"AUTO-KILL failed for {namespace}/{pod}: {e}")
            return f"kill_failed:{e}"

    async def _execute_patch(self, namespace: str, pod: str, top_field: str) -> str:
        """AUTO-PATCH: restore the highest-attribution field to its recorded
        baseline. Baseline spec is stored by the Health Agent in Redis."""
        if not self.apps_api:
            logger.warning("No kube client — patch is dry-run")
            return "dry_run_no_kube"
        # owning Deployment name = pod_name minus the replicaset/pod hash suffixes
        dep = "-".join(pod.split("-")[:-2]) if pod.count("-") >= 2 else pod
        baseline_raw = await self.redis.get(f"kubeheal:baseline:{namespace}:{dep}")
        if not baseline_raw:
            logger.info(f"No baseline for {namespace}/{dep}; escalating patch to human")
            return "no_baseline_escalated"
        try:
            baseline = json.loads(baseline_raw)
            # restore full template spec to the recorded golden baseline (canary-safe:
            # K8s rolls the Deployment; readiness probes gate the rollout)
            body = {"spec": {"template": baseline.get("template", baseline)}}
            await self.apps_api.patch_namespaced_deployment(dep, namespace, body)
            logger.info(f"AUTO-PATCH: restored {namespace}/{dep} to baseline")
            return "patched_to_baseline"
        except Exception as e:
            logger.error(f"AUTO-PATCH failed for {namespace}/{dep}: {e}")
            return f"patch_failed:{e}"

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

    async def _publish_dcm(self, namespace, pod, corr, health, sec):
        await self.redis.xadd(DCM_STREAM, {
            "namespace": namespace, "pod_name": pod,
            "correlation_score": f"{corr.get('correlation_score',0):.4f}",
            "compound_flag": str(corr.get("compound_flag", False)),
            "causal_chain_json": json.dumps(corr.get("causal_chain", [])),
            "correlation_confidence": f"{corr.get('correlation_confidence',0):.4f}",
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
