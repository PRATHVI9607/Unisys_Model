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
import uuid
from datetime import datetime
from typing import Dict, Optional

import aiohttp
import numpy as np
import redis.asyncio as aioredis

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
    def __init__(self):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.dcm_url = os.environ.get("DCM_URL", "http://kubeheal-dcm:8003")
        self.burn_in = os.environ.get("BURN_IN_MODE", "false").lower() == "true"
        self.redis: Optional[aioredis.Redis] = None
        self.consumer = os.environ.get("HOSTNAME") or f"fusion-{uuid.uuid4().hex[:6]}"
        self.running = False
        # short-term correlation buffer: pod → latest opposite-domain event
        self.pending_health: Dict[str, Dict] = {}
        self.pending_sec: Dict[str, Dict] = {}

    async def start(self):
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

    async def _on_health(self, f: Dict):
        key = self._key(f)
        self.pending_health[key] = f
        sec = self.pending_sec.get(key)
        await self._decide(key, f, sec)

    async def _on_security(self, f: Dict):
        key = self._key(f)
        self.pending_sec[key] = f
        health = self.pending_health.get(key)
        await self._decide(key, health, f)

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

        # consume the paired events so we don't re-fire on the same pair
        self.pending_health.pop(key, None)
        self.pending_sec.pop(key, None)

    async def _execute(self, namespace, pod, out, inp, causal_chain):
        logger.info(f"DECISION {out.decision.value} {namespace}/{pod} "
                    f"score={out.adjusted_score:.2f} :: {out.rationale}")
        if out.decision in (Decision.AUTO_KILL,):
            await self._cb_incr(f"kubeheal:cb:kill:{namespace}")
        elif out.decision in (Decision.AUTO_PATCH,):
            await self._cb_incr(f"kubeheal:cb:patch:{namespace}:{pod}")
        await self.redis.xadd(ACTIONS_STREAM, {
            "action_type": out.decision.value,
            "target": json.dumps({"namespace": namespace, "pod": pod}),
            "confidence": f"{out.adjusted_score:.4f}",
            "rationale": out.rationale,
            "compound": str(out.action_params.get("compound", False)),
            "nl_summary": out.action_params.get("nl_summary") or "",
            "causal_chain": json.dumps(causal_chain),
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
