"""
Interpretation client — KubeHeal v4 (PRD Section 11 / 3.7).
===========================================================
Fire-and-forget async client the Fusion Agent uses to fetch a natural-language
incident summary WITHOUT blocking the decision path. The DCM server already
returns nl_summary inline; this client is for the case where the summary is
requested separately / refreshed asynchronously and written back to the
incident record.
"""

import asyncio
import json
import logging
from typing import Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)


class InterpretationClient:
    def __init__(self, dcm_url: str, redis=None):
        self.dcm_url = dcm_url
        self.redis = redis

    async def summary(self, health: Dict, sec: Dict, h_emb, s_emb,
                      timeout: float = 4.0) -> Optional[str]:
        """Ask the DCM/interpretation layer for an NL summary. Returns None on
        any failure — callers must treat the summary as best-effort."""
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.dcm_url}/dcm/correlate",
                    json={"health_embedding": h_emb, "security_embedding": s_emb,
                          "health_assessment": health, "security_event": sec,
                          "want_nl_summary": True},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as r:
                    if r.status == 200:
                        return (await r.json()).get("nl_summary")
        except Exception as e:
            logger.debug(f"interpretation client: {e}")
        return None

    def fire_and_forget(self, incident_id: str, health: Dict, sec: Dict, h_emb, s_emb):
        """Schedule a non-blocking summary fetch; write it onto the incident
        hash when it lands. Never raises into the caller."""
        async def _run():
            nl = await self.summary(health, sec, h_emb, s_emb)
            if nl and self.redis and incident_id:
                try:
                    await self.redis.hset(f"kubeheal:incident:{incident_id}",
                                          mapping={"nl_summary": nl})
                except Exception:
                    pass
        asyncio.create_task(_run())
