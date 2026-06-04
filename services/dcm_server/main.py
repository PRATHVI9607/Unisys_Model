"""
DCM Server — KubeHeal v4 (port 8003, PRD Section 13).
=====================================================
Takes health_embedding[128] + security_embedding[64], returns correlation_score,
compound_flag, causal_chain, and (best-effort, non-blocking) nl_summary.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional

import torch
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from models.dcm.cross_modal_attention import CrossModalAttention
from models.dcm.causal_chain_builder import CausalChainBuilder
from models.dcm.correlation_head import COMPOUND_THRESHOLD, is_compound
from models.interpretation.nl_summary_generator import generate_incident_summary

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="KubeHeal DCM", version="4.0.0")
STATE: Dict = {"model": None, "chain": CausalChainBuilder(), "trained": False}


class CorrelateRequest(BaseModel):
    health_embedding: List[float]
    security_embedding: List[float]
    health_assessment: Optional[Dict] = None
    security_event: Optional[Dict] = None
    field_attribution: Optional[Dict] = None
    want_nl_summary: bool = False


@app.on_event("startup")
def startup():
    ckpt = os.environ.get("MODEL_PATH", str(ROOT / "models/dcm/checkpoints/best_dcm.pt"))
    m = CrossModalAttention()
    if os.path.exists(ckpt):
        try:
            m.load_state_dict(torch.load(ckpt, map_location="cpu"))
            STATE["trained"] = True
            logger.info(f"Loaded DCM from {ckpt} ({m.param_count():,} params)")
        except Exception as e:
            logger.error(f"DCM load failed: {e} — random weights (cold start)")
    else:
        logger.warning(f"No DCM checkpoint at {ckpt} — cold start (correlation ~0.5)")
    m.eval()
    STATE["model"] = m


@app.get("/health")
def health():
    return {"status": "ok", "model_version": "v4.0.0",
            "model_loaded": STATE["model"] is not None, "trained": STATE["trained"]}


@app.post("/dcm/correlate")
def correlate(req: CorrelateRequest):
    model = STATE["model"]
    if STATE["trained"]:
        score = model.correlate(req.health_embedding, req.security_embedding)
    else:
        # Cold-start fallback (Section 15 A.3): no compound escalation
        score = 0.5
    compound = is_compound(score) and STATE["trained"]

    chain = STATE["chain"].build(
        req.health_assessment, req.security_event, score, req.field_attribution
    )

    nl = None
    if req.want_nl_summary:
        incident = {
            "health_risk": (req.health_assessment or {}).get("risk_score"),
            "sec_risk": (req.security_event or {}).get("risk_score"),
            "correlation_score": score,
            "top_field": (req.health_assessment or {}).get("top_field"),
            "action_taken": "pending",
        }
        nl = generate_incident_summary(incident)

    return {
        "correlation_score": score,
        "compound_flag": compound,
        "causal_chain": chain,
        "correlation_confidence": abs(score - 0.5) * 2,  # distance from undecided
        "nl_summary": nl,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8003")))
