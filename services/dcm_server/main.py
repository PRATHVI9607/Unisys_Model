"""
DCM Server — KubeHeal v4 (port 8003, PRD Section 13).
=====================================================
Takes health_embedding[128] + security_embedding[64], returns correlation_score,
compound_flag, causal_chain, and (best-effort, non-blocking) nl_summary.
"""

import os
import sys
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

from contextlib import asynccontextmanager

import torch
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from models.dcm.cross_modal_attention import CrossModalAttention
from models.dcm.causal_chain_builder import CausalChainBuilder
from models.dcm.correlation_head import COMPOUND_THRESHOLD, is_compound
from services.ckpt import (load_model_checkpoint, health_payload, require_ready, model_format,
                           not_ready_status, load_onnx_session)
from models.interpretation.nl_summary_generator import generate_incident_summary
from agents.common.metrics import KubeHealMetrics, add_inflight_middleware, add_metrics_route

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATE: Dict = {"model": None, "chain": CausalChainBuilder(), "trained": False,
         "status": {"loaded": False, "error": "not started"}}
METRICS = KubeHealMetrics()


class CorrelateRequest(BaseModel):
    health_embedding: List[float]
    security_embedding: List[float]
    health_assessment: Optional[Dict] = None
    security_event: Optional[Dict] = None
    field_attribution: Optional[Dict] = None
    want_nl_summary: bool = False


class OnnxCorrelator:
    """Same `correlate` interface as CrossModalAttention, backed by the exported ONNX graph
    (models/export_dcm.py: inputs health_embedding[1,128], security_embedding[1,64] -> score)."""

    def __init__(self, session):
        self.session = session

    def correlate(self, health_embedding, security_embedding) -> float:
        import numpy as _np
        feeds = {"health_embedding": _np.asarray(health_embedding, dtype=_np.float32).reshape(1, -1),
                 "security_embedding": _np.asarray(security_embedding, dtype=_np.float32).reshape(1, -1)}
        return float(_np.asarray(self.session.run(None, feeds)[0]).reshape(-1)[0])

    def eval(self):
        return self


def _load_onnx_model():
    path = os.environ.get("MODEL_ONNX_PATH", str(ROOT / "models/dcm_v4.onnx"))
    status, session = load_onnx_session(path, "DCM")
    STATE["status"] = status
    STATE["model"] = OnnxCorrelator(session) if session is not None else None
    STATE["trained"] = bool(status["loaded"])


def _load_model():
    try:
        fmt = model_format()
    except ValueError as exc:
        STATE["status"] = not_ready_status("DCM", str(exc))
        STATE["model"], STATE["trained"] = None, False
        return
    if fmt == "onnx":
        # DCM is the only server whose ONNX graph is a drop-in: one output, the correlation score
        # (parity against torch is asserted in tests/test_platform_onnx_switch.py).
        _load_onnx_model()
        return
    ckpt = os.environ.get("MODEL_PATH", str(ROOT / "models/dcm/checkpoints/best_dcm.pt"))
    m = CrossModalAttention()
    status = load_model_checkpoint(m, ckpt, "DCM")
    STATE["trained"] = bool(status["loaded"] and not status["random_weights"])
    if STATE["trained"]:
        logger.info(f"Loaded DCM from {ckpt} ({m.param_count():,} params)")
    STATE["status"] = status
    m.eval()
    STATE["model"] = m
    if status["loaded"] and not status["random_weights"]:
        logger.info("Loaded DCM from %s:%s", status["source"], status["checkpoint"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_model()
    yield


app = FastAPI(title="KubeHeal DCM", version="4.0.0", lifespan=lifespan)
add_metrics_route(app, METRICS)
add_inflight_middleware(app, METRICS, ["/dcm/correlate"])


@app.get("/health")
def health():
    return health_payload(STATE["status"], {"trained": STATE["trained"]})


@app.post("/dcm/correlate")
def correlate(req: CorrelateRequest):
    require_ready(STATE["status"])
    started = time.perf_counter()
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

    METRICS.observe_model_latency("dcm", time.perf_counter() - started)

    return {
        "correlation_score": score,
        "compound_flag": compound,
        "causal_chain": chain,
        "correlation_confidence": abs(score - 0.5) * 2,  # distance from undecided
        "nl_summary": nl,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8003")))
