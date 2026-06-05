"""
Security Model Server — KubeHeal v4 (port 8002, PRD Section 13).
================================================================
Serves Transformer+Conv1D security model. GET /health, POST /security/score.
Accepts either tokenized inputs OR raw events+entropy (auto-encodes).
"""

import os
import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional

from contextlib import asynccontextmanager

import torch
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from models.security_model.security_model import (
    SecurityModel, encode_syscall_window, pad_entropy,
)
from models.security_model.security_output_head import SECURITY_LABELS
from models.security_model.security_conformal import ConformalRegressor
from models.interpretation.shap_explainer import SecurityModelSHAPExplainer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATE: Dict = {"model": None, "conformal": None, "shap": SecurityModelSHAPExplainer()}


class ScoreRequest(BaseModel):
    events: Optional[List[Dict]] = None          # [{syscall, fd_path}, ...]
    entropy_series: Optional[List[float]] = None
    early_signals: Optional[Dict] = None


def _load_model():
    ckpt = os.environ.get("MODEL_PATH",
                          str(ROOT / "models/security_model/checkpoints/best_security_model.pt"))
    m = SecurityModel()
    if os.path.exists(ckpt):
        try:
            m.load_state_dict(torch.load(ckpt, map_location="cpu"))
            logger.info(f"Loaded security model from {ckpt} ({m.param_count():,} params)")
        except Exception as e:
            logger.error(f"Checkpoint load failed: {e} — random weights")
    else:
        logger.warning(f"No checkpoint at {ckpt} — random weights")
    m.eval()
    STATE["model"] = m
    conf_path = str(Path(ckpt).parent / "security_conformal.json")
    STATE["conformal"] = ConformalRegressor.load(conf_path) if os.path.exists(conf_path) \
        else ConformalRegressor()
    logger.info("Security Model Server ready")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_model()
    yield


app = FastAPI(title="KubeHeal Security Model", version="4.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "model_version": "v4.0.0", "model_loaded": STATE["model"] is not None}


@app.post("/security/score")
def score(req: ScoreRequest):
    t0 = time.time()
    model = STATE["model"]
    events = req.events or []
    entropy = req.entropy_series or []
    sid, pid, mask = encode_syscall_window(events)
    ent = pad_entropy(entropy)

    with torch.no_grad():
        out = model(sid, pid, mask, ent)
    risk = float(out["risk_score"].reshape(-1)[0])
    probs = torch.softmax(out["label_logits"], dim=-1)[0]
    idx = int(torch.argmax(probs).item())
    label = SECURITY_LABELS[idx]

    n = min(len(events), out["syscall_salience"].shape[1])
    salience = out["syscall_salience"][0][:n].tolist()
    syscall_attr = STATE["shap"].explain_syscalls(events[:n], salience)
    top_syscall = next(iter(syscall_attr), "unknown")
    spike = STATE["shap"].entropy_spike(entropy)

    ci_width = float(1.0 - float(probs.max()))   # per-sample confidence uncertainty
    lo, hi, width = STATE["conformal"].interval(risk, ci_width)
    return {
        "risk_score": risk,
        "label": label,
        "label_probabilities": {l: float(probs[i]) for i, l in enumerate(SECURITY_LABELS)},
        "ci_lower": lo, "ci_upper": hi, "ci_width": width,
        "syscall_attention_weights": syscall_attr,
        "top_syscall": top_syscall,
        "entropy_spike": spike,
        "security_embedding": out["security_embedding"][0].tolist(),
        "inference_latency_ms": round((time.time() - t0) * 1000, 2),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8002")))
