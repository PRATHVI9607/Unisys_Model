"""
Health Model Server — KubeHeal v4 (port 8001, PRD Section 13).
==============================================================
Serves GATv2+BiLSTM health model. GET /health, POST /health/score.
Loads the PyTorch checkpoint (MODEL_PATH) + conformal stats; computes SHAP-
style metric attributions and GAT field attributions.
"""

import os
import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional

from contextlib import asynccontextmanager

import numpy as np
import torch
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel
from models.health_model.health_output_head import HEALTH_LABELS
from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
from models.health_model.health_conformal import ConformalRegressor
from models.interpretation.field_name_mapper import FieldNameMapper
from models.interpretation.shap_explainer import HealthModelSHAPExplainer
from services.ckpt import load_model_checkpoint, health_payload, require_ready, pt_only_status
from agents.common.metrics import KubeHealMetrics, add_inflight_middleware, add_metrics_route

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATE: Dict = {"model": None, "conformal": None, "status": {"loaded": False, "error": "not started"}, "mapper": FieldNameMapper(),
               "shap": HealthModelSHAPExplainer()}
METRICS = KubeHealMetrics()


class ScoreRequest(BaseModel):
    old_spec: Optional[Dict] = None
    new_spec: Optional[Dict] = None
    metrics: Optional[List[List[float]]] = None
    request_id: Optional[str] = None


def _load_model():
    refused = pt_only_status("health model")
    if refused is not None:
        STATE["status"] = refused
        STATE["model"] = None
        return
    ckpt = os.environ.get("MODEL_PATH",
                          str(ROOT / "models/health_model/checkpoints/best_health_model.pt"))
    m = HealthModel()
    status = load_model_checkpoint(m, ckpt, "health model")
    if status["loaded"] and not status["random_weights"]:
        logger.info(f"Loaded health model from {status['source']}:{status['checkpoint']} ({m.param_count():,} params)")
    STATE["status"] = status
    m.eval()
    STATE["model"] = m
    conf_path = str(Path(ckpt).parent / "health_conformal.json")
    STATE["conformal"] = ConformalRegressor.load(conf_path) if os.path.exists(conf_path) \
        else ConformalRegressor()
    logger.info("Health Model Server ready")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_model()
    yield


app = FastAPI(title="KubeHeal Health Model", version="4.0.0", lifespan=lifespan)
add_metrics_route(app, METRICS)
add_inflight_middleware(app, METRICS, ["/health/score"])


@app.get("/health")
def health():
    return health_payload(STATE["status"])


@app.post("/health/score")
def score(req: ScoreRequest):
    require_ready(STATE["status"])
    t0 = time.time()
    model = STATE["model"]
    graph = yaml_diff_to_graph(req.old_spec or {}, req.new_spec or {})
    metrics = np.asarray(req.metrics if req.metrics is not None
                         else np.zeros((60, 15)), dtype=np.float32)
    mt = torch.tensor(metrics, dtype=torch.float32)

    with torch.no_grad():
        out = model(graph, mt)
    METRICS.observe_model_latency("health", time.time() - t0)
    risk = float(out["risk_score"].reshape(-1)[0])
    probs = torch.softmax(out["label_logits"], dim=-1)[0]
    idx = int(torch.argmax(probs).item())
    label = HEALTH_LABELS[idx]

    # field attributions from GAT node importance → K8s field paths
    node_imp = {i: float(v) for i, v in enumerate(out["node_importance"].tolist())}
    field_attr = STATE["mapper"].map_node_attributions_to_fields(node_imp, graph.field_paths)
    top_field = next(iter(field_attr), "unknown")
    metric_attr = STATE["shap"].explain_metrics(metrics)
    top_metric = max(metric_attr, key=metric_attr.get) if metric_attr else "unknown"

    ci_width = float(1.0 - float(probs.max()))   # per-sample confidence uncertainty
    lo, hi, width = STATE["conformal"].interval(risk, ci_width)
    return {
        "risk_score": risk,
        "label": label,
        "label_probabilities": {l: float(probs[i]) for i, l in enumerate(HEALTH_LABELS)},
        "ci_lower": lo, "ci_upper": hi, "ci_width": width,
        "conformal_q": STATE["conformal"].q,
        "field_attention_weights": field_attr,
        "top_field": top_field,
        "top_metric": top_metric,
        "health_embedding": out["health_embedding"][0].tolist(),
        "inference_latency_ms": round((time.time() - t0) * 1000, 2),
        "request_id": req.request_id,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))
