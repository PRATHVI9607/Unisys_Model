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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATE: Dict = {"model": None, "conformal": None, "mapper": FieldNameMapper(),
               "shap": HealthModelSHAPExplainer()}


class ScoreRequest(BaseModel):
    old_spec: Optional[Dict] = None
    new_spec: Optional[Dict] = None
    metrics: Optional[List[List[float]]] = None
    request_id: Optional[str] = None


def _load_model():
    ckpt = os.environ.get("MODEL_PATH",
                          str(ROOT / "models/health_model/checkpoints/best_health_model.pt"))
    m = HealthModel()
    if os.path.exists(ckpt):
        try:
            m.load_state_dict(torch.load(ckpt, map_location="cpu"))
            logger.info(f"Loaded health model from {ckpt} ({m.param_count():,} params)")
        except Exception as e:
            logger.error(f"Checkpoint load failed: {e} — random weights")
    else:
        logger.warning(f"No checkpoint at {ckpt} — random weights")
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


@app.get("/health")
def health():
    return {"status": "ok", "model_version": "v4.0.0", "model_loaded": STATE["model"] is not None}


@app.post("/health/score")
def score(req: ScoreRequest):
    t0 = time.time()
    model = STATE["model"]
    graph = yaml_diff_to_graph(req.old_spec or {}, req.new_spec or {})
    metrics = np.asarray(req.metrics if req.metrics is not None
                         else np.zeros((60, 15)), dtype=np.float32)
    mt = torch.tensor(metrics, dtype=torch.float32)

    with torch.no_grad():
        out = model(graph, mt)
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
        "field_attention_weights": field_attr,
        "top_field": top_field,
        "top_metric": top_metric,
        "health_embedding": out["health_embedding"][0].tolist(),
        "inference_latency_ms": round((time.time() - t0) * 1000, 2),
        "request_id": req.request_id,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))
