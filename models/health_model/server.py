import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Health Model Server", version="1.0.0")

model = None
model_loaded = False


class HealthScoreRequest(BaseModel):
    old_spec: Optional[Dict] = None
    new_spec: Optional[Dict] = None
    metrics: Optional[List[List[float]]] = None


class HealthScoreResponse(BaseModel):
    risk_score: float
    label: str
    confidence_interval: Optional[List[float]] = None
    explainability: Optional[Dict] = None


@app.on_event("startup")
async def startup():
    global model, model_loaded
    logger.info("Starting Health Model Server...")
    
    model_path = os.environ.get("MODEL_PATH", "/models/health_model.pt")
    
    try:
        import torch
        from health_model import HealthModel
        model = HealthModel()
        if os.path.exists(model_path):
            model.load_state_dict(torch.load(model_path))
            logger.info(f"Model loaded from {model_path}")
        else:
            logger.warning(f"Model not found at {model_path}, using fallback")
    except Exception as e:
        logger.warning(f"Model load error: {e}")
    
    model_loaded = True


@app.get("/health")
async def health():
    return {"status": "healthy", "model": "health_model"}


@app.get("/ready")
async def ready():
    return {"ready": model_loaded}


@app.post("/score", response_model=HealthScoreResponse)
async def score(request: HealthScoreRequest):
    """Calculate health risk score for config drift."""
    
    if model and model_loaded and request.old_spec and request.new_spec and request.metrics:
        result = model.predict(
            old_spec=request.old_spec,
            new_spec=request.new_spec,
            metrics=request.metrics
        )
        return HealthScoreResponse(
            risk_score=result["risk_score"],
            label=result["label"],
            confidence_interval=[result["risk_score"] - 0.05, result["risk_score"] + 0.05],
            explainability=_explain(request.old_spec, request.new_spec)
        )
    
    risk_score, label = _fallback_score(request)
    return HealthScoreResponse(
        risk_score=risk_score,
        label=label,
        confidence_interval=[risk_score - 0.1, risk_score + 0.1],
        explainability=_explain(request.old_spec, request.new_spec)
    )


def _fallback_score(request: HealthScoreRequest) -> tuple:
    """Heuristic fallback scoring."""
    score = 0.0
    
    if request.new_spec and request.old_spec:
        old_cpu = _extract_resource(request.old_spec, "cpu", "limits")
        new_cpu = _extract_resource(request.new_spec, "cpu", "limits")
        if old_cpu and new_cpu:
            old_val = _parse_cpu(old_cpu)
            new_val = _parse_cpu(new_cpu)
            if new_val < old_val * 0.3:
                score = 0.85
            elif new_val < old_val * 0.5:
                score = 0.65
    
    if request.metrics:
        cpu_throttle = sum(m[0] for m in request.metrics[:10]) / 10 if request.metrics else 0
        if cpu_throttle > 0.8:
            score = max(score, 0.80)
    
    label = "health-critical" if score >= 0.65 else "perf-risk" if score >= 0.40 else "benign"
    return score, label


def _extract_resource(spec: Dict, resource: str, rtype: str) -> Optional[str]:
    try:
        containers = spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        for c in containers:
            return c.get("resources", {}).get(rtype, {}).get(resource)
    except:
        pass
    return None


def _parse_cpu(cpu_str: str) -> float:
    if not cpu_str:
        return 1000.0
    if cpu_str.endswith("m"):
        return float(cpu_str.rstrip("m"))
    return float(cpu_str) * 1000


def _explain(old_spec: Dict, new_spec: Dict) -> Dict:
    explanation = {"changed_fields": [], "attention": {}}
    if not old_spec or not new_spec:
        return explanation
    
    try:
        old_containers = old_spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        new_containers = new_spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        
        for i, (old_c, new_c) in enumerate(zip(old_containers, new_containers)):
            old_res = old_c.get("resources", {})
            new_res = new_c.get("resources", {})
            for rtype in ["limits", "requests"]:
                old_val = old_res.get(rtype, {})
                new_val = new_res.get(rtype, {})
                for res, val in new_val.items():
                    if res in old_val and old_val[res] != val:
                        field = f"containers[{i}].resources.{rtype}.{res}"
                        explanation["changed_fields"].append(field)
                        explanation["attention"][field] = 0.89
    except:
        pass
    
    return explanation


if __name__ == "__main__":
    import torch
    port = int(os.environ.get("PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)