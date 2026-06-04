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

app = FastAPI(title="Security Model Server", version="1.0.0")

model = None
model_loaded = False


class SecurityScoreRequest(BaseModel):
    syscalls: Optional[List[Dict]] = None
    entropy_series: Optional[List[float]] = None
    file_patterns: Optional[List[float]] = None


class SecurityScoreResponse(BaseModel):
    risk_score: float
    label: str
    confidence_interval: Optional[List[float]] = None
    explainability: Optional[Dict] = None


@app.on_event("startup")
async def startup():
    global model, model_loaded
    logger.info("Starting Security Model Server...")
    
    model_path = os.environ.get("MODEL_PATH", "/models/security_model.pt")
    
    try:
        import torch
        from security_model import SecurityModel
        model = SecurityModel()
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
    return {"status": "healthy", "model": "security_model"}


@app.get("/ready")
async def ready():
    return {"ready": model_loaded}


@app.post("/score", response_model=SecurityScoreResponse)
async def score(request: SecurityScoreRequest):
    """Calculate security risk score for ransomware detection."""
    
    if model and model_loaded and (request.syscalls or request.entropy_series):
        result = model.predict(
            syscalls=request.syscalls,
            entropy_series=request.entropy_series,
            file_patterns=request.file_patterns
        )
        return SecurityScoreResponse(
            risk_score=result["risk_score"],
            label=result["label"],
            confidence_interval=[result["risk_score"] - 0.05, result["risk_score"] + 0.05],
            explainability=_explain(request.syscalls, request.entropy_series)
        )
    
    risk_score, label = _fallback_score(request)
    return SecurityScoreResponse(
        risk_score=risk_score,
        label=label,
        confidence_interval=[risk_score - 0.1, risk_score + 0.1],
        explainability=_explain(request.syscalls, request.entropy_series)
    )


def _fallback_score(request: SecurityScoreRequest) -> tuple:
    """Heuristic fallback scoring."""
    score = 0.0
    
    if request.entropy_series and len(request.entropy_series) > 0:
        avg_entropy = sum(request.entropy_series) / len(request.entropy_series)
        if avg_entropy > 7.2:
            score = 0.93
        elif avg_entropy > 6.0:
            score = 0.70
        elif avg_entropy > 5.0:
            score = 0.50
    
    if request.syscalls:
        rename_count = sum(1 for s in request.syscalls if s.get("syscall") == "rename")
        write_count = sum(1 for s in request.syscalls if s.get("syscall") == "write")
        
        if rename_count > 10:
            score = max(score, 0.60)
        if write_count > 50:
            score = max(score, 0.70)
    
    if request.file_patterns and len(request.file_patterns) > 0:
        avg_pattern = sum(request.file_patterns) / len(request.file_patterns)
        if avg_pattern > 100:
            score = max(score, 0.75)
        elif avg_pattern > 50:
            score = max(score, 0.50)
    
    label = "ransomware-critical" if score >= 0.85 else "sec-medium" if score >= 0.40 else "benign"
    return score, label


def _explain(syscalls: Optional[List], entropy_series: Optional[List]) -> Dict:
    explanation = {"patterns": {}, "entropy_analysis": {}}
    
    if syscalls:
        syscall_counts = {}
        for call in syscalls:
            name = call.get("syscall", "unknown")
            syscall_counts[name] = syscall_counts.get(name, 0) + 1
        explanation["patterns"] = syscall_counts
    
    if entropy_series:
        avg = sum(entropy_series) / len(entropy_series)
        max_ent = max(entropy_series)
        explanation["entropy_analysis"] = {
            "max_entropy": max_ent,
            "avg_entropy": avg,
            "analysis": "encrypted" if max_ent > 7.2 else "suspicious" if max_ent > 6.0 else "normal"
        }
    
    return explanation


if __name__ == "__main__":
    import torch
    port = int(os.environ.get("PORT", "8002"))
    uvicorn.run(app, host="0.0.0.0", port=port)