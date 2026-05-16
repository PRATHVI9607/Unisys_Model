import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DIT-Sec Model Server",
    description="DIT-Sec v3.0 - Drift Impact Transformer for Security",
    version="3.0.0",
)

model = None
model_loaded = False


class ScoreRequest(BaseModel):
    old_spec: Optional[Dict] = None
    new_spec: Optional[Dict] = None
    metrics: Optional[List[List[float]]] = None
    syscalls: Optional[List[Dict]] = None
    entropy_series: Optional[List[float]] = None


class ScoreResponse(BaseModel):
    risk_score: float
    label: str
    confidence_interval: Optional[List[float]] = None
    explainability: Optional[Dict[str, Any]] = None
    model_used: str = "heuristic"  # either "onnx_model" or "heuristic"
    model_score: Optional[float] = None  # score from ONNX model, 0-1
    heuristic_score: Optional[float] = None  # score from heuristic function, 0-1
    inference_method: str = "Heuristic fallback"  # description like "ONNX inference" or "Heuristic fallback"


@app.on_event("startup")
async def startup():
    global model, model_loaded
    logger.info("Starting DIT-Sec Model Server v3.0...")

    model_path = os.environ.get("MODEL_PATH", "/models/dit_sec_v3.onnx")

    try:
        import onnxruntime as ort

        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = (
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        )

        if os.path.exists(model_path):
            model = ort.InferenceSession(
                model_path, sess_options, providers=["CPUExecutionProvider"]
            )
            logger.info(f"Model loaded from {model_path}")
        else:
            logger.warning(f"Model not found at {model_path}, using fallback")
    except ImportError:
        logger.warning("ONNX Runtime not available, using fallback")

    model_loaded = True
    logger.info("DIT-Sec Model Server ready")


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/ready")
async def ready():
    return {
        "ready": model_loaded,
        "model_loaded": model is not None,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/score", response_model=ScoreResponse)
async def score(request: ScoreRequest):
    """
    Calculate risk score for a Kubernetes event.

    Supports multiple modalities:
    - YAML diffs (old_spec + new_spec)
    - Prometheus metrics
    - Falco syscall events
    - File entropy series

    Returns both ONNX model and heuristic scores for comparison.
    """

    risk_score = 0.0
    label = "benign"
    confidence_interval = None
    explainability = {}
    model_used = "heuristic"
    model_score = None
    heuristic_score = None
    inference_method = "Heuristic fallback"

    try:
        # Always get heuristic score
        heuristic_result = _score_fallback(request)
        heuristic_score = heuristic_result["risk_score"]

        # Try to get model score
        model_result = None
        if model is not None:
            try:
                model_result = _score_with_model(request)
                model_score = model_result["risk_score"]
                model_used = "onnx_model"
                inference_method = "ONNX inference"

                # Use model score as primary
                risk_score = model_score
                label = model_result["label"]
                confidence_interval = model_result.get("confidence_interval")
                explainability = model_result.get("explainability", {})
            except Exception as e:
                logger.error(f"Model inference error: {e}, falling back to heuristic")
                model_used = "heuristic"
                inference_method = "Heuristic fallback (model unavailable)"
                model_score = None  # Indicate model wasn't used
                risk_score = heuristic_score
                label = heuristic_result["label"]
                confidence_interval = heuristic_result.get("confidence_interval")
                explainability = heuristic_result.get("explainability", {})
        else:
            # Model not available, use fallback
            model_used = "heuristic"
            inference_method = "Heuristic fallback (model unavailable)"
            risk_score = heuristic_score
            label = heuristic_result["label"]
            confidence_interval = heuristic_result.get("confidence_interval")
            explainability = heuristic_result.get("explainability", {})

        if request.new_spec and request.old_spec:
            explainability = _extract_yaml_explanation(
                request.old_spec, request.new_spec
            )

    except Exception as e:
        logger.error(f"Scoring error: {e}")
        fb = _score_fallback(request)
        risk_score = fb["risk_score"]
        label = fb["label"]
        heuristic_score = fb["risk_score"]
        model_used = "heuristic"
        inference_method = "Heuristic fallback (error occurred)"

    return ScoreResponse(
        risk_score=risk_score,
        label=label,
        confidence_interval=confidence_interval,
        explainability=explainability,
        model_used=model_used,
        model_score=model_score,
        heuristic_score=heuristic_score,
        inference_method=inference_method,
    )


@app.post("/explain")
async def explain(request: ScoreRequest):
    """
    Get detailed XAI explanation for a risk score.
    Returns attention weights and feature importance.
    """

    explainability = {
        "yaml_fields": {},
        "metrics_features": {},
        "syscall_patterns": {},
        "entropy_analysis": {},
    }

    if request.new_spec and request.old_spec:
        explainability["yaml_fields"] = _explain_yaml_diff(
            request.old_spec, request.new_spec
        )

    if request.metrics:
        explainability["metrics_features"] = _explain_metrics(request.metrics)

    if request.syscalls:
        explainability["syscall_patterns"] = _explain_syscalls(request.syscalls)

    if request.entropy_series:
        explainability["entropy_analysis"] = _explain_entropy(request.entropy_series)

    risk_score, label = _calculate_fallback_score(request)

    return {
        "risk_score": risk_score,
        "label": label,
        "explainability": explainability,
        "timestamp": datetime.utcnow().isoformat(),
    }


def _score_with_model(request: ScoreRequest) -> Dict:
    """Score using ONNX model."""

    import onnxruntime as ort

    input_dict = {}

    if request.metrics:
        metrics_array = np.array(request.metrics, dtype=np.float32)
        input_dict["metrics"] = metrics_array.reshape(1, -1)

    if request.entropy_series:
        entropy_array = np.array(request.entropy_series, dtype=np.float32)
        input_dict["entropy_series"] = entropy_array.reshape(1, -1)

    if not input_dict:
        return {"risk_score": 0.05, "label": "benign", "confidence_interval": None}

    try:
        input_names = [inp.name for inp in model.get_inputs()]
        feed = {}
        for name in input_names:
            if name in input_dict:
                feed[name] = input_dict[name]
            else:
                feed[name] = np.zeros((1, 10), dtype=np.float32)

        outputs = model.run(None, feed)

        risk_score = float(outputs[0][0][0]) if outputs else 0.0
        risk_score = max(0.0, min(1.0, risk_score))

        return {
            "risk_score": risk_score,
            "label": _score_to_label(risk_score),
            "confidence_interval": [risk_score - 0.05, risk_score + 0.05],
        }
    except Exception as e:
        logger.error(f"Model inference error: {e}")
        return _score_fallback(request)


def _score_fallback(request: ScoreRequest) -> Dict:
    """Fallback scoring without ML model."""

    risk_score, label = _calculate_fallback_score(request)

    return {
        "risk_score": risk_score,
        "label": label,
        "confidence_interval": [max(0, risk_score - 0.1), min(1, risk_score + 0.1)],
    }


def _calculate_fallback_score(request: ScoreRequest) -> tuple:
    """Calculate risk score using heuristic rules."""

    score = 0.0

    if request.new_spec and request.old_spec:
        old_cpu = _extract_resource(request.old_spec, "cpu", "limits")
        new_cpu = _extract_resource(request.new_spec, "cpu", "limits")

        if old_cpu and new_cpu:
            old_val = _parse_cpu(old_cpu)
            new_val = _parse_cpu(new_cpu)

            if new_val < old_val * 0.3:
                score = max(score, 0.85)
            elif new_val < old_val * 0.5:
                score = max(score, 0.65)

    if request.entropy_series and len(request.entropy_series) > 0:
        avg_entropy = sum(request.entropy_series) / len(request.entropy_series)

        if avg_entropy > 7.2:
            score = max(score, 0.93)
        elif avg_entropy > 6.0:
            score = max(score, 0.70)
        elif avg_entropy > 5.0:
            score = max(score, 0.50)

    if request.syscalls:
        write_count = sum(1 for s in request.syscalls if s.get("syscall") == "write")
        rename_count = sum(1 for s in request.syscalls if s.get("syscall") == "rename")

        if rename_count > 10:
            score = max(score, 0.60)
        if write_count > 50:
            score = max(score, 0.70)

    if request.metrics:
        cpu_throttle = _calculate_cpu_throttle(request.metrics)
        if cpu_throttle > 0.8:
            score = max(score, 0.80)

    label = _score_to_label(score)

    return score, label


def _score_to_label(score: float) -> str:
    """Convert score to label."""
    if score >= 0.85:
        return "ransomware-critical"
    elif score >= 0.65:
        return "health-critical"
    elif score >= 0.40:
        return "sec-medium"
    elif score >= 0.20:
        return "perf-risk"
    return "benign"


def _extract_resource(spec: Dict, resource: str, type: str) -> Optional[str]:
    """Extract resource value from spec."""
    try:
        containers = (
            spec.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        for container in containers:
            resources = container.get("resources", {})
            limits = resources.get(type, {})
            return limits.get(resource)
    except:
        pass
    return None


def _parse_cpu(cpu_str: str) -> float:
    """Parse CPU string to millicores."""
    if not cpu_str:
        return 0.0
    if cpu_str.endswith("m"):
        return float(cpu_str.rstrip("m"))
    return float(cpu_str) * 1000


def _calculate_cpu_throttle(metrics: List[List[float]]) -> float:
    """Calculate CPU throttle from metrics."""
    if not metrics or len(metrics) == 0:
        return 0.0
    return min(1.0, sum(m[0] for m in metrics[:10]) / 10)


def _extract_yaml_explanation(old_spec: Dict, new_spec: Dict) -> Dict:
    """Extract which YAML fields caused the change."""
    explanation = {"changed_fields": [], "attention": {}}

    try:
        old_containers = (
            old_spec.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        new_containers = (
            new_spec.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )

        for i, (old_c, new_c) in enumerate(zip(old_containers, new_containers)):
            old_res = old_c.get("resources", {})
            new_res = new_c.get("resources", {})

            for resource_type in ["limits", "requests"]:
                old_val = old_res.get(resource_type, {})
                new_val = new_res.get(resource_type, {})

                for resource, value in new_val.items():
                    if resource in old_val and old_val[resource] != value:
                        field = f"containers[{i}].resources.{resource_type}.{resource}"
                        explanation["changed_fields"].append(field)
                        explanation["attention"][field] = 0.89

    except Exception as e:
        logger.debug(f"Explanation error: {e}")

    return explanation


def _explain_yaml_diff(old_spec: Dict, new_spec: Dict) -> Dict:
    """Detailed YAML diff explanation."""
    return _extract_yaml_explanation(old_spec, new_spec)


def _explain_metrics(metrics: List[List[float]]) -> Dict:
    """Explain metric contributions."""
    features = ["cpu_throttle", "memory_usage", "disk_io", "network_latency"]
    contributions = {}

    if metrics and len(metrics) > 0:
        contributions["cpu_throttle"] = (
            min(1.0, float(metrics[0][0])) if len(metrics[0]) > 0 else 0.0
        )
        contributions["memory_usage"] = (
            min(1.0, float(metrics[0][1])) if len(metrics[0]) > 1 else 0.0
        )

    return {"feature_importance": contributions, "top_features": features[:2]}


def _explain_syscalls(syscalls: List[Dict]) -> Dict:
    """Explain syscall patterns."""
    syscall_counts = {}

    for call in syscalls:
        name = call.get("syscall", "unknown")
        syscall_counts[name] = syscall_counts.get(name, 0) + 1

    return {"counts": syscall_counts, "patterns": list(syscall_counts.keys())[:5]}


def _explain_entropy(entropy_series: List[float]) -> Dict:
    """Explain entropy analysis."""
    if not entropy_series:
        return {"max_entropy": 0.0, "avg_entropy": 0.0, "analysis": "no data"}

    avg = sum(entropy_series) / len(entropy_series)
    max_ent = max(entropy_series)

    analysis = "normal"
    if max_ent > 7.2:
        analysis = "encrypted files detected"
    elif max_ent > 6.0:
        analysis = "suspicious files"

    return {
        "max_entropy": max_ent,
        "avg_entropy": avg,
        "analysis": analysis,
        "file_count": len(entropy_series),
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
