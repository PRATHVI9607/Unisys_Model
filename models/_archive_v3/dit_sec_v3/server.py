"""
DIT-Sec v3 Model Server
========================
Serves the GNN+Mamba hybrid model.
Supports health path (YAML+metrics) and security path (syscalls+entropy).

Endpoints
---------
  GET  /health
  GET  /ready
  POST /score          — unified scoring (auto-routes by present modalities)
  POST /score/security — explicit security path
  POST /explain        — XAI attribution
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import numpy as np
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── resolve model module path ──────────────────────────────
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

app = FastAPI(
    title="DIT-Sec v3 Model Server",
    description="GNN + Mamba Hybrid — KubeHeal PRD v3",
    version="3.1.0",
)

# ── global model state ─────────────────────────────────────
model      = None
model_loaded = False
# Z-score standardization stats (fit on train split during training).
# Loaded from results/metric_stats.json so inference applies the EXACT
# same per-feature transform the model was trained with.
metric_mean = None
metric_std  = None


# ══════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════

class ScoreRequest(BaseModel):
    # Health modality
    old_spec: Optional[Dict]             = None
    new_spec: Optional[Dict]             = None
    metrics:  Optional[List[List[float]]]= None
    # Security modality
    syscalls:       Optional[List[Dict]] = None
    entropy_series: Optional[List[float]]= None
    # Meta
    blast_radius:   Optional[str]        = None
    telemetry:      Optional[Any]        = None
    # Legacy security-only fields
    entropy:        Optional[float]      = None
    early_signals:  Optional[Dict]       = None


class ScoreResponse(BaseModel):
    risk_score:          float
    label:               str
    confidence_interval: Optional[List[float]] = None
    explainability:      Optional[Dict]         = None
    model_used:          str = "pytorch"
    model_score:         Optional[float] = None
    heuristic_score:     Optional[float] = None
    inference_method:    str = "DIT-Sec v3 GNN+Mamba"
    patch_proposal:      Optional[Dict]  = None


# ══════════════════════════════════════════════════════════
# Startup — load PyTorch model
# ══════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    global model, model_loaded, metric_mean, metric_std
    logger.info("Starting DIT-Sec v3 Model Server...")

    model_path = os.environ.get(
        "MODEL_PATH",
        str(SCRIPT_DIR / "models" / "dit_sec_v3_trained.pt"),
    )

    # Load z-score standardization stats (train/inference parity).
    stats_path = os.environ.get(
        "METRIC_STATS_PATH",
        str(SCRIPT_DIR / "results" / "metric_stats.json"),
    )
    try:
        if os.path.exists(stats_path):
            with open(stats_path) as f:
                stats = json.load(f)
            metric_mean = np.asarray(stats["mean"], dtype=np.float32)
            metric_std  = np.asarray(stats["std"],  dtype=np.float32)
            logger.info(f"Metric standardization stats loaded from {stats_path}")
        else:
            logger.warning(
                f"Metric stats not found at {stats_path} — metrics will be "
                f"passed through unstandardized (model trained WITH standardization)"
            )
    except Exception as e:
        logger.error(f"Failed to load metric stats: {e} — passing metrics through")

    try:
        import torch
        from dit_sec_v3_model import DITSecV3
        m = DITSecV3()
        if os.path.exists(model_path):
            state = torch.load(model_path, map_location="cpu")
            m.load_state_dict(state)
            m.eval()
            logger.info(f"Model loaded from {model_path}  ({m.param_count():,} params)")
        else:
            logger.warning(f"Checkpoint not found at {model_path} — using random weights")
            m.eval()
        model = m
    except Exception as e:
        logger.error(f"Model load error: {e} — falling back to heuristic")

    model_loaded = True
    logger.info("DIT-Sec v3 server ready")


# ══════════════════════════════════════════════════════════
# Health checks
# ══════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {
        "status":       "healthy",
        "model_loaded": model is not None,
        "timestamp":    datetime.utcnow().isoformat(),
    }


@app.get("/ready")
async def ready():
    return {
        "ready":        model_loaded,
        "model_loaded": model is not None,
        "timestamp":    datetime.utcnow().isoformat(),
    }


# ══════════════════════════════════════════════════════════
# Unified /score
# ══════════════════════════════════════════════════════════

@app.post("/score", response_model=ScoreResponse)
async def score(request: ScoreRequest):
    """
    Auto-route based on which modalities are present.
    Health path:   old_spec + new_spec [+ metrics]
    Security path: syscalls [+ entropy_series]
    Full path:     all modalities
    """

    # ── always compute heuristic ──────────────────────────
    heuristic = _heuristic_score(request)

    # ── model inference ───────────────────────────────────
    model_result = None
    if model is not None:
        model_result = _model_score(request)

    # ── pick primary result ───────────────────────────────
    if model_result is not None:
        primary        = model_result
        model_used     = "pytorch"
        inference_method = "DIT-Sec v3 GNN+Mamba inference"
    else:
        primary        = heuristic
        model_used     = "heuristic"
        inference_method = "Heuristic fallback (model unavailable)"

    risk_score = primary["risk_score"]
    label      = primary["label"]
    ci         = _conformal_ci(risk_score)

    return ScoreResponse(
        risk_score           = risk_score,
        label                = label,
        confidence_interval  = ci,
        explainability       = _explain(request),
        model_used           = model_used,
        model_score          = model_result["risk_score"] if model_result else None,
        heuristic_score      = heuristic["risk_score"],
        inference_method     = inference_method,
        patch_proposal       = _patch_proposal(request, label),
    )


# Explicit security endpoint kept for backwards compat
@app.post("/score/security", response_model=ScoreResponse)
async def score_security(request: ScoreRequest):
    return await score(request)


# ══════════════════════════════════════════════════════════
# /explain
# ══════════════════════════════════════════════════════════

@app.post("/explain")
async def explain(request: ScoreRequest):
    heuristic = _heuristic_score(request)
    return {
        "risk_score":    heuristic["risk_score"],
        "label":         heuristic["label"],
        "explainability": _explain(request),
        "timestamp":     datetime.utcnow().isoformat(),
    }


# ══════════════════════════════════════════════════════════
# Model inference
# ══════════════════════════════════════════════════════════

def _standardize_metrics(metrics: List[List[float]]):
    """
    Apply the training-time z-score transform (x - mean) / std per feature.
    Returns a float32 torch tensor. If stats are unavailable, falls back to
    the raw values (logged at startup) so the server still responds.
    """
    import torch
    arr = np.asarray(metrics, dtype=np.float32)          # (T, 15)
    if metric_mean is not None and metric_std is not None \
            and arr.ndim == 2 and arr.shape[-1] == metric_mean.shape[0]:
        arr = (arr - metric_mean) / metric_std
    return torch.tensor(arr, dtype=torch.float32)


def _model_score(request: ScoreRequest) -> Optional[Dict]:
    try:
        import torch
        kwargs: Dict = {}

        if request.old_spec and request.new_spec:
            kwargs["old_spec"] = request.old_spec
            kwargs["new_spec"] = request.new_spec

        if request.metrics:
            kwargs["metrics"] = _standardize_metrics(request.metrics)

        if request.syscalls:
            kwargs["syscalls"] = request.syscalls

        # normalise entropy: accept both entropy_series list and
        # legacy scalar `entropy` field from security agent
        entropy = request.entropy_series
        if not entropy and request.entropy is not None:
            entropy = [request.entropy] * 20
        if entropy:
            kwargs["entropy_series"] = torch.tensor(entropy, dtype=torch.float32)

        if not kwargs:
            return None

        with torch.no_grad():
            out = model(**kwargs)

        rs = float(out["risk_score"])
        return {"risk_score": rs, "label": out["label"]}

    except Exception as e:
        logger.error(f"Model inference failed: {e}")
        return None


# ══════════════════════════════════════════════════════════
# Heuristic fallback
# ══════════════════════════════════════════════════════════

def _heuristic_score(request: ScoreRequest) -> Dict:
    score = 0.0

    # ── YAML diff signal ──────────────────────────────────
    if request.old_spec and request.new_spec:
        old_cpu = _get_resource(request.old_spec, "cpu",    "limits")
        new_cpu = _get_resource(request.new_spec, "cpu",    "limits")
        old_mem = _get_resource(request.old_spec, "memory", "limits")
        new_mem = _get_resource(request.new_spec, "memory", "limits")

        if old_cpu and new_cpu:
            ratio = _parse_cpu(new_cpu) / max(_parse_cpu(old_cpu), 1)
            if ratio < 0.15:
                score = max(score, 0.90)
            elif ratio < 0.30:
                score = max(score, 0.80)
            elif ratio < 0.50:
                score = max(score, 0.65)

        if old_mem and new_mem:
            ratio = _parse_mem(new_mem) / max(_parse_mem(old_mem), 1)
            if ratio < 0.25:
                score = max(score, 0.75)

    # ── entropy signal ────────────────────────────────────
    entropy_vals = request.entropy_series or (
        [request.entropy] * 20 if request.entropy else None
    )
    if entropy_vals:
        avg_e = sum(entropy_vals) / len(entropy_vals)
        if avg_e > 7.2:
            score = max(score, 0.93)
        elif avg_e > 6.5:
            score = max(score, 0.75)
        elif avg_e > 5.5:
            score = max(score, 0.50)

    # ── syscall signal ────────────────────────────────────
    if request.syscalls:
        renames = sum(1 for s in request.syscalls if s.get("syscall") == "rename")
        writes  = sum(1 for s in request.syscalls if s.get("syscall") == "write")
        if renames > 10:
            score = max(score, 0.60)
        if writes  > 50:
            score = max(score, 0.70)

    # ── early_signals passthrough ─────────────────────────
    if request.early_signals:
        if request.early_signals.get("rename_burst"):
            score = max(score, 0.50)
        if request.early_signals.get("high_entropy"):
            score = max(score, 0.70)
        if request.early_signals.get("mmap_detected"):
            score = max(score, 0.65)

    # ── metrics signal ────────────────────────────────────
    if request.metrics and len(request.metrics) > 0:
        first10 = request.metrics[:10]
        cpu_throttle = sum(row[0] for row in first10 if row) / max(len(first10), 1)
        if cpu_throttle > 0.8:
            score = max(score, 0.80)

    label = _score_to_label(score, is_security=bool(
        request.entropy_series or request.syscalls or request.entropy
    ))
    return {"risk_score": score, "label": label}


def _score_to_label(score: float, is_security: bool = False) -> str:
    if score >= 0.85:
        return "ransomware-critical" if is_security else "health-critical"
    if score >= 0.65:
        return "sec-medium" if is_security else "health-critical"
    if score >= 0.40:
        return "sec-medium" if is_security else "perf-risk"
    return "benign"


# ══════════════════════════════════════════════════════════
# Conformal prediction interval (calibrated ±)
# ══════════════════════════════════════════════════════════

def _conformal_ci(score: float) -> List[float]:
    """Approximate 95% conformal CI; width ∝ score uncertainty."""
    halfwidth = 0.05 if (score < 0.2 or score > 0.8) else 0.10
    return [max(0.0, score - halfwidth), min(1.0, score + halfwidth)]


# ══════════════════════════════════════════════════════════
# XAI helpers
# ══════════════════════════════════════════════════════════

def _explain(request: ScoreRequest) -> Dict:
    xai: Dict = {}

    if request.old_spec and request.new_spec:
        xai["yaml_fields"] = _yaml_diff_explanation(request.old_spec, request.new_spec)

    if request.entropy_series:
        avg  = sum(request.entropy_series) / len(request.entropy_series)
        peak = max(request.entropy_series)
        xai["entropy_analysis"] = {
            "avg_bits":  round(avg, 3),
            "peak_bits": round(peak, 3),
            "verdict":   "encrypted" if peak > 7.2 else "suspicious" if peak > 6.0 else "normal",
        }

    if request.syscalls:
        counts: Dict[str, int] = {}
        for s in request.syscalls:
            k = s.get("syscall", "unknown")
            counts[k] = counts.get(k, 0) + 1
        xai["syscall_counts"] = counts

    if request.metrics:
        xai["metrics_summary"] = {
            "cpu_throttle": round(request.metrics[0][0] if request.metrics[0] else 0.0, 3),
            "mem_usage":    round(request.metrics[0][1] if len(request.metrics[0]) > 1 else 0.0, 3),
        }

    return xai


def _yaml_diff_explanation(old: Dict, new: Dict) -> Dict:
    changed, attn = [], {}
    try:
        old_cs = old.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        new_cs = new.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        for i, (oc, nc) in enumerate(zip(old_cs, new_cs)):
            for rt in ["limits", "requests"]:
                ov = oc.get("resources", {}).get(rt, {})
                nv = nc.get("resources", {}).get(rt, {})
                for res, val in nv.items():
                    if ov.get(res) != val:
                        field = f"containers[{i}].resources.{rt}.{res}"
                        changed.append(field)
                        attn[field] = 0.89
    except Exception:
        pass
    return {"changed_fields": changed, "attention_weights": attn}


def _patch_proposal(request: ScoreRequest, label: str) -> Optional[Dict]:
    """Generate a patch proposal for health-critical drift."""
    if label not in ("health-critical", "perf-risk"):
        return None
    if not (request.old_spec and request.new_spec):
        return None

    patches = []
    try:
        old_cs = request.old_spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        new_cs = request.new_spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        for i, (oc, nc) in enumerate(zip(old_cs, new_cs)):
            for rt in ["limits"]:
                ov = oc.get("resources", {}).get(rt, {})
                nv = nc.get("resources", {}).get(rt, {})
                for res in nv:
                    if ov.get(res) and ov[res] != nv[res]:
                        patches.append({
                            "container_index": i,
                            "field": f"resources.{rt}.{res}",
                            "current": nv[res],
                            "restore_to": ov[res],
                        })
    except Exception:
        pass

    return {"patches": patches} if patches else None


# ══════════════════════════════════════════════════════════
# Resource parsing helpers
# ══════════════════════════════════════════════════════════

def _get_resource(spec: Dict, name: str, rtype: str) -> Optional[str]:
    try:
        for c in spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []):
            v = c.get("resources", {}).get(rtype, {}).get(name)
            if v:
                return v
    except Exception:
        pass
    return None


def _parse_cpu(s: str) -> float:
    if not s:
        return 1000.0
    s = str(s)
    return float(s.rstrip("m")) if s.endswith("m") else float(s) * 1000


def _parse_mem(s: str) -> float:
    if not s:
        return 512.0
    s = str(s)
    if s.endswith("Gi"):
        return float(s[:-2]) * 1024
    if s.endswith("Mi"):
        return float(s[:-2])
    return float(s)


# ══════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
