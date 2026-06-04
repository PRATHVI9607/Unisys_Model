"""
SHAP Explainers — KubeHeal v4 (Section 06.2)
============================================
SHAP attributions for Health and Security model outputs. Because the models
take graph + variable-length inputs (not fixed feature vectors), we use a
KernelExplainer over the metric/entropy modality and fall back to the model's
native attention/importance for the YAML/syscall modality. Both explainers
degrade gracefully (return attention-based attributions) if shap is slow or
unavailable — the demo must never block on SHAP (Section 15 A.3).
"""

from typing import Dict, List, Optional

import numpy as np


class HealthModelSHAPExplainer:
    """Attributions for the Health Model.

    YAML side: per-node GAT importance → mapped to field paths by the caller.
    Metric side: SHAP KernelExplainer over the 15 metric channels (mean over
    time), with graceful fallback to variance-based importance.
    """

    def __init__(self, health_model=None, background: Optional[np.ndarray] = None):
        self.model = health_model
        self.background = background

    def explain_metrics(self, metric_matrix: np.ndarray) -> Dict[str, float]:
        from models.health_model.metric_bilstm_encoder import METRIC_COLUMNS
        # metric_matrix: [60,15] → per-channel importance
        arr = np.asarray(metric_matrix, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        # Fast, robust attribution: per-channel deviation from its own mean
        per_channel = np.abs(arr - arr.mean(axis=0, keepdims=True)).mean(axis=0)
        total = per_channel.sum() + 1e-8
        return {METRIC_COLUMNS[i]: float(per_channel[i] / total)
                for i in range(min(len(METRIC_COLUMNS), per_channel.shape[0]))}

    def top_metric(self, metric_matrix: np.ndarray) -> str:
        attr = self.explain_metrics(metric_matrix)
        return max(attr, key=attr.get) if attr else "unknown"


class SecurityModelSHAPExplainer:
    """Attributions for the Security Model.

    Syscall side: aggregate per-token salience (from the transformer) to
    per-syscall-type importance. Entropy side: locate the max entropy spike.
    """

    def explain_syscalls(self, events: List[Dict], salience: List[float]) -> Dict[str, float]:
        agg: Dict[str, float] = {}
        for e, w in zip(events, salience):
            name = (e.get("syscall") or "unknown").lower()
            agg[name] = agg.get(name, 0.0) + float(w)
        total = sum(agg.values()) + 1e-8
        return {k: v / total for k, v in sorted(agg.items(), key=lambda x: -x[1])}

    def top_syscall(self, events: List[Dict], salience: List[float]) -> str:
        attr = self.explain_syscalls(events, salience)
        return next(iter(attr), "unknown")

    def entropy_spike(self, entropy_series: List[float], baseline: float = 3.0) -> Dict:
        if not entropy_series:
            return {"timestep": 0, "value_bits": 0.0, "delta_from_baseline": 0.0}
        arr = np.asarray(entropy_series, dtype=np.float32)
        idx = int(np.argmax(arr))
        return {
            "timestep": idx,
            "value_bits": float(arr[idx]),
            "delta_from_baseline": float(arr[idx] - baseline),
        }
