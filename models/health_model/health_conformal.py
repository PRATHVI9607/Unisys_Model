"""
Conformal classifier wrapper — KubeHeal v4 (Section 10.2 step 4).
=================================================================
Split-conformal on the CLASSIFIER (not the risk regressor). On a held-out
calibration set we collect the nonconformity score s = 1 - p(true_class) and
take the (1-alpha) quantile q. q is the calibrated confidence threshold:
a test prediction whose own nonconformity (1 - max_prob) exceeds q is
"uncertain" and should be escalated to a human.

Why on the classifier, not on |risk_pred - risk_true|: a confident
misclassification produces a large risk residual no matter how the risk is
parameterised, so regression-conformal never tightens (ci_width → ~1.0). The
classifier nonconformity is bounded in [0,1], tightens as accuracy improves,
and is the quantity the Fusion CI-gate actually wants.
"""

import json
from typing import List

import numpy as np


class ConformalClassifier:
    def __init__(self, alpha: float = 0.10):
        self.alpha = alpha          # 1 - coverage (0.10 → 90% coverage)
        self.q = 0.5                # default threshold until calibrated

    def calibrate_scores(self, scores: List[float]) -> float:
        """scores = [1 - p(true_class)] over the calibration set."""
        s = np.asarray(scores, dtype=np.float64)
        n = len(s)
        if n == 0:
            return self.q
        level = min(1.0, np.ceil((n + 1) * (1 - self.alpha)) / n)
        self.q = float(np.quantile(s, level))
        return self.q

    @staticmethod
    def width_from_probs(probs) -> float:
        """Per-sample uncertainty = 1 - max softmax prob (bounded [0,1])."""
        return float(1.0 - max(probs))

    def interval(self, risk: float, ci_width: float):
        lo = max(0.0, risk - ci_width / 2)
        hi = min(1.0, risk + ci_width / 2)
        return lo, hi, ci_width

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"alpha": self.alpha, "q": self.q}, f)

    @classmethod
    def load(cls, path: str):
        with open(path) as f:
            d = json.load(f)
        c = cls(alpha=d.get("alpha", 0.10))
        c.q = d.get("q", 0.5)
        return c


# Back-compat alias (older imports referenced ConformalRegressor)
ConformalRegressor = ConformalClassifier
