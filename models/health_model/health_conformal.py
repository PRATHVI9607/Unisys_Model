"""
Conformal prediction wrapper for the Health Model (Section 10.2 step 4).
========================================================================
Split-conformal: on a held-out calibration set, collect nonconformity scores
|risk_pred - risk_true|, take the (1-alpha) quantile q. At inference the
prediction interval is [risk - q, risk + q]; ci_width = 2q is a calibrated
uncertainty used by the Fusion Agent's CI gate.
"""

import json
from typing import List

import numpy as np


class ConformalRegressor:
    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha          # 1 - coverage (0.05 → 95% coverage)
        self.q = 0.10               # default half-width until calibrated

    def calibrate(self, preds: List[float], targets: List[float]) -> float:
        scores = np.abs(np.asarray(preds) - np.asarray(targets))
        n = len(scores)
        if n == 0:
            return self.q
        # finite-sample-corrected quantile level
        level = min(1.0, np.ceil((n + 1) * (1 - self.alpha)) / n)
        self.q = float(np.quantile(scores, level))
        return self.q

    def interval(self, risk: float):
        lo = max(0.0, risk - self.q)
        hi = min(1.0, risk + self.q)
        return lo, hi, hi - lo

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"alpha": self.alpha, "q": self.q}, f)

    @classmethod
    def load(cls, path: str):
        with open(path) as f:
            d = json.load(f)
        c = cls(alpha=d.get("alpha", 0.05))
        c.q = d.get("q", 0.10)
        return c
