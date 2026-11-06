"""Split-conformal prediction sets with the 1 - p(true class) score."""

from __future__ import annotations

import math

import numpy as np


def calibrate(probs: np.ndarray, y: np.ndarray, alpha: float) -> float:
    """Threshold q such that {c : 1 - p_c <= q} covers the true label w.p. >= 1 - alpha."""
    scores = np.sort(1.0 - probs[np.arange(len(y)), y])
    k = math.ceil((len(scores) + 1) * (1 - alpha))   # finite-sample rank: the k-th smallest score
    if k > len(scores):   # too few calibration points for this alpha: every label is in the set
        return 1.0
    return float(scores[k - 1])


def prediction_sets(probs: np.ndarray, q: float) -> np.ndarray:
    """Boolean mask (n, k): class c is in row i's set."""
    return (1.0 - probs) <= q
