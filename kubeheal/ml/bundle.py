"""A trained model on disk: LightGBM `model.txt` + `meta.json`.

meta.json keys: task, version, labels, class_risk, features, alpha, conformal_q,
metrics, data {source, rows, groups, synthetic, sha256}, created_at.
"""

from __future__ import annotations

import io
import json
import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np

from kubeheal.contracts import Factor, Prediction
from kubeheal.features.health import METRIC_FEATURES
from kubeheal.ml.conformal import prediction_sets

log = logging.getLogger(__name__)
TOP_FACTORS = 5
# Features the live agents can send as None (kubeheal/features/*). LightGBM scores a NaN as 0 on a split whose
# missing_type is not NaN (the feature had no NaN in training): cpu_limit_ratio=None (a Deployment without limits)
# then reads as "limit cut to 0". Health: resource ratios (no limits/requests), replicas_ratio (from 0), every metric.
LIVE_NONE: dict[str, list[str]] = {
    "health": ["cpu_limit_ratio", "cpu_request_ratio", "mem_limit_ratio", "mem_request_ratio", "replicas_ratio",
               *METRIC_FEATURES],
    "security": ["frac_rename_suffix_added", "frac_rename_temp_replace", "frac_rename_rotate", "rename_ext_added_ratio",
                 "suspicious_ext_ratio", "entropy_mean", "entropy_max", "entropy_p90", "entropy_high_frac",
                 "entropy_slope", "write_bytes_per_s", "net_out_bytes_per_s", "recent_frac_rename_suffix_added",
                 "recent_frac_rename_temp_replace", "recent_ext_added_frac", "recent_entropy_mean",
                 "recent_entropy_high_frac"],
}


def nan_blind(model: lgb.Booster | Path, features: list[str]) -> list[str]:
    """Of `features`, those some split reads with missing_type != NaN, i.e. scores a None as 0.

    Parses the model text, not dump_model(): the dict of a 2000-round 4-class model is several hundred MB
    and OOMKilled the inference pod at load. decision_type bits 2-3 are the missing type (2 = NaN).
    """
    names: list[str] = []
    bad: set[str] = set()
    split: list[str] = []
    # a model.txt path is read line by line (load time, no copy); a Booster is serialised (train time)
    src = open(model) if isinstance(model, Path) else io.StringIO(model.model_to_string())
    for line in src:
        line = line.rstrip("\n")
        if line.startswith("feature_names="):
            names = line[len("feature_names="):].split()
        elif line.startswith("split_feature="):
            split = line[len("split_feature="):].split()
        elif line.startswith("decision_type="):
            bad.update(names[int(f)] for f, dt in zip(split, line[len("decision_type="):].split(), strict=True)
                       if (int(dt) >> 2) & 3 != 2)
    src.close()
    return sorted(bad & set(features))


@dataclass
class ModelBundle:
    booster: lgb.Booster
    meta: dict[str, Any]

    @property
    def features(self) -> list[str]:
        return self.meta["features"]

    @property
    def labels(self) -> list[str]:
        return self.meta["labels"]

    @classmethod
    def load(cls, directory: str | Path) -> ModelBundle:
        d = Path(directory)
        meta = json.loads((d / "meta.json").read_text())
        booster = lgb.Booster(model_file=str(d / "model.txt"))
        if booster.feature_name() != meta["features"] or booster.num_model_per_iteration() != len(meta["labels"]):
            raise ValueError(f"{d}: model.txt does not match meta.json features/labels")
        if blind := nan_blind(d / "model.txt", LIVE_NONE.get(meta.get("task"), [])):
            log.error("%s: %s can be None live but the model scores None as 0 (no NaN in training); retrain",
                      d, blind)
        return cls(booster, meta)

    def save(self, directory: str | Path) -> None:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(d / "model.txt"))
        (d / "meta.json").write_text(json.dumps(self.meta, indent=2, sort_keys=True) + "\n")

    def matrix(self, rows: list[dict[str, float | None]]) -> np.ndarray:
        """Feature dicts → (n, n_features) float matrix; unknown keys raise, missing → NaN."""
        known = set(self.features)
        x = np.full((len(rows), len(self.features)), np.nan)
        for i, row in enumerate(rows):
            unknown = set(row) - known
            if unknown:
                raise ValueError(f"unknown features: {sorted(unknown)}")
            for j, name in enumerate(self.features):
                v = row.get(name)
                if v is not None and math.isfinite(v):
                    x[i, j] = v
        return x

    def _explained(self, x, rows, n_cls):
        """(probs, {row: contrib (n_cls, n_features)}) from one pred_contrib pass.

        pred_contrib for multiclass is (m, n_classes * (n_features + 1)); the last column per class is the bias, and
        a class's contributions sum to its raw score, so softmax over them is the predicted probability.
        """
        c = self.booster.predict(x[rows], pred_contrib=True, num_threads=1).reshape(rows.size, n_cls, -1)
        raw = c.sum(2)
        e = np.exp(raw - raw.max(1, keepdims=True))
        return e / e.sum(1, keepdims=True), dict(zip(rows.tolist(), c[:, :, :-1], strict=True))

    def predict(self, features: dict[str, float | None], explain_risk: float = 0.0) -> Prediction:
        return self.predict_batch([features], explain_risk)[0]

    def predict_batch(self, rows: list[dict[str, float | None]], explain_risk: float = 0.0) -> list[Prediction]:
        """One vectorised LightGBM pass over all rows; latency_ms is per row.

        TreeSHAP (most of the CPU) runs only on rows with risk >= explain_risk; the others get top_factors=[].
        """
        t0 = time.perf_counter()
        x = self.matrix(rows)
        n, n_cls = len(rows), len(self.labels)
        if n == 0:
            return []
        risk_w = np.asarray(self.meta["class_risk"])
        contribs = {}
        if explain_risk <= 0.0:   # every row explained: one pred_contrib pass also yields the probabilities
            probs, contribs = self._explained(x, np.arange(n), n_cls)
        else:
            probs = self.booster.predict(x, num_threads=1)
            explain = np.flatnonzero(np.clip(probs @ risk_w, 0.0, 1.0) >= explain_risk)
            if explain.size:
                contribs = self._explained(x, explain, n_cls)[1]
        in_sets = prediction_sets(probs, self.meta["conformal_q"])
        risks = np.clip(probs @ risk_w, 0.0, 1.0)
        latency_ms = (time.perf_counter() - t0) * 1000.0 / n
        out = []
        for i, p in enumerate(probs):
            k = int(np.argmax(p))
            pred_set = [lbl for lbl, keep in zip(self.labels, in_sets[i], strict=True) if keep]
            factors = []
            if i in contribs:
                contrib = contribs[i][k]
                top = [j for j in np.argsort(-np.abs(contrib))[:TOP_FACTORS] if contrib[j] != 0]
                factors = [Factor(feature=self.features[j], value=None if np.isnan(x[i, j]) else float(x[i, j]),
                                  contribution=float(contrib[j])) for j in top]
            out.append(Prediction(
                model_version=self.meta["version"],
                label=self.labels[k],
                risk=float(risks[i]),
                probabilities={lbl: float(v) for lbl, v in zip(self.labels, p, strict=True)},
                prediction_set=pred_set,
                uncertain=len(pred_set) != 1,
                top_factors=factors,
                latency_ms=latency_ms,
            ))
        return out
