"""A trained model on disk: LightGBM `model.txt` + `meta.json`.

meta.json keys: task, version, labels, class_risk, features, alpha, conformal_q,
metrics, data {source, rows, groups, synthetic, sha256}, created_at.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np

from kubeheal.contracts import Factor, Prediction
from kubeheal.ml.conformal import prediction_sets

TOP_FACTORS = 5


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
        probs = self.booster.predict(x, num_threads=1)
        in_sets = prediction_sets(probs, self.meta["conformal_q"])
        risks = np.clip(probs @ np.asarray(self.meta["class_risk"]), 0.0, 1.0)
        explain = np.flatnonzero(risks >= explain_risk)
        contribs = {}
        if explain.size:
            # pred_contrib for multiclass: (m, n_classes * (n_features + 1)); the last column per class is the bias.
            c = self.booster.predict(x[explain], pred_contrib=True, num_threads=1).reshape(explain.size, n_cls, -1)
            contribs = dict(zip(explain.tolist(), c[:, :, :-1], strict=True))
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
