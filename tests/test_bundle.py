import lightgbm as lgb
import numpy as np
import pytest

from kubeheal.ml.bundle import ModelBundle
from kubeheal.ml.conformal import calibrate, prediction_sets

FEATURES = ["a", "b", "c"]
LABELS = ["benign", "degradation", "critical"]


def _data(n: int, rng: np.random.Generator):
    x = rng.normal(size=(n, 3))
    y = np.digitize(x[:, 0] + 0.5 * x[:, 1] + rng.normal(scale=0.7, size=n), [-0.5, 0.8])
    return x, y


@pytest.fixture(scope="module")
def bundle() -> ModelBundle:
    rng = np.random.default_rng(0)
    x, y = _data(3000, rng)
    booster = lgb.train({"objective": "multiclass", "num_class": 3, "verbose": -1, "num_threads": 1, "seed": 0},
                        lgb.Dataset(x[:2000], y[:2000], feature_name=FEATURES), num_boost_round=40)
    q = calibrate(booster.predict(x[2000:]), y[2000:], alpha=0.1)
    return ModelBundle(booster, {"task": "health", "version": "test-1", "labels": LABELS, "class_risk": [0.05, 0.6, 0.95],
                                 "features": FEATURES, "alpha": 0.1, "conformal_q": q, "metrics": {}, "data": {},
                                 "created_at": "now"})


def test_roundtrip(bundle, tmp_path):
    bundle.save(tmp_path)
    loaded = ModelBundle.load(tmp_path)
    row = {"a": 1.2, "b": -0.3, "c": 0.0}
    assert loaded.predict(row).probabilities == pytest.approx(bundle.predict(row).probabilities)
    assert loaded.meta == bundle.meta


def test_load_rejects_mismatched_meta(bundle, tmp_path):
    bundle.save(tmp_path)
    (tmp_path / "meta.json").write_text((tmp_path / "meta.json").read_text().replace('"c"', '"zzz"'))
    with pytest.raises(ValueError):
        ModelBundle.load(tmp_path)


def test_prediction_fields(bundle):
    p = bundle.predict({"a": 3.0, "b": 2.0, "c": 0.1})
    assert p.label == "critical" and p.model_version == "test-1"
    assert sum(p.probabilities.values()) == pytest.approx(1.0)
    assert p.risk == pytest.approx(sum(p.probabilities[lbl] * r for lbl, r in zip(LABELS, [0.05, 0.6, 0.95], strict=True)))
    assert p.uncertain == (len(p.prediction_set) != 1)
    assert 0 < len(p.top_factors) <= 5 and p.top_factors[0].feature == "a"
    assert p.top_factors[0].value == 3.0


def test_shap_contributions_are_exact(bundle):
    x = np.array([[0.4, -1.0, 2.0]])
    contrib = bundle.booster.predict(x, pred_contrib=True).reshape(3, -1)
    raw = bundle.booster.predict(x, raw_score=True)[0]
    assert contrib.sum(axis=1) == pytest.approx(raw)   # TreeSHAP + bias == raw margin per class


def test_unknown_feature_raises(bundle):
    with pytest.raises(ValueError, match="unknown"):
        bundle.predict({"a": 1.0, "bogus": 2.0})


def test_missing_features_are_nan_not_zero(bundle):
    p = bundle.predict({"a": None})
    assert p.label in LABELS
    assert all(f.value is None for f in p.top_factors if f.feature in ("a", "b", "c"))
    assert np.isnan(bundle.matrix([{"a": None, "b": float("inf")}])).all()


def test_conformal_coverage_roughly_holds():
    rng = np.random.default_rng(1)
    x, y = _data(9000, rng)
    booster = lgb.train({"objective": "multiclass", "num_class": 3, "verbose": -1, "num_threads": 1, "seed": 0},
                        lgb.Dataset(x[:3000], y[:3000]), num_boost_round=40)
    for alpha in (0.05, 0.1, 0.2):
        q = calibrate(booster.predict(x[3000:6000]), y[3000:6000], alpha)
        sets = prediction_sets(booster.predict(x[6000:]), q)
        coverage = sets[np.arange(3000), y[6000:]].mean()
        assert 1 - alpha - 0.03 <= coverage <= 1 - alpha + 0.04, (alpha, coverage)


def test_calibrate_with_too_few_points_covers_everything():
    assert calibrate(np.array([[0.9, 0.1]]), np.array([0]), alpha=0.1) == 1.0


def test_calibrate_is_the_finite_sample_rank():
    # q = the ceil((n+1)(1-alpha))-th smallest score (n=19, alpha=0.1 → 18th), not one rank higher.
    scores = np.arange(1, 20) / 20
    probs = np.stack([1 - scores, scores], axis=1)
    assert calibrate(probs, np.zeros(19, int), alpha=0.1) == pytest.approx(scores[17])


def test_batch_matches_single_rows(bundle):
    rows = [{"a": 3.0, "b": 2.0, "c": 0.1}, {"a": -2.0, "b": None}, {}, {"a": 0.3, "b": -0.4, "c": 1.0}]
    batch = bundle.predict_batch(rows)
    for row, b in zip(rows, batch, strict=True):
        s = bundle.predict(row)
        assert (b.label, b.prediction_set, b.top_factors) == (s.label, s.prediction_set, s.top_factors)
        assert b.risk == pytest.approx(s.risk) and b.probabilities == pytest.approx(s.probabilities)
    assert bundle.predict_batch([]) == []


def test_only_rows_at_or_above_explain_risk_get_factors(bundle):
    rows = [{"a": 3.0, "b": 2.0, "c": 0.1}, {"a": -3.0, "b": -2.0, "c": 0.0}, {"a": 1.0, "b": 0.5}]
    full = bundle.predict_batch(rows)
    cut = sorted(p.risk for p in full)[1]                     # explain the two riskiest rows only
    part = bundle.predict_batch(rows, explain_risk=cut)
    for f, p in zip(full, part, strict=True):
        assert (p.label, p.risk, p.prediction_set) == (f.label, f.risk, f.prediction_set)
        assert p.top_factors == (f.top_factors if f.risk >= cut else [])
    assert sum(not p.top_factors for p in part) == 1
    assert bundle.predict_batch(rows, explain_risk=2.0)[0].top_factors == []   # nothing explained
