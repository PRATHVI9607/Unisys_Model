"""The two LightGBM bundles shipped under models/bundles, loaded through the shared kubeheal package."""

import copy
import json
import warnings
from pathlib import Path

import numpy as np
import pytest

from kubeheal.contracts import (
    HEALTH_CLASS_RISK,
    HEALTH_LABELS,
    SECURITY_CLASS_RISK,
    SECURITY_LABELS,
    Prediction,
)
from kubeheal.features.health import HEALTH_FEATURES, health_features
from kubeheal.features.security import SECURITY_FEATURES, security_features
from kubeheal.ml.bundle import BUNDLES_DIR, ModelBundle, default_bundle_dir

REPO = Path(__file__).resolve().parents[1]
TASKS = ("health", "security")
# Features the current kubeheal.features.security code emits that the shipped security bundle was not trained on.
SECURITY_NOT_IN_BUNDLE = {
    "frac_write_from_read", "frac_read_destroyed", "n_files_transformed",
    "recent_frac_write_from_read", "recent_frac_read_destroyed",
}


@pytest.fixture(scope="module", params=TASKS)
def task(request) -> str:
    return request.param


@pytest.fixture(scope="module")
def bundles() -> dict[str, ModelBundle]:
    return {t: ModelBundle.load(BUNDLES_DIR / t) for t in TASKS}


def test_bundles_dir_is_models_bundles():
    assert BUNDLES_DIR == REPO / "models" / "bundles"
    assert default_bundle_dir("health") == REPO / "models" / "bundles" / "health"


def test_gitattributes_never_converts_bundle_line_endings():
    lines = [ln.strip() for ln in (REPO / ".gitattributes").read_text().splitlines()]
    assert "models/bundles/** -text" in lines
    assert "* text=auto eol=lf" in lines            # the existing rule is kept


def test_model_txt_has_no_carriage_returns(task):
    """LightGBM refuses a model.txt with CRLF line endings, so the files must stay byte-exact LF."""
    for name in ("model.txt", "meta.json"):
        assert b"\r" not in (BUNDLES_DIR / task / name).read_bytes(), f"{task}/{name} contains CR"


def test_shipped_bundles_load(task):
    b = ModelBundle.load(BUNDLES_DIR / task)
    assert b.meta["task"] == task
    assert isinstance(b.meta["version"], str) and b.meta["version"]
    assert ModelBundle.load_default(task).meta == b.meta


def test_bundle_features_equal_meta_json(bundles, task):
    meta = json.loads((BUNDLES_DIR / task / "meta.json").read_text())
    b = bundles[task]
    assert b.features == meta["features"]
    assert b.booster.feature_name() == meta["features"]
    assert b.labels == meta["labels"]
    assert b.booster.num_model_per_iteration() == len(meta["labels"])


def test_bundle_labels_and_risk_match_contracts(bundles):
    assert bundles["health"].labels == HEALTH_LABELS
    assert bundles["health"].meta["class_risk"] == HEALTH_CLASS_RISK
    assert bundles["security"].labels == SECURITY_LABELS
    assert bundles["security"].meta["class_risk"] == SECURITY_CLASS_RISK


def test_health_bundle_uses_exactly_the_health_feature_list(bundles):
    assert bundles["health"].features == HEALTH_FEATURES


def test_security_bundle_vs_current_feature_code(bundles):
    """The shipped security bundle lists fewer features than the current code emits; the gap is pinned here so a
    retrained bundle or a feature change shows up as a test failure instead of silent drift."""
    bundle_features = bundles["security"].features
    assert set(bundle_features) <= set(SECURITY_FEATURES)
    assert set(SECURITY_FEATURES) - set(bundle_features) == SECURITY_NOT_IN_BUNDLE
    assert bundle_features == [f for f in SECURITY_FEATURES if f in set(bundle_features)]   # same relative order


def _check(p: Prediction, bundle: ModelBundle) -> None:
    assert p.model_version == bundle.meta["version"]
    assert p.label in bundle.labels
    assert set(p.probabilities) == set(bundle.labels)
    assert sum(p.probabilities.values()) == pytest.approx(1.0)
    assert 0.0 <= p.risk <= 1.0
    assert set(p.prediction_set) <= set(bundle.labels)
    assert p.uncertain == (len(p.prediction_set) != 1)       # exactly this rule, nothing else
    assert len(p.top_factors) <= 5
    assert all(f.feature in bundle.features for f in p.top_factors)


def test_predict_with_all_features_missing(bundles, task):
    b = bundles[task]
    for row in ({}, {name: None for name in b.features}):
        _check(b.predict(row), b)


def test_predict_batch_matches_single_predicts(bundles, task):
    b = bundles[task]
    rows = [{}, {name: None for name in b.features}]
    batch = b.predict_batch(rows)
    assert len(batch) == 2 and b.predict_batch([]) == []
    for p, row in zip(batch, rows, strict=True):
        assert p.probabilities == pytest.approx(b.predict(row).probabilities)


def _health_window(**over) -> dict[str, list[float]]:
    n = 12
    w = {
        "cpu_usage_cores": [0.1] * n, "cpu_limit_cores": [0.5] * n, "cpu_throttled_ratio": [0.0] * n,
        "memory_working_set_bytes": [1e8] * n, "memory_limit_bytes": [2.68e8] * n,
        "request_rate_rps": [50.0] * n, "error_rate_rps": [0.0] * n, "latency_p99_s": [0.05] * n,
        "restarts_total": [0] * n, "replicas_desired": [3] * n, "replicas_ready": [3] * n,
    }
    return w | over


SPEC = {
    "replicas": 3,
    "selector": {"matchLabels": {"app": "web"}},
    "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{
        "name": "web", "image": "nginx:1.27",
        "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "250m"}},
    }]}},
}


def test_health_bundle_predicts_a_plausible_unchanged_spec(bundles):
    b = bundles["health"]
    p = b.predict(b.restrict(health_features(SPEC, SPEC, _health_window())))
    _check(p, b)
    assert p.top_factors                         # a plausible health row is explained


def test_health_bundle_flags_a_cpu_limit_cut(bundles):
    b = bundles["health"]
    cut = copy.deepcopy(SPEC)
    cut["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "50m"
    n = 12
    w = _health_window(cpu_usage_cores=[0.3] * n, cpu_limit_cores=[0.05] * n, cpu_throttled_ratio=[0.9] * n,
                       error_rate_rps=[5.0] * n, latency_p99_s=[0.2 + 0.1 * i for i in range(n)])
    p = b.predict(b.restrict(health_features(SPEC, cut, w)))
    _check(p, b)
    assert p.label != "benign" and p.risk > 0.4


def test_security_bundle_predicts_plausible_windows(bundles):
    b = bundles["security"]
    quiet = security_features([{"syscall": "open_r", "path": "/data/a"}] * 5, [], 10.0)
    p = b.predict(b.restrict(quiet))
    _check(p, b)
    assert p.label == "benign"

    events = []
    for i in range(60):
        x = f"/data/f{i}.dat"
        events += [{"syscall": "open_r", "path": x}, {"syscall": "open_w", "path": x},
                   {"syscall": "rename", "path": x, "new_path": x + ".locked"}]
    attack = security_features(events, [7.9] * 8, 10.0, bytes_written=5e6, net_bytes_out=1e3)
    p = b.predict(b.restrict(attack))
    _check(p, b)
    assert p.label == "ransomware" and p.risk > 0.4


def test_restrict_drops_only_names_the_bundle_does_not_list(bundles):
    b = bundles["security"]
    full = security_features([{"syscall": "open_w", "path": "/data/a"}], [], 5.0)
    assert set(full) - set(b.restrict(full)) == SECURITY_NOT_IN_BUNDLE
    assert b.restrict({"n_events": 1.0}) == {"n_events": 1.0}
    with pytest.raises(ValueError, match="unknown features"):
        b.predict(full)                          # un-restricted: the extra names are rejected


@pytest.mark.parametrize("bad", ["not_a_feature", "n_changed_fields_typo"])
def test_unknown_feature_names_are_rejected(bundles, task, bad):
    b = bundles[task]
    with pytest.raises(ValueError, match="unknown features"):
        b.predict({bad: 1.0})
    with pytest.raises(ValueError, match="unknown features"):
        b.predict_batch([{}, {b.features[0]: 1.0, bad: 0.0}])
    with pytest.raises(ValueError, match="unknown features"):
        b.matrix([{bad: None}])                  # rejected even when the value is missing


def test_missing_nan_and_inf_are_all_treated_as_missing(bundles, task):
    b = bundles[task]
    name = b.features[0]
    x = b.matrix([{}, {name: None}, {name: float("nan")}, {name: float("inf")}, {name: float("-inf")}])
    assert np.isnan(x).all()                     # nothing was turned into 0
    rows = [{}, {name: None}, {name: float("nan")}, {name: float("inf")}]
    probs = [b.predict(row).probabilities for row in rows]
    for other in probs[1:]:
        assert other == pytest.approx(probs[0])
    present = b.matrix([{name: 0.0}])
    assert present[0, 0] == 0.0                  # a real zero stays a zero, not NaN


def test_top_factor_value_is_none_for_a_missing_input(bundles):
    b = bundles["health"]
    p = b.predict({})
    assert p.top_factors and all(f.value is None for f in p.top_factors)


def test_uncertain_flag_follows_set_size_across_many_rows(bundles, task):
    """`uncertain` is a pure function of the set size, whatever the row."""
    b = bundles[task]
    rng = np.random.default_rng(1)
    rows = [{name: float(v) for name, v in zip(b.features, rng.normal(size=len(b.features)), strict=True)}
            for _ in range(40)]
    for p in b.predict_batch(rows):
        assert p.uncertain == (len(p.prediction_set) != 1)


def test_loading_and_predicting_raise_no_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for t in TASKS:
            ModelBundle.load(BUNDLES_DIR / t).predict({})
