import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kubeheal.contracts import HEALTH_CLASS_RISK, HEALTH_LABELS, SECURITY_CLASS_RISK, SECURITY_LABELS
from kubeheal.features.health import HEALTH_FEATURES
from kubeheal.features.security import RECENT_FEATURES, SECURITY_FEATURES
from kubeheal.inference.app import app
from kubeheal.ml.bundle import ModelBundle

MODELS = Path(__file__).resolve().parents[1] / "models"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("KUBEHEAL_MODEL_DIR", str(MODELS))
    with TestClient(app) as c:
        yield c


def test_ready_and_predict_with_committed_bundles(client):
    assert client.get("/healthz").status_code == 200
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["ready"] is True

    features = {f: None for f in HEALTH_FEATURES} | {"cpu_limit_ratio": 0.1, "spec_changed": 1.0, "cpu_util_max": 1.4}
    r = client.post("/v1/health/predict", json={"features": features, "request_id": "t1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["label"] in ("benign", "degradation", "critical") and 0 <= body["risk"] <= 1
    assert body["model_version"].startswith("health-")

    r = client.post("/v1/security/predict", json={"features": {"n_events": 50.0, "entropy_mean": 7.9}})
    assert r.status_code == 200 and r.json()["label"] in ("benign", "suspicious", "ransomware", "exfiltration")
    assert set(SECURITY_FEATURES) >= {f["feature"] for f in r.json()["top_factors"]}

    metrics = client.get("/metrics").text
    assert 'kubeheal_inference_requests_total{status="ok",task="health"}' in metrics


@pytest.mark.parametrize("body", [
    {"features": {"not_a_feature": 1.0}},
    {"features": {"n_events": "lots"}},
    {"features": {f"f{i}": 1.0 for i in range(201)}},
    {"features": {}, "extra": 1},
    {},
])
def test_invalid_bodies_are_422(client, body):
    assert client.post("/v1/security/predict", json=body).status_code == 422


def test_non_finite_values_are_422(client):
    payload = json.dumps({"features": {"n_events": float("inf")}})   # Python json emits Infinity
    r = client.post("/v1/security/predict", content=payload, headers={"content-type": "application/json"})
    assert r.status_code == 422


def test_empty_model_dir_is_503_never_random_weights(monkeypatch, tmp_path):
    monkeypatch.setenv("KUBEHEAL_MODEL_DIR", str(tmp_path))
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200
        assert c.get("/readyz").status_code == 503
        assert c.post("/v1/health/predict", json={"features": {}}).status_code == 503
        assert c.post("/v1/security/predict", json={"features": {}}).status_code == 503


@pytest.mark.parametrize("task, features, labels, risk", [
    ("health", HEALTH_FEATURES, HEALTH_LABELS, HEALTH_CLASS_RISK),
    ("security", SECURITY_FEATURES, SECURITY_LABELS, SECURITY_CLASS_RISK),
])
def test_committed_bundles_match_the_feature_and_label_lists(task, features, labels, risk):
    meta = ModelBundle.load(MODELS / task).meta     # what the agents send == what the model was trained on
    assert (meta["labels"], meta["class_risk"]) == (labels, risk)
    # A security bundle may leave out recent_* / rename-kind features (older bundles) and may list the two retired
    # rename_ext_change names (the inference service sends them as missing); nothing else.
    retired = {"rename_ext_change_ratio", "recent_ext_change_frac"}
    new_names = ("recent_", "frac_rename_", "rename_ext_added")
    assert set(meta["features"]) <= set(features) | (retired if task == "security" else set())
    assert not {f for f in features if f not in meta["features"] and not f.startswith(new_names)}


def test_oversized_body_is_413(client):
    r = client.post("/v1/security/predict", content=b"x" * (65 * 1024), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_batch_predict_matches_single(client):
    rows = [{"n_events": 50.0, "entropy_mean": 7.9}, {"n_events": 3.0, "frac_read": 1.0}, {}]
    r = client.post("/v1/security/predict_batch", json={"items": [{"features": f} for f in rows]})
    assert r.status_code == 200, r.text
    for row, b in zip(rows, r.json(), strict=True):
        s = client.post("/v1/security/predict", json={"features": row}).json()
        assert (b["label"], b["prediction_set"]) == (s["label"], s["prediction_set"])
        assert b["risk"] == pytest.approx(s["risk"])
    assert client.post("/v1/health/predict_batch", json={"items": [{"features": {}}]}).status_code == 200


@pytest.mark.parametrize("body", [
    {"items": []},
    {"items": [{"features": {}}] * 257},
    {"items": [{"features": {}}, {"features": {"not_a_feature": 1.0}}]},
    {"items": [{"features": {"n_events": "lots"}}]},
    {"items": [{"features": {}, "extra": 1}]},
    {"features": {}},
])
def test_invalid_batch_bodies_are_422(client, body):
    assert client.post("/v1/security/predict_batch", json=body).status_code == 422


def test_batch_non_finite_and_size_caps(client):
    payload = json.dumps({"items": [{"features": {}}, {"features": {"n_events": float("nan")}}]})
    hdr = {"content-type": "application/json"}
    assert client.post("/v1/security/predict_batch", content=payload, headers=hdr).status_code == 422
    big = b"x" * (256 * 4 * 1024 + 1)
    assert client.post("/v1/security/predict_batch", content=big, headers=hdr).status_code == 413


def test_security_explains_only_publishable_rows(client):
    from kubeheal.contracts import SECURITY_PUBLISH_RISK
    ransomware = {"n_events": 451.0, "events_per_s": 8.26, "frac_read": 0.333, "frac_write": 0.313, "frac_open": 0.224,
                  "frac_rename": 0.131, "unique_paths": 59.0, "unique_dirs": 1.0, "files_written_per_s": 2.16,
                  "rename_ext_change_ratio": 1.0, "suspicious_ext_ratio": 0.0, "ransom_note": 0.0,
                  "n_entropy_samples": 0.0, "write_bytes_per_s": 3.47e6, "net_out_bytes_per_s": 1.2e4}
    quiet = {"n_events": 216.0, "events_per_s": 10.1, "frac_read": 0.514, "frac_write": 0.486, "unique_paths": 37.0,
             "unique_dirs": 3.0, "files_written_per_s": 1.64, "entropy_mean": 3.83, "entropy_max": 7.1,
             "n_entropy_samples": 7.0, "write_bytes_per_s": 2.7e4, "net_out_bytes_per_s": 1.7e3}   # a lab benign window
    rows = [quiet, ransomware]
    preds = client.post("/v1/security/predict_batch", json={"items": [{"features": f} for f in rows]}).json()
    bundle = ModelBundle.load(MODELS / "security")
    for row, p in zip(rows, preds, strict=True):
        if p["risk"] < SECURITY_PUBLISH_RISK:
            assert p["top_factors"] == []
        else:
            assert p["top_factors"] == [f.model_dump() for f in bundle.predict(row).top_factors]
    assert {p["risk"] >= SECURITY_PUBLISH_RISK for p in preds} == {True, False}   # both branches exercised
    benign_change = {"cpu_limit_ratio": 1.0, "cpu_request_ratio": 1.0, "mem_limit_ratio": 1.0, "mem_request_ratio": 1.0,
              "replicas_ratio": 1.0, "n_changed_fields": 1.0, "spec_changed": 1.0, "cpu_util_mean": 0.0495,
              "cpu_util_max": 0.0581, "cpu_throttle_mean": 0.0025, "mem_util_mean": 0.1708, "mem_util_max": 0.2357,
              "latency_p99_mean_s": 0.005, "latency_p99_max_s": 0.005, "latency_trend": 0.0, "error_ratio": 0.0,
              "request_rate_log": 2.6278, "restarts_delta": 0.0, "ready_ratio": 1.0}   # a lab "meta" label change
    health = ModelBundle.load(MODELS / "health").predict(benign_change)
    assert health.risk < SECURITY_PUBLISH_RISK and health.top_factors                 # health: low risk still explained
    r = client.post("/v1/health/predict_batch", json={"items": [{"features": benign_change}]}).json()
    assert r[0]["top_factors"] == [f.model_dump() for f in health.top_factors]


def test_old_bundle_ignores_recent_features(client):
    """A bundle trained before recent_* existed keeps serving when the agent sends them."""
    import lightgbm as lgb
    import numpy as np

    from kubeheal.ml.conformal import calibrate
    names = [f for f in SECURITY_FEATURES if f not in RECENT_FEATURES][:3]
    rng = np.random.default_rng(0)
    x = rng.normal(size=(600, 3))
    y = np.arange(600) % len(SECURITY_LABELS)
    booster = lgb.train({"objective": "multiclass", "num_class": len(SECURITY_LABELS), "verbose": -1, "num_threads": 1},
                        lgb.Dataset(x, y, feature_name=names), num_boost_round=5)
    client.app.state.bundles["security"] = ModelBundle(booster, {
        "task": "security", "version": "old-1", "labels": SECURITY_LABELS, "class_risk": SECURITY_CLASS_RISK,
        "features": names, "alpha": 0.1, "conformal_q": calibrate(booster.predict(x), y, alpha=0.1),
        "metrics": {}, "data": {}, "created_at": "now"})
    row = {names[0]: 50.0} | {f: 1.0 for f in RECENT_FEATURES}
    assert client.post("/v1/security/predict", json={"features": row}).status_code == 200
    assert client.post("/v1/security/predict", json={"features": {"not_a_feature": 1.0}}).status_code == 422


def test_old_bundle_gets_none_for_dropped_feature_names(client):
    """A bundle listing a feature we no longer compute (rename_ext_change_ratio) is served with it missing."""
    import lightgbm as lgb
    import numpy as np

    from kubeheal.ml.conformal import calibrate
    names = ["n_events", "rename_ext_change_ratio", "recent_ext_change_frac"]
    assert not {"rename_ext_change_ratio", "recent_ext_change_frac"} & set(SECURITY_FEATURES)
    rng = np.random.default_rng(0)
    x = rng.normal(size=(600, 3))
    y = np.arange(600) % len(SECURITY_LABELS)
    booster = lgb.train({"objective": "multiclass", "num_class": len(SECURITY_LABELS), "verbose": -1, "num_threads": 1},
                        lgb.Dataset(x, y, feature_name=names), num_boost_round=5)
    client.app.state.bundles["security"] = ModelBundle(booster, {
        "task": "security", "version": "old-2", "labels": SECURITY_LABELS, "class_risk": SECURITY_CLASS_RISK,
        "features": names, "alpha": 0.1, "conformal_q": calibrate(booster.predict(x), y, alpha=0.1),
        "metrics": {}, "data": {}, "created_at": "now"})
    row = {f: 1.0 for f in SECURITY_FEATURES}                     # what the agent sends today
    assert client.post("/v1/security/predict", json={"features": row}).status_code == 200
