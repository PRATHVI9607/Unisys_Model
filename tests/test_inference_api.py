import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kubeheal.contracts import HEALTH_CLASS_RISK, HEALTH_LABELS, SECURITY_CLASS_RISK, SECURITY_LABELS
from kubeheal.features.health import HEALTH_FEATURES
from kubeheal.features.security import SECURITY_FEATURES
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
    assert (meta["features"], meta["labels"], meta["class_risk"]) == (features, labels, risk)


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
    rows = [{"n_events": 3.0, "frac_read": 1.0}, ransomware]
    preds = client.post("/v1/security/predict_batch", json={"items": [{"features": f} for f in rows]}).json()
    bundle = ModelBundle.load(MODELS / "security")
    for row, p in zip(rows, preds, strict=True):
        if p["risk"] < SECURITY_PUBLISH_RISK:
            assert p["top_factors"] == []
        else:
            assert p["top_factors"] == [f.model_dump() for f in bundle.predict(row).top_factors]
    assert {p["risk"] >= SECURITY_PUBLISH_RISK for p in preds} == {True, False}   # both branches exercised
    health = ModelBundle.load(MODELS / "health").predict({})
    assert health.risk < SECURITY_PUBLISH_RISK and health.top_factors                 # health: low risk still explained
    r = client.post("/v1/health/predict_batch", json={"items": [{"features": {}}]}).json()
    assert r[0]["top_factors"] == [f.model_dump() for f in health.top_factors]
