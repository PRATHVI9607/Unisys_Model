"""V5-I2: the inference service (services/inference_server/main.py) with the REAL shipped bundles.

No mocks of the model: the bundles under models/bundles are loaded through kubeheal.ml.bundle.ModelBundle and
the HTTP answers are compared with calling the bundle directly.
"""
import json
import shutil
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from kubeheal.contracts import SECURITY_PUBLISH_RISK
from kubeheal.features.security import SECURITY_FEATURES
from kubeheal.ml.bundle import BUNDLES_DIR, ModelBundle
from services.inference_server import main as srv

NAME = "kubeheal_model_inflight_requests"
JSON = {"content-type": "application/json"}


@pytest.fixture(scope="module")
def bundles():
    return {t: ModelBundle.load(BUNDLES_DIR / t) for t in srv.TASKS}


@pytest.fixture(scope="module")
def client():
    with TestClient(srv.create_app()) as c:
        yield c


def row_for(bundle, kind):
    """A deterministic feature row. 'mid' is all 0.5, 'zeros' all 0.0, 'rand' seeded uniform values."""
    if kind == "rand":
        rng = np.random.default_rng(0)
        return {n: float(rng.random()) for n in bundle.features}
    return {n: {"mid": 0.5, "zeros": 0.0}[kind] for n in bundle.features}


def gauge(app):
    return app.state.metrics.inflight_requests._value.get()


# ---- probes and metrics ------------------------------------------------------------------------

def test_healthz_and_readyz_with_both_bundles(client, bundles):
    assert client.get("/healthz").json() == {"status": "ok"}
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"ready": True, "models": {t: bundles[t].meta["version"] for t in srv.TASKS}}


def test_metrics_export_the_inflight_gauge_and_request_series(client, bundles):
    client.post("/v1/health/predict", json={"features": row_for(bundles["health"], "mid")})
    text = client.get("/metrics").text
    assert any(line.startswith(NAME + " ") for line in text.splitlines())
    assert 'kubeheal_model_requests_total{model="health",status="ok"}' in text
    assert 'kubeheal_model_latency_seconds_count{model="health"}' in text
    assert "kubeheal_model_predictions_total{" in text


def test_scoring_paths_are_counted_and_the_gauge_returns_to_zero(client, bundles):
    for path in srv.SCORING_PATHS:
        assert client.post(path, json={"features": {"nope": 1.0}}).status_code in (413, 422)
    assert gauge(client.app) == 0
    assert srv.SCORING_PATHS == ["/v1/health/predict", "/v1/health/predict_batch",
                                 "/v1/security/predict", "/v1/security/predict_batch"]


def test_the_chart_series_name_matches_the_gauge():
    import yaml
    values = yaml.safe_load((Path(__file__).resolve().parents[1] / "deploy/helm/kubeheal/values.yaml").read_text())
    assert values["hpa"]["queue"]["seriesName"] == NAME
    assert srv.create_app().state.metrics.inflight_requests._name == NAME


# ---- predict -----------------------------------------------------------------------------------

def test_health_predict_matches_the_bundle_and_always_explains(client, bundles):
    b = bundles["health"]
    for kind in ("mid", "rand"):
        row = row_for(b, kind)
        r = client.post("/v1/health/predict", json={"features": row})
        assert r.status_code == 200
        body = r.json()
        direct = b.predict(row, 0.0)
        assert body["label"] == direct.label
        assert body["risk"] == pytest.approx(direct.risk)
        assert body["prediction_set"] == direct.prediction_set
        assert body["uncertain"] == (len(body["prediction_set"]) != 1) == direct.uncertain
        assert body["model_version"] == b.meta["version"]
        assert body["top_factors"], "health is always explained"
        assert {f["feature"] for f in body["top_factors"]} <= set(b.features)
        assert body["label"] in b.labels and all(lbl in b.labels for lbl in body["prediction_set"])


def test_security_top_factors_only_at_or_above_the_publish_risk(client, bundles):
    b = bundles["security"]
    high, low = row_for(b, "zeros"), row_for(b, "rand")
    assert b.predict(high, 0.0).risk >= SECURITY_PUBLISH_RISK > b.predict(low, 0.0).risk   # precondition
    hi = client.post("/v1/security/predict", json={"features": high}).json()
    lo = client.post("/v1/security/predict", json={"features": low}).json()
    assert hi["risk"] >= SECURITY_PUBLISH_RISK and hi["top_factors"]
    assert {f["feature"] for f in hi["top_factors"]} <= set(b.features)
    assert lo["risk"] < SECURITY_PUBLISH_RISK and lo["top_factors"] == []
    assert lo["model_version"] == hi["model_version"] == b.meta["version"]
    assert lo["label"] in b.labels and set(lo["prediction_set"]) <= set(b.labels)


def test_missing_and_null_values_are_accepted(client, bundles):
    names = bundles["health"].features
    for features in ({}, {names[0]: None}, {names[0]: 1, names[1]: 2.5}):
        assert client.post("/v1/health/predict", json={"features": features}).status_code == 200


def test_the_full_security_feature_dict_is_accepted_through_restrict(client, bundles):
    """The current feature code emits names the shipped security bundle was not trained on; restrict drops them."""
    extra = set(SECURITY_FEATURES) - set(bundles["security"].features)
    assert extra, "precondition: the code emits more security features than the shipped bundle lists"
    row = {n: 0.0 for n in SECURITY_FEATURES}
    assert client.post("/v1/security/predict", json={"features": row}).status_code == 200


# ---- batch -------------------------------------------------------------------------------------

@pytest.mark.parametrize("task,kinds", [("health", ("mid", "rand", "zeros")), ("security", ("zeros", "rand", "mid"))])
def test_batch_equals_single_predictions(client, bundles, task, kinds):
    rows = [row_for(bundles[task], k) for k in kinds]
    batch = client.post(f"/v1/{task}/predict_batch", json={"items": [{"features": r} for r in rows]})
    assert batch.status_code == 200 and len(batch.json()) == 3
    for row, got in zip(rows, batch.json()):
        single = client.post(f"/v1/{task}/predict", json={"features": row}).json()
        assert got["label"] == single["label"] and got["risk"] == pytest.approx(single["risk"])
        assert got["prediction_set"] == single["prediction_set"]
        assert bool(got["top_factors"]) == bool(single["top_factors"])


def test_batch_size_limits(client, bundles):
    item = {"features": row_for(bundles["health"], "mid")}
    assert client.post("/v1/health/predict_batch", json={"items": []}).status_code == 422
    assert client.post("/v1/health/predict_batch", json={"items": [item]}).status_code == 200
    assert len(client.post("/v1/health/predict_batch", json={"items": [item] * 256}).json()) == 256
    assert client.post("/v1/health/predict_batch", json={"items": [item] * 257}).status_code == 422
    assert client.post("/v1/health/predict_batch", json={"features": item["features"]}).status_code == 422


def test_batch_with_one_bad_item_is_refused_whole(client, bundles):
    good = {"features": row_for(bundles["health"], "mid")}
    r = client.post("/v1/health/predict_batch", json={"items": [good, {"features": {"bogus": 1.0}}]})
    assert r.status_code == 422 and "bogus" in r.text


# ---- 422 ---------------------------------------------------------------------------------------

def test_unknown_feature_names_are_422(client, bundles):
    for task in srv.TASKS:
        r = client.post(f"/v1/{task}/predict", json={"features": {"definitely_not_a_feature": 1.0}})
        assert r.status_code == 422 and "definitely_not_a_feature" in r.text
    # a name of the OTHER task is not in this task's universe either
    health_only = sorted(set(bundles["health"].features) - set(SECURITY_FEATURES))[0]
    assert client.post("/v1/security/predict", json={"features": {health_only: 1.0}}).status_code == 422
    sec_only = sorted(set(bundles["security"].features) - set(bundles["health"].features))[0]
    assert client.post("/v1/health/predict", json={"features": {sec_only: 1.0}}).status_code == 422


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nan_and_inf_are_422(client, bundles, literal):
    name = bundles["health"].features[0]
    r = client.post("/v1/health/predict", content='{"features": {"%s": %s}}' % (name, literal), headers=JSON)
    assert r.status_code == 422 and r.json()["detail"], r.text
    r = client.post("/v1/health/predict_batch", content='{"items": [{"features": {"%s": %s}}]}' % (name, literal),
                    headers=JSON)
    assert r.status_code == 422


@pytest.mark.parametrize("value", ['"1.0"', "true", "[1]", "{}"])
def test_non_numbers_are_422(client, bundles, value):
    name = bundles["health"].features[0]
    r = client.post("/v1/health/predict", content='{"features": {"%s": %s}}' % (name, value), headers=JSON)
    assert r.status_code == 422


def test_malformed_bodies_are_422(client):
    for content in ("not json", "[]", '{"features": []}', '{"feature": {}}', '{"features": {}, "extra": 1}'):
        assert client.post("/v1/health/predict", content=content, headers=JSON).status_code == 422, content
    too_many = {f"f{i}": 1.0 for i in range(srv.MAX_FEATURES + 1)}
    assert client.post("/v1/health/predict", json={"features": too_many}).status_code == 422
    assert client.post("/v1/health/predict", json={"features": {"x" * 65: 1.0}}).status_code == 422


# ---- body cap ----------------------------------------------------------------------------------

def test_body_cap_by_content_length(client):
    big = b'{"features": {}, "request_id": "' + b"a" * (srv.MAX_BODY_BYTES + 10) + b'"}'
    assert client.post("/v1/health/predict", content=big, headers=JSON).status_code == 413
    big_batch = b'{"items": [], "pad": "' + b"a" * (srv.MAX_BATCH_BODY_BYTES + 10) + b'"}'
    assert client.post("/v1/health/predict_batch", content=big_batch, headers=JSON).status_code == 413
    assert gauge(client.app) == 0


def test_body_cap_for_chunked_bodies_without_content_length(client):
    def chunks():
        for _ in range(srv.MAX_BODY_BYTES // 1024 + 8):
            yield b" " * 1024
    r = client.post("/v1/health/predict", content=chunks(), headers=JSON)
    assert r.status_code == 413
    assert gauge(client.app) == 0


# ---- fail closed: 503, never a fallback --------------------------------------------------------

def test_no_bundles_means_503_everywhere_and_not_ready(tmp_path):
    with TestClient(srv.create_app(tmp_path)) as c:
        assert c.get("/healthz").status_code == 200           # liveness is independent of the models
        r = c.get("/readyz")
        assert r.status_code == 503 and r.json() == {"ready": False, "models": {"health": None, "security": None}}
        for task in srv.TASKS:
            assert c.post(f"/v1/{task}/predict", json={"features": {}}).status_code == 503
            assert c.post(f"/v1/{task}/predict_batch", json={"items": [{"features": {}}]}).status_code == 503
        assert 'kubeheal_model_requests_total{model="health",status="unavailable"}' in c.get("/metrics").text
        assert gauge(c.app) == 0


def test_one_missing_bundle_keeps_the_service_not_ready(tmp_path):
    shutil.copytree(BUNDLES_DIR / "health", tmp_path / "health")        # byte copy: model.txt must keep its LF
    with TestClient(srv.create_app(tmp_path)) as c:
        r = c.get("/readyz")
        assert r.status_code == 503 and r.json()["models"]["security"] is None and r.json()["models"]["health"]
        assert c.post("/v1/health/predict", json={"features": {}}).status_code == 200
        assert c.post("/v1/security/predict", json={"features": {}}).status_code == 503


def test_corrupt_bundle_is_not_loaded(tmp_path):
    for task in srv.TASKS:
        shutil.copytree(BUNDLES_DIR / task, tmp_path / task)
    (tmp_path / "security" / "model.txt").write_text("this is not a lightgbm model\n")
    with TestClient(srv.create_app(tmp_path)) as c:
        assert c.get("/readyz").status_code == 503
        assert c.post("/v1/security/predict", json={"features": {}}).status_code == 503
        assert c.post("/v1/health/predict", json={"features": {}}).status_code == 200


def test_a_bundle_of_the_wrong_task_is_not_loaded(tmp_path):
    shutil.copytree(BUNDLES_DIR / "health", tmp_path / "health")
    shutil.copytree(BUNDLES_DIR / "health", tmp_path / "security")      # a health bundle in the security slot
    with TestClient(srv.create_app(tmp_path)) as c:
        assert c.get("/readyz").status_code == 503
        assert c.post("/v1/security/predict", json={"features": {}}).status_code == 503


def test_unstarted_app_answers_503_not_a_default_model():
    c = TestClient(srv.create_app())          # not used as a context manager: lifespan never ran
    assert c.post("/v1/health/predict", json={"features": {}}).status_code == 503
    assert c.get("/readyz").status_code == 503


# ---- bundle directory configuration ------------------------------------------------------------

def test_model_dir_env_var(monkeypatch, tmp_path):
    monkeypatch.delenv(srv.MODEL_DIR_ENV, raising=False)
    assert srv.model_root() is None                                    # default: the shipped bundles
    monkeypatch.setenv(srv.MODEL_DIR_ENV, str(tmp_path))
    assert srv.model_root() == tmp_path
    with TestClient(srv.create_app()) as c:                            # env root is empty: fail closed
        assert c.get("/readyz").status_code == 503
    for task in srv.TASKS:
        shutil.copytree(BUNDLES_DIR / task, tmp_path / task)
    with TestClient(srv.create_app()) as c:
        assert c.get("/readyz").status_code == 200


def test_module_level_app_exists_for_uvicorn():
    assert isinstance(srv.app.state.metrics.inflight_requests._value.get(), float)
    assert json.dumps(srv.EXPLAIN_RISK) == json.dumps({"health": 0.0, "security": SECURITY_PUBLISH_RISK})


def test_k6_load_script_body_matches_the_health_bundle(client, bundles):
    """demo/scripts/k6_health_model.js lives on the demo branch only; the check runs wherever the file exists."""
    import re
    js = Path(__file__).resolve().parents[1] / "demo" / "scripts" / "k6_health_model.js"
    if not js.exists():
        pytest.skip("demo/scripts/k6_health_model.js is on the demo branch")
    text = js.read_text(encoding="utf-8")
    assert "/v1/health/predict" in text
    block = text[text.index("const features = {"):text.index("};", text.index("const features = {"))]
    features = {k: float(v) for k, v in re.findall(r"(\w+):\s*(-?[0-9.]+)", block)}
    assert set(features) == set(bundles["health"].features)
    assert client.post("/v1/health/predict", json={"features": features}).status_code == 200
