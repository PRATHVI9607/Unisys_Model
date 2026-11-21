"""Hostile-input pass over the inference API: wrong types, NaN/inf, oversized and chunked bodies, absurd feature values."""

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

from kubeheal.features.health import HEALTH_FEATURES
from kubeheal.features.security import SECURITY_FEATURES
from kubeheal.inference import app as inference

MODELS = Path(__file__).resolve().parents[1] / "models"
H, S = "/v1/health/predict", "/v1/security/predict"


@pytest.fixture(scope="module")
def client():
    old = os.environ.get("KUBEHEAL_MODEL_DIR")
    os.environ["KUBEHEAL_MODEL_DIR"] = str(MODELS)
    with TestClient(inference.app, raise_server_exceptions=False) as c:
        yield c
    os.environ.pop("KUBEHEAL_MODEL_DIR") if old is None else os.environ.__setitem__("KUBEHEAL_MODEL_DIR", old)


def post(c, path, body, **kw):
    r = c.post(path, content=body if isinstance(body, bytes) else json.dumps(body), headers={"content-type": "application/json"}, **kw)
    assert r.status_code < 500, (path, r.status_code, r.text[:200])
    return r


@pytest.mark.parametrize("path", [H, S])
@pytest.mark.parametrize("body", [
    b"", b"null", b"[]", b"7", b'"x"', b"{", b"\xff\xfe", b"{}", b'{"features":null}', b'{"features":[]}', b'{"features":"n_events"}',
    b'{"features":{"n_events":"abc"}}', b'{"features":{"n_events":[1]}}', b'{"features":{"n_events":{"a":1}}}',
    b'{"features":{"n_events":NaN}}', b'{"features":{"n_events":Infinity}}', b'{"features":{"n_events":-Infinity}}',
    b'{"features":{"n_events":1e999}}', b'{"features":{"n_events":-1e999}}', b'{"features":{"nope":1}}', b'{"features":{},"x":1}',
    b'{"features":{"n_events":1},"request_id":5}', b'{"features":{"n_events":1},"request_id":"' + b"x" * 200 + b'"}',
    b'{"features":{"' + b"k" * 65 + b'":1}}', b'{"items":[]}',
])
def test_malformed_requests_are_4xx(client, path, body):
    r = post(client, path, body)
    assert 400 <= r.status_code < 500
    assert "NaN" not in r.text and "Infinity" not in r.text   # rejected values are not echoed back


def test_201_features_is_422(client):
    r = post(client, S, {"features": {f"f{i}": 1.0 for i in range(201)}})
    assert r.status_code == 422


@pytest.mark.parametrize("val", ["1.5", "true", "1e308", "-1e308", "5e-324", "0", "-0.0"])
def test_extreme_but_valid_numbers_score(client, val):
    for path, names in ((H, HEALTH_FEATURES), (S, SECURITY_FEATURES)):
        body = ('{"features":{' + ",".join(f'"{n}":{val}' for n in names) + "}}").encode()
        r = post(client, path, body)
        assert r.status_code in (200, 422)
        if r.status_code == 200:
            b = r.json()
            assert 0 <= b["risk"] <= 1 and abs(sum(b["probabilities"].values()) - 1) < 1e-6


# model-agnostic property: whatever finite numbers (or nulls) arrive, the answer is a valid prediction
num = st.none() | st.floats(allow_nan=False, allow_infinity=False, width=64)


@pytest.mark.parametrize("path,names", [(H, HEALTH_FEATURES), (S, SECURITY_FEATURES)])
def test_random_feature_vectors_always_score(client, path, names):
    @settings(max_examples=60, deadline=None, database=None)
    @given(st.dictionaries(st.sampled_from(names), num))
    def run(features):
        r = post(client, path, {"features": features})
        assert r.status_code == 200, r.text[:200]
        b = r.json()
        assert 0 <= b["risk"] <= 1 and b["label"] in b["probabilities"] and set(b["prediction_set"]) <= set(b["probabilities"])
    run()


# ── size limits ──────────────────────────────────────────────────────────────────────────────────
def row(names=SECURITY_FEATURES):
    return {"features": dict.fromkeys(names[:5], 1.0)}


def test_10k_row_batch_is_refused(client):
    r = post(client, S + "_batch", {"items": [row()] * 10_000})
    assert r.status_code in (413, 422)


def test_max_batch_is_served_and_one_over_is_422(client):
    r = post(client, S + "_batch", {"items": [row()] * inference.MAX_BATCH})
    assert r.status_code == 200 and len(r.json()) == inference.MAX_BATCH
    assert post(client, S + "_batch", {"items": [row()] * (inference.MAX_BATCH + 1)}).status_code == 422
    assert post(client, S + "_batch", {"items": []}).status_code == 422


def test_oversized_single_body_is_413_by_content_length(client):
    r = post(client, S, b'{"features":{"n_events":1},"request_id":"' + b"A" * (inference.MAX_BODY_BYTES + 1) + b'"}')
    assert r.status_code == 413


def test_chunked_oversized_body_is_413(client):
    def gen():   # no Content-Length: httpx sends Transfer-Encoding: chunked
        yield b'{"features":{"n_events":1},"request_id":"'
        for _ in range(inference.MAX_BODY_BYTES // 4096 + 4):
            yield b"A" * 4096
        yield b'"}'
    r = client.post(S, content=gen(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_chunked_body_within_limit_is_served(client):
    def gen():
        yield b'{"features":'
        yield b'{"n_events":3.0}}'
    assert client.post(S, content=gen(), headers={"content-type": "application/json"}).status_code == 200


@pytest.mark.parametrize("cl", ["abc", "-1", "99999999999999999999", "1e3", " "])
def test_bogus_content_length_is_413_not_500(client, cl):
    r = client.post(S, content=b"{}", headers={"content-type": "application/json", "content-length": cl})
    assert r.status_code in (400, 413, 422)


def test_deeply_nested_body_does_not_crash(client):
    for body in (b"[" * 100_000, b'{"features":' + b'{"a":' * 5000 + b"1" + b"}" * 5000 + b"}"):
        assert post(client, S, body).status_code in (400, 413, 422)


def test_health_endpoints_and_method_hygiene(client):
    assert client.get("/healthz").status_code == 200 and client.get("/readyz").status_code == 200
    for method in ("GET", "PUT", "DELETE"):
        assert client.request(method, S).status_code == 405
    assert client.get("/nope").status_code == 404
    assert client.get("/metrics").status_code == 200


# ── missing models: fail closed ──────────────────────────────────────────────────────────────────
def test_no_bundles_means_503_never_untrained_scores(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBEHEAL_MODEL_DIR", str(tmp_path))
    with TestClient(inference.app, raise_server_exceptions=False) as c:
        assert c.get("/healthz").status_code == 200 and c.get("/readyz").status_code == 503
        for path in (H, S, H + "_batch", S + "_batch"):
            body = {"items": [row()]} if path.endswith("batch") else row()
            assert c.post(path, json=body).status_code == 503
