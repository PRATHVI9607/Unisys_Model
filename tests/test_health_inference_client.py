"""V5-D4: the Health Agent's inference client fails closed (no score unless HTTP 200 and a valid Prediction)."""
import asyncio
import json

import aiohttp
import pytest

from agents.health_agent import inference_client as ic
from agents.health_agent.agent import HealthAgent
from health_helpers import prediction


def run(coro):
    return asyncio.run(coro)


class Resp:
    def __init__(self, status=200, body=None, raw=None):
        self.status, self.body, self.raw = status, body, raw

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        if self.raw is not None:
            return json.loads(self.raw)       # raises ValueError on bad JSON
        return self.body


class Session:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def post(self, url, json=None, timeout=None):
        self.calls.append((url, json, timeout))
        if self.exc is not None:
            raise self.exc
        return self.resp


def good():
    return prediction("benign", 0.05).model_dump()


def test_a_valid_answer_is_returned_and_the_request_matches_the_service_contract():
    s = Session(Resp(200, good()))
    pred = run(ic.predict_health(s, "http://svc:8000/", {"cpu_util_mean": 0.5, "latency_trend": None}, 3.0))
    assert pred.label == "benign" and pred.prediction_set == ["benign"] and pred.model_version == "test-bundle-1"
    url, body, timeout = s.calls[0]
    assert url == "http://svc:8000/v1/health/predict"
    assert body == {"features": {"cpu_util_mean": 0.5, "latency_trend": None}}
    assert timeout.total == 3.0


@pytest.mark.parametrize("status", [400, 422, 500, 503])
def test_an_error_status_is_no_score(status):
    assert run(ic.predict_health(Session(Resp(status, good())), "http://svc", {})) is None


@pytest.mark.parametrize("exc", [asyncio.TimeoutError(), aiohttp.ClientConnectionError("refused"), OSError("down")])
def test_a_timeout_or_connection_error_is_no_score(exc):
    assert run(ic.predict_health(Session(exc=exc), "http://svc", {})) is None


@pytest.mark.parametrize("body", [{"label": "benign"}, {}, [], "text", {**good(), "risk": 2.0}])
def test_a_malformed_body_is_no_score(body):
    assert run(ic.predict_health(Session(Resp(200, body)), "http://svc", {})) is None


def test_a_non_json_body_is_no_score():
    assert run(ic.predict_health(Session(Resp(200, raw="<html>")), "http://svc", {})) is None


def test_non_finite_features_become_null_never_zero():
    out = ic.finite_features({"a": float("nan"), "b": float("inf"), "c": 1, "d": None, "e": "x"})
    assert out == {"a": None, "b": None, "c": 1.0, "d": None, "e": None}


def test_url_and_timeout_come_from_the_environment(monkeypatch):
    monkeypatch.delenv("INFERENCE_URL", raising=False)
    assert ic.inference_url_from_env() == "http://kubeheal-inference:8000"
    monkeypatch.setenv("INFERENCE_URL", "http://x:1/")
    assert ic.inference_url_from_env() == "http://x:1"
    assert HealthAgent(redis_url="redis://unused").inference_url == "http://x:1"
    monkeypatch.setenv("INFERENCE_TIMEOUT_S", "2.5")
    assert ic.timeout_from_env() == 2.5
    monkeypatch.setenv("INFERENCE_TIMEOUT_S", "0")
    with pytest.raises(ValueError):
        ic.timeout_from_env()
