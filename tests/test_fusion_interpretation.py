"""P6-D6: interpretation client (field attributions, SHAP with a stub model, causal chain with T0) and the DCM
call deadline (P6-D1)."""
import asyncio
import json
import sys
from types import SimpleNamespace

import numpy as np
import pytest

from fusion_helpers import NOW_MS, health_event, run, sec_event
from agents.fusion_agent import interpretation_client as ic
from agents.fusion_agent.interpretation_client import InterpretationClient, build_causal_chain, parse_t0

T0 = NOW_MS - 20_000


# ---- T0 -------------------------------------------------------------------------------------------------
def test_parse_t0_reads_only_the_contract_field():
    assert parse_t0({"t0_ms": str(T0)}) == T0
    assert parse_t0({"t0_ms": T0}) == T0
    assert parse_t0({"timestamp_ms": str(NOW_MS)}) is None          # the publish time is never T0
    for bad in (None, "", "0", "-1", "x", "1.5"):
        assert parse_t0({"t0_ms": bad}) is None
    assert parse_t0(None) is None and parse_t0({}) is None


def test_earliest_t0_takes_the_minimum_and_ignores_missing():
    assert ic.earliest_t0({"t0_ms": "300"}, {"t0_ms": "200"}, None, known=250) == 200
    assert ic.earliest_t0({}, {"t0_ms": "bad"}) is None
    assert ic.earliest_t0({}, known=7) == 7


# ---- causal chain ---------------------------------------------------------------------------------------
def test_chain_without_t0_is_the_dcm_chain_unchanged():
    assert build_causal_chain(health_event(), sec_event(), ["T+2.0s: x", "DCM - y"], None) == \
        ["T+2.0s: x", "DCM - y"]
    assert build_causal_chain(None, None, [], None) == []


def test_chain_with_t0_has_the_onset_and_real_offsets():
    sec = sec_event(timestamp_ms=str(T0 + 4_000))
    health = health_event(timestamp_ms=str(T0 + 9_500))
    chain = build_causal_chain(health, sec, ["T+2.0s: template"], T0)
    assert chain[0].startswith("T0: attack onset 20") and f"t0_ms={T0}" in chain[0] and chain[0].count("Z") == 1
    assert chain[1].startswith("T+4.0s: security event sec-1") and "phase initial" in chain[1]
    assert chain[2].startswith("T+9.5s: health event health-1")
    assert chain[3] == "DCM: T+2.0s: template"           # the template offsets stay marked as the DCM layer's


def test_chain_offset_before_t0_is_signed_not_hidden():
    chain = build_causal_chain(None, sec_event(timestamp_ms=str(T0 - 1_000)), [], T0)
    assert chain[1].startswith("T-1.0s:")


# ---- attributions ---------------------------------------------------------------------------------------
def test_attributions_come_from_the_events_with_their_method_labels():
    health = health_event(field_attribution_json=json.dumps({"spec.limits.cpu": 0.7, "spec.replicas": 0.2,
                                                             "bad": "x"}), top_metric="cpu_throttle")
    sec = sec_event(syscall_attribution_json=json.dumps({"write": 0.6, "rename": 0.4}),
                    entropy_spike_json=json.dumps({"timestep": 3, "value_bits": 7.9}))
    attr = ic.normalise_attributions(health, sec)
    assert [r["name"] for r in attr["health_fields"]] == ["spec.limits.cpu", "spec.replicas"]
    assert attr["syscalls"][0] == {"name": "write", "weight": 0.6} and attr["entropy_spike"]["timestep"] == 3
    assert attr["health_top_metric"] == "cpu_throttle"
    assert all("not SHAP" in m for m in attr["methods"].values())
    assert ic.normalise_attributions(None, None) == {"methods": {}}
    assert ic.normalise_attributions({"field_attribution_json": "{broken"}, {})["methods"] == {}


def test_deviation_fallback_attribution_sums_to_one():
    window = np.array([[1.0, 5.0, 0.0], [1.0, 9.0, 0.0], [1.0, 1.0, 0.0]])
    attr = ic.deviation_attribution(window, ["a", "b", "c"])
    assert attr["b"] > 0.99 and attr["a"] == pytest.approx(0.0, abs=1e-6)


def test_kernel_shap_with_a_stub_model_finds_the_driving_channel():
    names = ["cpu", "mem", "lat"]
    w = np.array([0.0, 0.0, 5.0])                      # only latency drives the stub model's risk
    predict = lambda X: np.asarray(X) @ w              # noqa: E731
    background = np.zeros((5, 3))
    window = np.tile([1.0, 2.0, 3.0], (4, 1))          # [time, channels]
    attr, method = ic.kernel_metric_attribution(predict, window, background, names)
    assert method == "kernel_shap"
    assert max(attr, key=attr.get) == "lat" and attr["lat"] > 0.99
    assert sum(attr.values()) == pytest.approx(1.0, abs=1e-6)


def test_kernel_shap_failure_falls_back_to_the_labelled_deviation_attribution():
    boom = SimpleNamespace(KernelExplainer=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no shap")))
    window = np.array([[1.0, 5.0], [1.0, 9.0]])
    attr, method = ic.kernel_metric_attribution(lambda X: X.sum(axis=1), window, np.zeros((2, 2)), ["a", "b"],
                                                shap_module=boom)
    assert "fallback" in method and "not SHAP" in method and attr["b"] > attr["a"]


def test_explainer_result_is_merged_with_its_method_label():
    async def stub(health, sec):
        return {"health_metrics": {"cpu": 0.9}, "methods": {"health_metrics": "kernel_shap"}}
    client = InterpretationClient("http://x", explainer=stub)
    expl = run(client.explain(health_event(), sec_event(), [], T0, 1.0))
    assert expl.ok and expl.attributions["health_metrics"] == {"cpu": 0.9}
    assert expl.attributions["methods"]["health_metrics"] == "kernel_shap"
    assert expl.t0_ms == T0 and expl.causal_chain[0].startswith("T0:")


def test_explain_without_an_explainer_cannot_fail():
    expl = run(InterpretationClient("http://x").explain(health_event(), sec_event(), ["a"], None, 1.0))
    assert expl.ok and expl.causal_chain == ["a"]


def test_a_slow_or_crashing_explainer_makes_the_explanation_not_ok():
    async def slow(h, s):
        await asyncio.sleep(1)
    async def crash(h, s):
        raise RuntimeError("x")
    e1 = run(InterpretationClient("http://x", explainer=slow).explain(None, sec_event(), [], None, 0.02))
    e2 = run(InterpretationClient("http://x", explainer=crash).explain(None, sec_event(), [], None, 1.0))
    assert not e1.ok and "deadline" in e1.error and not e2.ok and "crashed" not in e2.error and e2.error


# ---- the DCM call and its deadline --------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status=200, body=None, delay=0.0):
        self.status, self.body, self.delay = status, body, delay

    async def __aenter__(self):
        await asyncio.sleep(self.delay)
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self.body


class FakeSession:
    response = FakeResponse()
    sent = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, json=None, timeout=None):
        FakeSession.sent = (url, json)
        return FakeSession.response


@pytest.fixture
def fake_http(monkeypatch):
    monkeypatch.setattr(ic.aiohttp, "ClientSession", FakeSession)
    return FakeSession


def correlate(deadline=1.0):
    return run(InterpretationClient("http://dcm").correlate(
        health_event(field_attribution_json=json.dumps({"spec.cpu": 0.9})), sec_event(), [0.1], [0.2], deadline))


def test_dcm_call_ok_sends_the_field_attribution(fake_http):
    fake_http.response = FakeResponse(200, {"correlation_score": 0.8, "compound_flag": True, "causal_chain": []})
    res = correlate()
    assert res.ok and res.data["compound_flag"] is True
    url, body = fake_http.sent
    assert url == "http://dcm/dcm/correlate" and body["field_attribution"] == {"spec.cpu": 0.9}


def test_dcm_answer_later_than_the_deadline_is_not_ok(fake_http):
    fake_http.response = FakeResponse(200, {"correlation_score": 0.8, "compound_flag": True}, delay=0.5)
    res = correlate(deadline=0.05)
    assert not res.ok and "deadline" in res.error


@pytest.mark.parametrize("response", [FakeResponse(503, {}), FakeResponse(200, {"nl_summary": "x"}),
                                      FakeResponse(200, ["not", "a", "dict"])])
def test_dcm_error_or_malformed_answer_is_not_ok(fake_http, response):
    fake_http.response = response
    assert not correlate().ok


def test_dcm_connection_error_is_not_ok(monkeypatch):
    class Down(FakeSession):
        def post(self, *a, **k):
            raise ConnectionError("refused")
    monkeypatch.setattr(ic.aiohttp, "ClientSession", Down)
    res = correlate()
    assert not res.ok and "refused" in res.error


def test_fusion_image_needs_neither_torch_nor_shap_at_import():
    # Dockerfile.fusion installs neither: the module must import without them
    src = open(ic.__file__, encoding="utf-8").read().split("def kernel_metric_attribution")[0]
    assert "import torch" not in src and "\nimport shap" not in src and "from models" not in src
