"""P9-H7: serve ONNX or .pt by config (MODEL_FORMAT). Default stays .pt; failures stay closed."""
import importlib
import sys
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import ckpt  # noqa: E402

DCM_BODY = {"health_embedding": [0.1] * 128, "security_embedding": [0.2] * 64}


class StubSession:
    """Stands in for onnxruntime.InferenceSession; returns a fixed score."""

    def __init__(self, score=0.75):
        self.score = score
        self.feeds = None

    def run(self, _outputs, feeds):
        self.feeds = feeds
        return [np.array([[self.score]], dtype=np.float32)]


class StubOrt:
    def __init__(self, session=None, error=None):
        self._session, self._error = session, error

    def InferenceSession(self, path, providers=None):  # noqa: N802 (mirrors the onnxruntime API)
        if self._error:
            raise self._error
        return self._session


def test_model_format_default_and_values():
    assert ckpt.model_format({}) == "pt"
    assert ckpt.model_format({"MODEL_FORMAT": ""}) == "pt"
    assert ckpt.model_format({"MODEL_FORMAT": " ONNX "}) == "onnx"
    with pytest.raises(ValueError):
        ckpt.model_format({"MODEL_FORMAT": "tflite"})


def test_load_onnx_session_fails_closed(tmp_path):
    missing, session = ckpt.load_onnx_session(str(tmp_path / "nope.onnx"), "t")
    assert session is None and missing["loaded"] is False and "not found" in missing["error"]
    f = tmp_path / "m.onnx"
    f.write_bytes(b"x")
    status, session = ckpt.load_onnx_session(str(f), "t", ort_module=StubOrt(error=RuntimeError("bad graph")))
    assert session is None and status["loaded"] is False and "bad graph" in status["error"]
    status, session = ckpt.load_onnx_session(str(f), "t", ort_module=StubOrt(session=StubSession()))
    assert status["loaded"] is True and status["source"] == "onnx" and session is not None


@pytest.fixture
def dcm():
    return importlib.import_module("services.dcm_server.main")


def test_dcm_onnx_served_through_stub(dcm, monkeypatch, tmp_path):
    f = tmp_path / "dcm.onnx"
    f.write_bytes(b"x")
    stub = StubSession(score=0.75)
    monkeypatch.setenv("MODEL_FORMAT", "onnx")
    monkeypatch.setenv("MODEL_ONNX_PATH", str(f))
    monkeypatch.setattr(ckpt, "load_onnx_session",
                        lambda path, name, ort_module=None: ({"loaded": True, "random_weights": False,
                                                              "checkpoint": path, "error": None, "source": "onnx"},
                                                             stub))
    monkeypatch.setattr(dcm, "load_onnx_session", ckpt.load_onnx_session)
    dcm._load_model()
    c = TestClient(dcm.app)
    assert c.get("/health").status_code == 200
    body = c.post("/dcm/correlate", json=DCM_BODY).json()
    assert body["correlation_score"] == pytest.approx(0.75)
    assert stub.feeds["health_embedding"].shape == (1, 128)
    assert stub.feeds["security_embedding"].shape == (1, 64)


def test_dcm_onnx_missing_file_fails_closed(dcm, monkeypatch, tmp_path):
    monkeypatch.setenv("MODEL_FORMAT", "onnx")
    monkeypatch.setenv("MODEL_ONNX_PATH", str(tmp_path / "absent.onnx"))
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    # A present .pt must NOT rescue a missing ONNX: no silent format fallback.
    monkeypatch.setenv("MODEL_PATH", str(ROOT / "models/dcm/checkpoints/best_dcm.pt"))
    dcm._load_model()
    c = TestClient(dcm.app)
    assert c.get("/health").status_code == 503
    assert c.post("/dcm/correlate", json=DCM_BODY).status_code == 503


def test_invalid_format_fails_closed_everywhere(monkeypatch):
    monkeypatch.setenv("MODEL_FORMAT", "bogus")
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    for name in ("dcm_server", "health_model_server", "security_model_server"):
        mod = importlib.import_module(f"services.{name}.main")
        mod._load_model()
        assert TestClient(mod.app).get("/health").status_code == 503


@pytest.mark.parametrize("name", ["health_model_server", "security_model_server"])
def test_health_and_security_refuse_onnx_explicitly(name, monkeypatch):
    mod = importlib.import_module(f"services.{name}.main")
    monkeypatch.setenv("MODEL_FORMAT", "onnx")
    monkeypatch.setenv("ALLOW_RANDOM_WEIGHTS", "true")  # must not turn the refusal into a pass
    mod._load_model()
    r = TestClient(mod.app).get("/health")
    assert r.status_code == 503
    assert "not supported" in r.json()["error"]


@pytest.mark.parametrize("fmt", [None, "", "pt"])
def test_default_pt_behaviour_unchanged(fmt, monkeypatch, tmp_path):
    mod = importlib.import_module("services.dcm_server.main")
    if fmt is None:
        monkeypatch.delenv("MODEL_FORMAT", raising=False)
    else:
        monkeypatch.setenv("MODEL_FORMAT", fmt)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "missing.pt"))
    monkeypatch.setenv("ALLOW_RANDOM_WEIGHTS", "true")
    mod._load_model()
    h = TestClient(mod.app).get("/health").json()
    assert h["random_weights"] is True and h["model_loaded"] is True


def test_dcm_onnx_parity_with_torch(tmp_path):
    """Export parity for the one drop-in server: ONNX score == torch score (random weights, small)."""
    ort = pytest.importorskip("onnxruntime")
    import torch
    from models.dcm.cross_modal_attention import CrossModalAttention
    torch.manual_seed(0)
    m = CrossModalAttention().eval()

    class W(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.m = inner

        def forward(self, h, s):  # same wrapper as models/export_dcm.py
            return self.m(h, s)[0]

    path = tmp_path / "dcm.onnx"
    try:
        torch.onnx.export(W(m).eval(), (torch.zeros(1, 128), torch.zeros(1, 64)), str(path), opset_version=17,
                          input_names=["health_embedding", "security_embedding"],
                          output_names=["correlation_score"],
                          dynamic_axes={"health_embedding": {0: "batch"}, "security_embedding": {0: "batch"},
                                        "correlation_score": {0: "batch"}})
    except Exception as exc:  # exporter dependencies missing in this environment
        pytest.skip(f"torch.onnx.export unavailable here: {exc}")
    status, session = ckpt.load_onnx_session(str(path), "dcm", ort_module=ort)
    assert status["loaded"]
    dcm = importlib.import_module("services.dcm_server.main")
    onnx_model = dcm.OnnxCorrelator(session)
    rng = np.random.default_rng(1)
    for _ in range(3):
        h = rng.normal(size=128).astype(np.float32)
        s = rng.normal(size=64).astype(np.float32)
        assert abs(onnx_model.correlate(h, s) - m.correlate(h, s)) <= 1e-3
