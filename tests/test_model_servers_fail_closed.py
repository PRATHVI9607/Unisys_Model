"""F1: model servers fail closed. F9: which conformal file is used is explicit and tested."""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SERVERS = [
    ("services.health_model_server.main", "/health/score",
     {"old_spec": {}, "new_spec": {}, "metrics": [[0.0] * 15] * 60}),
    ("services.security_model_server.main", "/security/score",
     {"events": [{"syscall": "write", "fd_path": "/data/f"}], "entropy_series": [2.0] * 30,
      "early_signals": {}}),
    ("services.dcm_server.main", "/dcm/correlate",
     {"health_embedding": [0.0] * 128, "security_embedding": [0.0] * 64}),
]


def _module(name):
    import importlib
    return importlib.import_module(name)


@pytest.mark.parametrize("modname,path,body", SERVERS)
def test_missing_checkpoint_fails_closed(modname, path, body, monkeypatch, tmp_path):
    mod = _module(modname)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "does_not_exist.pt"))
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    mod._load_model()
    c = TestClient(mod.app)
    r = c.get("/health")
    assert r.status_code == 503
    assert r.json()["model_loaded"] is False
    assert c.post(path, json=body).status_code == 503


@pytest.mark.parametrize("modname,path,body", SERVERS)
def test_corrupt_checkpoint_fails_closed(modname, path, body, monkeypatch, tmp_path):
    mod = _module(modname)
    bad = tmp_path / "bad.pt"
    bad.write_bytes(b"not a checkpoint")
    monkeypatch.setenv("MODEL_PATH", str(bad))
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    mod._load_model()
    c = TestClient(mod.app)
    assert c.get("/health").status_code == 503
    assert c.post(path, json=body).status_code == 503


@pytest.mark.parametrize("modname,path,body", SERVERS)
def test_random_weights_only_with_explicit_flag(modname, path, body, monkeypatch, tmp_path):
    mod = _module(modname)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "does_not_exist.pt"))
    monkeypatch.setenv("ALLOW_RANDOM_WEIGHTS", "true")
    mod._load_model()
    c = TestClient(mod.app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["random_weights"] is True      # never mistaken for a trained model
    assert c.post(path, json=body).status_code == 200


@pytest.mark.parametrize("modname,ckpt_dir,conf_name", [
    ("services.health_model_server.main", "models/health_model/checkpoints", "health_conformal.json"),
    ("services.security_model_server.main", "models/security_model/checkpoints", "security_conformal.json"),
])
def test_server_uses_the_conformal_json_next_to_the_checkpoint(modname, ckpt_dir, conf_name, monkeypatch):
    """F9: the *_conformal.json beside the checkpoint is what the server loads. The q stored in
    *_report.json is the training-time value and is not read at serve time."""
    mod = _module(modname)
    monkeypatch.delenv("MODEL_PATH", raising=False)
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    mod._load_model()
    expected = json.loads((ROOT / ckpt_dir / conf_name).read_text())["q"]
    assert mod.STATE["conformal"].q == pytest.approx(expected)
