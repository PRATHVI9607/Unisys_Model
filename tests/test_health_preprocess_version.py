"""Preprocessing version guard: the Health Model server refuses to start (fail closed) when the checkpoint's
expected preprocessing version differs from the code's PREPROCESS_VERSION."""
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from models.health_model import preprocess as pp
from services import ckpt

CKPT = ROOT / "models" / "health_model" / "checkpoints" / "best_health_model.pt"


def test_current_behaviour_is_v1_legacy_and_the_shipped_checkpoint_declares_it():
    assert pp.PREPROCESS_VERSION == "v1-legacy"
    assert pp.read_sidecar_version(CKPT) == "v1-legacy"
    data = json.loads(pp.sidecar_path(CKPT).read_text(encoding="utf-8"))
    assert data["preprocess_version"] == pp.PREPROCESS_VERSION and data["checkpoint"] == CKPT.name


def test_check_version_is_strict():
    pp.check_version("v1-legacy")
    with pytest.raises(pp.PreprocessVersionMismatch):
        pp.check_version("v2")
    with pytest.raises(pp.PreprocessVersionMismatch):
        pp.check_version(None)
    with pytest.raises(pp.PreprocessVersionMismatch):
        pp.check_version("V1-LEGACY")


def test_sidecar_roundtrip_names_and_parsing(tmp_path):
    c = tmp_path / "model_v7.pt"
    c.write_bytes(b"x")
    out = pp.write_sidecar(c, "v2")
    assert out.name == "model_v7.preprocess.json" and pp.read_sidecar_version(c) == "v2"
    assert pp.sidecar_object_name("v4/health_model_v4.pt") == "v4/health_model_v4.preprocess.json"
    assert pp.sidecar_object_name("health.pt") == "health.preprocess.json"
    assert pp.parse_sidecar("not json") is None and pp.parse_sidecar('{"preprocess_version": ""}') is None
    assert pp.read_sidecar_version(tmp_path / "missing.pt") is None


def _server(monkeypatch, ckpt_path):
    from services.health_model_server import main as srv
    monkeypatch.setenv("MODEL_PATH", str(ckpt_path))
    monkeypatch.delenv("MODEL_REGISTRY_OBJECT", raising=False)
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    return srv


@pytest.fixture
def ckpt_copy(tmp_path):
    dst = tmp_path / "best_health_model.pt"
    shutil.copy(CKPT, dst)
    return dst


def test_server_starts_when_the_versions_match(monkeypatch, ckpt_copy):
    pp.write_sidecar(ckpt_copy)
    srv = _server(monkeypatch, ckpt_copy)
    srv._load_model()
    assert srv.STATE["status"]["loaded"] and not srv.STATE["status"]["random_weights"]


def test_server_refuses_to_start_on_a_version_mismatch(monkeypatch, ckpt_copy):
    pp.write_sidecar(ckpt_copy, "v2")
    srv = _server(monkeypatch, ckpt_copy)
    with pytest.raises(pp.PreprocessVersionMismatch, match="v2"):
        srv._load_model()


def test_server_refuses_to_start_without_a_sidecar(monkeypatch, ckpt_copy):
    srv = _server(monkeypatch, ckpt_copy)
    assert not pp.sidecar_path(ckpt_copy).exists()
    with pytest.raises(pp.PreprocessVersionMismatch, match="no preprocessing version sidecar"):
        srv._load_model()


def test_the_app_itself_does_not_start_on_a_mismatch(monkeypatch, ckpt_copy):
    from fastapi.testclient import TestClient
    pp.write_sidecar(ckpt_copy, "v2")
    srv = _server(monkeypatch, ckpt_copy)
    with pytest.raises(pp.PreprocessVersionMismatch):
        with TestClient(srv.app):
            pass


def test_random_weights_for_development_have_no_checkpoint_and_no_check(monkeypatch, tmp_path):
    srv = _server(monkeypatch, tmp_path / "nope.pt")
    monkeypatch.setenv("ALLOW_RANDOM_WEIGHTS", "true")
    srv._load_model()
    assert srv.STATE["status"]["random_weights"] is True


# ---- registry (MinIO) checkpoints: the sidecar object travels with the checkpoint object ----------------
class _Resp:
    def __init__(self, data):
        self.data, self.done = data, False

    def read(self, n):
        if self.done:
            return b""
        self.done = True
        return self.data

    def close(self):
        pass

    def release_conn(self):
        pass


def _client_factory(objects):
    class C:
        def __init__(self, *a, **k):
            pass

        def get_object(self, bucket_name, object_name):
            if object_name not in objects:
                raise KeyError(object_name)
            return _Resp(objects[object_name])
    return C


ENV = {"MODEL_REGISTRY_OBJECT": "v4/health_model_v4.pt", "MINIO_ENDPOINT": "minio:9000",
       "MINIO_ACCESS_KEY": "a", "MINIO_SECRET_KEY": "b"}


def test_registry_checkpoint_reads_its_sidecar_object():
    objs = {"v4/health_model_v4.preprocess.json": json.dumps({"preprocess_version": "v1-legacy"}).encode()}
    v = ckpt.expected_preprocess_version({"source": "minio"}, "unused.pt", ENV, _client_factory(objs))
    assert v == "v1-legacy"


def test_registry_checkpoint_without_a_sidecar_object_has_no_version():
    v = ckpt.expected_preprocess_version({"source": "minio"}, "unused.pt", ENV, _client_factory({}))
    assert v is None
    with pytest.raises(pp.PreprocessVersionMismatch):
        pp.check_version(v)


def test_trainer_and_uploader_carry_the_sidecar():
    assert "write_sidecar(ckpt)" in (ROOT / "models" / "train_health_model.py").read_text(encoding="utf-8")
    assert "sidecar_path" in (ROOT / "models" / "upload_to_registry.py").read_text(encoding="utf-8")
