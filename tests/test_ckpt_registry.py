from pathlib import Path
from tempfile import TemporaryDirectory

import torch
import yaml

from services import ckpt

ROOT = Path(__file__).resolve().parents[1]


class _Model:
    def __init__(self):
        self.value = torch.tensor(0)

    def state_dict(self):
        return {"value": self.value}

    def load_state_dict(self, state):
        self.value = state["value"].clone() if isinstance(state["value"], torch.Tensor) else state["value"]
        if self.value == "invalid":
            raise ValueError("invalid state")


class _Response:
    def __init__(self):
        self.closed = False
        self.released = False
        self.reads = 0

    def read(self, size):
        self.reads += 1
        return b"checkpoint" if self.reads == 1 else b""

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


class _Client:
    def __init__(self, response=None, error=None):
        self.response = response or _Response()
        self.error = error
        self.request = None

    def get_object(self, **kwargs):
        self.request = kwargs
        if self.error:
            raise self.error
        return self.response


def _registry_env(object_name="models/health/model.pt"):
    return {
        "MODEL_REGISTRY_OBJECT": object_name,
        "MODEL_REGISTRY_BUCKET": "model-bucket",
        "MINIO_ENDPOINT": "http://minio:9000",
        "MINIO_ACCESS_KEY": "registry-user",
        "MINIO_SECRET_KEY": "registry-secret",
    }


def test_load_model_checkpoint_uses_registry_object_and_cleans_temp(monkeypatch):
    model = _Model()
    client = _Client()
    constructed = {}

    def factory(endpoint, **kwargs):
        constructed.update(endpoint=endpoint, **kwargs)
        return client

    loaded_paths = []

    def torch_load(path, map_location):
        loaded_paths.append(path)
        return {"value": torch.tensor(7)}

    monkeypatch.setattr(ckpt.torch, "load", torch_load)
    status = ckpt.load_model_checkpoint(model, "baked.pt", "health", _registry_env(), factory)

    assert status["loaded"] is True
    assert status["source"] == "minio"
    assert status["checkpoint"] == "models/health/model.pt"
    assert model.value.item() == 7
    assert constructed == {
        "endpoint": "minio:9000",
        "access_key": "registry-user",
        "secret_key": "registry-secret",
        "secure": False,
    }
    assert client.request == {"bucket_name": "model-bucket", "object_name": "models/health/model.pt"}
    assert client.response.closed and client.response.released
    assert not Path(loaded_paths[0]).exists()


def test_registry_download_error_uses_baked_checkpoint(monkeypatch):
    with TemporaryDirectory(prefix=".r1-test-", dir=ROOT) as temp_dir:
        baked = Path(temp_dir) / "baked.pt"
        baked.write_bytes(b"baked")
        model = _Model()
        client = _Client(error=RuntimeError("not found"))
        monkeypatch.setattr(ckpt.torch, "load", lambda path, map_location: {"value": torch.tensor(3)})

        status = ckpt.load_model_checkpoint(
            model, str(baked), "health", _registry_env(), lambda endpoint, **kwargs: client
        )

        assert status["loaded"] is True
        assert status["source"] == "baked_in"
        assert model.value.item() == 3


def test_invalid_registry_checkpoint_restores_model_then_falls_back(monkeypatch):
    with TemporaryDirectory(prefix=".r1-test-", dir=ROOT) as temp_dir:
        baked = Path(temp_dir) / "baked.pt"
        baked.write_bytes(b"baked")
        model = _Model()
        client = _Client()

        def torch_load(path, map_location):
            if Path(path).name == "baked.pt":
                return {"value": torch.tensor(5)}
            return {"value": "invalid"}

        monkeypatch.setattr(ckpt.torch, "load", torch_load)
        status = ckpt.load_model_checkpoint(
            model, str(baked), "health", _registry_env(), lambda endpoint, **kwargs: client
        )

        assert status["source"] == "baked_in"
        assert model.value.item() == 5


def test_missing_registry_credentials_uses_baked_checkpoint(monkeypatch):
    with TemporaryDirectory(prefix=".r1-test-", dir=ROOT) as temp_dir:
        baked = Path(temp_dir) / "baked.pt"
        baked.write_bytes(b"baked")
        model = _Model()
        env = {"MODEL_REGISTRY_OBJECT": "models/health/model.pt"}
        monkeypatch.setattr(ckpt.torch, "load", lambda path, map_location: {"value": torch.tensor(9)})

        status = ckpt.load_model_checkpoint(model, str(baked), "health", env)

        assert status["source"] == "baked_in"
        assert model.value.item() == 9


def test_model_server_manifests_use_optional_existing_registry_secret():
    manifest_paths = [
        ROOT / "k8s/health-model-deployment.yaml",
        ROOT / "k8s/security-model-deployment.yaml",
        ROOT / "k8s/dcm-deployment.yaml",
    ]
    for path in manifest_paths:
        workload = next(yaml.safe_load_all(path.read_text()))
        env = {item["name"]: item for item in workload["spec"]["template"]["spec"]["containers"][0]["env"]}
        assert env["MODEL_REGISTRY_OBJECT"]["value"]
        for name, key in (("MINIO_ACCESS_KEY", "access-key"), ("MINIO_SECRET_KEY", "secret-key")):
            secret_ref = env[name]["valueFrom"]["secretKeyRef"]
            assert secret_ref["name"] == "kubeheal-minio-client"
            assert secret_ref["key"] == key
            assert secret_ref["optional"] is True
