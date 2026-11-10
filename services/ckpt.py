"""
Checkpoint loading shared by the three model servers (fail closed).
===================================================================
A missing or unloadable checkpoint means the server is NOT ready: /health answers 503 with
model_loaded=false and every score endpoint answers 503. Random weights are only served when
ALLOW_RANDOM_WEIGHTS=true is set explicitly (development and unit tests), and /health then
reports random_weights=true so it is never mistaken for a trained model.
"""

import logging
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import torch
from fastapi import HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


MODEL_FORMATS = ("pt", "onnx")


def model_format(env=None) -> str:
    """Serving format from MODEL_FORMAT. Default and empty value: `pt` (the current behaviour).

    An unknown value raises ValueError so callers can fail closed instead of guessing.
    """
    env = os.environ if env is None else env
    value = (env.get("MODEL_FORMAT") or "pt").strip().lower()
    if value not in MODEL_FORMATS:
        raise ValueError(f"MODEL_FORMAT must be one of {MODEL_FORMATS}, got {value!r}")
    return value


def not_ready_status(name: str, error: str) -> dict:
    """Status dict for a server that must answer 503 (same shape as load_checkpoint)."""
    logger.error(f"{name}: {error} - failing closed (503)")
    return {"loaded": False, "random_weights": False, "checkpoint": None, "error": error, "source": None}


def pt_only_status(name: str, env=None):
    """For servers whose ONNX export is not a drop-in (it drops outputs the server returns).

    Returns None when serving `.pt` is what is configured; otherwise a not-ready status.
    """
    try:
        fmt = model_format(env)
    except ValueError as exc:
        return not_ready_status(name, str(exc))
    if fmt == "pt":
        return None
    return not_ready_status(
        name, f"MODEL_FORMAT={fmt} is not supported for {name}: its ONNX export drops outputs "
              f"(embeddings or attributions) that this server returns; serve the .pt checkpoint")


def load_onnx_session(path: str, name: str, ort_module=None):
    """Load an ONNX file into an onnxruntime session (CPU). Fails closed: returns (status, None)
    on a missing file, a missing onnxruntime, or a load error. Never falls back to random weights
    and never silently falls back to `.pt`."""
    status = {"loaded": False, "random_weights": False, "checkpoint": path, "error": None, "source": None}
    if not os.path.exists(path):
        status["error"] = f"onnx file not found: {path}"
        logger.error(f"{name}: {status['error']} - failing closed (503)")
        return status, None
    try:
        ort = ort_module
        if ort is None:
            import onnxruntime as ort
        session = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    except Exception as exc:
        status["error"] = f"onnx load failed: {exc}"
        logger.error(f"{name}: {status['error']} - failing closed (503)")
        return status, None
    status["loaded"] = True
    status["source"] = "onnx"
    logger.info(f"Loaded {name} from ONNX {path}")
    return status, session


def allow_random_weights() -> bool:
    return os.environ.get("ALLOW_RANDOM_WEIGHTS", "false").strip().lower() == "true"


def load_checkpoint(model, path: str, name: str) -> dict:
    """Load a state dict into `model`. Returns the status dict kept in the server STATE."""
    status = {"loaded": False, "random_weights": False, "checkpoint": path, "error": None}
    if os.path.exists(path):
        try:
            model.load_state_dict(torch.load(path, map_location="cpu"))
            status["loaded"] = True
            logger.info(f"Loaded {name} from {path}")
        except Exception as e:
            status["error"] = f"checkpoint load failed: {e}"
    else:
        status["error"] = f"checkpoint not found: {path}"
    if not status["loaded"]:
        if allow_random_weights():
            status["loaded"] = True
            status["random_weights"] = True
            logger.warning(f"{name}: {status['error']} - serving RANDOM weights "
                           f"because ALLOW_RANDOM_WEIGHTS=true")
        else:
            logger.error(f"{name}: {status['error']} - failing closed (503)")
    return status


def _download_registry_checkpoint(env, client_factory=None, object_name=None):
    object_name = (object_name or env.get("MODEL_REGISTRY_OBJECT") or "").strip()
    if not object_name:
        return None
    endpoint = env.get("MINIO_ENDPOINT", "minio.kubeheal.svc.cluster.local:9000")
    access_key = env.get("MINIO_ACCESS_KEY")
    secret_key = env.get("MINIO_SECRET_KEY")
    if not access_key or not secret_key:
        logger.warning("Model registry is configured but MinIO credentials are unavailable; using baked-in checkpoint")
        return None

    parsed = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
    host = parsed.netloc or parsed.path
    if not parsed.hostname:
        logger.warning("Model registry endpoint is invalid; using baked-in checkpoint")
        return None

    local_path = None
    try:
        if client_factory is None:
            from minio import Minio
            client_factory = Minio
        client = client_factory(
            host,
            access_key=access_key,
            secret_key=secret_key,
            secure=(parsed.scheme == "https") if parsed.scheme else False,
        )
        bucket = env.get("MODEL_REGISTRY_BUCKET") or env.get("MINIO_BUCKET", "kubeheal-ledger")
        response = client.get_object(bucket_name=bucket, object_name=object_name)
        try:
            with tempfile.NamedTemporaryFile(prefix="kubeheal-model-", suffix=Path(object_name).suffix or ".pt",
                                             delete=False) as output:
                local_path = output.name
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
        finally:
            response.close()
            release = getattr(response, "release_conn", None)
            if release:
                release()
        return local_path
    except Exception as exc:
        if local_path:
            try:
                os.unlink(local_path)
            except OSError:
                pass
        logger.warning("Could not download model registry object %s (%s); using baked-in checkpoint",
                       object_name, type(exc).__name__)
        return None


def load_model_checkpoint(model, fallback_path: str, name: str, env=None, client_factory=None) -> dict:
    """Try the configured MinIO model object, then fall back to the baked-in checkpoint."""
    env = os.environ if env is None else env
    downloaded_path = _download_registry_checkpoint(env, client_factory)
    if downloaded_path:
        initial_state = {key: value.detach().clone() for key, value in model.state_dict().items()}
        try:
            registry_status = load_checkpoint(model, downloaded_path, name)
            if registry_status["loaded"] and not registry_status["random_weights"]:
                registry_status.update({"source": "minio", "checkpoint": env["MODEL_REGISTRY_OBJECT"]})
                return registry_status
        finally:
            try:
                os.unlink(downloaded_path)
            except OSError:
                logger.warning("Could not remove temporary model checkpoint %s", downloaded_path)
        model.load_state_dict(initial_state)
        logger.warning("Model registry checkpoint was unusable; trying baked-in checkpoint")

    status = load_checkpoint(model, fallback_path, name)
    status["source"] = "baked_in" if status["loaded"] and not status["random_weights"] else None
    return status


def expected_preprocess_version(status: dict, fallback_path: str, env=None, client_factory=None):
    """Preprocessing version the loaded Health Model checkpoint expects, from its sidecar file: next to the
    baked-in checkpoint, or the registry object `<stem>.preprocess.json` for a MinIO checkpoint. None when
    the sidecar cannot be read (the caller then refuses to start)."""
    from models.health_model.preprocess import parse_sidecar, read_sidecar_version, sidecar_object_name
    env = os.environ if env is None else env
    if status.get("source") == "minio":
        obj = sidecar_object_name(env.get("MODEL_REGISTRY_OBJECT", ""))
        local = _download_registry_checkpoint(env, client_factory, object_name=obj)
        if not local:
            return None
        try:
            return parse_sidecar(Path(local).read_text(encoding="utf-8"))
        finally:
            try:
                os.unlink(local)
            except OSError:
                pass
    return read_sidecar_version(fallback_path)


def health_payload(status: dict, extra: dict = None):
    """Body and HTTP status for /health."""
    ok = bool(status.get("loaded"))
    body = {"status": "ok" if ok else "unavailable", "model_version": "v4.0.0",
            "model_loaded": ok, "random_weights": bool(status.get("random_weights")),
            "checkpoint_source": status.get("source"), "error": status.get("error")}
    body.update(extra or {})
    return JSONResponse(body, status_code=200 if ok else 503)


def require_ready(status: dict):
    """Call at the top of every score endpoint."""
    if not status.get("loaded"):
        raise HTTPException(status_code=503, detail=status.get("error") or "model not loaded")
