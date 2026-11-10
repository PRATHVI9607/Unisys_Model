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

import torch
from fastapi import HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


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


def health_payload(status: dict, extra: dict = None):
    """Body and HTTP status for /health."""
    ok = bool(status.get("loaded"))
    body = {"status": "ok" if ok else "unavailable", "model_version": "v4.0.0",
            "model_loaded": ok, "random_weights": bool(status.get("random_weights")),
            "error": status.get("error")}
    body.update(extra or {})
    return JSONResponse(body, status_code=200 if ok else 503)


def require_ready(status: dict):
    """Call at the top of every score endpoint."""
    if not status.get("loaded"):
        raise HTTPException(status_code=503, detail=status.get("error") or "model not loaded")
