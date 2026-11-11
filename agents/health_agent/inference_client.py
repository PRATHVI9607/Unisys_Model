"""Client of the inference service for the Health Agent (V5-D4).

POST {INFERENCE_URL}/v1/health/predict with {"features": {name: float|null}}. The service restricts the
features to what the shipped bundle was trained on, so the full feature dict is sent.

Fail closed: the answer counts only when it is HTTP 200 and parses as `kubeheal.contracts.Prediction`.
A timeout, a connection error, a 4xx or 5xx (503 means the bundle is not loaded) or a malformed body is
`None`: no score. This module never invents a score and has no fallback.
"""

from __future__ import annotations

import logging
import math
import os

import aiohttp
from pydantic import ValidationError

from kubeheal.contracts import Prediction

log = logging.getLogger("kubeheal.health.inference")

DEFAULT_INFERENCE_URL = "http://kubeheal-inference:8000"
# Chosen, not measured. The agent publishes a model_unavailable notice when the service does not answer
# within this time; configurable with INFERENCE_TIMEOUT_S.
DEFAULT_TIMEOUT_S = 5.0
PREDICT_PATH = "/v1/health/predict"


def inference_url_from_env() -> str:
    return (os.environ.get("INFERENCE_URL") or DEFAULT_INFERENCE_URL).rstrip("/")


def timeout_from_env() -> float:
    raw = os.environ.get("INFERENCE_TIMEOUT_S")
    if raw is None:
        return DEFAULT_TIMEOUT_S
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("INFERENCE_TIMEOUT_S must be a positive number") from exc
    if value <= 0 or not math.isfinite(value):
        raise ValueError("INFERENCE_TIMEOUT_S must be a positive finite number")
    return value


def finite_features(features: dict) -> dict[str, float | None]:
    """The service answers 422 to NaN and Infinity (which would look like an outage): send None instead."""
    out: dict[str, float | None] = {}
    for name, value in features.items():
        if value is None:
            out[name] = None
            continue
        try:
            f = float(value)
        except (TypeError, ValueError):
            out[name] = None
            continue
        out[name] = f if math.isfinite(f) else None
    return out


async def predict_health(session: aiohttp.ClientSession, base_url: str, features: dict,
                         timeout_s: float = DEFAULT_TIMEOUT_S) -> Prediction | None:
    """The service's Prediction for these features, or None when there is no usable answer."""
    try:
        async with session.post(f"{base_url.rstrip('/')}{PREDICT_PATH}",
                                json={"features": finite_features(features)},
                                timeout=aiohttp.ClientTimeout(total=timeout_s)) as resp:
            if resp.status != 200:
                log.warning("inference service answered HTTP %s; no score", resp.status)
                return None
            return Prediction.model_validate(await resp.json())
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError, ValidationError) as exc:
        # asyncio.TimeoutError is TimeoutError on Python 3.11; ValueError covers a non-JSON body.
        log.warning("inference service unusable: %r; no score", exc)
        return None
