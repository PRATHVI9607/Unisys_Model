"""
Client of the inference service's security route (V5-S2)
========================================================
`POST {INFERENCE_URL}/v1/security/predict` with `{"features": {name: float|null}}`. The service restricts the
dict to the names the shipped bundle lists (the code emits more), so the agent sends the full feature dict.

Fail closed: a timeout, a connection error, any non-200 answer (503 = no bundle loaded), a body that is not JSON
or an answer that is not a valid prediction gives `None`. There is no fallback model and no fabricated score; the
caller then reports `model_scored=false`. A valid answer has a finite risk in [0, 1], a label of the security
label set, a prediction set that is a list of those labels, a boolean `uncertain`, and a string `model_version`.
"""

import logging
import math
import os
import time
from typing import Any, Dict, List, Optional

import aiohttp

from agents.common.metrics import KubeHealMetrics
from kubeheal.contracts import SECURITY_LABELS

logger = logging.getLogger(__name__)

DEFAULT_INFERENCE_URL = "http://kubeheal-inference:8000"
SECURITY_PATH = "/v1/security/predict"
DEFAULT_TIMEOUT_S = 5.0          # the timeout of the old Security Model call, kept (chosen, not measured)


def finite_or_none(value) -> Optional[float]:
    """float(value) when it is a finite number, else None (JSON has no NaN; the service answers 422 to one)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def clean_features(features: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """The request's feature dict: every value a finite float or None."""
    return {str(k): finite_or_none(v) for k, v in features.items()}


def validate_prediction(raw: Any) -> Optional[Dict[str, Any]]:
    """The prediction as a plain dict, or None when the answer is not a valid one."""
    if not isinstance(raw, dict):
        return None
    risk = finite_or_none(raw.get("risk"))
    label, pset, version = raw.get("label"), raw.get("prediction_set"), raw.get("model_version")
    if (risk is None or not 0.0 <= risk <= 1.0 or label not in SECURITY_LABELS
            or not isinstance(pset, list) or any(x not in SECURITY_LABELS for x in pset)
            or not isinstance(raw.get("uncertain"), bool) or not isinstance(version, str)):
        return None
    factors: List[Dict[str, Any]] = []
    for item in raw.get("top_factors") or []:
        if isinstance(item, dict) and isinstance(item.get("feature"), str) \
                and finite_or_none(item.get("contribution")) is not None:
            factors.append({"feature": item["feature"], "value": finite_or_none(item.get("value")),
                            "contribution": float(item["contribution"])})
    return {"risk": risk, "label": label, "prediction_set": list(pset), "uncertain": raw["uncertain"],
            "model_version": version, "top_factors": factors}


class InferenceClient:
    """`predict(features)` returns the validated prediction dict or None (fail closed). `last_issue` says why the
    last call returned None ("unreachable", "http_<status>", "invalid_response"), "" after a good answer.
    `poster(url, body, timeout_s)` is injectable for tests: it returns (status, parsed JSON or None)."""

    def __init__(self, url: Optional[str] = None, timeout_s: Optional[float] = None, poster=None,
                 metrics: Optional[KubeHealMetrics] = None):
        self.url = (url or os.environ.get("INFERENCE_URL") or DEFAULT_INFERENCE_URL).rstrip("/")
        self.timeout_s = float(timeout_s if timeout_s is not None
                               else os.environ.get("INFERENCE_TIMEOUT_S", DEFAULT_TIMEOUT_S))
        self._poster = poster or self._http_post
        self.metrics = metrics
        self.last_issue = ""
        self.rejected: Dict[str, int] = {}          # unusable answers by reason

    async def _http_post(self, url: str, body: Dict, timeout_s: float):
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=body, timeout=aiohttp.ClientTimeout(total=timeout_s)) as resp:
                if resp.status != 200:
                    return resp.status, None
                try:
                    return resp.status, await resp.json()
                except (aiohttp.ContentTypeError, ValueError):
                    return resp.status, None

    def _reject(self, reason: str) -> None:
        self.last_issue = reason
        self.rejected[reason] = self.rejected.get(reason, 0) + 1
        logger.warning("inference service answer not usable (%s): no score; %d for this reason so far",
                       reason, self.rejected[reason])

    async def predict(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        started = time.perf_counter()
        try:
            status, body = await self._poster(f"{self.url}{SECURITY_PATH}", {"features": clean_features(features)},
                                              self.timeout_s)
        except Exception as e:            # timeout, connection refused, DNS, anything: fail closed
            self._reject("unreachable")
            logger.debug("inference call failed: %s", e)
            return None
        finally:
            if self.metrics is not None:
                self.metrics.observe_model_latency("security", time.perf_counter() - started)
        if status != 200:
            self._reject(f"http_{status}")
            return None
        pred = validate_prediction(body)
        if pred is None:
            self._reject("invalid_response")
            return None
        self.last_issue = ""
        return pred
