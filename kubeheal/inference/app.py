"""KubeHeal inference service (port 8000).

Loads the health and security bundles from KUBEHEAL_MODEL_DIR at startup. A
task whose bundle is missing or invalid answers 503 and /readyz stays 503:
the service never serves untrained weights.

    uvicorn kubeheal.inference.app:app --port 8000
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from kubeheal.contracts import SECURITY_PUBLISH_RISK, Prediction
from kubeheal.features.health import HEALTH_FEATURES
from kubeheal.features.security import SECURITY_FEATURES
from kubeheal.ml.bundle import ModelBundle

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("kubeheal.inference")
TASKS = ("health", "security")
# What the agents send per task. A bundle may list fewer (trained with --drop-features: the rest is ignored) or
# names no longer sent (served as missing, but /readyz reports the mismatch).
SENT = {"health": frozenset(HEALTH_FEATURES), "security": frozenset(SECURITY_FEATURES)}
# Only rows the agent can publish are explained; every health assessment is published, so all are explained.
EXPLAIN_RISK = {"health": 0.0, "security": SECURITY_PUBLISH_RISK}

REQUESTS = Counter("kubeheal_inference_requests_total", "Prediction requests", ["task", "status"])
LATENCY = Histogram("kubeheal_inference_latency_seconds", "Prediction latency", ["task"],
                    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25))
LABELS = Counter("kubeheal_inference_predictions_total", "Predicted labels", ["task", "label"])

FeatureValue = Annotated[float, Field(allow_inf_nan=False)] | None


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    features: Annotated[dict[Annotated[str, Field(max_length=64)], FeatureValue], Field(max_length=200)]
    request_id: Annotated[str, Field(max_length=128)] | None = None


MAX_BATCH = 256


class PredictBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: Annotated[list[PredictRequest], Field(min_length=1, max_length=MAX_BATCH)]


def load_bundles(model_dir: Path) -> dict[str, ModelBundle]:
    bundles = {}
    for task in TASKS:
        try:
            bundles[task] = ModelBundle.load(model_dir / task)
            log.info("loaded %s model %s", task, bundles[task].meta["version"])
        except Exception:
            log.exception("no usable %s bundle in %s; its predictions will return 503", task, model_dir / task)
    return bundles


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.bundles = load_bundles(Path(os.environ.get("KUBEHEAL_MODEL_DIR", "models")))
    yield


app = FastAPI(title="KubeHeal inference", version="5.0.0", lifespan=lifespan)
MAX_BODY_BYTES = 64 * 1024   # a full feature dict is < 4 KiB
MAX_BATCH_BODY_BYTES = MAX_BATCH * 4 * 1024


class BodyLimit:
    """Refuse huge bodies before they are buffered (the 200-key limit applies only after parsing): by
    Content-Length up front, and by counting received bytes for chunked bodies that carry none."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cap = MAX_BATCH_BODY_BYTES if scope["path"].endswith("/predict_batch") else MAX_BODY_BYTES
        length = dict(scope["headers"]).get(b"content-length")
        if length is not None and (not length.isdigit() or int(length) > cap):
            return await JSONResponse(status_code=413, content={"detail": "request body too large"})(scope, receive, send)
        seen = 0

        async def capped():
            nonlocal seen
            msg = await receive()
            seen += len(msg.get("body", b""))
            if seen > cap:     # raised inside body parsing: FastAPI re-raises HTTPException → 413 response
                raise StarletteHTTPException(413, "request body too large")
            return msg
        return await self.app(scope, capped, send)


app.add_middleware(BodyLimit)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Drop the echoed input: a rejected Infinity/NaN would make the default 422 body itself unserialisable (500).
    detail = [{k: e[k] for k in ("type", "loc", "msg") if k in e} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": detail})


def _predict(task: str, items: list[PredictRequest]) -> list[Prediction]:
    bundle = app.state.bundles.get(task)
    if bundle is None:
        REQUESTS.labels(task, "unavailable").inc()
        raise HTTPException(503, f"{task} model not loaded")
    known = set(bundle.features)
    unknown = sorted(set().union(*(r.features for r in items)) - known - SENT[task])
    if unknown:
        REQUESTS.labels(task, "invalid").inc()
        raise HTTPException(422, f"unknown features: {unknown}")
    t0 = time.perf_counter()
    # Names the bundle does not list (older bundle, --drop-features) are ignored; names it lists that are no longer
    # sent (renamed rename_* features) are absent from the row, which the bundle reads as missing (None).
    rows = [{k: v for k, v in r.features.items() if k in known} for r in items]
    preds = bundle.predict_batch(rows, EXPLAIN_RISK[task])
    LATENCY.labels(task).observe(time.perf_counter() - t0)
    REQUESTS.labels(task, "ok").inc(len(preds))
    for pred in preds:
        LABELS.labels(task, pred.label).inc()
    return preds


# Sync handlers: a ~1 ms CPU-bound predict runs in the threadpool instead of blocking the event loop.
@app.post("/v1/health/predict", response_model=Prediction)
def predict_health(req: PredictRequest) -> Prediction:
    return _predict("health", [req])[0]


@app.post("/v1/security/predict", response_model=Prediction)
def predict_security(req: PredictRequest) -> Prediction:
    return _predict("security", [req])[0]


@app.post("/v1/health/predict_batch", response_model=list[Prediction])
def predict_health_batch(req: PredictBatchRequest) -> list[Prediction]:
    return _predict("health", req.items)


@app.post("/v1/security/predict_batch", response_model=list[Prediction])
def predict_security_batch(req: PredictBatchRequest) -> list[Prediction]:
    return _predict("security", req.items)


# async: probes run on the event loop, never queued behind CPU-bound predictions in the threadpool.
@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz(response: Response) -> dict:
    bundles = app.state.bundles
    # A bundle feature the agents never send would be scored as missing on every request: not ready.
    unsent = {t: sorted(set(b.features) - SENT[t]) for t, b in bundles.items() if set(b.features) - SENT[t]}
    ready = all(t in bundles for t in TASKS) and not unsent
    if not ready:
        response.status_code = 503
    return {"ready": ready, "models": {t: bundles[t].meta["version"] if t in bundles else None for t in TASKS},
            "unsent_features": unsent}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
