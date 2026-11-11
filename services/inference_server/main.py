"""KubeHeal inference service (port 8000, V5-I2).

Serves the two shipped LightGBM bundles (health and security) from models/bundles through
`kubeheal.ml.bundle.ModelBundle`. Each answer carries the label, the risk, the split-conformal prediction set,
the `uncertain` flag (set is not a single label), the bundle version and the TreeSHAP top factors.

Fail closed: a bundle that is missing or invalid is not loaded, its predict routes answer HTTP 503 and /readyz
stays 503. There is no fallback model and no random weights.

Routes
  POST /v1/health/predict, /v1/security/predict              body {"features": {name: float|null}}
  POST /v1/health/predict_batch, /v1/security/predict_batch  body {"items": [{"features": {...}}, ...]}, 1..256 items
  GET  /healthz  liveness (always 200 while the process runs)
  GET  /readyz   200 only when BOTH bundles are loaded
  GET  /metrics  Prometheus, including kubeheal_model_inflight_requests (the queue-depth HPA signal)

Run: uvicorn services.inference_server.main:app --port 8000   (PYTHONPATH is the repo root)
Bundle directory: env KUBEHEAL_MODEL_DIR is a root holding <task>/{model.txt,meta.json}; unset means the shipped
bundles (kubeheal.ml.bundle.default_bundle_dir).
"""

from __future__ import annotations

import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from prometheus_client import Counter
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.common.metrics import KubeHealMetrics, add_inflight_middleware, add_metrics_route  # noqa: E402
from kubeheal.contracts import SECURITY_PUBLISH_RISK, Prediction  # noqa: E402
from kubeheal.ml.bundle import ModelBundle, default_bundle_dir  # noqa: E402

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("kubeheal.inference")

TASKS = ("health", "security")
MODEL_DIR_ENV = "KUBEHEAL_MODEL_DIR"
MAX_FEATURES = 200            # a full feature dict is far smaller
MAX_NAME_LEN = 64
MAX_BATCH = 256
MAX_BODY_BYTES = 64 * 1024
MAX_BATCH_BODY_BYTES = MAX_BATCH * 4 * 1024
# TreeSHAP is the CPU-heavy part. Health is explained on every row (every assessment is published); security only
# when the risk is at least SECURITY_PUBLISH_RISK (the Security Agent publishes only those windows).
EXPLAIN_RISK = {"health": 0.0, "security": SECURITY_PUBLISH_RISK}
SCORING_PATHS = [f"/v1/{t}/{suffix}" for t in TASKS for suffix in ("predict", "predict_batch")]

# Python's JSON parser accepts NaN and Infinity literals; reject them (422) and anything that is not a number.
FeatureValue = Annotated[float, Field(strict=True, allow_inf_nan=False)] | None


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    features: Annotated[dict[Annotated[str, Field(max_length=MAX_NAME_LEN)], FeatureValue],
                        Field(max_length=MAX_FEATURES)]
    request_id: Annotated[str, Field(max_length=128)] | None = None   # accepted for callers that send one, unused


class PredictBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: Annotated[list[PredictRequest], Field(min_length=1, max_length=MAX_BATCH)]


class BodyLimit:
    """Refuse huge bodies before they are buffered: by Content-Length up front, and by counting the received
    bytes of chunked bodies that carry no Content-Length."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cap = MAX_BATCH_BODY_BYTES if scope["path"].endswith("/predict_batch") else MAX_BODY_BYTES
        length = dict(scope["headers"]).get(b"content-length")
        if length is not None and (not length.isdigit() or int(length) > cap):
            return await JSONResponse(status_code=413, content={"detail": "request body too large"})(
                scope, receive, send)
        seen = 0

        async def capped():
            nonlocal seen
            msg = await receive()
            seen += len(msg.get("body", b""))
            if seen > cap:
                raise StarletteHTTPException(413, "request body too large")
            return msg

        return await self.app(scope, capped, send)


def model_root() -> Path | None:
    """The configured bundle root, or None for the shipped bundles."""
    raw = os.environ.get(MODEL_DIR_ENV, "").strip()
    return Path(raw) if raw else None


def load_bundles(root: Path | None) -> dict[str, ModelBundle]:
    """Load every bundle that loads. A task whose bundle is missing or invalid is simply absent (503)."""
    bundles: dict[str, ModelBundle] = {}
    for task in TASKS:
        directory = default_bundle_dir(task) if root is None else root / task
        try:
            bundle = ModelBundle.load(directory)
            if bundle.meta.get("task") not in (None, task):
                raise ValueError(f"{directory} holds a {bundle.meta.get('task')!r} bundle, expected {task!r}")
            bundles[task] = bundle
            log.info("loaded %s bundle %s from %s", task, bundle.meta.get("version"), directory)
        except Exception:
            log.exception("no usable %s bundle in %s: its predict routes answer 503", task, directory)
    return bundles


def create_app(root: Path | None = None) -> FastAPI:
    """Build the app. `root` overrides KUBEHEAL_MODEL_DIR (tests). Metrics live in a per-app registry."""
    metrics = KubeHealMetrics()
    requests_total = Counter("kubeheal_model_requests_total", "Prediction requests by model and outcome",
                             ["model", "status"], registry=metrics.registry)
    predictions_total = Counter("kubeheal_model_predictions_total", "Predicted labels by model",
                                ["model", "label"], registry=metrics.registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.bundles = load_bundles(root if root is not None else model_root())
        yield

    app = FastAPI(title="KubeHeal inference", version="5.0.0", lifespan=lifespan)
    app.state.bundles = {}            # not started or nothing loaded: every predict is a 503
    app.state.metrics = metrics
    add_metrics_route(app, metrics)
    app.add_middleware(BodyLimit)
    # Added last so it is the outermost middleware: every scoring request is counted, 413 included.
    add_inflight_middleware(app, metrics, SCORING_PATHS)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Drop the echoed input: a rejected Infinity/NaN would make the default 422 body unserialisable (500).
        detail = [{k: e[k] for k in ("type", "loc", "msg") if k in e} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": detail})

    def score(task: str, items: list[PredictRequest]) -> list[Prediction]:
        bundle = app.state.bundles.get(task)
        if bundle is None:
            requests_total.labels(task, "unavailable").inc()
            raise HTTPException(503, f"{task} model not loaded")
        known = set(bundle.features)
        # restrict drops only names the current feature code emits but this bundle was not trained on; a name that
        # is neither in the bundle nor in the task's feature universe survives it and is refused here.
        rows = [bundle.restrict(dict(item.features)) for item in items]
        unknown = sorted(set().union(*(row.keys() for row in rows)) - known)
        if unknown:
            requests_total.labels(task, "invalid").inc()
            raise HTTPException(422, f"unknown features: {unknown}")
        t0 = time.perf_counter()
        preds = bundle.predict_batch(rows, EXPLAIN_RISK[task])
        metrics.observe_model_latency(task, time.perf_counter() - t0)
        requests_total.labels(task, "ok").inc()
        for pred in preds:
            predictions_total.labels(task, pred.label).inc()
        return preds

    # Sync handlers: a CPU-bound predict runs in the threadpool and does not block the event loop.
    @app.post("/v1/health/predict", response_model=Prediction)
    def predict_health(req: PredictRequest) -> Prediction:
        return score("health", [req])[0]

    @app.post("/v1/security/predict", response_model=Prediction)
    def predict_security(req: PredictRequest) -> Prediction:
        return score("security", [req])[0]

    @app.post("/v1/health/predict_batch", response_model=list[Prediction])
    def predict_health_batch(req: PredictBatchRequest) -> list[Prediction]:
        return score("health", req.items)

    @app.post("/v1/security/predict_batch", response_model=list[Prediction])
    def predict_security_batch(req: PredictBatchRequest) -> list[Prediction]:
        return score("security", req.items)

    # async: probes run on the event loop and never queue behind CPU-bound predictions in the threadpool.
    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(response: Response) -> dict:
        bundles = app.state.bundles
        ready = all(task in bundles for task in TASKS)
        if not ready:
            response.status_code = 503
        return {"ready": ready,
                "models": {t: bundles[t].meta.get("version") if t in bundles else None for t in TASKS}}

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
