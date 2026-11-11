"""Small demo workload with Prometheus request metrics."""

import os
import threading
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, HTTPException, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest


DISK_PROBE_MAX_BYTES = 1024 * 1024  # chosen default, not measured


def create_app() -> FastAPI:
    """Create the API with an isolated registry, which also keeps tests independent."""
    registry = CollectorRegistry()
    requests_total = Counter(
        "http_requests_total",
        "Total HTTP requests handled by the victim application.",
        labelnames=("method", "path", "status"),
        registry=registry,
    )
    request_duration = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds for the victim application.",
        labelnames=("method", "path", "status"),
        registry=registry,
    )
    disk_io_bytes = Counter(
        "kubeheal_victim_disk_io_bytes_total",
        "Bytes written and synced by the victim's disk-metric probe.",
        registry=registry,
    )

    api = FastAPI(title="KubeHeal victim application")
    disk_lock = threading.Lock()
    disk_state = {"written": 0}

    @api.middleware("http")
    async def observe_requests(request: Request, call_next):
        # Scrapes should not affect application request rates or histogram observations.
        if request.url.path == "/metrics":
            return await call_next(request)
        started = perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            # Use the route template instead of the raw URL to avoid one time series per ID.
            route = request.scope.get("route")
            path = getattr(route, "path", "unmatched")
            labels = (request.method, path, str(status))
            requests_total.labels(*labels).inc()
            request_duration.labels(*labels).observe(perf_counter() - started)

    @api.get("/health")
    async def health():
        return {"status": "ok"}

    @api.get("/")
    async def home():
        return {"service": "kubeheal-victim-app"}

    @api.get("/items/{item_id}")
    async def get_item(item_id: str):
        return {"item_id": item_id}

    @api.get("/fail")
    async def fail_for_metrics():
        """Provide a deliberate 5xx so the error-rate query has an observed series."""
        raise HTTPException(status_code=500, detail="intentional victim metric probe")

    @api.get("/cpu")
    def burn_cpu(milliseconds: int = Query(default=200, ge=1, le=300)):
        """Bounded CPU work for observing CFS throttling under the configured limit."""
        deadline = perf_counter() + milliseconds / 1000
        value = 1
        while perf_counter() < deadline:
            value = (value * 33 + 17) & 0xFFFFFFFF
        return {"work_value": value}

    @api.get("/disk")
    def write_for_metrics():
        """Write and sync bytes under the mounted victim data path for disk I/O telemetry.

        A plain `def` so FastAPI runs the blocking fsync in its thread pool, not on the event loop. The probe
        file is a ring of DISK_PROBE_MAX_BYTES (chosen default, not measured): writes wrap around, so it never
        grows without bound and nothing is deleted.
        """
        path = Path(os.environ.get("KUBEHEAL_DISK_IO_PATH", "/data/.kubeheal-metric-probe"))
        payload = b"kubeheal-demo-disk-metric\n"
        with disk_lock:
            offset = disk_state["written"] % DISK_PROBE_MAX_BYTES
            try:
                with path.open("r+b" if path.exists() else "wb") as output:
                    output.seek(offset)
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
            except OSError as exc:
                raise HTTPException(status_code=503, detail="victim data path is not writable") from exc
            disk_state["written"] += len(payload)
        disk_io_bytes.inc(len(payload))
        return {"bytes_written": len(payload)}

    @api.get("/metrics", include_in_schema=False)
    async def metrics():
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    api.state.prometheus_registry = registry
    return api


app = create_app()
