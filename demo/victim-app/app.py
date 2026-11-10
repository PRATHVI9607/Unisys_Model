"""Small demo workload with Prometheus request metrics."""

from time import perf_counter

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest


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

    api = FastAPI(title="KubeHeal victim application")

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

    @api.get("/metrics", include_in_schema=False)
    async def metrics():
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    api.state.prometheus_registry = registry
    return api


app = create_app()
