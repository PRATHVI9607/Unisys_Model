"""Shared Prometheus metrics used by KubeHeal components."""

from __future__ import annotations

from typing import Optional

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)


class KubeHealMetrics:
    """Owns a component-local metric registry and its supported metric names."""

    def __init__(self, registry: Optional[CollectorRegistry] = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.decisions = Counter(
            "kubeheal_decisions_total", "Decisions by policy result", ["decision"], registry=self.registry
        )
        self.actions = Counter(
            "kubeheal_actions_total", "Actions by type and outcome", ["action", "outcome"], registry=self.registry
        )
        self.escalations = Counter(
            "kubeheal_escalations_total", "Escalations by reason", ["reason"], registry=self.registry
        )
        self.dry_run_actions = Counter(
            "kubeheal_dry_run_actions_total", "Actions suppressed by dry-run mode", ["action"], registry=self.registry
        )
        self.model_latency = Histogram(
            "kubeheal_model_latency_seconds", "Model request latency", ["model"], registry=self.registry
        )
        # Depth of a Redis stream queue (label: stream). Not the model server request gauge below.
        self.queue_depth = Gauge(
            "kubeheal_queue_depth", "Current queue depth", ["stream"], registry=self.registry
        )
        # Model servers: scoring requests that arrived and have not finished, i.e. running PLUS waiting
        # for a worker thread. This is the HPA signal (prometheus-adapter, per pod). See
        # add_inflight_middleware.
        self.inflight_requests = Gauge(
            "kubeheal_model_inflight_requests",
            "Scoring requests in flight or waiting for a worker in this pod",
            registry=self.registry,
        )
        self.stream_lag = Gauge(
            "kubeheal_stream_lag", "Current consumer stream lag", ["stream"], registry=self.registry
        )
        # Ledger failure policy (P7-RR-10). Alert on any increase of the fallback counter, on any
        # increase of the unavailable counter, and on a pending gauge that stays above zero.
        self.ledger_fallback_writes = Counter(
            "kubeheal_ledger_fallback_writes_total",
            "Ledger records written to the durable fallback stream because the ledger write failed",
            ["kind"], registry=self.registry
        )
        self.ledger_unavailable = Counter(
            "kubeheal_ledger_unavailable_total",
            "Automatic steps refused because the required ledger write could not be made",
            ["reason"], registry=self.registry
        )
        self.ledger_pending = Gauge(
            "kubeheal_ledger_pending_entries",
            "Entries waiting in the fallback stream to be flushed to the ledger", registry=self.registry
        )

    def record_decision(self, decision: str) -> None:
        self.decisions.labels(decision=decision).inc()

    def record_action(self, action: str, outcome: str) -> None:
        self.actions.labels(action=action, outcome=outcome).inc()

    def record_escalation(self, reason: str) -> None:
        self.escalations.labels(reason=reason).inc()

    def record_dry_run_action(self, action: str) -> None:
        self.dry_run_actions.labels(action=action).inc()

    def observe_model_latency(self, model: str, seconds: float) -> None:
        self.model_latency.labels(model=model).observe(seconds)

    def set_queue_depth(self, stream: str, depth: float) -> None:
        self.queue_depth.labels(stream=stream).set(depth)

    def set_stream_lag(self, stream: str, lag: float) -> None:
        self.stream_lag.labels(stream=stream).set(lag)

    def record_ledger_fallback(self, kind: str) -> None:
        self.ledger_fallback_writes.labels(kind=kind).inc()

    def record_ledger_unavailable(self, reason: str) -> None:
        self.ledger_unavailable.labels(reason=reason).inc()

    def set_ledger_pending(self, depth: float) -> None:
        self.ledger_pending.set(depth)

    def render(self) -> bytes:
        """Return the Prometheus text exposition for a component's ``/metrics`` route."""
        return generate_latest(self.registry)

    def start_server(self, port: int, addr: str = "0.0.0.0"):
        """Start a standalone HTTP listener exposing this component's registry."""
        return start_http_server(port, addr=addr, registry=self.registry)


def add_inflight_middleware(app, metrics: KubeHealMetrics, paths) -> None:
    """Count requests to the given scoring `paths` in `metrics.inflight_requests`.

    The gauge is incremented when the request arrives and decremented in a `finally` when the response
    is done (also when the handler raises), so requests queued behind busy worker threads are counted
    too. Other paths (/health, /metrics) are never counted.
    """
    scoring = frozenset(paths)

    @app.middleware("http")
    async def _count_inflight(request, call_next):
        if request.url.path not in scoring:
            return await call_next(request)
        metrics.inflight_requests.inc()
        try:
            return await call_next(request)
        finally:
            metrics.inflight_requests.dec()


def add_metrics_route(app, metrics: KubeHealMetrics) -> None:
    """Add the standard ``/metrics`` route to a FastAPI application."""
    from fastapi import Response

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint():
        return Response(content=metrics.render(), media_type=CONTENT_TYPE_LATEST)
