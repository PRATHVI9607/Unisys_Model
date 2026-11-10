"""Shared Prometheus metrics used by KubeHeal components."""

from __future__ import annotations

from typing import Optional

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest


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
        self.queue_depth = Gauge(
            "kubeheal_queue_depth", "Current queue depth", ["stream"], registry=self.registry
        )
        self.stream_lag = Gauge(
            "kubeheal_stream_lag", "Current consumer stream lag", ["stream"], registry=self.registry
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

    def render(self) -> bytes:
        """Return the Prometheus text exposition for a component's ``/metrics`` route."""
        return generate_latest(self.registry)
