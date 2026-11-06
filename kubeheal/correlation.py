"""Deterministic compound-incident scoring for a (health, security) event pair.

A compound incident is an attack that is also hurting the workload. The score
is a fixed weighted sum of evidence terms, halved unless both sides are
elevated, so one strong signal alone never crosses COMPOUND_THRESHOLD. Every
term that contributes is reported as a plain-English reason.
"""

from __future__ import annotations

from kubeheal.contracts import HealthEvent, SecurityEvent

CORRELATION_WINDOW_S = 120
COMPOUND_THRESHOLD = 0.6

SECURITY_ELEVATED = 0.4
HEALTH_ELEVATED = 0.3
WRITE_STRESS_FILES_PER_S = 10.0
# Changed spec fields that would by themselves explain a performance change.
_CONFIG_CAUSES = ("resources", "replicas", "image", "Probe", "command", "args")


def _num(features: dict, name: str) -> float:
    v = features.get(name)
    return float(v) if v is not None else 0.0


def compound_score(health: HealthEvent, security: SecurityEvent) -> tuple[float, list[str]]:
    """Score in [0, 1] plus the reasons behind it; 0 when the events are not about the same workload/time."""
    if (health.namespace, health.workload) != (security.namespace, security.workload):
        return 0.0, []
    dt_s = abs(health.timestamp_ms - security.timestamp_ms) / 1000.0
    if dt_s > CORRELATION_WINDOW_S:
        return 0.0, []

    degraded = health.label != "benign"
    onset_ms = security.window_start_ms or security.timestamp_ms
    explained = health.spec_changed and any(c in p for p in health.changed_fields for c in _CONFIG_CAUSES)
    resource_stress = max(min(_num(health.features, "cpu_util_max"), 1.0), min(_num(health.features, "mem_util_max"), 1.0))
    write_stress = min(_num(security.features, "files_written_per_s") / WRITE_STRESS_FILES_PER_S, 1.0)

    terms = [
        (0.35 * security.risk, f"security risk {security.risk:.2f} ({security.label})"),
        (0.25 * health.risk, f"health risk {health.risk:.2f} ({health.label})"),
        (0.15 * (onset_ms <= health.timestamp_ms), "suspicious activity started before or during the degradation"),
        (0.15 * (degraded and not explained), "degradation is not explained by a resource/replica/image/probe change"),
        (0.07 * resource_stress, f"resource pressure (cpu/mem utilisation up to {resource_stress:.0%})"),
        (0.03 * write_stress, f"heavy file writes ({_num(security.features, 'files_written_per_s'):.1f} files/s)"),
    ]
    score = sum(w for w, _ in terms)
    reasons = [f"same workload, events {dt_s:.0f}s apart"] + [r for w, r in terms if w > 0.01]
    if security.risk < SECURITY_ELEVATED or health.risk < HEALTH_ELEVATED:
        score *= 0.5
        reasons.append("halved: security and health are not both elevated")
    return round(min(max(score, 0.0), 1.0), 4), reasons
