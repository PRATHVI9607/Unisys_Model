"""Inference-side signal contract for the shared KubeHeal model layer.

This is a trimmed port of the v5 `kubeheal/contracts.py`. It keeps only what the pure
model layer needs: the model output types (`Prediction`, `Factor`), the label sets and
class-risk tables of the health and security models, a few shared constants, and the
`HealthEvent` / `SecurityEvent` pydantic models that `kubeheal.correlation.compound_score`
takes as its input types.

`HealthEvent` and `SecurityEvent` are the inference-side signal contract: our agents map
their own events onto these models before calling the correlation code. This module does
not define stream names, Redis keys or event serialisation; the repo's own agents and
services own those.
"""

from __future__ import annotations

import time

from pydantic import BaseModel, ConfigDict, Field

# Label sets (index order == model class order).
HEALTH_LABELS: list[str] = ["benign", "degradation", "critical"]
HEALTH_CLASS_RISK: list[float] = [0.05, 0.60, 0.95]
SECURITY_LABELS: list[str] = ["benign", "suspicious", "ransomware", "exfiltration"]
SECURITY_CLASS_RISK: list[float] = [0.05, 0.45, 0.95, 0.85]
# The security agent publishes windows at or above this risk; inference explains (TreeSHAP) only those rows.
SECURITY_PUBLISH_RISK = 0.4

# failure_reasons entry = prefix + posture feature name, for example "policy:privileged_added".
POLICY_REASON_PREFIX = "policy:"


def now_ms() -> int:
    return int(time.time() * 1000)


# `model_version` starts with pydantic's protected namespace "model_"; the empty tuple turns the warning off.
_NO_PROTECTED = ConfigDict(protected_namespaces=())


class Factor(BaseModel):
    feature: str
    value: float | None = None       # the input feature value (None = missing)
    contribution: float              # SHAP contribution toward the predicted class


class Prediction(BaseModel):
    model_config = _NO_PROTECTED

    model_version: str
    label: str
    risk: float = Field(ge=0.0, le=1.0)          # sum of p(class) * class_risk
    probabilities: dict[str, float]
    prediction_set: list[str]                    # split-conformal set at the bundle's alpha
    uncertain: bool                              # True when the set is not a single label
    top_factors: list[Factor] = []
    latency_ms: float = 0.0


class _Event(BaseModel):
    model_config = _NO_PROTECTED

    event_id: str
    namespace: str
    workload: str                     # Deployment of an RS-owned pod, else the controller, else the pod (join key)
    pod: str = ""                     # concrete pod when known (security); "" for health
    timestamp_ms: int = Field(default_factory=now_ms)
    model_version: str = ""
    label: str
    risk: float = Field(ge=0.0, le=1.0)
    uncertain: bool = False
    probabilities: dict[str, float] = {}
    top_factors: list[Factor] = []
    features: dict[str, float | None] = {}


class HealthEvent(_Event):
    """Health signal for one assessed spec change."""
    spec_changed: bool = True
    changed_fields: list[str] = []    # dotted paths that differ old to new (capped)
    has_baseline: bool = False        # a restore target exists for AUTO-PATCH
    # Kubernetes evidence the new spec's rollout failed (ImagePullBackOff, CrashLoopBackOff, OOMKilled,
    # ProgressDeadlineExceeded, ...) and security-posture violations the spec newly introduces vs the
    # baseline ("policy:privileged_added", ...); not model features.
    failure_reasons: list[str] = []


class SecurityEvent(_Event):
    """Security signal for one pod's syscall/entropy window."""
    pod_uid: str = ""                 # identifies exactly this pod instance (empty: unknown)
    window_start_ms: int = 0
    window_end_ms: int = 0
    n_events: int = 0
