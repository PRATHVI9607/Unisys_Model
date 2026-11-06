"""Wire contract shared by every KubeHeal component.

Redis stream names, Redis key layout, event payloads and label sets live here
and nowhere else. Agents, fusion, the inference service and the dashboard all
import from this module, so a field rename is a one-file change that the test
suite catches.

Stream entries are flat str->str maps (Redis requirement). Each event model
has `to_fields()` / `from_fields()` for that encoding; nested values travel as
JSON strings.
"""

from __future__ import annotations

import json
import time
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── Streams ──────────────────────────────────────────────────────────────────
STREAM_HEALTH = "kubeheal.health.events"
STREAM_SECURITY = "kubeheal.security.events"
STREAM_ACTIONS = "kubeheal.actions"
STREAM_DEADLETTER = "kubeheal.deadletter"
# Security agent capture mode (KUBEHEAL_CAPTURE=1, lab data collection only): every scored window as a
# SecurityEvent, whatever its risk. Read by training/collect/security_lab.py.
STREAM_CAPTURE = "kubeheal.security.capture"
STREAM_MAXLEN = 10_000  # approximate trim (XADD MAXLEN ~)

# ── Label sets (index order == model class order) ───────────────────────────
HEALTH_LABELS: list[str] = ["benign", "degradation", "critical"]
HEALTH_CLASS_RISK: list[float] = [0.05, 0.60, 0.95]
SECURITY_LABELS: list[str] = ["benign", "suspicious", "ransomware", "exfiltration"]
SECURITY_CLASS_RISK: list[float] = [0.05, 0.45, 0.95, 0.85]
# The security agent publishes windows at or above this risk; inference explains (TreeSHAP) only those rows.
SECURITY_PUBLISH_RISK = 0.4

# Namespaces KubeHeal never acts on, whatever the model says.
PROTECTED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "kubeheal"})
PROTECTED_LABEL = "kubeheal.io/protected"      # pod/deployment label "true" → never act
QUARANTINE_LABEL = "kubeheal.io/quarantined"   # set on a pod before isolation
TIER_LABEL = "kubeheal.io/namespace-tier"      # namespace label prod|staging|dev; overrides the name heuristic
TIERS = ("prod", "staging", "dev")


# ── Redis keys ───────────────────────────────────────────────────────────────
def key_spec(ns: str, workload: str) -> str:
    """Last canonical spec the health agent assessed."""
    return f"kubeheal:spec:{ns}:{workload}"


def key_baseline(ns: str, workload: str) -> str:
    """Last spec assessed benign-and-certain: the AUTO-PATCH restore target."""
    return f"kubeheal:baseline:{ns}:{workload}"


def key_event(kind: str, event_id: str) -> str:
    """Hash copy of an event for dashboard detail lookups (kind: health|security|action)."""
    return f"kubeheal:{kind}:{event_id}"


def key_circuit(action: str, ns: str, workload: str) -> str:
    return f"kubeheal:cb:{action}:{ns}:{workload}"


def key_lock(ns: str, workload: str) -> str:
    return f"kubeheal:lock:{ns}:{workload}"


def workload_key(ns: str, workload: str) -> str:
    """Join key fusion uses to pair health and security events."""
    return f"{ns}/{workload}"


def namespace_tier(namespace: str, label: str | None = None) -> str:
    """Tier from the namespace's TIER_LABEL value when valid, else from its name."""
    if label in TIERS:
        return label
    n = (namespace or "").lower()
    if "prod" in n:
        return "prod"
    if "stag" in n:
        return "staging"
    return "dev"


def now_ms() -> int:
    return int(time.time() * 1000)


def new_event_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


# ── Model output (inference service response body) ──────────────────────────
class Factor(BaseModel):
    feature: str
    value: float | None = None       # the input feature value (None = missing)
    contribution: float                 # SHAP contribution toward the predicted class


class Prediction(BaseModel):
    model_version: str
    label: str
    risk: float = Field(ge=0.0, le=1.0)          # Σ p(class)·class_risk
    probabilities: dict[str, float]
    prediction_set: list[str]                    # split-conformal set at the bundle's alpha
    uncertain: bool                              # True when the set is not a single label
    top_factors: list[Factor] = []
    latency_ms: float = 0.0


# ── Events on the streams ────────────────────────────────────────────────────
class _Event(BaseModel):
    event_id: str
    namespace: str
    workload: str                     # owning Deployment name (join key with namespace)
    pod: str = ""                     # concrete pod when known (security); "" for health
    timestamp_ms: int = Field(default_factory=now_ms)
    model_version: str = ""
    label: str
    risk: float = Field(ge=0.0, le=1.0)
    uncertain: bool = False
    probabilities: dict[str, float] = {}
    top_factors: list[Factor] = []
    features: dict[str, float | None] = {}

    @property
    def tier(self) -> str:
        return namespace_tier(self.namespace)

    def to_fields(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in self.model_dump(mode="json").items():   # json mode: Enum → value
            if isinstance(v, (dict, list)):
                out[k] = json.dumps(v, separators=(",", ":"))
            elif isinstance(v, bool):
                out[k] = "1" if v else "0"
            else:
                out[k] = "" if v is None else str(v)
        return out

    @classmethod
    def from_fields(cls, fields: dict[Any, Any]):
        raw = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
               for k, v in fields.items()}
        data: dict[str, Any] = {}
        for name, f in cls.model_fields.items():
            if name not in raw:
                continue
            v = raw[name]
            ann = str(f.annotation)
            if "Dict" in ann or "List" in ann or "dict" in ann or "list" in ann:
                data[name] = json.loads(v) if v else ({} if "ict" in ann else [])
            elif f.annotation is bool:
                data[name] = v in ("1", "true", "True")
            else:
                data[name] = v
        return cls.model_validate(data)


class HealthEvent(_Event):
    """Published by the health agent after a real spec change was assessed."""
    spec_changed: bool = True
    changed_fields: list[str] = []    # dotted paths that differ old→new (capped)
    has_baseline: bool = False        # a restore target exists for AUTO-PATCH
    # Kubernetes evidence the new spec's rollout failed (ImagePullBackOff, CrashLoopBackOff, OOMKilled,
    # ProgressDeadlineExceeded, ...) and security-posture violations the spec newly introduces vs the
    # baseline ("policy:privileged_added", ...); not model features. Non-empty → fusion's rule-based rollback.
    failure_reasons: list[str] = []


POLICY_REASON_PREFIX = "policy:"   # failure_reasons entry = prefix + posture feature name


class SecurityEvent(_Event):
    """Published by the security agent for one pod's syscall/entropy window."""
    window_start_ms: int = 0
    window_end_ms: int = 0
    n_events: int = 0


class Decision(StrEnum):
    AUTO_KILL = "AUTO_KILL"
    AUTO_PATCH = "AUTO_PATCH"
    HUMAN = "HUMAN"
    OBSERVE = "OBSERVE"
    BENIGN = "BENIGN"


class ActionEvent(BaseModel):
    """Published by fusion for every decision (including dry-run ones)."""
    event_id: str
    namespace: str
    workload: str
    pod: str = ""
    decision: Decision
    mode: str                          # "observe" (dry-run) | "enforce"
    outcome: str                       # e.g. would_kill, pod_killed, patched, skipped_protected, failed:<reason>
    score: float                       # adjusted score that drove the decision (≤ 1.0)
    compound_score: float = 0.0
    rationale: str
    summary: str = ""                  # one-paragraph plain-English explanation
    health_event_id: str = ""
    security_event_id: str = ""
    timestamp_ms: int = Field(default_factory=now_ms)

    to_fields = _Event.to_fields
    from_fields = classmethod(_Event.from_fields.__func__)
