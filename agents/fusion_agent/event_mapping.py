"""
Pure helpers that map the Redis event dicts the agents publish onto the inference-side contract
(kubeheal.contracts.HealthEvent / SecurityEvent) and read the JSON list fields the policy needs (V5-D3).

Nothing here does I/O or raises on a malformed event: a field that cannot be read becomes a marker the policy
treats as uncertain (a prediction set), NaN (a risk, which the policy sends to a human), or a None result
(an event that cannot be mapped, which makes models_ok false in the caller). Fail closed everywhere.
"""

import json
import math
from typing import Dict, List, Optional, Tuple

from kubeheal.contracts import HealthEvent, SecurityEvent
from kubeheal.correlation import COMPOUND_THRESHOLD, compound_score

# Passed to the policy as the prediction set of a PRESENT event whose set is missing or unparsable. It is not a
# list, so decision_policy.set_certain() returns False for it: the event counts as uncertain.
MALFORMED_SET = "malformed"


def _loads(raw):
    if isinstance(raw, (list, dict)):
        return raw
    if raw in (None, ""):
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def string_list(raw) -> List[str]:
    """A JSON list of strings (as a string or already a list). Anything else is an empty list."""
    value = _loads(raw)
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v.strip()]


def prediction_set(event: Optional[Dict], name: str):
    """None for an ABSENT event (nothing to be uncertain about). For a present event: the parsed list, or
    MALFORMED_SET when the field is absent, empty or not a JSON list."""
    if not event:
        return None
    value = _loads(event.get(name))
    if not isinstance(value, list):
        return MALFORMED_SET
    # A producer that marks the event uncertain (`health_uncertain` / `sec_uncertain`) must not pass the one-label
    # gate even if it sent a one-label set together with the flag: fail closed with an empty set.
    flag = event.get(name.replace("_prediction_set", "_uncertain"))
    if len(value) == 1 and str(flag).strip().lower() in ("true", "1"):
        return []
    return value


def safe_float(raw, default: float = 0.0) -> float:
    """default for a missing or empty value, NaN for garbage (the policy treats a non-finite risk as invalid and
    sends it to a human)."""
    if raw in (None, ""):
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float("nan")


def _int(raw) -> Optional[int]:
    try:
        return int(float(str(raw)))
    except (TypeError, ValueError, OverflowError):
        return None


def top_factors(raw) -> List[Dict]:
    """Rows {feature, value, contribution} from `top_factors_json`; unusable rows are dropped."""
    value = _loads(raw)
    rows = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("feature"), str):
            continue
        try:
            contribution = float(item.get("contribution"))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(contribution):
            continue
        raw_value = item.get("value")
        try:
            val = float(raw_value) if raw_value is not None else None
        except (TypeError, ValueError):
            val = None
        rows.append({"feature": item["feature"], "value": val, "contribution": contribution})
    rows.sort(key=lambda r: abs(r["contribution"]), reverse=True)
    return rows


def _common(f: Dict, namespace: str, workload: str, label_key: str, risk_key: str, uncertain_key: str) -> Dict:
    common = {
        "event_id": str(f.get("event_id") or ""),
        "namespace": namespace,
        "workload": workload,
        "pod": str(f.get("pod_name") or ""),
        "model_version": str(f.get("model_version") or ""),
        "label": str(f.get(label_key) or "benign"),
        "risk": safe_float(f.get(risk_key)),
        "uncertain": str(f.get(uncertain_key, "")).strip().lower() == "true",
        "top_factors": top_factors(f.get("top_factors_json")),
    }
    ts = _int(f.get("timestamp_ms"))
    if ts and ts > 0:
        common["timestamp_ms"] = ts
    return common


def to_health_event(f: Dict, namespace: str, workload: str) -> Optional[HealthEvent]:
    """None when the event cannot be mapped (for example a risk that is not a number in [0, 1])."""
    try:
        return HealthEvent(
            **_common(f, namespace, workload, "health_label", "health_risk", "health_uncertain"),
            spec_changed=str(f.get("spec_changed", "")).strip().lower() == "true",
            changed_fields=string_list(f.get("changed_fields_json")),
            has_baseline=str(f.get("has_baseline", "")).strip().lower() == "true",
            failure_reasons=string_list(f.get("failure_reasons_json")),
        )
    except Exception:
        return None


def to_security_event(f: Dict, namespace: str, workload: str) -> Optional[SecurityEvent]:
    """None when the event cannot be mapped. The window start falls back to `t0_ms` (the earliest syscall time
    of the process) when the agent publishes no explicit window bounds."""
    try:
        start = _int(f.get("window_start_ms")) or _int(f.get("t0_ms")) or 0
        return SecurityEvent(
            **_common(f, namespace, workload, "sec_label", "sec_risk", "sec_uncertain"),
            pod_uid=str(f.get("pod_uid") or ""),
            window_start_ms=max(start, 0),
            window_end_ms=max(_int(f.get("window_end_ms")) or 0, 0),
        )
    except Exception:
        return None


def correlate(health: HealthEvent, sec: SecurityEvent) -> Tuple[float, bool, List[str]]:
    """(score, compound flag, reasons) from kubeheal.correlation.compound_score; the flag is score >=
    COMPOUND_THRESHOLD, the constant that module defines."""
    score, reasons = compound_score(health, sec)
    return score, score >= COMPOUND_THRESHOLD, reasons


def _top_names(factors: List[Dict], n: int = 3) -> str:
    return ", ".join(r["feature"] for r in factors[:n])


def local_summary(health: Optional[HealthEvent], sec: Optional[SecurityEvent], score: float, compound: bool,
                  reasons: List[str]) -> str:
    """A short plain sentence built from the correlation reasons and the top factors. No model call."""
    parts = []
    if health and sec:
        kind = "compound incident" if compound else "health and security signals on one workload, not compound"
        parts.append(f"{kind[0].upper()}{kind[1:]} (correlation {score:.2f})")
        if reasons:
            parts.append("; ".join(reasons[:4]))
    elif sec:
        parts.append(f"Security signal: label {sec.label}, risk {sec.risk:.2f}")
    elif health:
        parts.append(f"Health signal: label {health.label}, risk {health.risk:.2f}")
    factors = []
    if health and health.top_factors:
        factors.append(f"health factors {_top_names([f.model_dump() for f in health.top_factors])}")
    if sec and sec.top_factors:
        factors.append(f"security factors {_top_names([f.model_dump() for f in sec.top_factors])}")
    if factors:
        parts.append("top " + " and ".join(factors))
    return ". ".join(parts) + "." if parts else ""
