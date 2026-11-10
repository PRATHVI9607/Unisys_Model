"""Build the incident view (S-DB-2): scores, attributions, causal chain, T0 and ledger timeline.

Everything shown comes from the incident's ledger records and from the health and security events they
reference. Nothing is computed or filled in here:
  - confidence is shown as the published CI width only (the interval position is not published, so no
    lower/upper bound is drawn);
  - the attack onset T0 is shown only if some record or event carries `t0_ms`; otherwise it is
    reported as not available;
  - a missing event (its Redis hash expired after 24 h) is reported as not available.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional

from dashboard.ledger_view import approval_status, step_payload

NOT_AVAILABLE = "not available"


def num(value: Any) -> Optional[float]:
    """float or None. Strings from Redis hashes are accepted; NaN and infinity are not numbers here."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _json_field(event: Optional[Dict[str, Any]], key: str) -> Any:
    raw = (event or {}).get(key)
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None


def _ranked(weights: Any) -> List[Dict[str, Any]]:
    if not isinstance(weights, dict):
        return []
    rows = [{"name": str(k), "weight": w} for k, v in weights.items() if (w := num(v)) is not None]
    rows.sort(key=lambda r: r["weight"], reverse=True)
    return rows


def _find_t0(*sources: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    for label, src in sources:  # type: ignore[misc]
        raw = (src or {}).get("t0_ms")
        value = num(raw)
        if value is not None and value > 0:
            return {"available": True, "t0_ms": int(value), "source": label}
    return {"available": False, "t0_ms": None, "source": None}


def _event_scores(event: Optional[Dict[str, Any]], ledger: Dict[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    risk_k, label_k, ci_k, top_k = (
        ("health_risk", "health_label", "health_ci_width", "top_field") if kind == "health"
        else ("sec_risk", "sec_label", "sec_ci_width", "top_syscall")
    )
    if not ledger and not event:
        return None
    src = {**(event or {}), **{k: v for k, v in ledger.items() if v is not None}}
    return {
        "risk": num(src.get(risk_k)),
        "label": src.get(label_k),
        "ci_width": num(src.get(ci_k)),
        "top": src.get(top_k) or None,
    }


def build_incident(
    incident_id: str,
    records: List[Dict[str, Any]],
    health_event: Optional[Dict[str, Any]] = None,
    security_event: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    steps = [r.get("step") for r in records]
    detection = step_payload(records, "detection")
    scores = step_payload(records, "scores")
    decision = step_payload(records, "decision")
    requested = step_payload(records, "approval_requested")

    status = approval_status(steps)
    chain = decision.get("causal_chain")
    chain = [str(x) for x in chain] if isinstance(chain, list) else []

    health_attr = _ranked(_json_field(health_event, "field_attribution_json"))
    sec_attr = _ranked(_json_field(security_event, "syscall_attribution_json"))

    return {
        "incident_id": incident_id,
        "status": status,
        "target": {
            "namespace": detection.get("namespace"),
            "deployment": detection.get("deployment"),
            "pod": detection.get("pod") or None,
        },
        "decision": {
            "decision": decision.get("decision"),
            "adjusted_score": num(decision.get("adjusted_score")),
            "rationale": decision.get("rationale"),
            "dry_run": decision.get("dry_run"),
            "namespace_tier": decision.get("namespace_tier"),
            "compound": decision.get("compound"),
            "approval_rationale": requested.get("rationale"),
        } if decision else None,
        "scores": {
            "health": _event_scores(health_event, scores.get("health") or {}, "health"),
            "security": _event_scores(security_event, scores.get("security") or {}, "security"),
            "correlation_score": num(scores.get("correlation_score")),
            "compound": scores.get("compound"),
        },
        "attribution": {
            "health": {
                "available": bool(health_attr),
                "fields": health_attr,
                "top_metric": (health_event or {}).get("top_metric") or None,
            },
            "security": {
                "available": bool(sec_attr),
                "syscalls": sec_attr,
                "early_signals": _json_field(security_event, "early_signals_json"),
                "entropy_spike": _json_field(security_event, "entropy_spike_json"),
            },
        },
        "causal_chain": {
            "steps": chain,
            "t0": _find_t0(("ledger decision", decision), ("ledger detection", detection),
                           ("ledger scores", scores), ("security event", security_event),
                           ("health event", health_event)),
        },
        "dry_run_approvals": [
            {
                "sequence": r.get("sequence"),
                "timestamp": r.get("timestamp"),
                "approved_by": (r.get("payload") or {}).get("approved_by"),
                "action": (r.get("payload") or {}).get("action"),
                "mode": (r.get("payload") or {}).get("mode"),
                "exec_stream_id": (r.get("payload") or {}).get("exec_stream_id"),
            }
            for r in records if r.get("step") == "dry_run_approved"
        ],
        "timeline": [
            {
                "sequence": r.get("sequence"),
                "step": r.get("step"),
                "timestamp": r.get("timestamp"),
                "payload": r.get("payload") if isinstance(r.get("payload"), dict) else {},
            }
            for r in records
        ],
    }
