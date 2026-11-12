"""Build the incident view (S-DB-2, V5-I3): scores, prediction sets, top factors, causal chain, T0 and timeline.

Everything shown comes from the incident's ledger records and from the health and security events they
reference. Nothing is computed or filled in here:
  - confidence is the conformal PREDICTION SET (the labels the model cannot rule out). Exactly one label is
    "certain"; anything else (several labels, an empty set, no set published, or a producer flag
    `*_uncertain`) is "not certain" (rule M2: an automatic action needs a one-label set);
  - the explanation is the model's TreeSHAP `top_factors` (feature, input value, signed contribution), bounded;
  - fields removed in V5 (`*_ci_width`, `field_attribution_json`, `top_field`, `top_syscall`, `top_metric`) are
    read only through `.get` and only shown as "legacy" when an older incident carries them. The incident view
    never requires them and never reads the neural-model vectors of the legacy stack at all;
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
MAX_TOP_FACTORS = 8        # chosen, not measured: the longest factor list shown per model
MAX_LIST_ITEMS = 20        # chosen: longest list of labels, reasons or fields shown
MAX_TEXT = 200             # chosen: longest label, feature name or reason shown


def num(value: Any) -> Optional[float]:
    """float or None. Strings from Redis hashes are accepted; NaN and infinity are not numbers here."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _loads(raw: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    if raw in (None, ""):
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    return str(value)[:MAX_TEXT]


def flag(value: Any) -> Optional[bool]:
    """True, False or None (absent or not a boolean). Redis hashes carry "true" and "false" strings."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("true", "1"):
        return True
    if text in ("false", "0"):
        return False
    return None


def string_list(raw: Any) -> List[str]:
    """A bounded list of strings from a list or a JSON list; anything else is an empty list."""
    value = _loads(raw)
    if not isinstance(value, list):
        return []
    return [_text(x) for x in value if isinstance(x, (str, int, float)) and str(x).strip()][:MAX_LIST_ITEMS]


def prediction_set_view(raw_set: Any, uncertain_flag: Any = None) -> Dict[str, Any]:
    """The conformal prediction set and whether it is certain.

    certain = exactly one label AND the producer did not mark the event uncertain. A set that is absent,
    malformed or empty is never certain."""
    value = _loads(raw_set)
    flagged = flag(uncertain_flag) is True
    if not isinstance(value, list):
        return {"published": False, "labels": [], "size": None, "certain": False, "marked_uncertain": flagged,
                "summary": "not certain: no prediction set was published"}
    labels = [_text(x) for x in value if isinstance(x, (str, int, float))][:MAX_LIST_ITEMS]
    certain = len(value) == 1 and len(labels) == 1 and not flagged
    shown = "{" + ", ".join(labels) + "}"
    if certain:
        summary = f"certain: {shown}"
    elif not labels:
        summary = "not certain: the prediction set is empty"
    elif len(value) == 1:
        summary = f"not certain: {shown} (the producer marked the event uncertain)"
    else:
        summary = f"not certain: {shown} holds {len(value)} labels"
    return {"published": True, "labels": labels, "size": len(value), "certain": certain,
            "marked_uncertain": flagged, "summary": summary}


def top_factors_view(raw: Any) -> Dict[str, Any]:
    """TreeSHAP top factors as {feature, value, contribution}, largest absolute contribution first, bounded.
    Entries without a finite contribution are dropped. `total` counts the valid entries before the bound."""
    value = _loads(raw)
    rows: List[Dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict) or not item.get("feature"):
                continue
            contribution = num(item.get("contribution"))
            if contribution is None:
                continue
            rows.append({"feature": _text(item["feature"]), "value": num(item.get("value")),
                         "contribution": contribution})
    rows.sort(key=lambda r: abs(r["contribution"]), reverse=True)
    return {"available": bool(rows), "factors": rows[:MAX_TOP_FACTORS], "total": len(rows)}


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


def _event_scores(event: Optional[Dict[str, Any]], ledger: Dict[str, Any], kind: str,
                  decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Score block of one model. The ledger `scores` record wins over the event hash; the decision record is the
    fallback for the prediction set and the factors (Fusion writes them there as well)."""
    if kind == "health":
        risk_k, label_k, set_k, unc_k, ci_k, top_k, side = (
            "health_risk", "health_label", "health_prediction_set", "health_uncertain", "health_ci_width",
            "top_field", "health")
    else:
        risk_k, label_k, set_k, unc_k, ci_k, top_k, side = (
            "sec_risk", "sec_label", "sec_prediction_set", "sec_uncertain", "sec_ci_width",
            "top_syscall", "security")
    if not ledger and not event:
        return None
    src = {**(event or {}), **{k: v for k, v in ledger.items() if v is not None}}
    pset = src.get(set_k)
    if pset in (None, ""):
        pset = decision.get(set_k)
    uncertain = src.get(unc_k)
    if uncertain is None:
        uncertain = decision.get(unc_k)
    factors_raw = src.get("top_factors_json")
    if factors_raw in (None, ""):
        both = decision.get("top_factors_json")
        factors_raw = both.get(side) if isinstance(both, dict) else None
    factors = top_factors_view(factors_raw)
    legacy: Dict[str, Any] = {}
    ci_width = num(src.get(ci_k))             # removed in V5: only an older incident carries it
    if ci_width is not None:
        legacy["ci_width"] = ci_width
    if src.get(top_k):
        legacy["top"] = _text(src[top_k])      # health: the first changed field, not a model attribution
    return {
        "risk": num(src.get(risk_k)),
        "label": src.get(label_k),
        "prediction_set": prediction_set_view(pset, uncertain),
        "top_factors": factors["factors"],
        "top_factors_total": factors["total"],
        "model_scored": flag(src.get("model_scored")),
        "model_version": src.get("model_version") or None,
        "legacy": legacy,
    }


def _containment(decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "containment_label" not in decision:
        return None
    return {"label": decision.get("containment_label") or None,
            "restore_after": flag(decision.get("restore_after")),
            "human_followup": flag(decision.get("human_followup"))}


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

    # Legacy attribution (removed in V5, empty or absent in new events): optional, never required.
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
            "rule_path": flag(decision.get("rule_path")),
            "rule_reasons": string_list(decision.get("rule_reasons")),
            "patch_fields": string_list(decision.get("patch_fields")),
            "containment": _containment(decision),
            "security_fresh": flag(decision.get("security_fresh")),
            "models_ok": flag(decision.get("models_ok")),
        } if decision else None,
        "scores": {
            "health": _event_scores(health_event, scores.get("health") or {}, "health", decision),
            "security": _event_scores(security_event, scores.get("security") or {}, "security", decision),
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
