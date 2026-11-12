"""Baseline promotion approvals of the dashboard (V5-I3, owner decision D3).

In prod (and for an unknown tier) the Health Agent does not overwrite the golden baseline by itself: it stores a
promotion CANDIDATE (`kubeheal:baseline-candidate:<namespace>:<deployment>`) and a human approves or rejects it
here. Every outcome is a ledger entry written by `agents.health_agent.baseline`; this module only authenticates
the admin, passes the dashboard's own Redis client, ledger and kill switch view, and turns each status of the
baseline functions into an HTTP answer with a plain message.

  GET  /api/baseline-candidates                              list (open, like GET /api/approvals)
  GET  /api/baseline-candidates/{namespace}/{deployment}     detail (open)
  POST /api/baseline-candidates/{namespace}/{deployment}/approve   admin only
  POST /api/baseline-candidates/{namespace}/{deployment}/reject    admin only
       body: {"candidate_id": "<id the approver saw>", "reason": "<optional>"}; candidate_id is required, so an
       approval can never apply to a candidate that replaced the one the approver looked at.
  GET  /baseline-candidates                                  page

Kill switch: the dashboard can only read the global ConfigMap `kubeheal-mode` (its RBAC covers that one object),
and only asynchronously, so `approve_promotion` gets a SNAPSHOT string read just before the call, not a live
callable. Anything but exactly `enforce`, or an unreadable ConfigMap, is a dry run: the ledger gets a
`baseline_promotion_dry_run` entry, nothing is overwritten and the candidate stays pending. The dashboard cannot
see a per-namespace `kubeheal/mode` label (no namespace read permission), so a namespace made stricter by that
label is not honoured here; that is a known limit, written down in the report of V5-I3.

The baseline module is imported lazily: the dashboard image copies only `agents/common/` today, and without
`agents/health_agent/baseline.py` these endpoints answer 503 while the rest of the dashboard keeps working.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from dashboard import pages
from dashboard.admin_auth import AdminIdentity, require_admin
from dashboard.admin_routes import (
    PAGE_HEADERS,
    DashboardServices,
    _body,
    current_mode,
    get_services,
)
from dashboard.incident_view import num, prediction_set_view, string_list
from dashboard.ledger_view import read_incident

logger = logging.getLogger(__name__)

MAX_ASSESSMENT_TEXT = 200      # chosen: longest assessment string shown

router = APIRouter()


class CandidateDecision(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=512)


def _baseline():
    try:
        from agents.health_agent import baseline
    except ImportError:
        raise HTTPException(status_code=503, detail="baseline promotion is not available in this dashboard image "
                                                    "(agents/health_agent/baseline.py is not installed)")
    return baseline


def _redis(svc: DashboardServices):
    client = svc.get_redis() if svc.get_redis is not None else None
    if client is None:
        raise HTTPException(status_code=503, detail="Redis is not connected")
    return client


def _check_workload(bl, namespace: str, deployment: str) -> None:
    try:
        bl.validate_workload(namespace, deployment)
    except ValueError:
        raise HTTPException(status_code=404, detail="baseline candidate not found")


def _short(value: Any) -> Optional[str]:
    return None if value in (None, "") else str(value)[:MAX_ASSESSMENT_TEXT]


def candidate_summary(c: Dict[str, Any]) -> Dict[str, Any]:
    """What the approver sees of a candidate. The full spec and template stay in Redis."""
    a = c.get("assessment") if isinstance(c.get("assessment"), dict) else {}
    return {
        "namespace": c.get("namespace"),
        "deployment": c.get("deployment"),
        "tier": c.get("tier"),
        "candidate_id": c.get("candidate_id"),
        "status": c.get("status"),
        "created_at": c.get("created_at"),
        "changed_fields": string_list(c.get("changed_fields")),
        "assessment": {
            "label": _short(a.get("label")),
            "risk": num(a.get("risk")),
            "prediction_set": prediction_set_view(a.get("prediction_set")),
            "model_version": _short(a.get("model_version")),
            "event_id": _short(a.get("event_id")),
        },
    }


async def _list(svc: DashboardServices) -> List[Dict[str, Any]]:
    bl = _baseline()
    try:
        return [candidate_summary(c) for c in await bl.list_candidates(_redis(svc))]
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("baseline candidate listing failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="could not read the baseline candidates from Redis")


@router.get("/api/baseline-candidates")
async def list_baseline_candidates(svc: DashboardServices = Depends(get_services)):
    rows = await _list(svc)
    return {"candidates": rows, "count": len(rows)}


async def _history(svc: DashboardServices, bl, namespace: str, deployment: str) -> List[Dict[str, Any]]:
    """The ledger entries of this workload's baseline (promotions, dry runs, rejections), newest last, bounded."""
    try:
        records = await asyncio.to_thread(read_incident, svc.ledger, bl.ledger_incident_id(namespace, deployment))
    except Exception as exc:
        logger.warning("baseline history unreadable: %s", type(exc).__name__)
        return []
    out = []
    for r in records[-20:]:
        p = r.get("payload") if isinstance(r.get("payload"), dict) else {}
        out.append({"sequence": r.get("sequence"), "step": r.get("step"), "timestamp": r.get("timestamp"),
                    "approver": _short(p.get("approver")), "candidate_id": _short(p.get("candidate_id")),
                    "applied": p.get("applied")})
    return out


@router.get("/api/baseline-candidates/{namespace}/{deployment}")
async def baseline_candidate_detail(namespace: str, deployment: str, svc: DashboardServices = Depends(get_services)):
    bl = _baseline()
    _check_workload(bl, namespace, deployment)
    redis = _redis(svc)
    try:
        candidate = await bl.get_candidate(redis, namespace, deployment)
    except Exception as exc:
        logger.error("baseline candidate read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="could not read the baseline candidate from Redis")
    if candidate is None:
        raise HTTPException(status_code=404, detail="baseline candidate not found")
    out = candidate_summary(candidate)
    out["spec_hash"] = candidate.get("spec_hash")
    out["golden_sha256"] = candidate.get("golden_sha256")
    golden_current: Optional[bool] = None
    try:
        held = await bl.load_baseline_raw(redis, namespace, deployment)
        golden_current = None if held is None else bl.raw_digest(held[0]) == candidate.get("golden_sha256")
    except Exception as exc:
        logger.warning("golden baseline read failed: %s", type(exc).__name__)
    out["golden_baseline_unchanged"] = golden_current       # False: an approval would answer stale
    out["blocker"] = await bl.coordination_blocker(redis, namespace, deployment, candidate.get("spec_hash"))
    mode = await current_mode(svc)
    out["mode"] = {"mode": mode["mode"], "readable": mode["readable"],
                   "approval_is_dry_run": mode["dry_run"]}
    out["history"] = await _history(svc, bl, namespace, deployment)
    return out


# ---------------------------------------------------------------- decisions

_APPROVE_HTTP = {"promoted": 200, "dry_run": 200, "not_found": 404, "id_mismatch": 409, "no_ledger": 503,
                 "no_baseline": 409, "blocked": 409, "stale": 409, "ledger_failed": 500, "aborted": 409,
                 "conflict": 409}
_REJECT_HTTP = {"rejected": 200, "not_found": 404, "id_mismatch": 409, "no_ledger": 503, "ledger_failed": 500}

_MESSAGES = {
    "promoted": "Approved: the golden baseline was replaced and the promotion is in the ledger.",
    "rejected": "Rejected: the candidate was removed and the same spec will not be proposed again.",
    "not_found": "There is no pending candidate for this workload (it may already be decided or superseded).",
    "id_mismatch": "The candidate changed since you opened the page: reload and look at the current one. "
                   "Nothing was changed.",
    "no_ledger": "The dashboard has no ledger, so nothing can be approved or rejected. Nothing was changed.",
    "no_baseline": "There is no golden baseline for this workload to replace. Nothing was changed.",
    "blocked": "Another actor is working on this workload, so the approval was refused. The candidate stays "
               "pending: try again later.",
    "stale": "The golden baseline moved since the candidate was assessed, so the candidate was superseded. "
             "Nothing was promoted.",
    "ledger_failed": "The ledger write failed, so nothing was changed (the candidate stays pending).",
    "aborted": "The promotion was stopped before the overwrite (the spec, the mode or a cool-off changed while it "
               "was ledgered). The golden baseline is unchanged.",
    "conflict": "The golden baseline changed while the promotion was in progress. It was not overwritten.",
}


def _dry_run_message(mode: str, readable: bool) -> str:
    why = (f"the kill switch mode is {mode}" if readable
           else "the kill switch mode could not be read, which counts as test")
    return (f"DRY RUN: {why}, so nothing was changed. The golden baseline is unchanged and the candidate is "
            "still pending. A baseline_promotion_dry_run entry was written to the ledger. Switch the mode to "
            "enforce and approve again to promote.")


def _answer(status: str, table: Dict[str, int], extra: Dict[str, Any], message: Optional[str] = None):
    code = table.get(status, 500)
    text = message or _MESSAGES.get(status) or f"The baseline function answered with an unexpected status: {status}"
    body = {"status": status, "message": text, "detail": text, **extra}
    return JSONResponse(status_code=code, content=body)


async def _decide(kind: str, namespace: str, deployment: str, request: Request, admin: AdminIdentity,
                  svc: DashboardServices):
    body = await _body(request, CandidateDecision, required=True)     # after authentication: 422 for no candidate_id
    bl = _baseline()
    _check_workload(bl, namespace, deployment)
    redis = _redis(svc)
    reason = (body.reason or "").strip()
    mode = await current_mode(svc)
    try:
        if kind == "approve":
            result = await bl.approve_promotion(redis, namespace, deployment, admin.actor, svc.ledger,
                                                body.candidate_id, reason, mode=mode["mode"])
        else:
            result = await bl.reject_promotion(redis, namespace, deployment, admin.actor, svc.ledger,
                                               body.candidate_id, reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("baseline %s of %s/%s failed: %s", kind, namespace, deployment, type(exc).__name__)
        raise HTTPException(status_code=502, detail="the baseline decision failed on Redis or the ledger; "
                                                    "check the candidate before trying again")
    status = str(result.get("status"))
    logger.info("baseline %s %s/%s by %s: %s", kind, namespace, deployment, admin.actor, status)
    if status == "ledger_failed":
        logger.error("baseline %s of %s/%s: ledger write failed: %s", kind, namespace, deployment, result.get("error"))
    extra: Dict[str, Any] = {"namespace": namespace, "deployment": deployment, "candidate_id": body.candidate_id,
                             "actor": admin.actor, "mode": mode["mode"], "mode_readable": mode["readable"],
                             "applied": status == "promoted"}
    for key in ("ledger_key", "reason"):
        if result.get(key):
            extra[key] = result[key]
    if status == "id_mismatch":
        extra["current_candidate_id"] = result.get("candidate_id")
    if status == "dry_run":
        extra["candidate_unchanged"] = True
        return _answer(status, _APPROVE_HTTP, extra, _dry_run_message(mode["mode"], mode["readable"]))
    return _answer(status, _APPROVE_HTTP if kind == "approve" else _REJECT_HTTP, extra)


@router.post("/api/baseline-candidates/{namespace}/{deployment}/approve")
async def approve_baseline_candidate(namespace: str, deployment: str, request: Request,
                                     admin: AdminIdentity = Depends(require_admin),
                                     svc: DashboardServices = Depends(get_services)):
    return await _decide("approve", namespace, deployment, request, admin, svc)


@router.post("/api/baseline-candidates/{namespace}/{deployment}/reject")
async def reject_baseline_candidate(namespace: str, deployment: str, request: Request,
                                    admin: AdminIdentity = Depends(require_admin),
                                    svc: DashboardServices = Depends(get_services)):
    return await _decide("reject", namespace, deployment, request, admin, svc)


# ---------------------------------------------------------------- page

@router.get("/baseline-candidates", response_class=HTMLResponse)
async def baseline_candidates_page(svc: DashboardServices = Depends(get_services)):
    candidates = await _list(svc)
    mode = await current_mode(svc)
    return HTMLResponse(pages.baseline_candidates_page(candidates, mode), headers=PAGE_HEADERS)
