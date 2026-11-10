"""Approvals, incident view and kill switch endpoints of the dashboard (P8: S-DB-1/2, S-KS-6).

Reads are open like the rest of the dashboard (it sits behind the Ingress). Every mutating endpoint
depends on `require_admin` (503 without a configured token, 401 without credentials, 403 for a wrong
token). Collaborators (ledger, Redis queue, kill switch ConfigMap) come from `DashboardServices` on
`app.state.services`, so tests inject fakes and never need Redis, MinIO or a cluster.

Approval flow (HUMAN_PATCH / HUMAN_CONTAIN decisions written by Fusion with an `approval_requested` entry):
  pending = approval_requested present, no `approved` and no `rejected` entry
  approve : claim the incident, queue a request on kubeheal.exec (approved_by = admin identity,
            dry_run from the current kill switch mode), then ledger `approved`
  reject  : claim the incident, ledger `rejected`, nothing queued
The claim is a Redis SET NX in deployments, so two replicas cannot decide the same incident twice.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from agents.common.killswitch import ENFORCE, TEST, is_dry_run, normalize
from agents.common.ledger import Ledger
from dashboard import pages
from dashboard.admin_auth import AdminIdentity, require_admin
from dashboard.incident_view import build_incident, num
from dashboard.ledger_view import (
    HUMAN_DECISIONS,
    STEP_APPROVED,
    STEP_REJECTED,
    approval_status,
    index_steps,
    mode_history,
    read_incident,
    step_payload,
    valid_incident_id,
)
from dashboard.mode_admin import ModeStore

logger = logging.getLogger(__name__)

EXEC_STREAM = "kubeheal.exec"
CLAIM_KEY = "kubeheal:approval:{incident_id}"
CLAIM_TTL_S = 30 * 86400
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


@dataclass
class DashboardServices:
    ledger: Ledger
    mode_store: ModeStore
    enqueue_exec: Callable[[Dict[str, str]], Awaitable[str]]
    claim: Callable[[str], Awaitable[bool]]
    release: Callable[[str], Awaitable[None]]
    fetch_event: Callable[[str, str], Awaitable[Optional[Dict[str, Any]]]]


def redis_services(ledger: Ledger, mode_store: ModeStore, get_redis: Callable[[], Any]) -> DashboardServices:
    """Production wiring: Redis for the exec stream, the claim and the event hashes."""

    def _redis():
        r = get_redis()
        if r is None:
            raise HTTPException(status_code=503, detail="Redis is not connected")
        return r

    async def enqueue_exec(fields: Dict[str, str]) -> str:
        msg_id = await _redis().xadd(EXEC_STREAM, fields)
        return msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)

    async def claim(incident_id: str) -> bool:
        return bool(await _redis().set(CLAIM_KEY.format(incident_id=incident_id), "1", nx=True, ex=CLAIM_TTL_S))

    async def release(incident_id: str) -> None:
        await _redis().delete(CLAIM_KEY.format(incident_id=incident_id))

    async def fetch_event(kind: str, event_id: str) -> Optional[Dict[str, Any]]:
        if not event_id or get_redis() is None:
            return None
        try:
            raw = await get_redis().hgetall(f"kubeheal:{kind}:{event_id}")
        except Exception as exc:
            logger.warning("event lookup failed: %s", type(exc).__name__)
            return None
        if not raw:
            return None
        return {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in raw.items()}

    return DashboardServices(ledger, mode_store, enqueue_exec, claim, release, fetch_event)


def get_services(request: Request) -> DashboardServices:
    svc = getattr(request.app.state, "services", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="dashboard services are not initialised")
    return svc


def _check_id(incident_id: str) -> None:
    if not valid_incident_id(incident_id):
        raise HTTPException(status_code=404, detail="incident not found")


async def _records(svc: DashboardServices, incident_id: str) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(read_incident, svc.ledger, incident_id)


async def _append(svc: DashboardServices, incident_id: str, step: str, payload: Dict[str, Any]):
    return await asyncio.to_thread(svc.ledger.append, incident_id, step, payload)


async def current_mode(svc: DashboardServices) -> Dict[str, Any]:
    """Kill switch state as the components see it: unreadable or anything but exactly `enforce` is test."""
    raw: Optional[str] = None
    readable = True
    try:
        raw = await svc.mode_store.read_mode()
    except Exception as exc:
        logger.warning("kill switch read failed: %s", type(exc).__name__)
        readable = False
    if raw is None:
        readable = False
    mode = normalize(raw) if readable else TEST
    return {"mode": mode, "readable": readable, "dry_run": is_dry_run(mode), "raw": raw if readable else None}


# ---------------------------------------------------------------- models

class DecisionNote(BaseModel):
    note: Optional[str] = Field(default=None, max_length=500)


class ModeRequest(BaseModel):
    mode: Literal["test", "enforce"]


# ---------------------------------------------------------------- helpers

def _pending_summary(incident_id: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    decision = step_payload(records, "decision")
    detection = step_payload(records, "detection")
    requested = next((r for r in records if r.get("step") == "approval_requested"), {})
    return {
        "incident_id": incident_id,
        "decision": decision.get("decision"),
        "adjusted_score": num(decision.get("adjusted_score")),
        "rationale": decision.get("rationale"),
        "namespace": detection.get("namespace"),
        "deployment": detection.get("deployment"),
        "pod": detection.get("pod") or None,
        "requested_at": requested.get("timestamp"),
    }


def _pending_incidents(ledger: Ledger) -> List[str]:
    index = index_steps(ledger)
    return sorted(i for i, items in index.items() if approval_status(s for _q, s, _k in items) == "pending")


def _exec_request(incident_id: str, records: List[Dict[str, Any]], approver: str, dry_run: bool) -> Dict[str, str]:
    """Executor request for an approved HUMAN decision, or HTTPException if it cannot be built.
    Field names follow agents/executor/validation.py; the Executor validates again and re-checks the mode."""
    decision = step_payload(records, "decision").get("decision")
    detection = step_payload(records, "detection")
    namespace = detection.get("namespace") or ""
    deployment = detection.get("deployment") or ""
    pod = detection.get("pod") or ""
    if decision == "human_patch":
        action = "patch"
        field = (step_payload(records, "scores").get("health") or {}).get("top_field") or ""
        if not (namespace and deployment and field and str(field).lower() != "unknown"):
            raise HTTPException(status_code=422, detail="cannot approve: the incident names no drifted field to restore")
    elif decision == "human_contain":
        action = "contain"
        field = ""
        if not (namespace and pod):
            raise HTTPException(status_code=422, detail="cannot approve: the incident names no pod to contain")
    else:
        raise HTTPException(status_code=409, detail="incident has no human approval decision")
    return {
        "incident_id": incident_id,
        "action": action,
        "namespace": namespace,
        "deployment": deployment,
        "pod": pod,
        "patch_field": str(field),
        "approved_by": approver,
        "dry_run": "true" if dry_run else "false",
        "source": "dashboard",
        "rationale": str(step_payload(records, "decision").get("rationale") or ""),
        "timestamp_ms": str(int(time.time() * 1000)),
    }


async def _load_pending_or_raise(svc: DashboardServices, incident_id: str):
    _check_id(incident_id)
    records = await _records(svc, incident_id)
    if not records:
        raise HTTPException(status_code=404, detail="incident not found")
    status = approval_status(r.get("step") for r in records)
    if status == "none":
        raise HTTPException(status_code=409, detail="no approval was requested for this incident")
    decision = step_payload(records, "decision").get("decision")
    if decision not in HUMAN_DECISIONS:
        raise HTTPException(status_code=409, detail="incident has no human approval decision")
    return records, status


# ---------------------------------------------------------------- router

router = APIRouter()


@router.get("/api/approvals")
async def list_pending_approvals(svc: DashboardServices = Depends(get_services)):
    ids = await asyncio.to_thread(_pending_incidents, svc.ledger)
    out = []
    for incident_id in ids:
        records = await _records(svc, incident_id)
        if step_payload(records, "decision").get("decision") in HUMAN_DECISIONS:
            out.append(_pending_summary(incident_id, records))
    return {"pending": out, "count": len(out)}


@router.post("/api/approvals/{incident_id}/approve")
async def approve(incident_id: str, body: Optional[DecisionNote] = None,
                  admin: AdminIdentity = Depends(require_admin),
                  svc: DashboardServices = Depends(get_services)):
    records, status = await _load_pending_or_raise(svc, incident_id)
    if status == "approved":
        return {"status": "already_approved", "incident_id": incident_id, "queued": False}
    if status == "rejected":
        raise HTTPException(status_code=409, detail="incident was already rejected")
    mode = await current_mode(svc)
    fields = _exec_request(incident_id, records, admin.actor, mode["dry_run"])
    if not await svc.claim(incident_id):
        raise HTTPException(status_code=409, detail="another decision for this incident is in progress")
    try:
        stream_id = await svc.enqueue_exec(fields)
    except Exception as exc:
        await svc.release(incident_id)
        logger.error("approve %s: queueing failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="could not queue the request for the Executor; nothing was approved")
    try:
        await _append(svc, incident_id, STEP_APPROVED, {
            "approved_by": admin.actor,
            "action": fields["action"],
            "dry_run": mode["dry_run"],
            "mode": mode["mode"],
            "mode_readable": mode["readable"],
            "exec_stream_id": stream_id,
            "note": (body.note if body else None),
        })
    except Exception as exc:
        logger.error("approve %s: request queued but ledger write failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="request queued but the ledger write failed; do not retry")
    return {"status": "approved", "incident_id": incident_id, "action": fields["action"],
            "dry_run": mode["dry_run"], "queued": True, "approved_by": admin.actor}


@router.post("/api/approvals/{incident_id}/reject")
async def reject(incident_id: str, body: Optional[DecisionNote] = None,
                 admin: AdminIdentity = Depends(require_admin),
                 svc: DashboardServices = Depends(get_services)):
    _records_, status = await _load_pending_or_raise(svc, incident_id)
    if status == "rejected":
        return {"status": "already_rejected", "incident_id": incident_id, "queued": False}
    if status == "approved":
        raise HTTPException(status_code=409, detail="incident was already approved")
    if not await svc.claim(incident_id):
        raise HTTPException(status_code=409, detail="another decision for this incident is in progress")
    try:
        await _append(svc, incident_id, STEP_REJECTED, {"rejected_by": admin.actor, "note": (body.note if body else None)})
    except Exception as exc:
        await svc.release(incident_id)
        logger.error("reject %s: ledger write failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="the ledger write failed; nothing was rejected")
    return {"status": "rejected", "incident_id": incident_id, "queued": False, "rejected_by": admin.actor}


# ---- incidents (read only)

async def _incident(svc: DashboardServices, incident_id: str) -> Dict[str, Any]:
    _check_id(incident_id)
    records = await _records(svc, incident_id)
    if not records:
        raise HTTPException(status_code=404, detail="incident not found")
    detection = step_payload(records, "detection")
    health = await svc.fetch_event("health", detection.get("health_event_id") or "")
    security = await svc.fetch_event("security", detection.get("security_event_id") or "")
    return build_incident(incident_id, records, health, security)


@router.get("/api/incidents")
async def list_incidents(svc: DashboardServices = Depends(get_services)):
    index = await asyncio.to_thread(index_steps, svc.ledger)
    rows = []
    for incident_id, items in index.items():
        steps = [s for _q, s, _k in items]
        if "detection" not in steps:      # mode-change and executor-only ledger entries are not incidents
            continue
        rows.append({"incident_id": incident_id, "status": approval_status(steps), "steps": steps})
    rows.sort(key=lambda r: r["incident_id"], reverse=True)
    return {"incidents": rows, "count": len(rows)}


@router.get("/api/incidents/{incident_id}")
async def incident_json(incident_id: str, svc: DashboardServices = Depends(get_services)):
    return await _incident(svc, incident_id)


# ---- kill switch

@router.get("/api/kill-switch")
async def kill_switch_status(svc: DashboardServices = Depends(get_services)):
    state = await current_mode(svc)
    history = await asyncio.to_thread(mode_history, svc.ledger)
    return {"mode": state["mode"], "readable": state["readable"], "dry_run": state["dry_run"], "history": history}


@router.post("/api/kill-switch")
async def kill_switch_toggle(body: ModeRequest, admin: AdminIdentity = Depends(require_admin),
                             svc: DashboardServices = Depends(get_services)):
    before = await current_mode(svc)
    if before["readable"] and before["raw"] == body.mode:
        return {"status": "unchanged", "mode": body.mode, "changed": False}
    try:
        await svc.mode_store.write_mode(body.mode)
    except Exception as exc:
        logger.error("kill switch write failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="could not update the kubeheal-mode ConfigMap")
    ledger_id = f"mode-{uuid.uuid4().hex}"
    try:
        await _append(svc, ledger_id, "mode_change", {
            "from": before["raw"] if before["readable"] else None,
            "to": body.mode,
            "source": "dashboard",
            "actor": admin.actor,
        })
    except Exception as exc:
        logger.error("kill switch change not recorded in the ledger: %s", type(exc).__name__)
        if body.mode == ENFORCE:       # never leave enforcement on without an audit record
            try:
                await svc.mode_store.write_mode(TEST)
            except Exception as exc2:
                logger.error("kill switch revert to test failed: %s", type(exc2).__name__)
        raise HTTPException(status_code=500, detail="the ledger write failed; the mode change was not kept")
    return {"status": "changed", "mode": body.mode, "changed": True, "actor": admin.actor, "ledger_id": ledger_id}


# ---- pages

@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(svc: DashboardServices = Depends(get_services)):
    pending = (await list_pending_approvals(svc))["pending"]
    incidents = (await list_incidents(svc))["incidents"]
    status = await kill_switch_status(svc)
    return HTMLResponse(pages.approvals_page(pending, incidents, status), headers=PAGE_HEADERS)


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_page(incident_id: str, svc: DashboardServices = Depends(get_services)):
    incident = await _incident(svc, incident_id)
    return HTMLResponse(pages.incident_page(incident), headers=PAGE_HEADERS)
