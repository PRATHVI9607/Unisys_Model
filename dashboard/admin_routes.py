"""Approvals, incident view and kill switch endpoints of the dashboard (P8: S-DB-1/2, S-KS-6).

Reads are open like the rest of the dashboard (it sits behind the Ingress). Every mutating endpoint
depends on `require_admin` (503 without a configured token, 401 without credentials, 403 for a wrong
token). Collaborators (ledger, Redis queue, kill switch ConfigMap) come from `DashboardServices` on
`app.state.services`, so tests inject fakes and never need Redis, MinIO or a cluster.

Approval flow (HUMAN_PATCH / HUMAN_CONTAIN decisions written by Fusion with an `approval_requested` entry):
  pending = approval_requested present, no `approved` and no `rejected` entry
  approve : mode enforce: claim the incident, queue a request on kubeheal.exec (approved_by = admin
            identity, dry_run=false), store the stream id in the claim, then ledger `approved`. If the
            ledger write fails after queueing, a repeated approve finishes the record from the claim and
            never queues again.
            mode test or unreadable: queue the request with dry_run=true and write `dry_run_approved`;
            the incident stays pending and can be approved again once the mode is enforce.
  reject  : claim the incident, ledger `rejected`, nothing queued
The claim is a Redis SET NX in deployments, so two replicas cannot decide the same incident twice.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ValidationError

from agents.common.killswitch import ENFORCE, TEST, is_dry_run, normalize
from agents.common.ledger import Ledger
from dashboard import pages
from dashboard.admin_auth import AdminIdentity, require_admin
from dashboard.incident_view import build_incident, num
from dashboard.ledger_view import (
    HUMAN_DECISIONS,
    STEP_APPROVED,
    STEP_DRY_RUN_APPROVED,
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
# Same value as agents.executor.snapshots.FREEZE_PREFIX (tests/test_dashboard_freeze.py checks it); the
# dashboard image does not import the Executor package.
FREEZE_PREFIX = "kubeheal:snapfreeze"
FREEZE_REASON_MIN_CHARS = 10   # chosen, not measured: a written reason must be more than a word
BARE_CLAIM_MIN_AGE_S = 60      # chosen, not measured: reconcile leaves a younger bare claim to its owner
CLAIM_KEY = "kubeheal:approval:{incident_id}"
CLAIM_TTL_S = 10 * 60  # chosen, not measured; override with KUBEHEAL_APPROVAL_CLAIM_TTL_S
LEDGER_APPEND_ATTEMPTS = 3      # tries to write `approved` after the request was queued
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
    claim_set: Callable[[str, str], Awaitable[None]]            # store a value in an existing claim
    claim_get: Callable[[str], Awaitable[Optional[str]]]
    list_claims: Callable[[], Awaitable[List[tuple[str, str]]]]
    exec_entry_exists: Callable[[str], Awaitable[bool]]
    fetch_event: Callable[[str, str], Awaitable[Optional[Dict[str, Any]]]]
    # SnapshotFreeze keys (namespace, pvc, key) held by an incident, and their removal. Optional so the
    # older fakes keep working; the release tool answers 503 without them.
    freeze_list: Optional[Callable[[str], Awaitable[List[tuple[str, str, str]]]]] = None
    freeze_delete: Optional[Callable[[List[str]], Awaitable[None]]] = None
    # Compare-and-delete: remove a key only while its value is still the given incident id. Returns the keys
    # that were removed. Preferred over `freeze_delete` when present (older fakes only have `freeze_delete`).
    freeze_delete_if_owned: Optional[Callable[[List[str], str], Awaitable[List[str]]]] = None


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
        return bool(await _redis().set(CLAIM_KEY.format(incident_id=incident_id),
                                       f"{BARE_CLAIM_PREFIX}{int(time.time())}", nx=True, ex=_claim_ttl_s()))

    async def release(incident_id: str) -> None:
        await _redis().delete(CLAIM_KEY.format(incident_id=incident_id))

    async def claim_set(incident_id: str, value: str) -> None:
        # No expiry: a claim that holds a queued stream id must outlive the TTL until `approved` is in the
        # ledger, otherwise a repeated approve could queue the same request again.
        await _redis().set(CLAIM_KEY.format(incident_id=incident_id), value, xx=True)

    async def claim_get(incident_id: str) -> Optional[str]:
        v = await _redis().get(CLAIM_KEY.format(incident_id=incident_id))
        return v.decode() if isinstance(v, bytes) else v

    async def list_claims() -> List[tuple[str, str]]:
        r = _redis()
        claims = []
        async for key in r.scan_iter(match=CLAIM_KEY.format(incident_id="*")):
            key = key.decode() if isinstance(key, bytes) else str(key)
            incident_id = key.removeprefix("kubeheal:approval:")
            value = await r.get(key)
            if value is not None and valid_incident_id(incident_id):
                claims.append((incident_id, value.decode() if isinstance(value, bytes) else str(value)))
        return claims

    async def exec_entry_exists(stream_id: str) -> bool:
        return bool(await _redis().xrange(EXEC_STREAM, min=stream_id, max=stream_id, count=1))

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

    async def freeze_list(incident_id: str) -> List[tuple[str, str, str]]:
        r = _redis()
        found = []
        async for key in r.scan_iter(match=f"{FREEZE_PREFIX}:*"):
            key = key.decode() if isinstance(key, bytes) else str(key)
            value = await r.get(key)
            value = value.decode() if isinstance(value, bytes) else value
            if value == incident_id:
                rest = key[len(FREEZE_PREFIX) + 1:]
                namespace, _, pvc = rest.partition(":")
                found.append((namespace, pvc, key))
        return found

    async def freeze_delete(keys: List[str]) -> None:
        if keys:
            await _redis().delete(*keys)

    async def freeze_delete_if_owned(keys: List[str], incident_id: str) -> List[str]:
        """Delete each key only while it still holds `incident_id`. Between the listing and the delete another
        incident may have taken the PVC's freeze key over; that key must stay."""
        r = _redis()
        removed = []
        for key in keys:
            run_script = getattr(r, "eval", None)
            if run_script is not None:
                gone = bool(await run_script(_DELETE_IF_VALUE, 1, key, incident_id))
            else:                                   # client without EVAL: not atomic
                value = await r.get(key)
                value = value.decode() if isinstance(value, bytes) else value
                gone = value == incident_id
                if gone:
                    await r.delete(key)
            if gone:
                removed.append(key)
        return removed

    return DashboardServices(ledger, mode_store, enqueue_exec, claim, release, claim_set, claim_get,
                             list_claims, exec_entry_exists, fetch_event, freeze_list, freeze_delete,
                             freeze_delete_if_owned)


BARE_CLAIM_PREFIX = "claimed@"
_DELETE_IF_VALUE = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"


def _bare_claim_age_s(value: Optional[str]) -> Optional[float]:
    """Age of a claim that holds no stream id yet, from `claimed@<epoch>`. None when unknown (an older
    claim written as plain `claimed`), which callers treat as old."""
    if value and value.startswith(BARE_CLAIM_PREFIX):
        try:
            return max(0.0, time.time() - float(value[len(BARE_CLAIM_PREFIX):]))
        except ValueError:
            return None
    return None


def _claim_ttl_s() -> int:
    """Return the chosen short claim lease, tunable per deployment and never disabled by bad config."""
    raw = os.getenv("KUBEHEAL_APPROVAL_CLAIM_TTL_S")
    if raw is None:
        return CLAIM_TTL_S
    try:
        value = int(raw)
        if value > 0:
            return value
    except ValueError:
        pass
    logger.warning("KUBEHEAL_APPROVAL_CLAIM_TTL_S must be a positive integer; using the chosen default")
    return CLAIM_TTL_S


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

async def _body(request: Request, model, required: bool = False):
    """Parse the JSON body AFTER authentication (the admin dependency has already run), so a malformed
    body without credentials is 401 or 503, never 422."""
    raw = await request.body()
    if not raw.strip():
        if required:
            raise HTTPException(status_code=422, detail="request body required")
        return model()
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=[{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()])


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
        # Candidates are the changed fields of the spec diff that Fusion recorded with the decision (V5-D9). Older
        # incidents carried a model attribution (top_field); it is only a fallback for those.
        decision_record = step_payload(records, "decision")
        recorded = decision_record.get("patch_fields")
        patch_fields = [str(f) for f in recorded if isinstance(f, str) and f.strip()] if isinstance(recorded, list) else []
        if "patch_fields" not in decision_record:          # an older incident; a recorded empty list is final
            legacy = (step_payload(records, "scores").get("health") or {}).get("top_field") or ""
            patch_fields = [str(legacy)] if legacy and str(legacy).lower() != "unknown" else []
        field = patch_fields[0] if patch_fields else ""
        if not (namespace and deployment and field):
            raise HTTPException(status_code=422, detail="cannot approve: the incident names no drifted field to restore")
    elif decision == "human_contain":
        action = "contain"
        field, patch_fields = "", []
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
        "patch_fields": json.dumps(patch_fields),
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


async def _append_with_retry(svc: DashboardServices, incident_id: str, step: str, payload: Dict[str, Any]) -> bool:
    for _attempt in range(LEDGER_APPEND_ATTEMPTS):
        try:
            await _append(svc, incident_id, step, payload)
            return True
        except Exception as exc:
            logger.error("ledger write %s/%s failed: %s", incident_id, step, type(exc).__name__)
    return False


async def reconcile_approval_claims(svc: DashboardServices) -> Dict[str, int]:
    """Repair interrupted approvals at startup using the durable exec stream and audit ledger.

    A queued claim is completed only when its exact Redis stream entry still exists. Claims without a
    matching stream entry and without a terminal ledger record are released so the pending decision can
    be handled again. A bare `claimed` value means the process stopped before it stored a stream id.
    """
    counts = {"completed": 0, "released": 0, "skipped": 0}
    for incident_id, value in await svc.list_claims():
        try:
            records = await _records(svc, incident_id)
            steps = [str(r.get("step", "")) for r in records]
            status = approval_status(steps)
            if status in {"approved", "rejected"}:
                counts["skipped"] += 1
                continue
            queued = _queued_claim(value)
            if queued and await svc.exec_entry_exists(str(queued["stream_id"])):
                payload = {k: queued.get(k) for k in
                           ("approved_by", "action", "dry_run", "mode", "mode_readable", "note")}
                payload.update({"exec_stream_id": queued["stream_id"], "reconciled_by": "startup"})
                if await _append_with_retry(svc, incident_id, STEP_APPROVED, payload):
                    await svc.release(incident_id)      # `approved` is in the ledger, the claim is done
                    counts["completed"] += 1
                else:
                    counts["skipped"] += 1
            elif status == "pending":
                age = _bare_claim_age_s(value)
                if not queued and age is not None and age < BARE_CLAIM_MIN_AGE_S:
                    counts["skipped"] += 1      # probably another replica's approval still in progress
                    continue
                await svc.release(incident_id)
                counts["released"] += 1
        except Exception as exc:
            logger.warning("approval claim reconciliation failed for %s: %s", incident_id, type(exc).__name__)
            counts["skipped"] += 1
    return counts


def _queued_claim(value: Optional[str]) -> Optional[Dict[str, Any]]:
    """The claim of an approval whose request is queued: JSON with the stream id."""
    if not value or not value.startswith("{"):
        return None
    try:
        data = json.loads(value)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("stream_id") else None


@router.post("/api/approvals/{incident_id}/approve")
async def approve(incident_id: str, request: Request,
                  admin: AdminIdentity = Depends(require_admin),
                  svc: DashboardServices = Depends(get_services)):
    note = (await _body(request, DecisionNote)).note
    records, status = await _load_pending_or_raise(svc, incident_id)
    if status == "approved":
        return {"status": "already_approved", "incident_id": incident_id, "queued": False}
    if status == "rejected":
        raise HTTPException(status_code=409, detail="incident was already rejected")

    # An earlier approval queued its request but could not write `approved`: finish the record, never queue again.
    queued = _queued_claim(await svc.claim_get(incident_id))
    if queued:
        payload = {k: queued.get(k) for k in ("approved_by", "action", "dry_run", "mode", "mode_readable", "note")}
        payload.update({"exec_stream_id": queued["stream_id"], "reconciled_by": admin.actor})
        if not await _append_with_retry(svc, incident_id, STEP_APPROVED, payload):
            raise HTTPException(status_code=500, detail="the request is already queued but the ledger write still fails; "
                                                        "repeat the approve to finish the record, it will not queue again")
        await svc.release(incident_id)
        return {"status": "already_queued", "incident_id": incident_id, "queued": False, "recorded": True}

    mode = await current_mode(svc)
    fields = _exec_request(incident_id, records, admin.actor, mode["dry_run"])
    if not await svc.claim(incident_id):
        raise HTTPException(status_code=409, detail="another decision for this incident is in progress")

    # The status read at the top may be stale: another approve could have queued, written `approved` and
    # released its claim between that read and our claim. Read the ledger again now that the claim is ours.
    try:
        _recheck_records, recheck_status = await _load_pending_or_raise(svc, incident_id)
    except BaseException:
        await svc.release(incident_id)
        raise
    if recheck_status != "pending":
        await svc.release(incident_id)
        if recheck_status == "approved":
            return {"status": "already_approved", "incident_id": incident_id, "queued": False}
        raise HTTPException(status_code=409, detail=f"incident was already {recheck_status}")

    if mode["dry_run"]:
        # Mode is test or unreadable: queue a dry run and keep the incident open (approvable again in enforce mode).
        try:
            try:
                stream_id = await svc.enqueue_exec(fields)
            except Exception as exc:
                logger.error("approve %s: queueing failed: %s", incident_id, type(exc).__name__)
                raise HTTPException(status_code=502, detail="could not queue the request for the Executor; nothing was approved")
            ok = await _append_with_retry(svc, incident_id, STEP_DRY_RUN_APPROVED, {
                "approved_by": admin.actor, "action": fields["action"], "dry_run": True,
                "mode": mode["mode"], "mode_readable": mode["readable"],
                "exec_stream_id": stream_id, "note": note,
            })
        finally:
            await svc.release(incident_id)
        if not ok:
            raise HTTPException(status_code=500, detail="the dry run was queued but the ledger write failed; "
                                                        "the incident is still pending")
        return {"status": "dry_run_approved", "incident_id": incident_id, "action": fields["action"],
                "dry_run": True, "queued": True, "approved_by": admin.actor, "incident_closed": False}

    try:
        stream_id = await svc.enqueue_exec(fields)
    except Exception as exc:
        await svc.release(incident_id)
        logger.error("approve %s: queueing failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="could not queue the request for the Executor; nothing was approved")
    payload = {"approved_by": admin.actor, "action": fields["action"], "dry_run": False,
               "mode": mode["mode"], "mode_readable": mode["readable"], "note": note}
    try:
        await svc.claim_set(incident_id, json.dumps({**payload, "stream_id": stream_id}))
    except Exception as exc:
        logger.error("approve %s: could not store the stream id in the claim: %s", incident_id, type(exc).__name__)
    if not await _append_with_retry(svc, incident_id, STEP_APPROVED, {**payload, "exec_stream_id": stream_id}):
        raise HTTPException(status_code=500, detail="the request is queued but the ledger write failed; "
                                                    "repeat the approve to finish the record, it will not queue again")
    try:
        await svc.release(incident_id)          # `approved` is in the ledger, the claim is done
    except Exception as exc:
        logger.warning("approve %s: claim cleanup failed: %s", incident_id, type(exc).__name__)
    return {"status": "approved", "incident_id": incident_id, "action": fields["action"],
            "dry_run": False, "queued": True, "approved_by": admin.actor, "incident_closed": True}


@router.post("/api/approvals/{incident_id}/reject")
async def reject(incident_id: str, request: Request,
                 admin: AdminIdentity = Depends(require_admin),
                 svc: DashboardServices = Depends(get_services)):
    note = (await _body(request, DecisionNote)).note
    _records_, status = await _load_pending_or_raise(svc, incident_id)
    if status == "rejected":
        return {"status": "already_rejected", "incident_id": incident_id, "queued": False}
    if status == "approved":
        raise HTTPException(status_code=409, detail="incident was already approved")
    if not await svc.claim(incident_id):
        raise HTTPException(status_code=409, detail="another decision for this incident is in progress")
    try:
        await _append(svc, incident_id, STEP_REJECTED, {"rejected_by": admin.actor, "note": note})
    except Exception as exc:
        await svc.release(incident_id)
        logger.error("reject %s: ledger write failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="the ledger write failed; nothing was rejected")
    return {"status": "rejected", "incident_id": incident_id, "queued": False, "rejected_by": admin.actor}


@router.post("/api/approvals/{incident_id}/release-claim")
async def release_claim(incident_id: str, request: Request,
                       admin: AdminIdentity = Depends(require_admin),
                       svc: DashboardServices = Depends(get_services)):
    """Admin recovery for an abandoned approval claim. Audit the release before deleting the claim."""
    note = (await _body(request, DecisionNote)).note
    records, status = await _load_pending_or_raise(svc, incident_id)
    if status != "pending":
        raise HTTPException(status_code=409, detail="only a pending approval claim can be released")
    value = await svc.claim_get(incident_id)
    if value is None:
        raise HTTPException(status_code=404, detail="approval claim not found")
    if _queued_claim(value):
        # The request is already on kubeheal.exec. Releasing would let the next approve queue it again.
        raise HTTPException(status_code=409, detail="the approval is already queued; approve again to finish "
                                                    "the ledger record, it will not queue a second request")
    try:
        await _append(svc, incident_id, "claim_released", {
            "actor": admin.actor, "note": note, "claim_value": value,
        })
    except Exception as exc:
        logger.error("release claim %s: ledger write failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="the ledger write failed; the claim was not released")
    await svc.release(incident_id)
    return {"status": "claim_released", "incident_id": incident_id, "actor": admin.actor}


# ---- SnapshotFreeze release (operator tool, P7-RR-10)

class FreezeReleaseRequest(BaseModel):
    force: bool = False
    reason: Optional[str] = Field(default=None, max_length=1000)


def _incident_closed(records: List[Dict[str, Any]]) -> bool:
    """Closed means the Executor recorded a finished restore: an `executor_result` whose outcome is exactly
    `restored`. Contained, kept-isolated, failed and escalated outcomes leave the incident open."""
    return any(r.get("step") == "executor_result"
               and str((r.get("payload") or {}).get("outcome", "")) == "restored" for r in records)


@router.post("/api/incidents/{incident_id}/release-snapshot-freeze")
async def release_snapshot_freeze(incident_id: str, request: Request,
                                  admin: AdminIdentity = Depends(require_admin),
                                  svc: DashboardServices = Depends(get_services)):
    """Lift the rolling-snapshot freeze that one incident holds on its PVCs.

    One incident id per call. A written reason (at least FREEZE_REASON_MIN_CHARS characters) is always
    required, a closed incident included. Refused unless the incident is closed, or `force` is true. Only
    the Redis freeze keys are removed: no snapshot, PVC or other data is ever deleted. The ledger entry
    (actor, reason) is written BEFORE the keys are removed. A key is deleted only while it still holds this
    incident id (compare-and-delete); one taken over meanwhile is left in place. In mode test or unreadable
    the call is a dry run: it records `snapshot_freeze_release_dry_run` and removes nothing."""
    body = await _body(request, FreezeReleaseRequest)
    _check_id(incident_id)
    # The owner rule asks for actor and reason on every release, a closed incident included.
    if len((body.reason or "").strip()) < FREEZE_REASON_MIN_CHARS:
        raise HTTPException(status_code=422, detail=f"a written reason of at least "
                                                    f"{FREEZE_REASON_MIN_CHARS} characters is required")
    if svc.freeze_list is None or (svc.freeze_delete is None and svc.freeze_delete_if_owned is None):
        raise HTTPException(status_code=503, detail="snapshot freeze access is not configured")
    records = await _records(svc, incident_id)
    if not records:
        raise HTTPException(status_code=404, detail="incident not found")
    reason = (body.reason or "").strip()
    closed = _incident_closed(records)
    if not closed and not body.force:
        raise HTTPException(status_code=409, detail="the incident is not closed; pass force=true with a "
                                                    "written reason to release the freeze anyway")
    held = await svc.freeze_list(incident_id)
    if not held:
        raise HTTPException(status_code=404, detail="this incident holds no snapshot freeze")
    mode = await current_mode(svc)
    pvcs = [{"namespace": ns, "pvc": pvc} for ns, pvc, _key in held]
    entry = {"actor": admin.actor, "reason": reason or None, "forced": bool(body.force and not closed),
             "incident_closed": closed, "pvcs": pvcs, "mode": mode["mode"], "mode_readable": mode["readable"]}
    if mode["dry_run"]:
        try:
            await _append(svc, incident_id, "snapshot_freeze_release_dry_run", {
                **entry, "note": "DRY RUN: would have released the freeze; nothing was removed"})
        except Exception as exc:
            logger.error("freeze release dry run %s: ledger write failed: %s", incident_id, type(exc).__name__)
            raise HTTPException(status_code=500, detail="the ledger write failed")
        return {"status": "dry_run", "incident_id": incident_id, "released": False, "pvcs": pvcs,
                "actor": admin.actor}
    try:
        await _append(svc, incident_id, "snapshot_freeze_released", entry)
    except Exception as exc:
        logger.error("freeze release %s: ledger write failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="the ledger write failed; the freeze was not released")
    keys = [key for _ns, _pvc, key in held]
    try:
        if svc.freeze_delete_if_owned is not None:
            removed = await svc.freeze_delete_if_owned(keys, incident_id)
        else:
            await svc.freeze_delete(keys)
            removed = keys
    except Exception as exc:
        logger.error("freeze release %s: key removal failed: %s", incident_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="the release is recorded but removing the freeze failed; "
                                                    "repeat the call")
    kept = [key for key in keys if key not in set(removed)]
    if kept:
        logger.warning("freeze release %s: %d key(s) no longer held by this incident were left in place",
                       incident_id, len(kept))
    return {"status": "released", "incident_id": incident_id, "released": True, "pvcs": pvcs,
            "actor": admin.actor, "forced": entry["forced"], "left_in_place": kept}


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
async def kill_switch_toggle(request: Request, admin: AdminIdentity = Depends(require_admin),
                             svc: DashboardServices = Depends(get_services)):
    body = await _body(request, ModeRequest, required=True)
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
                raise HTTPException(status_code=500, detail="the ledger write failed and the revert to test also failed; "
                                                            "the ConfigMap may still say enforce, check it now")
            raise HTTPException(status_code=500, detail="the ledger write failed; the mode was reverted to test")
        raise HTTPException(status_code=500, detail="the mode was changed to test but the audit entry is missing "
                                                    "from the ledger")
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
