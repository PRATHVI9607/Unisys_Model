"""Approvals, ledger, mode switch and model info. Reads are open like the rest of the dashboard; every non-GET
route depends on `require_admin` (tests/test_dashboard_admin.py enumerates the routes to keep it that way).

Approval state lives in key_approval(<HUMAN action event id>), written by fusion. The dashboard never changes
`state`: it records `requested` {decision, actor, approval_id, ts_ms} on the pending key and, in the same
MULTI, XADDs STREAM_APPROVALS (for fusion) and STREAM_LEDGER (audit). A second decision then sees `requested`
and gets 409; fusion moves the state on to executing / executed / failed / rejected.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from dashboard.auth import Admin, require_admin
from kubeheal.contracts import (
    KEY_MODE,
    LEDGER_RETENTION_DAYS,
    STREAM_APPROVALS,
    STREAM_LEDGER,
    key_approval,
    now_ms,
)

log = logging.getLogger("kubeheal.dashboard")
router = APIRouter()
Reason = Annotated[str, Field(max_length=500)]
AdminDep = Annotated[Admin, Depends(require_admin)]
LEDGER_KINDS = ("action", "approval_pending", "approval", "rejection", "mode")
INFERENCE_URL = os.getenv("INFERENCE_URL", "http://kubeheal-inference.kubeheal.svc:8000").rstrip("/")
MODELS_DIR = Path(os.getenv("KUBEHEAL_MODELS_DIR", "models"))
SCAN_BATCH, SCAN_MAX = 500, 5000   # ledger filter: entries examined per page request


def _redis(request: Request) -> aioredis.Redis:
    r = request.app.state.hub.redis
    if r is None:
        raise HTTPException(503, "redis unavailable")
    return r


def _ledger_entry(**f: Any) -> dict[str, str]:
    base = dict.fromkeys(("namespace", "workload", "pod", "decision", "outcome", "action_event_id", "detail"), "")
    return {**base, "mode": "", **{k: str(v) for k, v in f.items()}, "ts_ms": str(now_ms())}


def _xadd_ledger(pipe, entry: dict[str, str]) -> None:
    cutoff = now_ms() - LEDGER_RETENTION_DAYS * 86_400_000
    pipe.xadd(STREAM_LEDGER, entry, minid=f"{cutoff}-0", approximate=True)


# ── session / mode ──────────────────────────────────────────────────────────────────────────────

@router.get("/api/admin/session")
async def session(admin: AdminDep):
    return {"actor": admin.actor}


@router.get("/api/mode")
async def get_mode(request: Request):
    hub = request.app.state.hub
    raw = await hub.redis.get(KEY_MODE) if hub.redis is not None else None
    last = next(iter(reversed(hub.buffers["action"])), None)
    return {"runtime": raw if raw in ("observe", "enforce") else None,
            "last_action_mode": last["mode"] if last else None}


class ModeBody(BaseModel):
    mode: Literal["observe", "enforce"]
    reason: Reason = ""


@router.post("/api/mode")
async def set_mode(body: ModeBody, request: Request, admin: AdminDep):
    r = _redis(request)
    prev = await r.get(KEY_MODE)
    async with r.pipeline(transaction=True) as pipe:
        pipe.set(KEY_MODE, body.mode)
        _xadd_ledger(pipe, _ledger_entry(kind="mode", actor=admin.actor, decision=body.mode, mode=body.mode,
                                         outcome="set", detail=json.dumps({"previous": prev, "reason": body.reason})))
        await pipe.execute()
    return {"runtime": body.mode, "previous": prev}


# ── approvals ───────────────────────────────────────────────────────────────────────────────────

def _view(action_id: str, state: dict, action: dict | None) -> dict:
    req = state.get("requested") or {}
    st = state.get("state", "pending")
    shown = f"{req['decision']} requested" if st == "pending" and req.get("decision") else st
    out = {"action_event_id": action_id, "state": st, "display_state": shown, "requested": req or None}
    for k in ("candidate", "namespace", "workload", "pod", "pod_uid", "health_event_id", "security_event_id",
              "rationale", "score", "created_ms", "outcome"):
        out[k] = state.get(k, action.get(k) if action else None)
    return out


@router.get("/api/approvals")
async def list_approvals(request: Request, limit: int = Query(100, ge=1, le=200)):
    hub = request.app.state.hub
    humans = [a for a in reversed(hub.buffers["action"]) if a["decision"] == "HUMAN"][:limit]
    states: list[Any] = []
    if humans and hub.redis is not None:
        try:
            states = await hub.redis.mget([key_approval(a["event_id"]) for a in humans])
        except aioredis.RedisError as exc:
            raise HTTPException(503, "redis unavailable") from exc
    items = []
    for a, raw in zip(humans, states, strict=False):
        try:
            state = json.loads(raw) if raw else None
        except ValueError:
            state = None
        if isinstance(state, dict):
            items.append(_view(a["event_id"], state, a))
    return {"items": items, "pending": sum(i["state"] == "pending" and not i["requested"] for i in items)}


class DecisionBody(BaseModel):
    reason: Reason = ""


async def _decide(request: Request, action_id: str, decision: str, reason: str, admin: Admin) -> dict:
    r = _redis(request)
    key = key_approval(action_id)
    try:
        async with r.pipeline(transaction=True) as pipe:
            await pipe.watch(key)
            raw = await pipe.get(key)
            if raw is None:
                raise HTTPException(404, "no approval for this event (never requested or expired)")
            state = json.loads(raw)
            if state.get("state") != "pending" or state.get("requested"):
                raise HTTPException(409, f"already {state.get('display_state') or state.get('state')}")
            approval_id = uuid.uuid4().hex
            state["requested"] = {"decision": decision, "actor": admin.actor, "approval_id": approval_id,
                                  "ts_ms": now_ms()}
            pipe.multi()
            pipe.set(key, json.dumps(state), keepttl=True)
            pipe.xadd(STREAM_APPROVALS, {"approval_id": approval_id, "action_event_id": action_id,
                                         "decision": decision, "actor": admin.actor, "reason": reason,
                                         "ts_ms": str(now_ms())})
            _xadd_ledger(pipe, _ledger_entry(
                kind="approval" if decision == "approve" else "rejection", actor=admin.actor,
                namespace=state.get("namespace", ""), workload=state.get("workload", ""), pod=state.get("pod", ""),
                decision=state.get("candidate", "") if decision == "approve" else "REJECT",
                outcome=f"{decision}_requested", action_event_id=action_id, detail=reason))
            await pipe.execute()
    except aioredis.WatchError as exc:
        raise HTTPException(409, "approval changed concurrently, reload") from exc
    return _view(action_id, state, None)


@router.post("/api/approvals/{action_event_id}/approve")
async def approve(action_event_id: str, request: Request, admin: AdminDep, body: DecisionBody | None = None):
    return await _decide(request, action_event_id, "approve", body.reason if body else "", admin)


@router.post("/api/approvals/{action_event_id}/reject")
async def reject(action_event_id: str, request: Request, admin: AdminDep, body: DecisionBody | None = None):
    return await _decide(request, action_event_id, "reject", body.reason if body else "", admin)


@router.get("/api/approvals/{action_event_id}")
async def approval(action_event_id: str, request: Request):
    raw = await _redis(request).get(key_approval(action_event_id))
    if raw is None:
        raise HTTPException(404, "no approval for this event")
    return _view(action_event_id, json.loads(raw), None)


# ── ledger ──────────────────────────────────────────────────────────────────────────────────────

@router.get("/api/ledger")
async def ledger(request: Request, limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
                 namespace: str | None = None, kind: str | None = None, actor: str | None = None):
    """Newest first. `cursor` is the previous page's next_cursor (a stream id); filters are exact matches."""
    r = _redis(request)
    if kind and kind not in LEDGER_KINDS:
        raise HTTPException(422, f"kind must be one of {LEDGER_KINDS}")
    want = {k: v for k, v in (("namespace", namespace), ("kind", kind), ("actor", actor)) if v}
    out: list[dict] = []
    upper, scanned, more = f"({cursor}" if cursor else "+", 0, False
    try:
        while scanned < SCAN_MAX:
            batch = await r.xrevrange(STREAM_LEDGER, max=upper, min="-", count=SCAN_BATCH)
            full = len(batch) == SCAN_BATCH
            for i, (eid, f) in enumerate(batch):
                scanned += 1
                upper = f"({eid}"
                if all(f.get(k) == v for k, v in want.items()):
                    out.append({"id": eid, **f})
                    if len(out) == limit:
                        more = full or i + 1 < len(batch)
                        break
            else:
                more = full
                if full:
                    continue
            break
    except aioredis.RedisError as exc:
        raise HTTPException(503, "redis unavailable") from exc
    return {"entries": out, "next_cursor": upper[1:] if more else None}


# ── models ──────────────────────────────────────────────────────────────────────────────────────

def _fetch_ready() -> dict | None:
    try:
        with urllib.request.urlopen(f"{INFERENCE_URL}/readyz", timeout=1.5) as resp:   # noqa: S310  fixed http(s) URL from env
            return json.load(resp)
    except urllib.error.HTTPError as exc:   # 503 still carries the JSON body
        try:
            return json.load(exc)
        except ValueError:
            return None
    except (OSError, ValueError):
        return None


def _meta(task: str) -> dict | None:
    try:
        m = json.loads((MODELS_DIR / task / "meta.json").read_text())
    except (OSError, ValueError):
        return None
    mt = m.get("metrics", {})
    return {"version": m.get("version"), "created_at": m.get("created_at"), "labels": m.get("labels"),
            "synthetic": (m.get("data") or {}).get("synthetic") if isinstance(m.get("data"), dict) else None,
            "test_macro_f1": mt.get("test", {}).get("macro_f1"),
            "cv_macro_f1": mt.get("cv5_grouped", {}).get("macro_f1"),
            "heldout_macro_f1": mt.get("heldout_family", {}).get("pooled", {}).get("macro_f1"),
            "coverage": mt.get("test", {}).get("coverage"), "alpha": m.get("alpha"),
            "latency_p50_ms": mt.get("latency_ms", {}).get("p50"), "latency_p99_ms": mt.get("latency_ms", {}).get("p99")}


_models_cache: tuple[float, dict] | None = None


@router.get("/api/models")
async def models():
    global _models_cache
    if _models_cache and time.monotonic() - _models_cache[0] < 10:
        return _models_cache[1]
    ready = await asyncio.to_thread(_fetch_ready)
    data = {"inference": {"reachable": ready is not None, "ready": bool(ready and ready.get("ready")),
                          "versions": (ready or {}).get("models", {})},
            "meta": {t: _meta(t) for t in ("health", "security")}}
    _models_cache = (time.monotonic(), data)
    return data
