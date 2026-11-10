"""Read side of the audit ledger for the dashboard.

`agents.common.ledger.Ledger` is write-only (`append`); its stores expose `keys(prefix)` but no read.
The dashboard therefore reads objects through whichever backend the store is: the in-memory store
(tests, local runs) or the MinIO adapter. Keys look like `incidents/<incident_id>/<seq>-<step>.json`.
Nothing here ever writes. Writes go through `Ledger.append`.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

STEP_REQUESTED = "approval_requested"
STEP_APPROVED = "approved"
STEP_REJECTED = "rejected"
STEP_MODE_CHANGE = "mode_change"
HUMAN_DECISIONS = frozenset({"human_patch", "human_contain"})

_KEY = re.compile(r"^incidents/([^/]+)/(\d+)-(.+)\.json$")
INCIDENT_ID_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def valid_incident_id(incident_id: str) -> bool:
    return bool(incident_id) and len(incident_id) <= 63 and bool(INCIDENT_ID_RE.match(incident_id))


def parse_key(key: str) -> Optional[Tuple[str, int, str]]:
    m = _KEY.match(key)
    return (m.group(1), int(m.group(2)), m.group(3)) if m else None


def _read_bytes(store: Any, key: str) -> bytes:
    if hasattr(store, "read"):
        return store.read(key)
    if hasattr(store, "objects"):                      # InMemoryLedgerStore
        return store.objects[key]
    if hasattr(store, "client") and hasattr(store, "bucket"):   # MinioLedgerStore
        resp = store.client.get_object(bucket_name=store.bucket, object_name=key)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()
    raise TypeError(f"ledger store {type(store).__name__} has no read path for the dashboard")


def index_steps(ledger: Any, prefix: str = "incidents/") -> Dict[str, List[Tuple[int, str, str]]]:
    """incident_id -> [(sequence, step, key)] sorted by sequence. Uses key names only (no object reads)."""
    out: Dict[str, List[Tuple[int, str, str]]] = {}
    for key in ledger.store.keys(prefix):
        parsed = parse_key(key)
        if parsed:
            incident_id, seq, step = parsed
            out.setdefault(incident_id, []).append((seq, step, key))
    for items in out.values():
        items.sort()
    return out


def read_incident(ledger: Any, incident_id: str) -> List[Dict[str, Any]]:
    """All ledger records of one incident in sequence order. Unreadable objects are skipped."""
    records: List[Dict[str, Any]] = []
    for seq, step, key in index_steps(ledger, f"incidents/{incident_id}/").get(incident_id, []):
        try:
            rec = json.loads(_read_bytes(ledger.store, key))
        except Exception as exc:   # one bad object must not hide the rest of the timeline
            logger.warning("ledger object %s unreadable: %s", key, type(exc).__name__)
            continue
        if isinstance(rec, dict):
            rec.setdefault("sequence", seq)
            rec.setdefault("step", step)
            records.append(rec)
    return records


def approval_status(steps: Iterable[str]) -> str:
    """none | pending | approved | rejected, from the step names of one incident."""
    s: Set[str] = set(steps)
    if STEP_REQUESTED not in s:
        return "none"
    if STEP_APPROVED in s:
        return "approved"
    if STEP_REJECTED in s:
        return "rejected"
    return "pending"


def step_payload(records: List[Dict[str, Any]], step: str) -> Dict[str, Any]:
    """Payload of the first record with this step (the newest for repeated steps is not needed here)."""
    for rec in records:
        if rec.get("step") == step and isinstance(rec.get("payload"), dict):
            return rec["payload"]
    return {}


def mode_history(ledger: Any, limit: int = 50) -> List[Dict[str, Any]]:
    """Every `mode_change` ledger entry (Executor, Fusion hook and dashboard), oldest first."""
    entries: List[Dict[str, Any]] = []
    for incident_id, items in index_steps(ledger).items():
        for _seq, step, key in items:
            if step != STEP_MODE_CHANGE:
                continue
            try:
                rec = json.loads(_read_bytes(ledger.store, key))
            except Exception as exc:
                logger.warning("ledger object %s unreadable: %s", key, type(exc).__name__)
                continue
            payload = rec.get("payload") if isinstance(rec, dict) else None
            if not isinstance(payload, dict):
                continue
            entries.append({
                "timestamp": rec.get("timestamp"),
                "from": payload.get("from"),
                "to": payload.get("to"),
                "source": payload.get("source"),
                "actor": payload.get("actor"),
                "ledger_id": incident_id,
            })
    entries.sort(key=lambda e: str(e.get("timestamp") or ""))
    return entries[-limit:] if limit else entries
