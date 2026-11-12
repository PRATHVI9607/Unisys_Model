"""
Request validation for the Executor (P7-RR-8).
==============================================
Runs BEFORE any Kubernetes call. A request is one of:

  ok        -> proceed
  refused   -> malformed or inconsistent; recorded as `refused:<reason>`, nothing is touched
  escalate  -> well formed but cannot be executed safely; recorded as `escalated:<reason>` and sent
               to a human (for example a restore without t0_ms: the Executor never guesses T0)

The name-prefix check (pod starts with `<workload>-`) is a cheap first filter. Once the paths have
read the pod, its ownerReferences are the authority (see `workload_owns_pod` in quarantine.py).
`deployment` is optional for `contain` (the pod's owner is then taken from the cluster).
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ACTIONS = frozenset({"contain", "patch", "restore"})
WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet"})

CONTAINMENT_LABELS = frozenset({"ransomware", "exfiltration"})   # Q2: the only labels that may contain automatically
MAX_LIST_ITEMS = 64          # chosen bound on patch_fields and rule_reasons
MAX_ITEM_CHARS = 256         # chosen bound on one field path or reason

_DNS_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")   # also a valid label value


@dataclass
class Request:
    action: str
    namespace: str
    incident_id: str
    deployment: str = ""
    pod: str = ""
    patch_field: str = ""
    kind: str = "Deployment"
    kind_given: bool = False      # False: contain accepts either owner chain
    t0_ms: Optional[int] = None
    dry_run: bool = False
    # V5-D6/D9 fields Fusion sends. patch_fields are the CANDIDATE drifted fields from the spec diff against the
    # baseline (the Executor re-derives and verifies the real diff itself); the rest is recorded in the ledger.
    patch_fields: List[str] = field(default_factory=list)
    rule_path: bool = False
    rule_reasons: List[str] = field(default_factory=list)
    containment_label: str = ""
    restore_after: bool = False
    human_followup: bool = False


def _name_ok(v: str, maxlen: int = 253) -> bool:
    return bool(v) and len(v) <= maxlen and bool(_DNS_SUBDOMAIN.match(v))


def _flag(v) -> bool:
    return str(v).strip().lower() in ("true", "1")


def _string_list(raw, what: str) -> Tuple[Optional[List[str]], str]:
    """A JSON list of non-empty short strings (or an already parsed list); empty for a missing value.
    (None, reason) for anything malformed: the request is then refused, never guessed."""
    if raw in (None, ""):
        return [], ""
    value = raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError:
            return None, f"{what} is not valid JSON"
    if not isinstance(value, list):
        return None, f"{what} is not a JSON list"
    if len(value) > MAX_LIST_ITEMS:
        return None, f"{what} has more than {MAX_LIST_ITEMS} entries"
    items: List[str] = []
    for item in value:
        if not isinstance(item, str) or len(item) > MAX_ITEM_CHARS or any(ord(c) < 32 for c in item):
            return None, f"{what} holds an entry that is not a short plain string"
        if item.strip():
            items.append(item.strip())
    return items, ""


def parse_request(f: Dict) -> Tuple[str, str, Optional[Request]]:
    """(status, reason, request). status is 'ok', 'refused' or 'escalate'."""
    action = f.get("action")
    if action not in ACTIONS:
        return "refused", f"unknown action {action!r}", None
    namespace = f.get("namespace", "") or ""
    if not _DNS_LABEL.match(namespace) or len(namespace) > 63:
        return "refused", f"invalid namespace {namespace!r}", None
    incident_id = f.get("incident_id", "") or ""
    # contain and restore put the id into labels and object names, so they need a valid one; the
    # drift path only uses it for the ledger and the rollback record, so a missing id is allowed there.
    id_needed = action in ("contain", "restore") or incident_id != ""
    if id_needed and (not _DNS_LABEL.match(incident_id) or len(incident_id) > 63):
        return "refused", ("missing or invalid incident_id (lowercase DNS label, "
                           "at most 63 characters)"), None
    deployment = f.get("deployment", "") or ""
    pod = f.get("pod", "") or ""
    kind = f.get("workload_kind") or "Deployment"
    if kind not in WORKLOAD_KINDS:
        return "refused", f"unsupported workload_kind {kind!r}", None
    if deployment and not _name_ok(deployment, 63):
        return "refused", f"invalid deployment name {deployment!r}", None
    if pod and not _name_ok(pod):
        return "refused", f"invalid pod name {pod!r}", None
    if deployment and pod and not pod.startswith(deployment + "-"):
        return "refused", f"pod {pod} does not belong to workload {deployment}", None

    if action in ("patch", "restore") and not deployment:
        return "refused", f"{action} needs a deployment", None
    if action in ("contain", "restore") and not pod:
        return "refused", f"{action} needs a pod", None
    if action == "patch" and kind != "Deployment":
        return "refused", "patch supports Deployments only", None

    fields, why = _string_list(f.get("patch_fields"), "patch_fields")
    if fields is None:
        return "refused", why, None
    reasons, why = _string_list(f.get("rule_reasons"), "rule_reasons")
    if reasons is None:
        return "refused", why, None
    label = (f.get("containment_label") or "").strip().lower()
    if action == "contain" and label and label not in CONTAINMENT_LABELS:
        return "refused", f"unknown containment_label {label!r}", None

    req = Request(action=action, namespace=namespace, incident_id=incident_id, deployment=deployment,
                  pod=pod, patch_field=(f.get("patch_field") or "").strip(), kind=kind,
                  kind_given=bool(f.get("workload_kind")),
                  dry_run=str(f.get("dry_run", "false")).lower() == "true",
                  patch_fields=fields, rule_path=_flag(f.get("rule_path")), rule_reasons=reasons,
                  containment_label=label, restore_after=_flag(f.get("restore_after")),
                  human_followup=_flag(f.get("human_followup")))
    # Candidate fields: the list Fusion sent, or the single legacy field. "unknown" is no field.
    if not req.patch_fields and req.patch_field:
        req.patch_fields = [req.patch_field]
    req.patch_fields = [x for x in req.patch_fields if x.lower() != "unknown"]
    if not req.patch_field and req.patch_fields:
        req.patch_field = req.patch_fields[0]

    raw_t0 = f.get("t0_ms")
    if raw_t0 not in (None, ""):
        try:
            req.t0_ms = int(str(raw_t0))
        except ValueError:
            return "refused", f"t0_ms is not an integer: {raw_t0!r}", None
        if req.t0_ms <= 0:
            return "refused", f"t0_ms must be positive: {raw_t0!r}", None
    if action == "restore" and req.t0_ms is None:
        return "escalate", ("t0_missing: restore needs the attack onset time t0_ms; "
                            "the Executor never guesses T0"), req
    if action == "patch" and not req.patch_fields:
        return "escalate", "no_patch_field: the request names no drifted field to restore", req
    return "ok", "", req
