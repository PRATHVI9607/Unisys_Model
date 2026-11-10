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

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

ACTIONS = frozenset({"contain", "patch", "restore"})
WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet"})

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
    t0_ms: Optional[int] = None
    dry_run: bool = False


def _name_ok(v: str, maxlen: int = 253) -> bool:
    return bool(v) and len(v) <= maxlen and bool(_DNS_SUBDOMAIN.match(v))


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

    req = Request(action=action, namespace=namespace, incident_id=incident_id, deployment=deployment,
                  pod=pod, patch_field=(f.get("patch_field") or "").strip(), kind=kind,
                  dry_run=str(f.get("dry_run", "false")).lower() == "true")

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
    if action == "patch" and (not req.patch_field or req.patch_field.lower() == "unknown"):
        return "escalate", "no_patch_field: the request names no drifted field to restore", req
    return "ok", "", req
