"""
Target guard for the Executor (S-EX-1, S-CL-4).
===============================================
The Executor refuses any action whose namespace is a system namespace or the KubeHeal namespace
itself, and any namespace outside the configured protected set (default prod, staging, dev). RBAC
enforces the same limit on the API side (RoleBindings exist only in those namespaces); this is the
in-process hard check that produces a clear ledger entry instead of a Forbidden error.
"""

import os
from typing import Tuple

NEVER_ACT = frozenset({"kubeheal", "kube-system", "kube-public", "kube-node-lease"})


def allowed_namespaces() -> frozenset:
    raw = os.environ.get("EXEC_NAMESPACES", "prod,staging,dev")
    return frozenset(n.strip() for n in raw.split(",") if n.strip())


def check_target(namespace: str) -> Tuple[bool, str]:
    """(ok, reason). `reason` is empty when ok."""
    if not namespace:
        return False, "missing namespace"
    if namespace in NEVER_ACT:
        return False, f"namespace {namespace} is never acted on"
    if namespace not in allowed_namespaces():
        return False, f"namespace {namespace} is not in the protected set {sorted(allowed_namespaces())}"
    return True, ""
