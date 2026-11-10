"""Admin token authentication for the mutating dashboard endpoints (S-KS-6, S-DB-2).

The token comes from the environment variable KUBEHEAL_ADMIN_TOKEN (in a cluster: a Secret mounted as
an env var). There is no default. If it is unset or blank, every mutating endpoint answers 503, so a
missing Secret can never leave the write paths open.

  missing credentials -> 401 (with WWW-Authenticate)
  wrong token         -> 403
  right token         -> the request is attributed to the admin identity

The token is compared in constant time and is never logged or echoed. One shared token cannot tell
two people apart: the identity recorded in the ledger and in `approved_by` is the configured name
(KUBEHEAL_ADMIN_IDENTITY, default "dashboard-admin"), not a per-person claim.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, Request

ADMIN_TOKEN_ENV = "KUBEHEAL_ADMIN_TOKEN"
ADMIN_IDENTITY_ENV = "KUBEHEAL_ADMIN_IDENTITY"
DEFAULT_IDENTITY = "dashboard-admin"
_IDENTITY_OK = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


@dataclass(frozen=True)
class AdminIdentity:
    name: str

    @property
    def actor(self) -> str:
        """Value for ledger `actor` fields and for the Executor request's `approved_by`."""
        return f"admin:{self.name}"


def constant_time_equals(supplied: str, expected: str) -> bool:
    """Compare digests so neither the content nor the length of the expected token leaks via timing."""
    a = hashlib.sha256(supplied.encode("utf-8")).digest()
    b = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(a, b)


def _supplied_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    alt = request.headers.get("x-admin-token", "").strip()
    return alt or None


def admin_identity_name() -> str:
    name = os.environ.get(ADMIN_IDENTITY_ENV, "").strip()
    return name if _IDENTITY_OK.match(name) else DEFAULT_IDENTITY


def require_admin(request: Request) -> AdminIdentity:
    """FastAPI dependency guarding every mutating endpoint."""
    expected = os.environ.get(ADMIN_TOKEN_ENV, "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail=f"admin endpoints are disabled: {ADMIN_TOKEN_ENV} is not configured",
        )
    supplied = _supplied_token(request)
    if supplied is None:
        raise HTTPException(
            status_code=401,
            detail="admin token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not constant_time_equals(supplied, expected):
        raise HTTPException(status_code=403, detail="invalid admin token")
    return AdminIdentity(name=admin_identity_name())
