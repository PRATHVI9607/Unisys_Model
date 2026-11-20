"""Admin gate for every mutating route. Token only (Authorization: Bearer), no cookies, so there is no CSRF surface."""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass

from fastapi import HTTPException, Request

ADMIN_TOKEN_ENV = "KUBEHEAL_ADMIN_TOKEN"  # noqa: S105  env var name, not a secret
ACTOR_MAX = 40
_ACTOR_BAD = re.compile(r"[^A-Za-z0-9._@ -]")


@dataclass(frozen=True)
class Admin:
    actor: str   # recorded in the ledger and the approvals stream


def clean_actor(raw: str | None) -> str:
    """Free-text X-Actor made safe for log and ledger lines; the token, not this name, is the credential."""
    name = _ACTOR_BAD.sub("", raw or "").strip()[:ACTOR_MAX].strip()
    return f"admin:{name}" if name else "admin"


def require_admin(request: Request) -> Admin:
    expected = os.environ.get(ADMIN_TOKEN_ENV, "").strip()
    if not expected:
        raise HTTPException(503, "admin disabled: KUBEHEAL_ADMIN_TOKEN is not set")
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not supplied.strip():
        raise HTTPException(401, "admin token required", headers={"WWW-Authenticate": "Bearer"})
    if not hmac.compare_digest(supplied.strip().encode(), expected.encode()):
        raise HTTPException(403, "invalid admin token")
    return Admin(clean_actor(request.headers.get("x-actor")))
