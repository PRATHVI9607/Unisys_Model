"""Admin gate for every mutating route. Token only (Authorization: Bearer), no cookies, so there is no CSRF surface.

KUBEHEAL_ADMIN_TOKENS="name1:token1,name2:token2" gives each admin a named token (the name is the actor);
KUBEHEAL_ADMIN_TOKEN is one shared token whose actor is "admin" plus an optional self-declared X-Actor label.
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass

from fastapi import HTTPException, Request

from dashboard.ratelimit import Bucket

ADMIN_TOKEN_ENV = "KUBEHEAL_ADMIN_TOKEN"  # noqa: S105  env var name, not a secret
ADMIN_TOKENS_ENV = "KUBEHEAL_ADMIN_TOKENS"  # noqa: S105  env var name, not a secret
ACTOR_MAX = 40
_ACTOR_BAD = re.compile(r"[^A-Za-z0-9._@ -]")
failed_auth = Bucket(burst=10, per_second=10 / 60)   # wrong tokens per client: 10, then about 10 a minute


@dataclass(frozen=True)
class Admin:
    actor: str   # recorded in the ledger and the approvals stream


def clean_actor(raw: str | None) -> str:
    """Free-text X-Actor made safe for log and ledger lines; the token, not this name, is the credential."""
    name = _ACTOR_BAD.sub("", raw or "").strip()[:ACTOR_MAX].strip()
    return f"admin:{name}" if name else "admin"


def _tokens() -> list[tuple[str | None, str]]:
    """(name, token) pairs; name None = the shared token."""
    out: list[tuple[str | None, str]] = []
    for part in os.environ.get(ADMIN_TOKENS_ENV, "").split(","):
        name, _, tok = part.partition(":")
        name = _ACTOR_BAD.sub("", name).strip()[:ACTOR_MAX].strip()
        if name and tok.strip():
            out.append((name, tok.strip()))
    if shared := os.environ.get(ADMIN_TOKEN_ENV, "").strip():
        out.append((None, shared))
    return out


def require_admin(request: Request) -> Admin:
    known = _tokens()
    if not known:
        raise HTTPException(503, "admin disabled: KUBEHEAL_ADMIN_TOKEN(S) is not set")
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not supplied.strip():
        raise HTTPException(401, "admin token required", headers={"WWW-Authenticate": "Bearer"})
    client = request.client.host if request.client else "?"
    if not failed_auth.has(client):
        raise HTTPException(429, "too many failed attempts, wait a minute", headers={"Retry-After": "60"})
    matched: tuple[str | None, str] | None = None
    for entry in known:   # no early exit: every comparison runs
        if hmac.compare_digest(supplied.strip().encode(), entry[1].encode()):
            matched = matched or entry
    if matched is None:
        failed_auth.take(client)
        raise HTTPException(403, "invalid admin token")
    name = matched[0]
    return Admin(name if name else clean_actor(request.headers.get("x-actor")))
