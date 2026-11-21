"""Admin gate for every mutating route.

KUBEHEAL_AUTH_MODE=token (default): Authorization: Bearer, no cookies, so there is no CSRF surface.
KUBEHEAL_ADMIN_TOKENS="name1:token1,name2:token2" gives each admin a named token (the name is the actor);
KUBEHEAL_ADMIN_TOKEN is one shared token whose actor is "admin" plus an optional self-declared X-Actor label.

KUBEHEAL_AUTH_MODE=proxy: oauth2-proxy (OIDC) fronts the dashboard and sends X-Auth-Request-Email/-User/-Groups plus
X-Kubeheal-Proxy = KUBEHEAL_PROXY_SECRET. Those headers are trusted only when that secret matches (unset secret = every
request refused), so a pod that reaches the dashboard port directly cannot forge an identity. Any authenticated user is
a viewer; members of KUBEHEAL_ADMIN_GROUPS (comma list) are admins, and the actor is the authenticated email.
Every mutating request also needs X-Kubeheal-CSRF: 1 and a same-origin Origin/Sec-Fetch-Site (X-Forwarded-Host
is the expected host behind the proxy). Tokens and X-Actor are ignored in this mode; in token mode the identity headers are ignored.
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from dashboard.ratelimit import Bucket

ADMIN_TOKEN_ENV = "KUBEHEAL_ADMIN_TOKEN"  # noqa: S105  env var name, not a secret
ADMIN_TOKENS_ENV = "KUBEHEAL_ADMIN_TOKENS"  # noqa: S105  env var name, not a secret
AUTH_MODE_ENV = "KUBEHEAL_AUTH_MODE"
ADMIN_GROUPS_ENV = "KUBEHEAL_ADMIN_GROUPS"
ADMIN_USERS_ENV = "KUBEHEAL_ADMIN_USERS"
ACTOR_CLAIM_ENV = "KUBEHEAL_ACTOR_CLAIM"
PROXY_SECRET_ENV = "KUBEHEAL_PROXY_SECRET"  # noqa: S105  env var name, not a secret
PROXY_HEADER = "x-kubeheal-proxy"
CSRF_HEADER = "x-kubeheal-csrf"
ACTOR_MAX = 40
_IDENT_BAD = re.compile(r"[^A-Za-z0-9._@+-]")
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


def proxy_mode() -> bool:
    return os.environ.get(AUTH_MODE_ENV, "token").strip().lower() == "proxy"


@dataclass(frozen=True)
class Identity:
    actor: str
    admin: bool


def _proxy_trusted(headers) -> bool:
    secret = os.environ.get(PROXY_SECRET_ENV, "").strip()
    return bool(secret) and hmac.compare_digest(headers.get(PROXY_HEADER, "").encode(), secret.encode())


def public_host(headers) -> str:
    """The host the browser used: X-Forwarded-Host only when the SSO proxy vouched for the request (secret valid)."""
    if proxy_mode() and _proxy_trusted(headers) and (fwd := headers.get("x-forwarded-host", "").split(",")[0].strip()):
        return fwd
    return headers.get("host", "")


def check_csrf(request: Request) -> None:
    """Mutating requests: same-origin only AND the custom header util.js api() sends (a cross-site form or simple
    fetch cannot set it; the cookie in proxy mode would otherwise authenticate a forged POST)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    h = request.headers
    if h.get(CSRF_HEADER) != "1":
        raise HTTPException(403, f"{CSRF_HEADER} header required")
    if h.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        raise HTTPException(403, "cross-site request refused")
    if (origin := h.get("origin")) and urlparse(origin).netloc != public_host(h):
        raise HTTPException(403, "cross-origin request refused")


def proxy_identity(request: Request) -> Identity:
    """The user oauth2-proxy vouched for. 503 without a configured secret, 401 when the proxy did not send it."""
    if not os.environ.get(PROXY_SECRET_ENV, "").strip():
        raise HTTPException(503, "sso misconfigured: KUBEHEAL_PROXY_SECRET is not set")
    h = request.headers
    if not _proxy_trusted(h):
        raise HTTPException(401, "sign in through the SSO proxy")
    claim = "user" if os.environ.get(ACTOR_CLAIM_ENV, "email").strip().lower() == "user" else "email"
    who = (h.get(f"x-auth-request-{claim}") or "").strip()
    if not who or len(who) > 120 or _IDENT_BAD.search(who):   # reject, never strip: stripping could forge an admin name
        raise HTTPException(401, "sso identity missing or invalid")
    csv = lambda raw: {g.strip() for g in raw.split(",") if g.strip()}   # noqa: E731
    groups = csv(h.get("x-auth-request-groups", "")) & csv(os.environ.get(ADMIN_GROUPS_ENV, ""))
    users = {u.lower() for u in csv(os.environ.get(ADMIN_USERS_ENV, ""))}
    return Identity(who, bool(groups or who.lower() in users))


def require_admin(request: Request) -> Admin:
    admin = _authenticate(request)
    check_csrf(request)   # after auth: X-Forwarded-Host is trusted only once the proxy secret checked out
    return admin


def _authenticate(request: Request) -> Admin:
    if proxy_mode():
        who = proxy_identity(request)
        if not who.admin:
            raise HTTPException(403, "admin group membership required")
        return Admin(who.actor)
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
