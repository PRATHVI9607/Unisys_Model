# ruff: noqa: F401, F811  (fixtures imported from test_dashboard_admin)
"""SSO (KUBEHEAL_AUTH_MODE=proxy): identity headers count only with the proxy's shared secret."""

import pytest

from dashboard import auth
from kubeheal.contracts import STREAM_LEDGER
from tests.dashboard_seed import HUMAN_PENDING
from tests.test_dashboard_admin import TOKEN, _fresh_limits, env, state_of

SECRET = "proxy-secret"
PROXY = {"X-Kubeheal-Proxy": SECRET, "X-Auth-Request-Email": "li@example.com", "X-Auth-Request-Groups": "dev,sre"}
POST = (f"/api/approvals/{HUMAN_PENDING}/approve", {"reason": "ok"})


@pytest.fixture
def sso(env, monkeypatch):
    monkeypatch.setenv(auth.AUTH_MODE_ENV, "proxy")
    monkeypatch.setenv(auth.PROXY_SECRET_ENV, SECRET)
    monkeypatch.setenv(auth.ADMIN_GROUPS_ENV, "sre, platform")
    monkeypatch.setenv(auth.ADMIN_USERS_ENV, "PRATHVI9607, other")
    return env


def test_token_mode_ignores_identity_headers(env):
    sync, client = env
    r = client.post(POST[0], json=POST[1], headers=PROXY)
    assert r.status_code == 401
    assert client.get("/api/me", headers=PROXY).json() == {"mode": "token", "user": None, "admin": False}
    assert state_of(sync, HUMAN_PENDING).get("requested") is None


def test_headers_without_proxy_secret_are_rejected(sso):
    sync, client = sso
    for extra in ({}, {"X-Kubeheal-Proxy": "guess"}):
        h = {**PROXY, **extra}
        if not extra:
            del h["X-Kubeheal-Proxy"]
        assert client.post(POST[0], json=POST[1], headers=h).status_code == 401
        assert client.get("/api/me", headers=h).status_code == 401
    assert client.post(POST[0], json=POST[1], headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 401   # tokens are off
    assert state_of(sync, HUMAN_PENDING).get("requested") is None


def test_proxy_mode_without_secret_is_closed(sso, monkeypatch):
    _, client = sso
    monkeypatch.delenv(auth.PROXY_SECRET_ENV)
    assert client.post(POST[0], json=POST[1], headers={**PROXY, "X-Kubeheal-Proxy": ""}).status_code == 503


def test_viewer_cannot_write(sso):
    sync, client = sso
    h = {**PROXY, "X-Auth-Request-Groups": "dev"}
    assert client.get("/api/me", headers=h).json() == {"mode": "proxy", "user": "li@example.com", "admin": False}
    assert client.post(POST[0], json=POST[1], headers=h).status_code == 403
    assert client.post("/api/mode", json={"mode": "observe"}, headers=h).status_code == 403
    assert state_of(sync, HUMAN_PENDING).get("requested") is None


def test_admin_group_acts_as_email(sso):
    sync, client = sso
    assert client.get("/api/me", headers=PROXY).json()["admin"] is True
    assert client.post(POST[0], json=POST[1], headers={**PROXY, "X-Actor": "someone else"}).status_code == 200
    assert state_of(sync, HUMAN_PENDING)["requested"]["actor"] == "li@example.com"
    assert any(f.get("actor") == "li@example.com" for _, f in sync.xrange(STREAM_LEDGER))


def test_no_admin_groups_means_nobody_is_admin(sso, monkeypatch):
    _, client = sso
    monkeypatch.setenv(auth.ADMIN_GROUPS_ENV, "")
    assert client.post(POST[0], json=POST[1], headers=PROXY).status_code == 403


def test_github_login_admin_allow_list_and_actor(sso, monkeypatch):
    sync, client = sso
    monkeypatch.setenv(auth.ACTOR_CLAIM_ENV, "user")
    gh = {"X-Kubeheal-Proxy": SECRET, "X-Auth-Request-User": "prathvi9607", "X-Auth-Request-Email": "p@example.com"}
    assert client.get("/api/me", headers=gh).json() == {"mode": "proxy", "user": "prathvi9607", "admin": True}   # logins are case-insensitive
    assert client.post(POST[0], json=POST[1], headers=gh).status_code == 200
    assert state_of(sync, HUMAN_PENDING)["requested"]["actor"] == "prathvi9607"
    viewer = {**gh, "X-Auth-Request-User": "stranger", "X-Auth-Request-Email": "s@example.com"}
    assert client.get("/api/me", headers=viewer).json()["admin"] is False
    assert client.post("/api/mode", json={"mode": "observe"}, headers=viewer).status_code == 403
