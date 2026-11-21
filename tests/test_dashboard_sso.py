# ruff: noqa: F401, F811  (fixtures imported from test_dashboard_admin)
"""SSO (KUBEHEAL_AUTH_MODE=proxy): identity headers count only with the proxy's shared secret."""

import pytest

from dashboard import auth
from kubeheal.contracts import STREAM_LEDGER
from tests.dashboard_seed import HUMAN_PENDING
from tests.test_dashboard_admin import TOKEN, _fresh_limits, env, state_of

SECRET = "proxy-secret"
PROXY = {"X-Kubeheal-CSRF": "1", "X-Kubeheal-Proxy": SECRET, "X-Auth-Request-Email": "li@example.com", "X-Auth-Request-Groups": "dev,sre"}
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
    gh = {"X-Kubeheal-CSRF": "1", "X-Kubeheal-Proxy": SECRET, "X-Auth-Request-User": "prathvi9607", "X-Auth-Request-Email": "p@example.com"}
    assert client.get("/api/me", headers=gh).json() == {"mode": "proxy", "user": "prathvi9607", "admin": True}   # logins are case-insensitive
    assert client.post(POST[0], json=POST[1], headers=gh).status_code == 200
    assert state_of(sync, HUMAN_PENDING)["requested"]["actor"] == "prathvi9607"
    viewer = {**gh, "X-Auth-Request-User": "stranger", "X-Auth-Request-Email": "s@example.com"}
    assert client.get("/api/me", headers=viewer).json()["admin"] is False
    assert client.post("/api/mode", json={"mode": "observe"}, headers=viewer).status_code == 403


def _post(client, **h):
    return client.post(POST[0], json=POST[1], headers={**PROXY, **h})


def test_csrf_cross_site_and_missing_header_rejected(sso):
    sync, client = sso
    no_hdr = {k: v for k, v in PROXY.items() if k != "X-Kubeheal-CSRF"}
    assert client.post(POST[0], json=POST[1], headers=no_hdr).status_code == 403          # cookie-only forged form
    assert _post(client, Origin="https://evil.example").status_code == 403
    assert _post(client, **{"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert _post(client, Origin="https://evil.example", **{"X-Forwarded-Host": "evil.example", "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert state_of(sync, HUMAN_PENDING).get("requested") is None


def test_csrf_same_origin_with_header_ok_behind_proxy(sso):
    sync, client = sso
    # proxy forwards Host=127.0.0.1:8080 (passHostHeader false); the browser origin is the public host
    r = _post(client, Origin="https://kubeheal.example.com", **{"X-Forwarded-Host": "kubeheal.example.com", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200
    assert state_of(sync, HUMAN_PENDING)["requested"]["actor"] == "li@example.com"


def test_forwarded_host_ignored_without_proxy_secret(sso):
    _, client = sso
    r = client.post(POST[0], json=POST[1], headers={"X-Kubeheal-CSRF": "1", "Origin": "https://evil.example", "X-Forwarded-Host": "evil.example"})
    assert r.status_code == 401


def test_ws_origin_uses_forwarded_host_only_in_proxy_mode(sso):
    _, client = sso
    from starlette.testclient import WebSocketDenialResponse
    from starlette.websockets import WebSocketDisconnect
    ok = {"host": "127.0.0.1", "origin": "https://kubeheal.example.com", "x-forwarded-host": "kubeheal.example.com", "x-kubeheal-proxy": SECRET}
    with client.websocket_connect("/ws", headers=ok) as ws:
        assert ws.receive_json()["type"] == "stats"
    for bad in ({**ok, "x-kubeheal-proxy": "guess"}, {**ok, "origin": "https://evil.example"}):
        with pytest.raises((WebSocketDisconnect, WebSocketDenialResponse)), client.websocket_connect("/ws", headers=bad) as ws:
            ws.receive_json()


def test_identity_only_from_configured_claim_and_rejects_bad_chars(sso, monkeypatch):
    _, client = sso
    monkeypatch.setenv(auth.ADMIN_USERS_ENV, "root")
    h = {**PROXY, "X-Auth-Request-Groups": "dev", "X-Auth-Request-User": "root"}   # email claim is configured: user ignored
    assert client.get("/api/me", headers=h).json()["admin"] is False
    for evil in ("ro ot@x.io", "r/oot"):
        assert client.get("/api/me", headers={**h, "X-Auth-Request-Email": evil}).status_code == 401
    monkeypatch.setenv(auth.ACTOR_CLAIM_ENV, "user")
    assert client.get("/api/me", headers={**h, "X-Auth-Request-User": "ROOT"}).json()["admin"] is True
    assert client.get("/api/me", headers={**h, "X-Auth-Request-User": "r!oot"}).status_code == 401
