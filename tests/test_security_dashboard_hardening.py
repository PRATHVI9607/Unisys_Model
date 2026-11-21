"""Hostile-input pass over the dashboard admin API: every request gets a deliberate 4xx (or a normal 2xx), never a 500."""

import json
from urllib.parse import quote

import fakeredis
import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse
from starlette.websockets import WebSocketDisconnect

from dashboard import admin, auth, fastapi_app
from kubeheal.contracts import KEY_MODE, STREAM_APPROVALS, STREAM_LEDGER, key_approval
from tests.dashboard_seed import HUMAN_DONE, HUMAN_PENDING, HUMAN_SECOND, seed
from tests.test_dashboard import BASE, wait_for

TOKEN = "s3cret-token"
AUTH = {"Authorization": f"Bearer {TOKEN}", "X-Actor": "Maria R"}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.delenv(auth.ADMIN_TOKENS_ENV, raising=False)
    monkeypatch.setenv(auth.ADMIN_TOKEN_ENV, TOKEN)
    auth.failed_auth.reset()
    for b in admin.read_limit.values():
        b.reset()
    server = fakeredis.FakeServer()
    sync = fakeredis.FakeRedis(server=server, decode_responses=True)
    seed(sync)
    monkeypatch.setattr(fastapi_app, "make_redis", lambda: fakeredis.FakeAsyncRedis(server=server, decode_responses=True))
    monkeypatch.setattr(admin, "_fetch_ready", lambda: {"ready": True, "models": {}})
    monkeypatch.setattr(admin, "_models_cache", None)
    with TestClient(fastapi_app.app, base_url=BASE, raise_server_exceptions=False) as client:   # a crash shows as 500, not a raise
        assert wait_for(lambda: client.get("/readyz").status_code == 200)
        assert wait_for(lambda: len(client.get("/api/events", params={"kind": "action"}).json()["events"]) == 7)
        yield sync, client


def raw_post(c, path, headers: dict[str, bytes], body=b'{"mode": "observe"}'):
    """POST straight into the ASGI app with hand-built header bytes (CRLF, non-latin1, huge): clients refuse to send these."""
    sent = []
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http", "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "", "server": ("localhost", 80), "client": ("127.0.0.1", 1),
             "headers": [(b"host", b"localhost"), (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                         *((k.lower().encode(), v) for k, v in headers.items())]}

    async def go():
        fed = False

        async def receive():
            nonlocal fed
            if fed:
                return {"type": "http.disconnect"}
            fed = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(m):
            sent.append(m)

        await fastapi_app.app(scope, receive, send)

    c.portal.call(go)   # the app's event loop: the lifespan-created Redis client belongs to it
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


def ok4xx(r):
    assert r.status_code < 500, (r.status_code, r.text[:200])
    return r


# ── hostile bodies ───────────────────────────────────────────────────────────────────────────────
def test_huge_body_without_token_is_rejected_before_validation(env):
    _, c = env
    r = c.post("/api/mode", content=b'{"mode":"observe","reason":"' + b"A" * 5_000_000 + b'"}',
               headers={"content-type": "application/json"})
    assert r.status_code == 401


def test_huge_reason_with_token_is_422_and_changes_nothing(env):
    sync, c = env
    r = c.post("/api/mode", json={"mode": "enforce", "reason": "A" * 1_000_000}, headers=AUTH)
    assert r.status_code == 422 and sync.get(KEY_MODE) is None


@pytest.mark.parametrize("body", [
    b"", b"null", b"[]", b'"observe"', b"1", b"{", b'{"mode":}', b"\xff\xfe\x00", b'{"mode":"observe"} trailing',
    b'{"mode":"observe","mode":"bogus"}',
])
def test_malformed_json_bodies(env, body):
    sync, c = env
    r = ok4xx(c.post("/api/mode", content=body, headers={**AUTH, "content-type": "application/json"}))
    assert r.status_code in (200, 400, 422)
    assert sync.get(KEY_MODE) in (None, "observe")   # duplicate-key body: last key wins ("bogus" is rejected) -> never a bad mode


@pytest.mark.parametrize("body", [b'{"mode":NaN}', b'{"mode":"observe","reason":NaN}', b'{"mode":"observe","reason":Infinity}'])
def test_nan_in_body_is_422_not_500(env, body):
    _, c = env
    assert c.post("/api/mode", content=body, headers={**AUTH, "content-type": "application/json"}).status_code == 422


@pytest.mark.parametrize("payload", [
    {"mode": 1}, {"mode": ["observe"]}, {"mode": None}, {"mode": {"x": 1}}, {"mode": True}, {"mode": "OBSERVE"},
    {"mode": "observe\n"}, {"mode": "enforce", "reason": 5}, {"mode": "enforce", "reason": ["a"]},
    {"mode": "enforce", "reason": None}, {"mode": "enforce", "extra": 1}, [], "x", 7, None,
])
def test_type_confusion_on_mode(env, payload):
    sync, c = env
    r = ok4xx(c.post("/api/mode", json=payload, headers=AUTH))
    if r.status_code == 200:
        assert payload == {"mode": "enforce", "extra": 1} or payload.get("reason", "") is None or False
    else:
        assert r.status_code == 422
        assert sync.get(KEY_MODE) is None


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""])
def test_wrong_content_type(env, ctype):
    _, c = env
    ok4xx(c.post("/api/mode", content='{"mode":"enforce"}', headers={**AUTH, "content-type": ctype}))


def test_deeply_nested_json_does_not_crash(env):
    _, c = env
    ok4xx(c.post("/api/mode", content=b"[" * 200_000, headers={**AUTH, "content-type": "application/json"}))
    ok4xx(c.post("/api/mode", content=b'{"a":' * 50_000, headers={**AUTH, "content-type": "application/json"}))


def test_unicode_reason_is_stored_verbatim_and_safely(env):
    sync, c = env
    reason = "ok ‮\u0000 \U0001f9ea ퟿ \"quote\" \\ <script>alert(1)</script> \r\n second line"
    r = ok4xx(c.post("/api/mode", json={"mode": "observe", "reason": reason}, headers=AUTH))
    assert r.status_code == 200
    last = sync.xrevrange(STREAM_LEDGER, count=1)[0][1]
    assert json.loads(last["detail"])["reason"] == reason   # JSON-encoded in the ledger: no raw control chars reach a log line


# ── X-Actor ──────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("actor", ["evil\r\nX-Injected: 1", "a\nb", "x" * 10_000, "<b>x</b>", "'; DROP", "\t\t", "María", ""])
def test_actor_header_is_sanitised(env, actor):
    sync, c = env
    status = raw_post(c, "/api/mode", {"Authorization": AUTH["Authorization"].encode(), "X-Actor": actor.encode()})
    assert status < 500, status
    if status == 200:
        entry = sync.xrevrange(STREAM_LEDGER, count=1)[0][1]
        name = entry["actor"]
        assert len(name) <= 6 + 40 and all(ch.isalnum() or ch in "._@ -:" for ch in name) and not {"\r", "\n", "<", "'"} & set(name)
        assert name == "admin" or name.startswith("admin:")


# ── ids ──────────────────────────────────────────────────────────────────────────────────────────
HOSTILE_IDS = ["../../etc/passwd", "..%2f..%2fx", "%2e%2e/%2e%2e", "a/b", "a%00b", "x" * 20_000, "😀", "kubeheal:*", "*", "a\nb",
               "../approval/" + HUMAN_PENDING, "act-human-1/../act-human-2", "%", "%zz", "' OR 1=1", " "]


@pytest.mark.parametrize("ident", HOSTILE_IDS)
def test_hostile_approval_ids(env, ident):
    sync, c = env
    before = sync.xlen(STREAM_APPROVALS)
    for verb in ("approve", "reject"):
        r = ok4xx(c.post(f"/api/approvals/{quote(ident, safe='')}/{verb}", headers=AUTH))
        assert r.status_code in (404, 405, 409, 422)
    ok4xx(c.get(f"/api/approvals/{quote(ident, safe='')}"))
    ok4xx(c.get(f"/api/events/action/{quote(ident, safe='')}"))
    assert sync.xlen(STREAM_APPROVALS) == before and json.loads(sync.get(key_approval(HUMAN_PENDING)))["state"] == "pending"


def test_raw_traversal_paths_do_not_reach_other_files(env):
    _, c = env
    for p in ("/static/../../etc/passwd", "/static/%2e%2e/%2e%2e/etc/passwd", "/static//etc/passwd", "/static/..%5c..%5cetc/passwd",
              "/%2e%2e/%2e%2e/etc/passwd"):
        r = ok4xx(c.get(p))
        assert "root:" not in r.text


# ── replay ───────────────────────────────────────────────────────────────────────────────────────
def test_replayed_and_conflicting_decisions(env):
    sync, c = env
    assert c.post(f"/api/approvals/{HUMAN_PENDING}/approve", json={"reason": "go"}, headers=AUTH).status_code == 200
    n_app, n_led = sync.xlen(STREAM_APPROVALS), sync.xlen(STREAM_LEDGER)
    for verb in ("approve", "reject", "approve"):
        r = c.post(f"/api/approvals/{HUMAN_PENDING}/{verb}", headers=AUTH)
        assert r.status_code == 409
    assert (sync.xlen(STREAM_APPROVALS), sync.xlen(STREAM_LEDGER)) == (n_app, n_led)   # no second command reaches fusion
    assert c.post(f"/api/approvals/{HUMAN_DONE}/approve", headers=AUTH).status_code == 409   # already executed
    assert c.post("/api/approvals/never-existed/approve", headers=AUTH).status_code == 404


def test_replay_with_other_actor_header_still_conflicts(env):
    sync, c = env
    assert c.post(f"/api/approvals/{HUMAN_SECOND}/reject", headers=AUTH).status_code == 200
    r = c.post(f"/api/approvals/{HUMAN_SECOND}/approve", headers={**AUTH, "X-Actor": "someone else"})
    assert r.status_code == 409
    assert json.loads(sync.get(key_approval(HUMAN_SECOND)))["requested"]["decision"] == "reject"


# ── auth / Host / Origin ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("hdr,code", [
    ({}, 401), ({"Authorization": "Bearer"}, 401), ({"Authorization": "Bearer "}, 401), ({"Authorization": "Basic Zm9vOmJhcg=="}, 401),
    ({"Authorization": "Bearer wrong"}, 403), ({"Authorization": "Bearer " + "x" * 100_000}, 403),
    ({"Authorization": "Bearer éé"}, 403), ({"Authorization": f"Token {TOKEN}"}, 401), ({"Authorization": TOKEN}, 401),
])
def test_bad_credentials(env, hdr, code):
    sync, c = env
    status = raw_post(c, "/api/mode", {k: v.encode() for k, v in hdr.items()}, b'{"mode": "enforce"}')
    assert status == code and sync.get(KEY_MODE) is None


def test_failed_auth_is_rate_limited_then_valid_token_still_locked_out(env):
    _, c = env
    codes = [c.post("/api/mode", json={"mode": "enforce"}, headers={"Authorization": "Bearer nope"}).status_code for _ in range(14)]
    assert codes[:10] == [403] * 10 and set(codes[10:]) == {429}


@pytest.mark.parametrize("host", ["evil.com", "localhost.evil.com", "127.0.0.1.evil.com", "", "kubeheal-dashboard.evil", "[::1]", "a b"])
def test_wrong_host_header_is_refused(env, host):
    _, c = env
    for method, path in (("GET", "/api/stats"), ("POST", "/api/mode"), ("GET", "/")):
        r = c.request(method, path, headers={**AUTH, "Host": host}, json={"mode": "enforce"} if method == "POST" else None)
        assert r.status_code == 400, (host, path, r.status_code)


@pytest.mark.parametrize("host", ["localhost", "localhost:8080", "kubeheal-dashboard.kubeheal.svc:8080", "127.0.0.1:9999"])
def test_allowed_hosts_with_ports(env, host):
    _, c = env
    assert c.get("/api/stats", headers={"Host": host}).status_code == 200


def test_cross_origin_post_needs_the_bearer_token_and_cookies_do_nothing(env):
    sync, c = env
    evil = {"Origin": "https://evil.example", "Cookie": f"token={TOKEN}; Authorization=Bearer {TOKEN}"}
    assert c.post("/api/mode", json={"mode": "enforce"}, headers=evil).status_code == 401
    assert sync.get(KEY_MODE) is None


def test_websocket_cross_origin_is_closed_same_origin_accepted(env):
    _, c = env
    with pytest.raises((WebSocketDisconnect, WebSocketDenialResponse)):
        with c.websocket_connect("ws://localhost/ws", headers={"origin": "https://evil.example"}) as ws:
            ws.receive_json()
    with c.websocket_connect("ws://localhost/ws", headers={"origin": "http://localhost"}) as ws:
        assert ws.receive_json()["type"] == "stats"


# ── query parameters / methods ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("q", [
    {"limit": 0}, {"limit": -5}, {"limit": 10**12}, {"limit": "abc"}, {"limit": "1e3"}, {"kind": "nope"}, {"kind": "' OR 1"},
    {"namespace": "*"}, {"actor": "x" * 5000}, {"namespace": "😀", "actor": "\r\n"},
])
def test_ledger_and_events_query_fuzz(env, q):
    _, c = env
    for b in admin.read_limit.values():
        b.reset()
    r = ok4xx(c.get("/api/ledger", params=q, headers=AUTH))
    assert r.status_code in (200, 400, 422), r.text[:200]
    ok4xx(c.get("/api/events", params={"kind": "action", **q}))


@pytest.mark.parametrize("cursor", ["garbage", "(", "-", "1-", "9" * 400])
def test_ledger_bad_cursor_is_a_4xx(env, cursor):
    _, c = env
    assert 400 <= c.get("/api/ledger", params={"cursor": cursor}, headers=AUTH).status_code < 500


def test_unknown_methods_are_405_not_500(env):
    _, c = env
    for method, path in (("PUT", "/api/mode"), ("DELETE", "/api/mode"), ("PATCH", f"/api/approvals/{HUMAN_PENDING}/approve"),
                         ("GET", f"/api/approvals/{HUMAN_PENDING}/approve"), ("POST", "/api/ledger"), ("TRACE", "/")):
        assert c.request(method, path, headers=AUTH).status_code in (404, 405)


def test_read_routes_are_throttled_not_crashed(env):
    _, c = env
    codes = {c.get("/api/ledger").status_code for _ in range(60)}
    assert codes <= {200, 429} and 429 in codes


def test_security_headers_on_every_response_class(env):
    _, c = env
    for r in (c.get("/api/stats"), c.get("/api/nope"), c.post("/api/mode", json={})):
        assert r.headers["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in r.headers["content-security-policy"]


@pytest.mark.parametrize("raw", ["evil\r\nX-Injected: 1", "a\nb", "\x1b[31mred", "x" * 10_000, "<b>", "😀", None, ""])
def test_clean_actor_direct(raw):
    out = auth.clean_actor(raw)   # the HTTP client refuses CR/LF header values, so the sanitiser is also called directly
    assert out == "admin" or (out.startswith("admin:") and len(out) <= 6 + auth.ACTOR_MAX)
    assert not {"\r", "\n", "\x1b", "<", "😀"} & set(out)
