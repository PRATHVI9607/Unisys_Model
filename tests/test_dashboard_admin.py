import json

import fakeredis
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from dashboard import admin, auth, fastapi_app
from kubeheal.contracts import (
    KEY_APPROVALS_PENDING,
    KEY_MODE,
    STREAM_ACTIONS,
    STREAM_APPROVALS,
    STREAM_LEDGER,
    ActionEvent,
    Decision,
    key_approval,
    now_ms,
)
from tests.dashboard_seed import HUMAN_DONE, HUMAN_PENDING, HUMAN_SECOND, seed
from tests.test_dashboard import BASE, wait_for

TOKEN = "s3cret-token"
AUTH = {"Authorization": f"Bearer {TOKEN}", "X-Actor": "Maria R"}


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.delenv(auth.ADMIN_TOKENS_ENV, raising=False)
    auth.failed_auth.reset()
    for b in admin.read_limit.values():
        b.reset()


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv(auth.ADMIN_TOKEN_ENV, TOKEN)
    server = fakeredis.FakeServer()
    sync = fakeredis.FakeRedis(server=server, decode_responses=True)
    seed(sync)
    monkeypatch.setattr(fastapi_app, "make_redis", lambda: fakeredis.FakeAsyncRedis(server=server, decode_responses=True))
    monkeypatch.setattr(admin, "_fetch_ready", lambda: {"ready": True, "models": {"health": "health-5.0.0-x", "security": "security-5.0.0-y"}})
    monkeypatch.setattr(admin, "_models_cache", None)
    with TestClient(fastapi_app.app, base_url=BASE) as client:
        assert wait_for(lambda: client.get("/readyz").status_code == 200)
        assert wait_for(lambda: len(client.get("/api/events", params={"kind": "action"}).json()["events"]) == 7)
        yield sync, client


def state_of(sync, action_id):
    return json.loads(sync.get(key_approval(action_id)))


# ── auth matrix ──────────────────────────────────────────────────────────────────────────────────

def test_every_mutating_route_requires_admin():
    def flat(routes):   # FastAPI wraps included routers; walk into them
        for r in routes:
            yield from flat(r.original_router.routes) if hasattr(r, "original_router") else [r]

    mutating = [r for r in flat(fastapi_app.app.routes) if isinstance(r, APIRoute) and r.methods - {"GET", "HEAD", "OPTIONS"}]
    assert len(mutating) >= 3   # mode, approve, reject

    def deps(dependant):
        for d in dependant.dependencies:
            yield d.call
            yield from deps(d)

    for route in mutating:
        assert auth.require_admin in set(deps(route.dependant)), f"{route.methods} {route.path} is not behind require_admin"


MUTATIONS = [("post", "/api/mode", {"mode": "observe"}), ("post", f"/api/approvals/{HUMAN_PENDING}/approve", {}),
             ("post", f"/api/approvals/{HUMAN_PENDING}/reject", {}), ("post", f"/api/approvals/{HUMAN_PENDING}/release", {}), ("get", "/api/admin/session", None)]


@pytest.mark.parametrize(("method", "path", "body"), MUTATIONS)
def test_auth_matrix(env, monkeypatch, method, path, body):
    sync, client = env
    send = lambda headers: getattr(client, method)(path, headers=headers, **({"json": body} if body is not None else {}))   # noqa: E731
    assert send({}).status_code == 401
    assert send({}).headers["www-authenticate"] == "Bearer"
    assert send({"Authorization": "Bearer wrong"}).status_code == 403
    assert send({"Authorization": f"Basic {TOKEN}"}).status_code == 401
    assert send({"X-Admin-Token": TOKEN}).status_code == 401           # only the bearer header counts
    assert state_of(sync, HUMAN_PENDING).get("requested") is None      # nothing happened
    monkeypatch.delenv(auth.ADMIN_TOKEN_ENV)
    assert send(AUTH).status_code == 503                               # no token configured: closed, even with a header
    monkeypatch.setenv(auth.ADMIN_TOKEN_ENV, "  ")
    assert send(AUTH).status_code == 503


def test_actor_is_sanitized():
    assert auth.clean_actor("Maria R") == "admin:Maria R"
    assert auth.clean_actor("<script>x</script>\n" + "a" * 100) == "admin:scriptxscript" + "a" * 27
    assert auth.clean_actor("") == auth.clean_actor("%%%") == "admin"


# ── approvals ────────────────────────────────────────────────────────────────────────────────────

def test_list_approvals(env):
    _, client = env
    d = client.get("/api/approvals").json()
    by = {i["action_event_id"]: i for i in d["items"]}
    assert set(by) == {HUMAN_PENDING, HUMAN_SECOND, HUMAN_DONE} and d["pending"] == 2
    assert by[HUMAN_PENDING]["candidate"] == "AUTO_PATCH" and by[HUMAN_PENDING]["display_state"] == "pending"
    assert by[HUMAN_DONE]["state"] == "executed" and by[HUMAN_DONE]["requested"]["actor"] == "admin:maria"


def test_release_is_an_admin_request_ledgered_as_release(env):
    sync, client = env
    assert client.post(f"/api/approvals/{HUMAN_PENDING}/release", json={}).status_code in (401, 403)
    r = client.post(f"/api/approvals/{HUMAN_PENDING}/release", json={"reason": "false alarm"}, headers=AUTH)
    assert r.status_code == 200 and r.json()["display_state"] == "release requested"
    [(_, e)] = sync.xrange(STREAM_APPROVALS)
    assert (e["decision"], e["actor"]) == ("release", "admin:Maria R")
    [(_, led)] = sync.xrange(STREAM_LEDGER, min="(0-0", count=1000)[-1:]
    assert (led["kind"], led["decision"], led["outcome"]) == ("approval", "RELEASE", "release_requested")


def test_approve_writes_request_stream_and_ledger_atomically(env):
    sync, client = env
    ttl = sync.ttl(key_approval(HUMAN_PENDING))
    r = client.post(f"/api/approvals/{HUMAN_PENDING}/approve", json={"reason": "baseline is gone, patch is right"}, headers=AUTH)
    assert r.status_code == 200 and r.json()["display_state"] == "approve requested"
    [(_, e)] = sync.xrange(STREAM_APPROVALS)
    assert (e["action_event_id"], e["decision"], e["actor"], e["reason"]) == (HUMAN_PENDING, "approve", "admin:Maria R", "baseline is gone, patch is right")
    assert e["approval_id"] == state_of(sync, HUMAN_PENDING)["requested"]["approval_id"]
    [(_, led)] = sync.xrange(STREAM_LEDGER, min="(0-0", count=1000)[-1:]
    assert (led["kind"], led["decision"], led["outcome"], led["namespace"]) == ("approval", "AUTO_PATCH", "approve_requested", "shop-prod")
    assert state_of(sync, HUMAN_PENDING)["state"] == "pending"   # only fusion advances the state
    assert 0 < sync.ttl(key_approval(HUMAN_PENDING)) <= ttl
    assert client.get("/api/approvals").json()["pending"] == 1


def test_approval_state_machine(env):
    sync, client = env
    ok = lambda act, key, **kw: client.post(f"/api/approvals/{key}/{act}", headers=AUTH, json={})   # noqa: E731
    assert ok("approve", HUMAN_PENDING).status_code == 200
    assert ok("approve", HUMAN_PENDING).status_code == 409            # double approve
    assert ok("reject", HUMAN_PENDING).status_code == 409             # reject after approve
    assert ok("reject", HUMAN_SECOND).status_code == 200
    assert ok("approve", HUMAN_SECOND).status_code == 409             # approve after reject
    assert ok("approve", HUMAN_DONE).status_code == 409               # already executed
    assert ok("approve", "act-gone").status_code == 404               # stale / expired / never existed
    assert len(sync.xrange(STREAM_APPROVALS)) == 2                    # rejected attempts wrote nothing
    kinds = [f["kind"] for _, f in sync.xrange(STREAM_LEDGER)]
    assert kinds.count("approval") == 2 and kinds.count("rejection") == 1


def test_state_changes_by_fusion_show_through(env):
    sync, client = env
    client.post(f"/api/approvals/{HUMAN_PENDING}/approve", headers=AUTH, json={})
    st = state_of(sync, HUMAN_PENDING) | {"state": "executing"}
    sync.set(key_approval(HUMAN_PENDING), json.dumps(st), keepttl=True)
    assert client.get(f"/api/approvals/{HUMAN_PENDING}").json()["display_state"] == "executing"
    assert client.post(f"/api/approvals/{HUMAN_PENDING}/approve", headers=AUTH, json={}).status_code == 409


def test_reason_is_length_capped(env):
    _, client = env
    r = client.post(f"/api/approvals/{HUMAN_PENDING}/approve", headers=AUTH, json={"reason": "x" * 501})
    assert r.status_code == 422


# ── mode ─────────────────────────────────────────────────────────────────────────────────────────

def test_mode_switch_is_ledgered(env):
    sync, client = env
    assert client.get("/api/mode").json() == {"runtime": None, "effective": "observe", "last_action_mode": "observe"}
    assert client.post("/api/mode", json={"mode": "bogus"}, headers=AUTH).status_code == 422
    assert client.post("/api/mode", json={"mode": "observe", "reason": "incident 4411"}, headers=AUTH).json() == {"runtime": "observe", "previous": None}
    assert sync.get(KEY_MODE) == "observe"
    assert client.post("/api/mode", json={"mode": "enforce"}, headers=AUTH).json()["previous"] == "observe"
    assert client.get("/api/mode").json()["runtime"] == "enforce"
    e = client.get("/api/ledger", params={"kind": "mode", "limit": 1}).json()["entries"][0]
    assert (e["actor"], e["decision"], e["outcome"]) == ("admin:Maria R", "enforce", "set") and json.loads(e["detail"])["previous"] == "observe"


# ── ledger ───────────────────────────────────────────────────────────────────────────────────────

def test_ledger_paging_and_filters(env):
    sync, client = env
    for i in range(120):
        sync.xadd(STREAM_LEDGER, {"ts_ms": str(i), "kind": "action", "actor": "fusion", "namespace": f"ns-{i % 3}", "decision": "AUTO_KILL"})
    first = client.get("/api/ledger", params={"limit": 50}).json()
    assert len(first["entries"]) == 50 and first["next_cursor"]
    seen = [e["id"] for e in first["entries"]]
    page = first
    while page["next_cursor"]:
        page = client.get("/api/ledger", params={"limit": 50, "cursor": page["next_cursor"]}).json()
        seen += [e["id"] for e in page["entries"]]
    assert len(seen) == len(set(seen)) == 125 and page["next_cursor"] is None
    assert [e["id"] for e in first["entries"]] == sorted(seen, reverse=True)[:50]          # newest first
    ns = client.get("/api/ledger", params={"namespace": "ns-1", "limit": 200}).json()
    assert len(ns["entries"]) == 40 and {e["namespace"] for e in ns["entries"]} == {"ns-1"}
    by_actor = client.get("/api/ledger", params={"actor": "admin:maria"}).json()["entries"]
    assert {e["kind"] for e in by_actor} == {"mode", "approval"}
    assert client.get("/api/ledger", params={"kind": "nope"}).status_code == 422
    assert client.get("/api/ledger", params={"limit": 201}).status_code == 422


def test_ledger_has_no_write_route(env):
    _, client = env
    assert client.post("/api/ledger", json={}, headers=AUTH).status_code == 405
    assert client.delete("/api/ledger", headers=AUTH).status_code == 405


# ── models, stats, headers ───────────────────────────────────────────────────────────────────────

def test_models(env, tmp_path, monkeypatch):
    _, client = env
    d = client.get("/api/models").json()
    assert d["inference"] == {"reachable": True, "ready": True, "versions": {"health": "health-5.0.0-x", "security": "security-5.0.0-y"}}
    assert d["meta"]["health"] is None or d["meta"]["health"]["version"]   # repo models/ dir may or may not be present
    monkeypatch.setattr(admin, "_fetch_ready", lambda: None)
    monkeypatch.setattr(admin, "_models_cache", None)
    assert client.get("/api/models").json()["inference"]["reachable"] is False


def test_stats_kpis(env):
    _, client = env
    s = client.get("/api/stats").json()
    assert (s["kills"], s["kills_dry_run"], s["patches"], s["human"], s["guard_rails"], s["containment_requested"]) == (1, 1, 1, 3, 1, 1)
    assert s["latency_ms"] == {"p50": 840, "p95": 30_000, "n": 2}   # the live kill (840 ms) and the dry-run one


def test_csp_is_strict_and_api_is_not_cached(env):
    _, client = env
    csp = client.get("/").headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "style-src 'self';" in csp
    assert client.get("/api/stats").headers["cache-control"] == "no-store"


# ── review fixes ─────────────────────────────────────────────────────────────────────────────────

def test_named_tokens_set_the_actor(env, monkeypatch):
    _, client = env
    monkeypatch.setenv(auth.ADMIN_TOKENS_ENV, "maria:tok-m,li:tok:with:colons")
    who = lambda tok, **h: client.get("/api/admin/session", headers={"Authorization": f"Bearer {tok}", **h})   # noqa: E731
    assert who("tok-m", **{"X-Actor": "someone else"}).json() == {"actor": "maria"}     # X-Actor ignored
    assert who("tok:with:colons").json() == {"actor": "li"}                             # name = part before the first ':'
    assert who("li:tok:with:colons").status_code == 403                                 # the name is not part of the token
    assert who(TOKEN, **{"X-Actor": "Maria R"}).json() == {"actor": "admin:Maria R"}    # shared token keeps the label
    assert who(TOKEN).json() == {"actor": "admin"}
    monkeypatch.delenv(auth.ADMIN_TOKEN_ENV)
    assert who("tok-m").json() == {"actor": "maria"} and who(TOKEN).status_code == 403


def test_failed_auth_is_rate_limited_per_client(env):
    _, client = env
    codes = [client.get("/api/admin/session", headers={"Authorization": "Bearer nope"}).status_code for _ in range(12)]
    assert codes[:10] == [403] * 10 and codes[10:] == [429, 429]
    assert client.get("/api/admin/session", headers=AUTH).status_code == 429   # blocked until the bucket refills
    auth.failed_auth.reset()
    assert client.get("/api/admin/session", headers=AUTH).status_code == 200


def test_ledger_and_approvals_reads_are_rate_limited(env):
    _, client = env
    for path in ("/api/ledger", "/api/approvals"):
        codes = [client.get(path).status_code for _ in range(25)]
        assert codes[:20] == [200] * 20 and 429 in codes[20:], path
    assert client.get("/api/stats").status_code == 200   # other reads are not throttled


def test_ledger_scan_is_capped(env):
    assert admin.SCAN_MAX <= 1000


def test_approvals_listed_from_pending_index_with_expiry(env):
    sync, client = env
    old = now_ms() - 40 * 60_000
    sync.set(key_approval("act-old"), json.dumps({"state": "pending", "candidate": "AUTO_KILL", "namespace": "ns", "workload": "w",
                                                  "created_ms": old, "score": 0.7}), ex=3600)
    sync.set(key_approval("act-exp"), json.dumps({"state": "expired", "candidate": "AUTO_PATCH", "namespace": "ns", "workload": "e",
                                                  "created_ms": old - 1, "score": 0.7}), ex=3600)
    sync.zadd(KEY_APPROVALS_PENDING, {"act-old": old, "act-exp": old - 1, "act-gone": old - 2})   # act-gone: record expired from Redis
    items = {i["action_event_id"]: i for i in client.get("/api/approvals").json()["items"]}   # none of these is in the action buffer
    assert items["act-old"]["expires_ms"] == old + 3_600_000 and items["act-exp"]["state"] == "expired"
    assert "act-gone" not in items
    assert client.post("/api/approvals/act-exp/approve", headers=AUTH, json={}).status_code == 409


def test_dashboard_only_adds_requested_to_the_record(env):
    sync, client = env
    sync.set(key_approval(HUMAN_PENDING), json.dumps({**state_of(sync, HUMAN_PENDING), "sig": "abc", "rev": 3}), keepttl=True)
    before = state_of(sync, HUMAN_PENDING)
    client.post(f"/api/approvals/{HUMAN_PENDING}/approve", headers=AUTH, json={})
    after = state_of(sync, HUMAN_PENDING)
    assert {k: v for k, v in after.items() if k != "requested"} == before and after["requested"]["decision"] == "approve"


def test_ledger_and_approvals_streams_are_capped(env, monkeypatch):
    from redis.asyncio.client import Pipeline

    _, client = env
    seen = []
    real = Pipeline.xadd
    monkeypatch.setattr(Pipeline, "xadd", lambda self, name, fields, *a, **kw: (seen.append((name, kw)), real(self, name, fields, *a, **kw))[1])
    client.post("/api/mode", json={"mode": "enforce"}, headers=AUTH)
    client.post(f"/api/approvals/{HUMAN_PENDING}/approve", headers=AUTH, json={})
    caps = {name: kw for name, kw in seen}
    assert caps[STREAM_LEDGER] == {"maxlen": admin.LEDGER_MAXLEN, "approximate": True}   # no MINID: fusion trims by age
    assert caps[STREAM_APPROVALS] == {"maxlen": 10_000, "approximate": True}


def test_detection_to_kill_ignores_approved_kills(env):
    sync, client = env
    sec = client.get("/api/events", params={"kind": "security"}).json()["events"][-1]
    sync.xadd(STREAM_ACTIONS, ActionEvent(event_id="a-approved", namespace="shop-prod", workload="reports", decision=Decision.AUTO_KILL, score=0.9,
                                          rationale="approved", mode="enforce", outcome="pod_killed", security_event_id=sec["event_id"],
                                          approved_by="admin:maria", timestamp_ms=sec["window_end_ms"] + 600_000).to_fields())
    assert wait_for(lambda: client.get("/api/stats").json()["kills"] == 2)
    assert client.get("/api/stats").json()["latency_ms"]["n"] == 2   # unchanged: the approved kill waited for a human
