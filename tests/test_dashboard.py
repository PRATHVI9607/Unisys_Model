import time

import fakeredis
import pytest
from fastapi.testclient import TestClient

from dashboard import fastapi_app
from kubeheal.contracts import (
    STREAM_ACTIONS,
    STREAM_HEALTH,
    STREAM_SECURITY,
    ActionEvent,
    Decision,
    Factor,
    HealthEvent,
    SecurityEvent,
    key_event,
)

HEALTH = HealthEvent(event_id="h-1", namespace="shop-prod", workload="cart", label="critical", risk=0.91,
                     uncertain=True, changed_fields=["spec.replicas"],
                     top_factors=[Factor(feature="replicas_delta", value=-3, contribution=0.4)])
SECURITY = SecurityEvent(event_id="s-1", namespace="shop-prod", workload="cart", pod="cart-abc",
                         label="ransomware", risk=0.95, n_events=120, window_start_ms=1, window_end_ms=30_001)
ACTION = ActionEvent(event_id="a-1", namespace="shop-prod", workload="cart", pod="cart-abc",
                     decision=Decision.AUTO_KILL, mode="observe", outcome="would_kill", score=0.97,
                     compound_score=0.8, rationale="ransomware certain", summary="Would kill cart-abc.",
                     health_event_id="h-1", security_event_id="s-1")


def wait_for(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def redis_and_client(monkeypatch):
    server = fakeredis.FakeServer()
    sync = fakeredis.FakeRedis(server=server, decode_responses=True)
    sync.xadd(STREAM_HEALTH, {"event_id": "broken", "risk": "not-a-number"})   # malformed, must be skipped
    sync.xadd(STREAM_HEALTH, HEALTH.to_fields())
    sync.xadd(STREAM_SECURITY, SECURITY.to_fields())
    monkeypatch.setattr(fastapi_app, "make_redis",
                        lambda: fakeredis.FakeAsyncRedis(server=server, decode_responses=True))
    with TestClient(fastapi_app.app) as client:
        assert wait_for(lambda: client.get("/readyz").status_code == 200)
        yield sync, client


def test_backfill_parses_contract_and_skips_malformed(redis_and_client):
    _, client = redis_and_client
    [h] = client.get("/api/events", params={"kind": "health"}).json()["events"]
    assert h["label"] == "critical" and h["uncertain"] is True and h["changed_fields"] == ["spec.replicas"]
    assert h["top_factors"][0] == {"feature": "replicas_delta", "value": -3.0, "contribution": 0.4}
    [s] = client.get("/api/events", params={"kind": "security"}).json()["events"]
    assert s["n_events"] == 120 and s["pod"] == "cart-abc"


def test_live_action_reaches_rest_and_websocket(redis_and_client):
    sync, client = redis_and_client
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_json()["type"] == "stats"
        sync.xadd(STREAM_HEALTH, {"garbage": "1"})    # bad entry in the same read must not drop the good one
        sync.xadd(STREAM_ACTIONS, ACTION.to_fields())
        assert wait_for(lambda: client.get("/api/events", params={"kind": "action"}).json()["events"])
        msg = ws.receive_json()
    assert msg["type"] == "events"
    [a] = [e for e in msg["events"] if e["kind"] == "action"]
    assert (a["decision"], a["mode"], a["security_event_id"]) == ("AUTO_KILL", "observe", "s-1")
    assert msg["stats"]["actions"] == 1 and msg["stats"]["actions_dry_run"] == 1
    assert client.get("/api/stats").json()["health_high_risk"] == 1


def test_list_validation(redis_and_client):
    _, client = redis_and_client
    for params in ({"kind": "health", "limit": 0}, {"kind": "health", "limit": 201}, {"kind": "bogus"}, {}):
        assert client.get("/api/events", params=params).status_code == 422


def test_detail_buffer_hash_and_404(redis_and_client):
    sync, client = redis_and_client
    assert client.get("/api/events/health/h-1").json()["risk"] == 0.91
    old = ActionEvent(**{**ACTION.model_dump(), "event_id": "a-old"})   # aged out of the stream, still in the hash
    sync.hset(key_event("action", "a-old"), mapping=old.to_fields())
    assert client.get("/api/events/action/a-old").json()["outcome"] == "would_kill"
    assert client.get("/api/events/action/nope").status_code == 404


def test_readyz_503_when_redis_down(monkeypatch):
    class Down(fakeredis.FakeAsyncRedis):
        async def ping(self, **kw):
            raise fastapi_app.aioredis.ConnectionError("down")

    monkeypatch.setattr(fastapi_app, "make_redis", lambda: Down())
    with TestClient(fastapi_app.app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 503
        assert client.get("/api/events/health/x").status_code == 503
