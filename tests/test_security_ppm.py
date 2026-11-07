import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from kubeheal.contracts import HealthEvent, namespace_tier
from kubeheal.correlation import _is_config_cause
from kubeheal.features.security import open_syscall


@pytest.mark.parametrize("flags,want", [("1", "open_r"), ("2", "open_w"), ("3", "open_w"), ("5", "open_w"),
                                        ("9", "open_w"), ("257", "open_w"), ("O_RDONLY|O_CLOEXEC", "open_r")])
def test_open_syscall_ppm_flags(flags, want):
    assert open_syscall("openat", flags) == want


@pytest.mark.parametrize("ns,want", [("nonprod", "dev"), ("preprod", "dev"), ("reproduce", "dev"),
                                     ("my-prod-ns", "prod"), ("production", "prod"), ("staging", "staging"),
                                     ("team_stg", "staging")])
def test_namespace_tier_tokens(ns, want):
    assert namespace_tier(ns) == want


def test_config_cause_exact_segment():
    assert not _is_config_cause("spec.template.spec.containers[0].imagePullPolicy")
    assert _is_config_cause("spec.template.spec.containers[0].image")
    assert _is_config_cause("spec.template.spec.containers[0].resources.limits.cpu")


def test_from_fields_exact_types_and_bad_json():
    base = {"event_id": "h", "namespace": "n", "workload": "w", "label": "benign", "risk": "0.1"}
    ev = HealthEvent.from_fields({**base, "changed_fields": '["a"]', "features": ""})
    assert ev.changed_fields == ["a"] and ev.features == {}
    with pytest.raises(ValueError):    # json.JSONDecodeError
        HealthEvent.from_fields({**base, "changed_fields": "{not json"})


@pytest.fixture
def client():
    from types import SimpleNamespace

    from dashboard import fastapi_app
    fastapi_app.app.state.hub = SimpleNamespace(stats=lambda: {}, clients=set())    # no lifespan: stub the hub
    yield TestClient(fastapi_app.app)
    del fastapi_app.app.state.hub


def test_ws_rejects_cross_origin(client):
    with pytest.raises(WebSocketDisconnect) as e:
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
            pass
    assert e.value.code == 1008


@pytest.mark.parametrize("headers", [{"origin": "http://testserver"}, {}])    # same host:port as Host; no Origin
def test_ws_accepts_same_origin_and_no_origin(client, headers):
    with client.websocket_connect("/ws", headers=headers) as ws:
        assert ws.receive_json()["type"] == "stats"
