import asyncio
import re
import sys
import types
from pathlib import Path

import pytest

from test_dashboard_seed import AUTH, TOKEN, client, harness  # noqa: F401


def toggle(client, mode, headers=None):
    return client.post("/api/kill-switch", headers=headers or {}, json={"mode": mode})


def test_status_reports_mode_and_history_from_the_ledger(client, harness):
    # an entry written by the Executor's mode hook has no actor
    harness.ledger.append("mode-aaa", "mode_change", {"from": None, "to": "test", "source": "configmap"})
    r = client.get("/api/kill-switch")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "test" and body["readable"] is True and body["dry_run"] is True
    assert [(h["from"], h["to"], h["source"]) for h in body["history"]] == [(None, "test", "configmap")]


def test_unreadable_configmap_is_reported_as_test(client, harness):
    harness.mode_store.fail_read = True
    body = client.get("/api/kill-switch").json()
    assert body["mode"] == "test" and body["readable"] is False and body["dry_run"] is True


def test_enforce_only_for_the_exact_string(client, harness):
    harness.mode_store.mode = "ENFORCE "
    assert client.get("/api/kill-switch").json()["mode"] == "enforce"      # same normalisation as the ModeWatcher
    harness.mode_store.mode = "on"
    assert client.get("/api/kill-switch").json()["mode"] == "test"


def test_toggle_without_token_is_refused(client, harness, monkeypatch):
    assert toggle(client, "enforce").status_code == 401
    assert toggle(client, "enforce", {"Authorization": "Bearer nope"}).status_code == 403
    assert harness.mode_store.writes == [] and harness.steps("mode-x") == []
    assert list(harness.ledger.store.keys("incidents/")) == []
    monkeypatch.delenv("KUBEHEAL_ADMIN_TOKEN")
    assert toggle(client, "enforce", AUTH).status_code == 503
    assert harness.mode_store.writes == []


def test_toggle_with_token_writes_configmap_and_ledger_with_actor(client, harness):
    r = toggle(client, "enforce", AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] is True and body["mode"] == "enforce" and body["actor"] == "admin:dashboard-admin"
    assert harness.mode_store.writes == ["enforce"]
    (key,) = list(harness.ledger.store.keys("incidents/mode-"))
    assert key.endswith("-mode_change.json")
    rec = harness.records(body["ledger_id"])[0]
    assert rec["payload"] == {"from": "test", "to": "enforce", "source": "dashboard", "actor": "admin:dashboard-admin"}
    hist = client.get("/api/kill-switch").json()
    assert hist["mode"] == "enforce" and hist["history"][-1]["actor"] == "admin:dashboard-admin"
    assert TOKEN not in str(rec) and TOKEN not in r.text


def test_toggle_back_to_test(client, harness):
    toggle(client, "enforce", AUTH)
    r = toggle(client, "test", AUTH)
    assert r.json()["changed"] is True and harness.mode_store.mode == "test"
    assert [h["to"] for h in client.get("/api/kill-switch").json()["history"]] == ["enforce", "test"]


def test_toggle_to_the_current_mode_changes_nothing(client, harness):
    r = toggle(client, "test", AUTH)
    assert r.status_code == 200 and r.json()["changed"] is False
    assert harness.mode_store.writes == [] and list(harness.ledger.store.keys("incidents/")) == []


@pytest.mark.parametrize("value", ["Enforce", "ENFORCE", "enforce ", "on", "true", "", "dry-run", None, 1, True])
def test_only_exactly_test_or_enforce_is_accepted(client, harness, value):
    r = client.post("/api/kill-switch", headers=AUTH, json={"mode": value})
    assert r.status_code == 422
    assert harness.mode_store.writes == []


def test_missing_body_is_rejected(client, harness):
    assert client.post("/api/kill-switch", headers=AUTH, json={}).status_code == 422
    assert harness.mode_store.writes == []


def test_configmap_write_failure_is_502_and_not_recorded(client, harness):
    harness.mode_store.fail_write = True
    r = toggle(client, "enforce", AUTH)
    assert r.status_code == 502 and "api down" not in r.text
    assert list(harness.ledger.store.keys("incidents/")) == []


def test_ledger_failure_reverts_enforce_to_test(client, harness, monkeypatch):
    def broken(*a, **k):
        raise OSError("minio down")
    monkeypatch.setattr(harness.ledger, "append", broken)
    r = toggle(client, "enforce", AUTH)
    assert r.status_code == 500
    assert harness.mode_store.writes == ["enforce", "test"] and harness.mode_store.mode == "test"


def test_ledger_failure_when_switching_to_test_keeps_test(client, harness, monkeypatch):
    harness.mode_store.mode = "enforce"
    monkeypatch.setattr(harness.ledger, "append", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    assert toggle(client, "test", AUTH).status_code == 500
    assert harness.mode_store.mode == "test"


def test_dashboard_has_a_single_kubernetes_write_path():
    """The ConfigMap patch verb is referenced in dashboard/mode_admin.py and nowhere else in dashboard/."""
    root = Path(__file__).resolve().parents[1] / "dashboard"
    hits = []
    for p in root.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if re.search(r"patch_namespaced|config_map|call_api|\.(replace|create|delete|patch)_namespaced", text):
            hits.append(p.name)
    assert hits == ["mode_admin.py"], hits


def test_kubernetes_store_patches_only_the_mode_key(monkeypatch):
    calls = []

    class Core:
        def __init__(self, api):
            pass

        async def patch_namespaced_config_map(self, name, namespace, body):
            calls.append((name, namespace, body))

        async def read_namespaced_config_map(self, name, namespace):
            return types.SimpleNamespace(data={"mode": "test"})

    class Api:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def load_kube_config():
        return None

    def incluster():
        raise RuntimeError("not in a cluster")

    fake_client = types.SimpleNamespace(ApiClient=Api, CoreV1Api=Core)
    fake_config = types.SimpleNamespace(load_incluster_config=incluster, load_kube_config=load_kube_config)
    pkg = types.ModuleType("kubernetes_asyncio")
    pkg.client, pkg.config = fake_client, fake_config
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio", pkg)

    from dashboard.mode_admin import KubernetesModeStore
    store = KubernetesModeStore()
    assert asyncio.run(store.read_mode()) == "test"
    asyncio.run(store.write_mode("enforce"))
    assert calls == [("kubeheal-mode", "kubeheal", {"data": {"mode": "enforce"}})]
    with pytest.raises(ValueError):
        asyncio.run(store.write_mode("Enforce"))
    assert len(calls) == 1
