"""P7-RR-10: admin tool that lifts the SnapshotFreeze of one incident, plus the approval-claim fixes from the
P6/P8 review (queued claim cannot be released, fresh bare claims survive startup reconciliation)."""
import asyncio
import json
import time

import pytest

from test_dashboard_seed import AUTH, INC, client, harness, seed_incident  # noqa: F401

PATH = f"/api/incidents/{INC}/release-snapshot-freeze"
WHY = {"reason": "restore verified by operator"}      # a written reason is required in every case


def key(ns, pvc):
    return f"kubeheal:snapfreeze:{ns}:{pvc}"


class Freezes:
    """In-memory freeze keys wired into the harness services (key -> incident id)."""

    def __init__(self, harness, held):
        self.keys = dict(held)
        self.deleted = []
        self.fail_delete = False
        svc = harness.services()

        async def freeze_list(incident_id):
            out = []
            for k, v in self.keys.items():
                if v == incident_id:
                    ns, _, pvc = k[len("kubeheal:snapfreeze:"):].partition(":")
                    out.append((ns, pvc, k))
            return out

        async def freeze_delete(keys):
            if self.fail_delete:
                raise RuntimeError("redis down")
            for k in keys:
                self.keys.pop(k, None)
                self.deleted.append(k)

        svc.freeze_list, svc.freeze_delete = freeze_list, freeze_delete
        from dashboard.fastapi_app import app
        app.state.services = svc


def closed_incident(harness):
    seed_incident(harness, approval=False)
    harness.ledger.append(INC, "executor_result", {"action": "restore", "outcome": "restored"})


@pytest.fixture
def enforce(harness):
    harness.mode_store.mode = "enforce"
    return harness


def test_freeze_prefix_matches_the_executor():
    from agents.executor.snapshots import FREEZE_PREFIX, SnapshotFreeze
    from dashboard.admin_routes import FREEZE_PREFIX as DASH
    assert DASH == FREEZE_PREFIX
    assert SnapshotFreeze.key("prod", "data") == key("prod", "data")


def test_requires_admin_and_is_guarded_like_every_mutating_route(client, enforce):
    closed_incident(enforce)
    Freezes(enforce, {key("prod", "data"): INC})
    assert client.post(PATH).status_code == 401
    assert client.post(PATH, headers={"Authorization": "Bearer wrong"}).status_code == 403


def test_closed_incident_is_released_audited_first_and_keeps_other_incidents(client, enforce):
    closed_incident(enforce)
    f = Freezes(enforce, {key("prod", "data"): INC, key("prod", "other"): "inc-other"})
    r = client.post(PATH, headers=AUTH, json={"reason": "restore verified by operator"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "released" and body["released"] is True and body["forced"] is False
    assert body["pvcs"] == [{"namespace": "prod", "pvc": "data"}]
    assert f.deleted == [key("prod", "data")] and key("prod", "other") in f.keys
    entry = enforce.records()[-1]
    assert entry["step"] == "snapshot_freeze_released"
    assert entry["payload"]["actor"] == "admin:dashboard-admin"
    assert entry["payload"]["reason"] == "restore verified by operator"
    assert entry["payload"]["incident_closed"] is True and entry["payload"]["forced"] is False


@pytest.mark.parametrize("body", [{}, {"reason": None}, {"reason": ""}, {"reason": "   "}, {"reason": "too short"},
                                  {"reason": "x" * 9}, {"force": True}])
def test_a_written_reason_is_required_even_for_a_closed_incident(client, enforce, body):
    """The owner rule asks for actor and reason on every release, so `closed` does not waive the reason."""
    closed_incident(enforce)
    f = Freezes(enforce, {key("prod", "data"): INC})
    r = client.post(PATH, headers=AUTH, json=body)
    assert r.status_code == 422, r.text
    assert f.deleted == [] and "snapshot_freeze_released" not in enforce.steps()


def test_reason_of_exactly_the_minimum_length_is_accepted_and_trimmed(client, enforce):
    closed_incident(enforce)
    Freezes(enforce, {key("prod", "data"): INC})
    r = client.post(PATH, headers=AUTH, json={"reason": "  " + "x" * 10 + "  "})
    assert r.status_code == 200
    assert enforce.records()[-1]["payload"]["reason"] == "x" * 10


def test_open_incident_is_refused_without_force(client, enforce):
    seed_incident(enforce, approval=False)
    f = Freezes(enforce, {key("prod", "data"): INC})
    r = client.post(PATH, headers=AUTH, json={"reason": "a perfectly good reason"})
    assert r.status_code == 409
    assert f.deleted == [] and "snapshot_freeze_released" not in enforce.steps()


@pytest.mark.parametrize("outcome", ["contained", "restored_kept_isolated:high entropy", "restore_failed:x",
                                     "escalated:preflight_error"])
def test_only_a_finished_restore_closes_an_incident(client, enforce, outcome):
    seed_incident(enforce, approval=False)
    enforce.ledger.append(INC, "executor_result", {"action": "restore", "outcome": outcome})
    Freezes(enforce, {key("prod", "data"): INC})
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 409


def test_force_needs_a_written_reason(client, enforce):
    seed_incident(enforce, approval=False)
    f = Freezes(enforce, {key("prod", "data"): INC})
    assert client.post(PATH, headers=AUTH, json={"force": True}).status_code == 422
    assert client.post(PATH, headers=AUTH, json={"force": True, "reason": "   short "}).status_code == 422
    assert f.deleted == []
    r = client.post(PATH, headers=AUTH, json={"force": True, "reason": "evidence copied, volume retired"})
    assert r.status_code == 200 and r.json()["forced"] is True
    payload = enforce.records()[-1]["payload"]
    assert payload["forced"] is True and payload["incident_closed"] is False
    assert payload["reason"] == "evidence copied, volume retired"
    assert f.deleted == [key("prod", "data")]


def test_test_mode_is_a_dry_run_that_removes_nothing(client, harness):
    closed_incident(harness)           # mode is test by default
    f = Freezes(harness, {key("prod", "data"): INC})
    r = client.post(PATH, headers=AUTH, json={"reason": "restore verified by operator"})
    assert r.status_code == 200 and r.json()["status"] == "dry_run" and r.json()["released"] is False
    assert f.deleted == [] and f.keys == {key("prod", "data"): INC}
    assert harness.records()[-1]["step"] == "snapshot_freeze_release_dry_run"
    assert "DRY RUN" in harness.records()[-1]["payload"]["note"]
    assert "snapshot_freeze_released" not in harness.steps()


def test_unreadable_mode_is_a_dry_run(client, harness):
    harness.mode_store.fail_read = True
    closed_incident(harness)
    f = Freezes(harness, {key("prod", "data"): INC})
    assert client.post(PATH, headers=AUTH, json=WHY).json()["status"] == "dry_run"
    assert f.deleted == []


def test_ledger_failure_means_nothing_is_released(client, enforce):
    from test_dashboard_approvals import FlakyLedger, use_ledger
    closed_incident(enforce)
    f = Freezes(enforce, {key("prod", "data"): INC})
    use_ledger(FlakyLedger(enforce.ledger, "snapshot_freeze_released", 1))
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 500
    assert f.deleted == [] and f.keys


def test_unknown_incident_unknown_freeze_and_bad_ids(client, enforce):
    Freezes(enforce, {})
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 404            # no such incident
    closed_incident(enforce)
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 404            # holds no freeze
    assert client.post("/api/incidents/..%2Fx/release-snapshot-freeze", headers=AUTH, json=WHY).status_code == 404


def test_removal_failure_is_reported_after_the_audit_entry(client, enforce):
    closed_incident(enforce)
    f = Freezes(enforce, {key("prod", "data"): INC})
    f.fail_delete = True
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 502
    assert enforce.records()[-1]["step"] == "snapshot_freeze_released" and f.keys
    f.fail_delete = False
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 200 and f.deleted


def test_only_redis_freeze_keys_are_touched():
    """The tool deletes freeze keys only: no Kubernetes client, no snapshot call anywhere in the route."""
    import inspect
    import dashboard.admin_routes as mod
    src = inspect.getsource(mod.release_snapshot_freeze)
    for banned in ("delete_namespaced", "VolumeSnapshot", "custom_api", "core_api"):
        assert banned not in src


def test_service_is_503_when_freeze_access_is_not_wired(client, enforce):
    closed_incident(enforce)
    assert client.post(PATH, headers=AUTH, json=WHY).status_code == 503


# ---- compare-and-delete (review fix 6a) -----------------------------------------------------------------------

def test_a_key_taken_over_by_another_incident_before_the_delete_is_left_in_place(client, enforce):
    closed_incident(enforce)
    f = Freezes(enforce, {key("prod", "data"): INC, key("prod", "logs"): INC})
    svc = enforce.services()

    async def freeze_list(incident_id):
        out = []
        for k, v in f.keys.items():
            if v == incident_id:
                ns, _, pvc = k[len("kubeheal:snapfreeze:"):].partition(":")
                out.append((ns, pvc, k))
        f.keys[key("prod", "logs")] = "inc-other"     # another incident takes the PVC after the listing
        return out

    async def delete_if_owned(keys, incident_id):
        removed = []
        for k in keys:
            if f.keys.get(k) == incident_id:
                del f.keys[k]
                removed.append(k)
        return removed

    async def plain_delete(keys):                      # must NOT be used when the compare-and-delete exists
        raise AssertionError("unconditional delete used")

    svc.freeze_list, svc.freeze_delete, svc.freeze_delete_if_owned = freeze_list, plain_delete, delete_if_owned
    from dashboard.fastapi_app import app
    app.state.services = svc
    r = client.post(PATH, headers=AUTH, json=WHY)
    assert r.status_code == 200, r.text
    assert r.json()["left_in_place"] == [key("prod", "logs")]
    assert f.keys == {key("prod", "logs"): "inc-other"}            # ours is gone, theirs is untouched


def test_redis_wiring_deletes_a_freeze_key_only_while_it_holds_the_incident_id():
    from dashboard.admin_routes import redis_services

    class R:
        def __init__(self):
            self.store = {key("prod", "a"): INC, key("prod", "b"): "inc-other"}

        async def get(self, k):
            return self.store.get(k)

        async def delete(self, *keys):
            for k in keys:
                self.store.pop(k, None)

    class WithEval(R):
        def __init__(self):
            super().__init__()
            self.scripts = []

        async def eval(self, script, n, k, token):
            self.scripts.append((k, token))
            if self.store.get(k) != token:
                return 0
            del self.store[k]
            return 1

    for redis in (R(), WithEval()):
        svc = redis_services(None, None, lambda redis=redis: redis)
        removed = asyncio.run(svc.freeze_delete_if_owned([key("prod", "a"), key("prod", "b")], INC))
        assert removed == [key("prod", "a")] and redis.store == {key("prod", "b"): "inc-other"}
    assert redis.scripts and all(token == INC for _k, token in redis.scripts)


# ---- approval claim fixes from the review ------------------------------------------------------

def test_release_claim_refuses_a_queued_claim(client, enforce):
    seed_incident(enforce)
    enforce.claims[INC] = json.dumps({"stream_id": "1-0", "approved_by": "admin:a", "action": "patch"})
    r = client.post(f"/api/approvals/{INC}/release-claim", headers=AUTH, json=WHY)
    assert r.status_code == 409
    assert INC in enforce.claims and "claim_released" not in enforce.steps()


def test_a_fresh_bare_claim_survives_startup_reconciliation(client, harness):
    from dashboard.admin_routes import reconcile_approval_claims
    seed_incident(harness)
    harness.claims[INC] = f"claimed@{int(time.time())}"
    result = asyncio.run(reconcile_approval_claims(harness.services()))
    assert result == {"completed": 0, "released": 0, "skipped": 1} and INC in harness.claims


def test_an_old_bare_claim_is_released_by_startup_reconciliation(client, harness):
    from dashboard.admin_routes import reconcile_approval_claims
    seed_incident(harness)
    harness.claims[INC] = f"claimed@{int(time.time()) - 3600}"
    result = asyncio.run(reconcile_approval_claims(harness.services()))
    assert result == {"completed": 0, "released": 1, "skipped": 0} and INC not in harness.claims


def test_claim_is_released_once_approved_is_recorded(client, enforce):
    seed_incident(enforce)
    assert client.post(f"/api/approvals/{INC}/approve", headers=AUTH).status_code == 200
    assert enforce.claims == {}


def test_claim_that_holds_a_stream_id_has_no_expiry_in_the_redis_wiring():
    """claim_set must not pass `ex`: a queued claim has to outlive the TTL until the ledger is written."""
    import inspect
    from dashboard.admin_routes import redis_services
    src = inspect.getsource(redis_services)
    start = src.index("async def claim_set")
    block = src[start:src.index("async def claim_get")]
    assert "xx=True" in block and "ex=" not in block


# ---- health listener ignores the Health Agent's model_unavailable notice ----------------------------------

def test_health_listener_skips_model_unavailable_events_and_keeps_real_ones():
    from dashboard.fastapi_app import KubeHealDashboard

    class R:
        def __init__(self, dash):
            self.dash, self.calls = dash, 0

        async def xread(self, streams, count=None, block=None):
            self.calls += 1
            if self.calls > 1:
                self.dash.running = False
                return []
            return [(b"kubeheal.health.events", [
                (b"1-0", {b"event_id": b"e-down", b"namespace": b"prod", b"health_label": b"model_unavailable",
                          b"model_unavailable": b"true"}),
                (b"2-0", {b"event_id": b"e-ok", b"namespace": b"prod", b"pod_name": b"web-1",
                          b"health_risk": b"0.2", b"health_label": b"benign", b"timestamp_ms": b"1"}),
            ])]

    async def go():
        dash = KubeHealDashboard()
        dash.running = True
        dash.redis = R(dash)
        await dash._listen_health_events()
        return dash

    dash = asyncio.run(go())
    assert [e.event_id for e in dash.health_events] == ["e-ok"]
