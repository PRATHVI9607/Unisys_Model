import json
import logging

import pytest

from test_dashboard_seed import AUTH, INC, TOKEN, client, harness, seed_incident  # noqa: F401


def post(client, path, headers=None, json_body=None):
    return client.post(path, headers=headers or {}, json=json_body)


@pytest.fixture
def enforce(harness):
    """Kill switch in enforce mode: an approval is a real one and closes the incident."""
    harness.mode_store.mode = "enforce"
    return harness


class FlakyLedger:
    """Wraps the ledger so the next `fail` appends of one step raise."""

    def __init__(self, ledger, step, fail):
        self.ledger, self.step, self.fail = ledger, step, fail
        self.store = ledger.store

    def append(self, incident_id, step, payload):
        if step == self.step and self.fail > 0:
            self.fail -= 1
            raise OSError("minio down")
        return self.ledger.append(incident_id, step, payload)


def use_ledger(ledger):
    from dashboard.fastapi_app import app
    app.state.services.ledger = ledger


def test_pending_list_shows_only_undecided_human_decisions(client, harness):
    seed_incident(harness, INC)
    seed_incident(harness, "inc-auto", decision="auto_patch", approval=False)
    seed_incident(harness, "inc-done")
    harness.ledger.append("inc-done", "rejected", {})
    r = client.get("/api/approvals")
    assert r.status_code == 200
    assert [p["incident_id"] for p in r.json()["pending"]] == [INC]
    p = r.json()["pending"][0]
    assert p["decision"] == "human_patch" and p["namespace"] == "staging" and p["deployment"] == "web"


def test_approve_queues_executor_request_and_writes_ledger(client, enforce):
    harness = enforce
    seed_incident(harness)
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved" and r.json()["queued"] is True
    assert r.json()["incident_closed"] is True
    (req,) = harness.exec_requests
    assert req["action"] == "patch"
    assert req["incident_id"] == INC
    assert req["namespace"] == "staging" and req["deployment"] == "web"
    assert req["patch_field"] == "resources.limits.cpu"
    assert req["approved_by"] == "admin:dashboard-admin"
    assert req["dry_run"] == "false"
    assert harness.steps()[-1] == "approved"
    approved = harness.records()[-1]["payload"]
    assert approved["approved_by"] == "admin:dashboard-admin" and approved["mode"] == "enforce"
    assert approved["dry_run"] is False and approved["exec_stream_id"] == "1-0"
    assert client.get("/api/approvals").json()["count"] == 0


def test_approve_in_test_mode_queues_a_dry_run_and_leaves_the_incident_pending(client, harness):
    seed_incident(harness)
    r = post(client, f"/api/approvals/{INC}/approve", AUTH, {"note": "try it"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "dry_run_approved" and r.json()["incident_closed"] is False
    (req,) = harness.exec_requests
    assert req["dry_run"] == "true" and req["approved_by"] == "admin:dashboard-admin"
    assert harness.steps()[-1] == "dry_run_approved" and "approved" not in harness.steps()
    rec = harness.records()[-1]["payload"]
    assert rec["approved_by"] == "admin:dashboard-admin" and rec["dry_run"] is True and rec["note"] == "try it"
    assert harness.claims == {}                                  # released, a real approval stays possible
    assert client.get("/api/approvals").json()["count"] == 1     # still pending
    assert client.get(f"/api/incidents/{INC}").json()["status"] == "pending"
    page = client.get(f"/incidents/{INC}").text
    assert "Dry-run approvals" in page and "dry-run approved by" in page and 'data-action="approve"' in page


def test_dry_run_approved_incident_can_be_approved_for_real_in_enforce_mode(client, harness):
    seed_incident(harness)
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert harness.exec_requests[0]["dry_run"] == "true"
    harness.mode_store.mode = "enforce"
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.json()["status"] == "approved" and r.json()["incident_closed"] is True
    assert [q["dry_run"] for q in harness.exec_requests] == ["true", "false"]
    assert harness.steps()[-2:] == ["dry_run_approved", "approved"]
    assert client.get("/api/approvals").json()["count"] == 0
    again = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert again.json()["status"] == "already_approved"
    assert len(harness.exec_requests) == 2 and harness.steps().count("approved") == 1
    assert "dry-run approved by" in client.get(f"/incidents/{INC}").text      # history stays visible


def test_repeated_dry_run_approvals_each_queue_a_dry_run(client, harness):
    seed_incident(harness)
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert [q["dry_run"] for q in harness.exec_requests] == ["true", "true"]
    assert harness.steps().count("dry_run_approved") == 2


def test_reject_still_closes_an_incident_with_a_dry_run_approval(client, harness):
    seed_incident(harness)
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert post(client, f"/api/approvals/{INC}/reject", AUTH).json()["status"] == "rejected"
    assert client.get("/api/approvals").json()["count"] == 0


def test_approve_with_unreadable_mode_is_a_dry_run_approval(client, harness):
    harness.mode_store.fail_read = True
    seed_incident(harness)
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).json()["status"] == "dry_run_approved"
    assert harness.exec_requests[0]["dry_run"] == "true"
    assert harness.records()[-1]["payload"]["mode_readable"] is False
    assert client.get("/api/approvals").json()["count"] == 1


def test_dry_run_queue_failure_is_502_and_releases_the_claim(client, harness):
    seed_incident(harness)
    harness.enqueue_error = RuntimeError("redis down")
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 502
    assert harness.claims == {} and "dry_run_approved" not in harness.steps()


def test_approve_identity_comes_from_configuration(client, enforce, monkeypatch):
    harness = enforce
    monkeypatch.setenv("KUBEHEAL_ADMIN_IDENTITY", "oncall.priya")
    seed_incident(harness)
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert harness.exec_requests[0]["approved_by"] == "admin:oncall.priya"
    monkeypatch.setenv("KUBEHEAL_ADMIN_IDENTITY", "bad identity\nwith newline")
    seed_incident(harness, "inc-2")
    post(client, "/api/approvals/inc-2/approve", AUTH)
    assert harness.exec_requests[1]["approved_by"] == "admin:dashboard-admin"


def test_contain_request_carries_the_pod(client, enforce):
    harness = enforce
    seed_incident(harness, decision="human_contain", pod="web-abc-123")
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200
    req = harness.exec_requests[0]
    assert req["action"] == "contain" and req["pod"] == "web-abc-123" and req["patch_field"] == ""


def test_second_approve_does_nothing(client, enforce):
    harness = enforce
    seed_incident(harness)
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200
    again = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert again.status_code == 200
    assert again.json() == {"status": "already_approved", "incident_id": INC, "queued": False}
    assert len(harness.exec_requests) == 1
    assert harness.steps().count("approved") == 1


def test_reject_writes_ledger_and_queues_nothing(client, harness):
    seed_incident(harness)
    r = post(client, f"/api/approvals/{INC}/reject", AUTH, {"note": "not now"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert harness.exec_requests == []
    assert harness.steps()[-1] == "rejected"
    assert harness.records()[-1]["payload"] == {"rejected_by": "admin:dashboard-admin", "note": "not now"}
    again = post(client, f"/api/approvals/{INC}/reject", AUTH)
    assert again.json()["status"] == "already_rejected"
    assert harness.steps().count("rejected") == 1


def test_conflicting_decisions_are_refused(client, enforce):
    harness = enforce
    seed_incident(harness)
    seed_incident(harness, "inc-2")
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert post(client, f"/api/approvals/{INC}/reject", AUTH).status_code == 409
    post(client, "/api/approvals/inc-2/reject", AUTH)
    assert post(client, "/api/approvals/inc-2/approve", AUTH).status_code == 409
    assert len(harness.exec_requests) == 1


def test_incident_without_approval_request_cannot_be_approved(client, harness):
    seed_incident(harness, decision="auto_patch", approval=False)
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 409
    assert harness.exec_requests == []


def test_unknown_and_malformed_incident_ids(client, harness):
    assert post(client, "/api/approvals/inc-nope/approve", AUTH).status_code == 404
    assert post(client, "/api/approvals/Not_A_Label/approve", AUTH).status_code == 404
    assert post(client, "/api/approvals/%2e%2e/approve", AUTH).status_code == 404


def test_request_that_cannot_be_built_is_refused_and_stays_pending(client, harness):
    seed_incident(harness, decision="human_contain", pod="")
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 422
    seed_incident(harness, "inc-2", top_field="unknown")
    assert post(client, "/api/approvals/inc-2/approve", AUTH).status_code == 422
    assert harness.exec_requests == [] and harness.claims == {}
    assert client.get("/api/approvals").json()["count"] == 2


def test_concurrent_decision_in_progress_is_refused(client, harness):
    seed_incident(harness)
    harness.claim_denied = True
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 409
    assert post(client, f"/api/approvals/{INC}/reject", AUTH).status_code == 409
    assert harness.exec_requests == [] and "approved" not in harness.steps()


def test_queue_failure_releases_the_claim_so_a_retry_works(client, enforce):
    harness = enforce
    seed_incident(harness)
    harness.enqueue_error = RuntimeError("redis down")
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 502 and "approved" not in harness.steps()
    assert harness.claims == {}
    harness.enqueue_error = None
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200


def test_mutating_endpoints_return_503_without_a_configured_token(client, harness, monkeypatch):
    monkeypatch.delenv("KUBEHEAL_ADMIN_TOKEN")
    seed_incident(harness)
    for path in (f"/api/approvals/{INC}/approve", f"/api/approvals/{INC}/reject"):
        assert post(client, path).status_code == 503
        assert post(client, path, AUTH).status_code == 503       # a supplied token does not help
    monkeypatch.setenv("KUBEHEAL_ADMIN_TOKEN", "   ")
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 503
    assert harness.exec_requests == [] and harness.steps()[-1] == "approval_requested"


def test_missing_token_is_401_and_wrong_token_is_403(client, harness, caplog):
    seed_incident(harness)
    caplog.set_level(logging.DEBUG)
    for path in (f"/api/approvals/{INC}/approve", f"/api/approvals/{INC}/reject"):
        missing = post(client, path)
        assert missing.status_code == 401 and missing.headers["www-authenticate"] == "Bearer"
        wrong = post(client, path, {"Authorization": "Bearer not-the-token"})
        assert wrong.status_code == 403
        assert "not-the-token" not in wrong.text and TOKEN not in wrong.text
        assert post(client, path, {"Authorization": "Basic abc"}).status_code == 401
    assert harness.exec_requests == [] and harness.steps()[-1] == "approval_requested"
    assert "not-the-token" not in caplog.text and TOKEN not in caplog.text


def test_x_admin_token_header_is_accepted_and_token_is_never_echoed(client, enforce, caplog):
    harness = enforce
    seed_incident(harness)
    caplog.set_level(logging.DEBUG)
    r = post(client, f"/api/approvals/{INC}/approve", {"X-Admin-Token": TOKEN})
    assert r.status_code == 200
    assert TOKEN not in r.text and TOKEN not in caplog.text
    assert TOKEN not in str(harness.records()) and TOKEN not in str(harness.exec_requests)


def test_token_check_uses_constant_time_comparison():
    import hmac
    from dashboard import admin_auth
    src = open(admin_auth.__file__, encoding="utf-8").read()
    assert "hmac.compare_digest" in src and hmac is not None
    assert admin_auth.constant_time_equals("a", "a")
    assert not admin_auth.constant_time_equals("a", "ab")
    assert not admin_auth.constant_time_equals("", "x")


# ---- ledger failure after queueing: no stuck state, no duplicate request

def test_ledger_write_is_retried_a_bounded_number_of_times(client, enforce):
    from dashboard import admin_routes
    harness = enforce
    seed_incident(harness)
    flaky = FlakyLedger(harness.ledger, "approved", admin_routes.LEDGER_APPEND_ATTEMPTS - 1)
    use_ledger(flaky)
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert flaky.fail == 0 and harness.steps().count("approved") == 1 and len(harness.exec_requests) == 1


def test_failed_ledger_write_after_queueing_is_finished_by_a_repeat_approve(client, enforce):
    from dashboard import admin_routes
    harness = enforce
    seed_incident(harness)
    flaky = FlakyLedger(harness.ledger, "approved", admin_routes.LEDGER_APPEND_ATTEMPTS)
    use_ledger(flaky)
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 500 and "will not queue again" in r.text
    assert flaky.fail == 0                                       # every allowed attempt was used
    assert "approved" not in harness.steps() and len(harness.exec_requests) == 1
    claim = json.loads(harness.claims[INC])                      # the claim holds the stream id
    assert claim["stream_id"] == "1-0" and claim["approved_by"] == "admin:dashboard-admin"
    assert client.get("/api/approvals").json()["count"] == 1     # still listed as pending

    again = post(client, f"/api/approvals/{INC}/approve", AUTH)  # the ledger works again
    assert again.status_code == 200
    assert again.json() == {"status": "already_queued", "incident_id": INC, "queued": False, "recorded": True}
    assert len(harness.exec_requests) == 1                       # nothing was queued twice
    rec = harness.records()[-1]
    assert rec["step"] == "approved" and rec["payload"]["exec_stream_id"] == "1-0"
    assert rec["payload"]["approved_by"] == "admin:dashboard-admin" and rec["payload"]["dry_run"] is False
    assert client.get("/api/approvals").json()["count"] == 0
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).json()["status"] == "already_approved"
    assert len(harness.exec_requests) == 1


def test_repeat_approve_finishes_the_record_even_if_the_mode_is_now_test(client, enforce):
    from dashboard import admin_routes
    harness = enforce
    seed_incident(harness)
    use_ledger(FlakyLedger(harness.ledger, "approved", admin_routes.LEDGER_APPEND_ATTEMPTS))
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    harness.mode_store.mode = "test"
    again = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert again.json()["status"] == "already_queued" and len(harness.exec_requests) == 1
    assert harness.steps()[-1] == "approved" and "dry_run_approved" not in harness.steps()


def test_reject_is_refused_while_a_queued_approval_is_unrecorded(client, enforce):
    from dashboard import admin_routes
    harness = enforce
    seed_incident(harness)
    use_ledger(FlakyLedger(harness.ledger, "approved", admin_routes.LEDGER_APPEND_ATTEMPTS))
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert post(client, f"/api/approvals/{INC}/reject", AUTH).status_code == 409


def test_claim_without_a_stream_id_is_an_approval_in_progress_not_a_finished_one(client, enforce):
    harness = enforce
    seed_incident(harness)
    harness.claims[INC] = "claimed"
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 409
    assert harness.exec_requests == []


def test_claim_update_failure_still_records_approved(client, enforce):
    harness = enforce
    seed_incident(harness)
    harness.claim_set_error = RuntimeError("redis blip")
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200
    assert harness.steps()[-1] == "approved"


# ---- auth wins over body validation, every mutating route is guarded

def test_malformed_body_without_credentials_is_401_or_503_never_422(client, harness, monkeypatch):
    seed_incident(harness)
    bad_bodies = ["{not json", '{"note": 5}', '{"note": "' + "x" * 600 + '"}']
    paths = (f"/api/approvals/{INC}/approve", f"/api/approvals/{INC}/reject", "/api/kill-switch")
    hdr = {"Content-Type": "application/json"}
    for path in paths:
        for raw in bad_bodies:
            assert client.post(path, content=raw, headers=hdr).status_code == 401
            assert client.post(path, content=raw, headers={**hdr, "Authorization": "Bearer wrong"}).status_code == 403
    monkeypatch.delenv("KUBEHEAL_ADMIN_TOKEN")
    for path in paths:
        assert client.post(path, content="{not json", headers=hdr).status_code == 503


def test_malformed_body_with_credentials_is_422(client, harness):
    seed_incident(harness)
    hdr = {**AUTH, "Content-Type": "application/json"}
    assert client.post(f"/api/approvals/{INC}/approve", content="{not json", headers=hdr).status_code == 422
    assert client.post(f"/api/approvals/{INC}/approve", content='{"note": 5}', headers=hdr).status_code == 422
    assert client.post("/api/kill-switch", content="", headers=hdr).status_code == 422
    assert harness.exec_requests == [] and harness.mode_store.writes == []


def test_every_non_get_route_depends_on_require_admin():
    from fastapi.routing import APIRoute
    from dashboard.admin_auth import require_admin
    from dashboard.fastapi_app import app

    def depends_on(dependant):
        return any(d.call is require_admin or depends_on(d) for d in dependant.dependencies)

    mutating = [r for r in app.routes if isinstance(r, APIRoute) and (r.methods - {"GET", "HEAD", "OPTIONS"})]
    assert {r.path for r in mutating} >= {"/api/approvals/{incident_id}/approve",
                                          "/api/approvals/{incident_id}/reject", "/api/kill-switch"}
    unguarded = [f"{sorted(r.methods)} {r.path}" for r in mutating if not depends_on(r.dependant)]
    assert unguarded == []
