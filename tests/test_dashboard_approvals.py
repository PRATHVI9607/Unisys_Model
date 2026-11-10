import logging

from test_dashboard_seed import AUTH, INC, TOKEN, client, harness, seed_incident  # noqa: F401


def post(client, path, headers=None, json_body=None):
    return client.post(path, headers=headers or {}, json=json_body)


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


def test_approve_queues_executor_request_and_writes_ledger(client, harness):
    seed_incident(harness)
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved" and r.json()["queued"] is True
    (req,) = harness.exec_requests
    assert req["action"] == "patch"
    assert req["incident_id"] == INC
    assert req["namespace"] == "staging" and req["deployment"] == "web"
    assert req["patch_field"] == "resources.limits.cpu"
    assert req["approved_by"] == "admin:dashboard-admin"
    assert req["dry_run"] == "true"            # kill switch is in test mode
    assert harness.steps()[-1] == "approved"
    approved = harness.records()[-1]["payload"]
    assert approved["approved_by"] == "admin:dashboard-admin" and approved["mode"] == "test"
    assert client.get("/api/approvals").json()["count"] == 0


def test_approve_uses_enforce_mode_for_dry_run_flag(client, harness):
    harness.mode_store.mode = "enforce"
    seed_incident(harness)
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200
    assert harness.exec_requests[0]["dry_run"] == "false"


def test_approve_with_unreadable_mode_is_dry_run(client, harness):
    harness.mode_store.fail_read = True
    seed_incident(harness)
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200
    assert harness.exec_requests[0]["dry_run"] == "true"
    assert harness.records()[-1]["payload"]["mode_readable"] is False


def test_approve_identity_comes_from_configuration(client, harness, monkeypatch):
    monkeypatch.setenv("KUBEHEAL_ADMIN_IDENTITY", "oncall.priya")
    seed_incident(harness)
    post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert harness.exec_requests[0]["approved_by"] == "admin:oncall.priya"
    monkeypatch.setenv("KUBEHEAL_ADMIN_IDENTITY", "bad identity\nwith newline")
    seed_incident(harness, "inc-2")
    post(client, "/api/approvals/inc-2/approve", AUTH)
    assert harness.exec_requests[1]["approved_by"] == "admin:dashboard-admin"


def test_contain_request_carries_the_pod(client, harness):
    seed_incident(harness, decision="human_contain", pod="web-abc-123")
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 200
    req = harness.exec_requests[0]
    assert req["action"] == "contain" and req["pod"] == "web-abc-123" and req["patch_field"] == ""


def test_second_approve_does_nothing(client, harness):
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


def test_conflicting_decisions_are_refused(client, harness):
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
    assert harness.exec_requests == [] and harness.claims == set()
    assert client.get("/api/approvals").json()["count"] == 2


def test_concurrent_decision_in_progress_is_refused(client, harness):
    seed_incident(harness)
    harness.claim_denied = True
    assert post(client, f"/api/approvals/{INC}/approve", AUTH).status_code == 409
    assert post(client, f"/api/approvals/{INC}/reject", AUTH).status_code == 409
    assert harness.exec_requests == [] and "approved" not in harness.steps()


def test_queue_failure_releases_the_claim_so_a_retry_works(client, harness):
    seed_incident(harness)
    harness.enqueue_error = RuntimeError("redis down")
    r = post(client, f"/api/approvals/{INC}/approve", AUTH)
    assert r.status_code == 502 and "approved" not in harness.steps()
    assert harness.claims == set()
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


def test_x_admin_token_header_is_accepted_and_token_is_never_echoed(client, harness, caplog):
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
