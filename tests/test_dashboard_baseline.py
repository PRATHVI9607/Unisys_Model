"""V5-I3: baseline promotion approvals through the dashboard (owner decision D3). The dashboard's Redis client
returns bytes (decode_responses=False): every test here goes through the bytes-returning fake."""
import asyncio
import json
import re

import pytest

from agents.health_agent import baseline as bl
from test_dashboard_seed import AUTH, TOKEN, client, harness  # noqa: F401

NS, DEP = "prod", "web"
BASE = f"/api/baseline-candidates/{NS}/{DEP}"


def run(coro):
    return asyncio.run(coro)


def spec(image):
    return {"replicas": 3, "template": {"spec": {"containers": [{"name": "app", "image": image}]}}}


def put_candidate(h, namespace=NS, deployment=DEP, *, new_image="img:2", tier="prod", fields=None,
                  assessment=None):
    """A golden baseline (img:1) and a pending candidate for img:2, written with the real baseline code."""
    async def go():
        r = h.redis_inner
        await bl.get_or_set_baseline(r, namespace, deployment, spec("img:1"))
        raw = r.store[bl.baseline_key(namespace, deployment)]
        res = await bl.store_candidate(
            r, h.ledger, namespace, deployment, new_spec=spec(new_image), spec_hash="hash-" + new_image,
            golden_raw=raw, tier=tier,
            changed_fields=fields if fields is not None else ["spec.template.spec.containers[0].image"],
            assessment=assessment if assessment is not None else
            {"label": "benign", "risk": 0.05, "prediction_set": ["benign"], "model_version": "health-fixture-1",
             "event_id": "hev-9"})
        assert res["status"] == "stored"
        return res["candidate_id"]
    return run(go())


def golden_image(h, namespace=NS, deployment=DEP):
    rec = json.loads(h.redis_inner.store[bl.baseline_key(namespace, deployment)])
    return rec["spec"]["template"]["spec"]["containers"][0]["image"]


def candidate_present(h, namespace=NS, deployment=DEP):
    return bl.candidate_key(namespace, deployment) in h.redis_inner.store


def baseline_steps(h, namespace=NS, deployment=DEP):
    prefix = f"incidents/{bl.ledger_incident_id(namespace, deployment)}/"
    return [k[len(prefix):].split("-", 1)[1][:-5] for k in sorted(h.ledger.store.keys(prefix))]


def baseline_records(h, step):
    prefix = f"incidents/{bl.ledger_incident_id(NS, DEP)}/"
    return [json.loads(h.ledger.store.objects[k])["payload"] for k in sorted(h.ledger.store.keys(prefix))
            if k.endswith(f"-{step}.json")]


def post(client, action, body, headers=AUTH, ns=NS, dep=DEP):
    return client.post(f"/api/baseline-candidates/{ns}/{dep}/{action}", headers=headers, json=body)


@pytest.fixture
def enforce(harness):
    harness.mode_store.mode = "enforce"
    return harness


# ------------------------------------------------------------------ list and detail

def test_list_is_open_and_lists_pending_candidates_without_the_spec(client, harness):
    cid = put_candidate(harness)
    put_candidate(harness, "staging", "api", tier="staging")
    r = client.get("/api/baseline-candidates")                      # no admin token, like GET /api/approvals
    assert r.status_code == 200 and r.json()["count"] == 2
    rows = r.json()["candidates"]
    assert [(c["namespace"], c["deployment"]) for c in rows] == [("prod", "web"), ("staging", "api")]
    c = rows[0]
    assert c["candidate_id"] == cid and c["tier"] == "prod" and c["status"] == "pending"
    assert c["changed_fields"] == ["spec.template.spec.containers[0].image"]
    assert c["assessment"]["prediction_set"]["certain"] is True and c["assessment"]["label"] == "benign"
    assert c["assessment"]["risk"] == 0.05 and c["assessment"]["model_version"] == "health-fixture-1"
    assert "spec" not in c and "template" not in c


def test_list_empty(client, harness):
    assert client.get("/api/baseline-candidates").json() == {"candidates": [], "count": 0}


def test_detail_has_fields_assessment_tier_mode_and_blocker(client, harness):
    cid = put_candidate(harness)
    r = client.get(BASE)
    assert r.status_code == 200
    d = r.json()
    assert d["candidate_id"] == cid and d["tier"] == "prod"
    assert d["changed_fields"] == ["spec.template.spec.containers[0].image"]
    assert d["assessment"]["prediction_set"]["labels"] == ["benign"]
    assert d["golden_baseline_unchanged"] is True and d["blocker"] is None
    assert d["spec_hash"] == "hash-img:2" and d["golden_sha256"]
    assert d["mode"] == {"mode": "test", "readable": True, "approval_is_dry_run": True}
    assert [h["step"] for h in d["history"]] == ["baseline_candidate_created"]


def test_detail_reports_a_blocker_and_a_moved_golden_baseline(client, harness):
    put_candidate(harness)
    harness.redis_inner.store[f"{bl.LOCK_PREFIX}:{NS}:{DEP}"] = "held"
    assert "incident lock" in client.get(BASE).json()["blocker"]
    harness.redis_inner.store[bl.baseline_key(NS, DEP)] = json.dumps({"spec": spec("img:9")})
    assert client.get(BASE).json()["golden_baseline_unchanged"] is False


def test_detail_unknown_or_invalid_workload_is_404(client, harness):
    assert client.get(BASE).status_code == 404
    assert client.get("/api/baseline-candidates/Prod/web").status_code == 404
    assert client.get("/api/baseline-candidates/prod/..%2Fx").status_code in (404,)


def test_read_endpoints_need_redis(client, harness):
    from dashboard.fastapi_app import app
    app.state.services.get_redis = lambda: None
    assert client.get("/api/baseline-candidates").status_code == 503
    assert client.get(BASE).status_code == 503
    app.state.services.get_redis = None
    assert client.get("/api/baseline-candidates").status_code == 503


# ------------------------------------------------------------------ approve

def test_approve_in_enforce_promotes_and_ledgers(client, enforce):
    h = enforce
    cid = put_candidate(h)
    r = post(client, "approve", {"candidate_id": cid, "reason": "checked the diff"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "promoted" and body["applied"] is True and body["mode"] == "enforce"
    assert body["actor"] == "admin:dashboard-admin" and body["ledger_key"] and "replaced" in body["message"]
    assert golden_image(h) == "img:2" and not candidate_present(h)
    (entry,) = baseline_records(h, "baseline_promoted")
    assert entry["approver"] == "admin:dashboard-admin" and entry["kind"] == "approved"
    assert entry["reason"] == "checked the diff" and entry["candidate_id"] == cid
    assert entry["previous"]["spec"]["template"]["spec"]["containers"][0]["image"] == "img:1"   # kept
    assert client.get("/api/baseline-candidates").json()["count"] == 0


def test_approve_in_test_mode_is_a_dry_run_and_the_candidate_stays(client, harness):
    cid = put_candidate(harness)
    r = post(client, "approve", {"candidate_id": cid})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "dry_run" and body["applied"] is False and body["candidate_unchanged"] is True
    assert "DRY RUN" in body["message"] and "nothing was changed" in body["message"]
    assert "test" in body["message"] and "pending" in body["message"]
    assert golden_image(harness) == "img:1" and candidate_present(harness)
    assert baseline_steps(harness)[-1] == "baseline_promotion_dry_run"
    (entry,) = baseline_records(harness, "baseline_promotion_dry_run")
    assert entry["mode"] == "test" and entry["approver"] == "admin:dashboard-admin" and entry["applied"] is False
    assert "baseline_promoted" not in baseline_steps(harness)
    # still pending, and approvable for real once the mode is enforce
    assert client.get("/api/baseline-candidates").json()["count"] == 1
    harness.mode_store.mode = "enforce"
    assert post(client, "approve", {"candidate_id": cid}).json()["status"] == "promoted"
    assert golden_image(harness) == "img:2"


def test_approve_with_an_unreadable_mode_is_a_dry_run(client, harness):
    cid = put_candidate(harness)
    harness.mode_store.mode = "enforce"
    harness.mode_store.fail_read = True
    body = post(client, "approve", {"candidate_id": cid}).json()
    assert body["status"] == "dry_run" and body["mode_readable"] is False
    assert "could not be read" in body["message"]
    assert golden_image(harness) == "img:1" and candidate_present(harness)


def test_approve_passes_the_candidate_id_actor_and_mode_string(client, enforce, monkeypatch):
    seen = {}

    async def fake_approve(redis, namespace, deployment, approver, ledger, candidate_id, reason="", *, mode=None):
        seen.update(redis=redis, namespace=namespace, deployment=deployment, approver=approver, ledger=ledger,
                    candidate_id=candidate_id, reason=reason, mode=mode)
        return {"status": "promoted", "ledger_key": "k"}
    monkeypatch.setattr(bl, "approve_promotion", fake_approve)
    r = post(client, "approve", {"candidate_id": "abc123", "reason": "  because  "})
    assert r.status_code == 200
    assert seen["candidate_id"] == "abc123" and seen["approver"] == "admin:dashboard-admin"
    assert seen["mode"] == "enforce" and seen["reason"] == "because"
    assert seen["redis"] is enforce.redis and seen["ledger"] is enforce.ledger        # the dashboard's own


def test_reject_in_any_mode_removes_the_candidate_and_remembers_the_spec(client, harness):
    cid = put_candidate(harness)                       # mode is test: reject still works
    r = post(client, "reject", {"candidate_id": cid, "reason": "not intended"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rejected" and r.json()["applied"] is False
    assert not candidate_present(harness) and golden_image(harness) == "img:1"
    assert harness.redis_inner.store[bl.rejected_key(NS, DEP)] == "hash-img:2"
    (entry,) = baseline_records(harness, "baseline_candidate_rejected")
    assert entry["approver"] == "admin:dashboard-admin" and entry["reason"] == "not intended"
    assert entry["candidate_id"] == cid


# ------------------------------------------------------------------ errors of the baseline functions

def test_id_mismatch_is_409_and_changes_nothing(client, enforce):
    cid = put_candidate(enforce)
    for action in ("approve", "reject"):
        r = post(client, action, {"candidate_id": "0" * 24})
        assert r.status_code == 409 and r.json()["status"] == "id_mismatch"
        assert r.json()["current_candidate_id"] == cid and "reload" in r.json()["message"]
    assert candidate_present(enforce) and golden_image(enforce) == "img:1"
    assert baseline_steps(enforce) == ["baseline_candidate_created"]


def test_missing_candidate_id_is_422(client, enforce):
    put_candidate(enforce)
    for action in ("approve", "reject"):
        assert post(client, action, {}).status_code == 422
        assert post(client, action, {"reason": "no id"}).status_code == 422
        assert post(client, action, {"candidate_id": ""}).status_code == 422
        assert post(client, action, {"candidate_id": 5}).status_code == 422
        assert client.post(f"{BASE}/{action}", headers=AUTH).status_code == 422          # empty body
    assert candidate_present(enforce) and golden_image(enforce) == "img:1"


def test_reason_too_long_is_422(client, enforce):
    cid = put_candidate(enforce)
    r = post(client, "approve", {"candidate_id": cid, "reason": "x" * 513})
    assert r.status_code == 422 and golden_image(enforce) == "img:1"


def test_no_candidate_is_404(client, enforce):
    for action in ("approve", "reject"):
        r = post(client, action, {"candidate_id": "abc"})
        assert r.status_code == 404 and r.json()["status"] == "not_found"


def test_invalid_workload_name_is_404(client, enforce):
    assert post(client, "approve", {"candidate_id": "abc"}, ns="Prod", dep="web").status_code == 404


@pytest.mark.parametrize("action", ["approve", "reject"])
def test_admin_token_rules_match_the_other_endpoints(client, harness, monkeypatch, action):
    cid = put_candidate(harness)
    body = {"candidate_id": cid}
    assert post(client, action, body, headers={}).status_code == 401
    assert post(client, action, body, headers={"Authorization": "Bearer wrong"}).status_code == 403
    assert post(client, action, body, headers={"X-Admin-Token": "wrong"}).status_code == 403
    # a malformed body without credentials is 401, never 422
    assert client.post(f"{BASE}/{action}", content="{not json").status_code == 401
    assert candidate_present(harness) and baseline_steps(harness) == ["baseline_candidate_created"]
    monkeypatch.delenv("KUBEHEAL_ADMIN_TOKEN")
    assert post(client, action, body).status_code == 503
    assert candidate_present(harness)


def test_x_admin_token_header_works(client, enforce):
    cid = put_candidate(enforce)
    assert post(client, "reject", {"candidate_id": cid}, headers={"X-Admin-Token": TOKEN}).status_code == 200


def test_stale_golden_baseline_supersedes_the_candidate(client, enforce):
    cid = put_candidate(enforce)
    enforce.redis_inner.store[bl.baseline_key(NS, DEP)] = json.dumps({"spec": spec("img:9")})   # someone moved it
    r = post(client, "approve", {"candidate_id": cid})
    assert r.status_code == 409 and r.json()["status"] == "stale" and "superseded" in r.json()["message"]
    assert golden_image(enforce) == "img:9" and not candidate_present(enforce)
    assert "baseline_candidate_superseded" in baseline_steps(enforce)


def test_blocked_by_another_actor_keeps_the_candidate(client, enforce):
    cid = put_candidate(enforce)
    enforce.redis_inner.store[f"{bl.LOCK_PREFIX}:{NS}:{DEP}"] = "held"
    r = post(client, "approve", {"candidate_id": cid})
    assert r.status_code == 409 and r.json()["status"] == "blocked"
    assert "lock" in r.json()["reason"] and "try again" in r.json()["message"]
    assert candidate_present(enforce) and golden_image(enforce) == "img:1"


def test_blocked_by_a_pending_rollback_and_an_open_fusion_incident(client, enforce):
    cid = put_candidate(enforce)
    enforce.redis_inner.store[f"{bl.ROLLBACK_PREFIX}:{NS}:{DEP}"] = json.dumps({"state": "pending"})
    assert post(client, "approve", {"candidate_id": cid}).json()["status"] == "blocked"
    del enforce.redis_inner.store[f"{bl.ROLLBACK_PREFIX}:{NS}:{DEP}"]
    enforce.redis_inner.hashes[f"{bl.FUSION_INCIDENT_PREFIX}:inc-1"] = {
        "namespace": NS, "deployment": DEP, "action_state": "human_pending"}
    assert post(client, "approve", {"candidate_id": cid}).json()["status"] == "blocked"
    assert golden_image(enforce) == "img:1"


def test_no_ledger_is_503_and_nothing_changes(client, enforce):
    from dashboard.fastapi_app import app
    cid = put_candidate(enforce)
    app.state.services.ledger = None
    for action in ("approve", "reject"):
        r = post(client, action, {"candidate_id": cid})
        assert r.status_code == 503 and r.json()["status"] == "no_ledger"
    assert candidate_present(enforce) and golden_image(enforce) == "img:1"


def test_no_baseline_is_409(client, enforce):
    cid = put_candidate(enforce)
    del enforce.redis_inner.store[bl.baseline_key(NS, DEP)]
    r = post(client, "approve", {"candidate_id": cid})
    assert r.status_code == 409 and r.json()["status"] == "no_baseline" and candidate_present(enforce)


class FailingLedger:
    def __init__(self, ledger, step):
        self.ledger, self.step = ledger, step
        self.store = ledger.store

    def append(self, incident_id, step, payload):
        if step == self.step:
            raise OSError("minio down")
        return self.ledger.append(incident_id, step, payload)


def test_approve_ledger_failure_is_500_and_fails_closed(client, enforce):
    from dashboard.fastapi_app import app
    cid = put_candidate(enforce)
    app.state.services.ledger = FailingLedger(enforce.ledger, "baseline_promoted")
    r = post(client, "approve", {"candidate_id": cid})
    assert r.status_code == 500 and r.json()["status"] == "ledger_failed" and "minio" not in r.text
    assert golden_image(enforce) == "img:1" and candidate_present(enforce)


def test_reject_ledger_failure_is_500_and_the_candidate_stays(client, enforce):
    from dashboard.fastapi_app import app
    cid = put_candidate(enforce)
    app.state.services.ledger = FailingLedger(enforce.ledger, "baseline_candidate_rejected")
    r = post(client, "reject", {"candidate_id": cid})
    assert r.status_code == 500 and r.json()["status"] == "ledger_failed" and candidate_present(enforce)


def test_lost_compare_and_set_is_a_409_conflict(client, enforce):
    cid = put_candidate(enforce)

    async def lost(*a, **k):
        return 0
    enforce.redis_inner.eval = lost
    r = post(client, "approve", {"candidate_id": cid})
    assert r.status_code == 409 and r.json()["status"] == "conflict" and r.json()["applied"] is False
    assert golden_image(enforce) == "img:1" and candidate_present(enforce)


@pytest.mark.parametrize("status, code", [
    ("promoted", 200), ("dry_run", 200), ("not_found", 404), ("id_mismatch", 409), ("no_ledger", 503),
    ("no_baseline", 409), ("blocked", 409), ("stale", 409), ("ledger_failed", 500), ("aborted", 409),
    ("conflict", 409), ("something_new", 500)])
def test_every_approve_status_has_a_code_and_a_message(client, enforce, monkeypatch, status, code):
    async def fake(*a, **k):
        return {"status": status, "reason": "why", "ledger_key": "k", "candidate_id": "cur", "error": "secret"}
    monkeypatch.setattr(bl, "approve_promotion", fake)
    r = post(client, "approve", {"candidate_id": "abc"})
    assert r.status_code == code and r.json()["status"] == status
    assert r.json()["message"] and r.json()["detail"] == r.json()["message"]
    assert "secret" not in r.text
    assert (r.json()["applied"] is True) == (status == "promoted")


@pytest.mark.parametrize("status, code", [("rejected", 200), ("not_found", 404), ("id_mismatch", 409),
                                           ("no_ledger", 503), ("ledger_failed", 500)])
def test_every_reject_status_has_a_code_and_a_message(client, enforce, monkeypatch, status, code):
    async def fake(*a, **k):
        return {"status": status}
    monkeypatch.setattr(bl, "reject_promotion", fake)
    r = post(client, "reject", {"candidate_id": "abc"})
    assert r.status_code == code and r.json()["status"] == status and r.json()["message"]


def test_value_error_and_redis_error_are_reported_not_raised(client, enforce, monkeypatch):
    async def bad(*a, **k):
        raise ValueError("approver must be a non-empty string")
    monkeypatch.setattr(bl, "approve_promotion", bad)
    r = post(client, "approve", {"candidate_id": "abc"})
    assert r.status_code == 422 and "approver" in r.json()["detail"]

    async def down(*a, **k):
        raise ConnectionError("redis down")
    monkeypatch.setattr(bl, "approve_promotion", down)
    r = post(client, "approve", {"candidate_id": "abc"})
    assert r.status_code == 502 and "redis down" not in r.text


def test_a_corrupt_candidate_does_not_crash_the_list(client, harness):
    put_candidate(harness)
    harness.redis_inner.store[bl.candidate_key("prod", "broken")] = "{not json"
    r = client.get("/api/baseline-candidates")
    assert r.status_code == 502 and "Traceback" not in r.text


def test_baseline_module_missing_in_the_image_is_503(client, harness, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "agents.health_agent.baseline", None)
    import agents.health_agent as pkg
    monkeypatch.delattr(pkg, "baseline", raising=False)
    assert client.get("/api/baseline-candidates").status_code == 503
    assert post(client, "approve", {"candidate_id": "x"}).status_code == 503


# ------------------------------------------------------------------ the bytes client

def test_every_call_path_works_with_a_bytes_returning_client(client, enforce):
    """list, detail, approve and reject all read through BytesRedis (the harness client)."""
    from test_dashboard_seed import BytesRedis
    assert isinstance(enforce.redis, BytesRedis)
    cid = put_candidate(enforce)
    put_candidate(enforce, "prod", "other", tier="prod")
    assert client.get("/api/baseline-candidates").json()["count"] == 2
    assert client.get(BASE).json()["candidate_id"] == cid
    assert post(client, "approve", {"candidate_id": cid}).json()["status"] == "promoted"
    other = client.get("/api/baseline-candidates/prod/other").json()["candidate_id"]
    assert post(client, "reject", {"candidate_id": other}, dep="other").json()["status"] == "rejected"
    assert client.get("/api/baseline-candidates").json()["count"] == 0


def test_bytes_client_still_blocks(client, enforce):
    cid = put_candidate(enforce)
    enforce.redis_inner.store[bl.cooloff_key(NS, DEP)] = "1"
    assert post(client, "approve", {"candidate_id": cid}).json()["status"] == "blocked"
    del enforce.redis_inner.store[bl.cooloff_key(NS, DEP)]
    enforce.redis_inner.store[bl.veto_key(NS, DEP)] = json.dumps(["hash-img:2"])
    assert post(client, "approve", {"candidate_id": cid}).json()["status"] == "blocked"


# ------------------------------------------------------------------ page

def test_page_lists_candidates_with_decision_controls_and_no_secret(client, harness):
    cid = put_candidate(harness)
    r = client.get("/baseline-candidates")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    page = r.text
    assert 'data-action="baseline-approve"' in page and 'data-action="baseline-reject"' in page
    assert f'data-candidate="{cid}"' in page and 'data-namespace="prod"' in page and 'data-deployment="web"' in page
    assert "spec.template.spec.containers[0].image" in page and "certain: {benign}" in page
    assert 'id="admin-token"' in page and 'type="password"' in page and 'id="baseline-reason"' in page
    assert TOKEN not in page
    assert re.findall(r"<script\b[^>]*>", page) == ['<script src="/static/admin.js">']
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert 'href="/baseline-candidates"' in page            # nav link
    assert "kill switch mode is test" in page and "NOT replaced" in page


def test_page_in_enforce_mode_says_the_approval_replaces_the_baseline(client, enforce):
    put_candidate(enforce)
    page = client.get("/baseline-candidates").text
    assert "mode is enforce" in page and "NOT replaced" not in page


def test_page_empty_and_escaped(client, harness):
    assert "no pending baseline candidates" in client.get("/baseline-candidates").text
    nasty = "<script>alert(1)</script>"
    put_candidate(harness, fields=[nasty], assessment={"label": nasty, "prediction_set": [nasty, "b"],
                                                      "model_version": nasty})
    page = client.get("/baseline-candidates").text
    assert nasty not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_static_js_posts_candidate_id_and_keeps_dry_run_message():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "dashboard" / "static" / "admin.js").read_text(encoding="utf-8")
    assert "baseline-approve" in js and "data-candidate" in js and "candidate_id" in js
    assert 'status !== "dry_run"' in js                       # a dry run is not followed by a reload
