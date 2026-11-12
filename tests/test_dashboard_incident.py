import re

from test_dashboard_seed import AUTH, INC, client, harness, seed_incident  # noqa: F401

XSS_TAG = "<script>alert(1)</script>"


def test_incident_json_has_scores_attribution_chain_and_timeline(client, harness):
    seed_incident(harness, decision="human_contain", pod="web-abc-1")
    body = client.get(f"/api/incidents/{INC}").json()
    assert body["incident_id"] == INC and body["status"] == "pending"
    assert body["target"] == {"namespace": "staging", "deployment": "web", "pod": "web-abc-1"}
    h, s = body["scores"]["health"], body["scores"]["security"]
    # A legacy incident (it carries CI widths and top_field): they are shown as legacy, never required.
    assert (h["risk"], h["label"], h["legacy"]) == (0.7, "high", {"ci_width": 0.2, "top": "resources.limits.cpu"})
    assert (s["risk"], s["legacy"]) == (0.6, {"ci_width": 0.1, "top": "rename"})
    assert h["prediction_set"]["published"] is False and h["prediction_set"]["certain"] is False
    assert body["scores"]["correlation_score"] == 0.5
    assert body["decision"]["decision"] == "human_contain" and body["decision"]["adjusted_score"] == 0.66
    fields = body["attribution"]["health"]["fields"]
    assert [f["name"] for f in fields] == ["resources.limits.cpu", "replicas"]       # ranked by weight
    assert [f["name"] for f in body["attribution"]["security"]["syscalls"]] == ["rename", "write"]
    assert body["attribution"]["security"]["early_signals"] == {"rename_burst": True}
    assert body["causal_chain"]["steps"] == ["T+0.0s: Config field changed", "DCM: compound"]
    assert [t["step"] for t in body["timeline"]] == ["detection", "scores", "decision", "approval_requested"]
    assert [t["sequence"] for t in body["timeline"]] == [1, 2, 3, 4]


def test_t0_is_never_invented(client, harness):
    seed_incident(harness)
    t0 = client.get(f"/api/incidents/{INC}").json()["causal_chain"]["t0"]
    assert t0 == {"available": False, "t0_ms": None, "source": None}
    html = client.get(f"/incidents/{INC}").text
    assert "Attack onset T0: <span class=\"na\">not available</span>" in html


def test_t0_is_shown_when_a_record_carries_it(client, harness):
    seed_incident(harness, t0_ms=1767225600000)
    t0 = client.get(f"/api/incidents/{INC}").json()["causal_chain"]["t0"]
    assert t0["available"] is True and t0["t0_ms"] == 1767225600000 and t0["source"] == "ledger decision"
    html = client.get(f"/incidents/{INC}").text
    assert "1767225600000 ms since the epoch" in html and "2026-01-01T00:00:00+00:00" in html


def test_t0_from_a_security_event_hash(client, harness):
    seed_incident(harness)
    harness.events[("security", "sev-1")]["t0_ms"] = "1767225600000"
    t0 = client.get(f"/api/incidents/{INC}").json()["causal_chain"]["t0"]
    assert t0["available"] and t0["source"] == "security event"


def test_a_bad_t0_value_is_ignored(client, harness):
    seed_incident(harness, t0_ms="soon")
    assert client.get(f"/api/incidents/{INC}").json()["causal_chain"]["t0"]["available"] is False


def test_page_renders_a_seeded_incident(client, harness):
    seed_incident(harness)
    r = client.get(f"/incidents/{INC}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    page = r.text
    for expected in (INC, "Health model", "Security model", "CI width", "0.7000", "0.2000", "0.1000",
                     "resources.limits.cpu", "replicas", "rename", "cpu_throttling",
                     "T+0.0s: Config field changed", "Ledger timeline", "approval_requested",
                     'data-action="approve"', 'data-action="reject"'):
        assert expected in page, expected
    assert re.findall(r"<script\b[^>]*>", page) == ['<script src="/static/admin.js">']      # no inline script
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "unit-test-admin-token" not in page


def test_page_shows_status_instead_of_buttons_once_decided(client, harness):
    seed_incident(harness)
    client.post(f"/api/approvals/{INC}/reject", headers=AUTH)
    page = client.get(f"/incidents/{INC}").text
    assert "<strong>rejected</strong>" in page and 'data-action="approve"' not in page


def test_missing_events_are_reported_as_not_available(client, harness):
    seed_incident(harness, with_events=False)
    body = client.get(f"/api/incidents/{INC}").json()
    assert body["attribution"]["health"]["available"] is False
    assert body["attribution"]["security"]["available"] is False
    page = client.get(f"/incidents/{INC}").text
    assert page.count('class="na">not available') >= 2
    assert body["scores"]["health"]["risk"] == 0.7        # the ledger scores still show


def test_event_text_is_escaped_everywhere(client, harness):
    nasty = '"><img src=x onerror=alert(2)>'
    seed_incident(harness, INC, rationale=XSS_TAG, chain=[XSS_TAG, nasty], namespace="staging",
                  deployment="web", top_field=nasty,
                  field_weights={nasty: 0.9}, syscall_weights={XSS_TAG: 0.4})
    harness.events[("security", "sev-1")]["early_signals_json"] = '{"%s": true}' % "<b>x</b>"
    pages = [client.get(f"/incidents/{INC}").text, client.get("/approvals").text]
    for page in pages:
        assert XSS_TAG not in page and "<img src=x" not in page and "<b>x</b>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in pages[0]
    assert "&quot;&gt;&lt;img src=x onerror=alert(2)&gt;" in pages[0]
    assert "&lt;b&gt;x&lt;/b&gt;" in pages[0]


def test_incident_id_in_the_path_is_validated_not_rendered(client, harness):
    r = client.get("/incidents/%3Cscript%3E")
    assert r.status_code == 404 and "<script>" not in r.text
    assert client.get("/incidents/inc-unknown").status_code == 404
    assert client.get("/api/incidents/inc-unknown").status_code == 404


def test_approvals_page_lists_pending_incidents_and_kill_switch(client, harness):
    seed_incident(harness)
    seed_incident(harness, "inc-auto", decision="auto_patch", approval=False)
    harness.ledger.append("mode-1", "mode_change", {"from": "test", "to": "enforce", "source": "dashboard",
                                                    "actor": "admin:dashboard-admin"})
    r = client.get("/approvals")
    assert r.status_code == 200
    page = r.text
    assert f'href="/incidents/{INC}"' in page and "no pending approvals" not in page
    assert "Kill switch" in page and "admin:dashboard-admin" in page and 'data-mode="enforce"' in page
    assert 'href="/incidents/inc-auto"' in page                     # incidents list includes decided and non-human ones
    assert 'href="/incidents/mode-1"' not in page                   # mode-change ledger entries are not incidents


def test_incident_list_api_skips_mode_entries(client, harness):
    seed_incident(harness)
    harness.ledger.append("mode-1", "mode_change", {"to": "test"})
    body = client.get("/api/incidents").json()
    assert [i["incident_id"] for i in body["incidents"]] == [INC] and body["incidents"][0]["status"] == "pending"


def test_read_endpoints_are_open_but_services_must_exist(client, harness):
    from dashboard.fastapi_app import app
    app.state.services = None
    assert client.get("/api/approvals").status_code == 503
    assert client.get("/approvals").status_code == 503


def test_existing_dashboard_pages_still_work(client):
    assert client.get("/health").json()["status"] == "healthy"
    root = client.get("/")
    assert root.status_code == 200 and 'href="/approvals"' in root.text
    assert client.get("/static/admin.js").status_code == 200
