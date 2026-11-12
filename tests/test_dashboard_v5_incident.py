"""V5-I3: the incident view shows prediction sets, TreeSHAP top factors, containment and rule path fields, and
tolerates incidents with and without the fields V5 removed. The numbers are arbitrary fixtures."""
import json
import re

import pytest

from test_dashboard_seed import INC, SECURITY_EVENT, HEALTH_EVENT, client, harness, seed_incident, seed_v5_incident  # noqa: F401
from dashboard import incident_view as iv


# ------------------------------------------------------------------ prediction set (unit)

@pytest.mark.parametrize("raw, flag, certain", [
    ('["benign"]', "false", True),
    (["benign"], None, True),
    ('["benign"]', "true", False),                     # a producer flag beats a one-label set
    ('["benign", "degradation"]', "false", False),
    ("[]", "true", False),
    ("[]", None, False),
    (None, None, False),
    ("", "false", False),
    ("malformed", None, False),                        # what Fusion's own parser calls an unusable set
    ('{"a": 1}', None, False),
    ("not json", None, False),
])
def test_prediction_set_certain_only_for_exactly_one_label(raw, flag, certain):
    view = iv.prediction_set_view(raw, flag)
    assert view["certain"] is certain
    assert view["summary"].startswith("certain: " if certain else "not certain: ")


def test_prediction_set_view_reports_published_and_labels():
    view = iv.prediction_set_view('["a", "b"]', "false")
    assert view == {"published": True, "labels": ["a", "b"], "size": 2, "certain": False,
                    "marked_uncertain": False, "summary": "not certain: {a, b} holds 2 labels"}
    assert iv.prediction_set_view(None)["published"] is False
    assert iv.prediction_set_view("[]")["published"] is True and iv.prediction_set_view("[]")["labels"] == []


def test_prediction_set_labels_are_bounded():
    view = iv.prediction_set_view(json.dumps([f"l{i}" for i in range(100)]))
    assert len(view["labels"]) == iv.MAX_LIST_ITEMS and view["size"] == 100 and view["certain"] is False


# ------------------------------------------------------------------ top factors (unit)

def test_top_factors_sorted_signed_bounded_and_garbage_dropped():
    raw = json.dumps([{"feature": "a", "value": 1, "contribution": -0.5},
                      {"feature": "b", "value": None, "contribution": 0.9},
                      {"feature": "nan", "contribution": "x"},
                      {"feature": "inf", "contribution": float("inf")},
                      {"contribution": 1.0},
                      "junk", 5, None] + [{"feature": f"f{i}", "contribution": 0.01 * i} for i in range(20)])
    view = iv.top_factors_view(raw)
    assert [f["feature"] for f in view["factors"][:2]] == ["b", "a"]
    assert view["factors"][1]["contribution"] == -0.5                      # the sign is kept
    assert view["factors"][0]["value"] is None
    assert len(view["factors"]) == iv.MAX_TOP_FACTORS and view["total"] == 22
    assert all(abs(view["factors"][i]["contribution"]) >= abs(view["factors"][i + 1]["contribution"])
               for i in range(len(view["factors"]) - 1))


@pytest.mark.parametrize("raw", [None, "", "[]", "{}", "nope", 5, '"x"', '{"feature": "a"}'])
def test_top_factors_tolerates_anything(raw):
    assert iv.top_factors_view(raw) == {"available": False, "factors": [], "total": 0}


def test_top_factors_accepts_a_list_object_and_json_text():
    factors = [{"feature": "a", "value": 1.0, "contribution": 0.3}]
    assert iv.top_factors_view(factors) == iv.top_factors_view(json.dumps(factors))


# ------------------------------------------------------------------ incident JSON

def test_v5_incident_json_has_sets_factors_and_containment(client, harness):
    seed_v5_incident(harness)
    body = client.get(f"/api/incidents/{INC}").json()
    h, s = body["scores"]["health"], body["scores"]["security"]
    assert h["prediction_set"]["labels"] == ["degradation"] and h["prediction_set"]["certain"] is True
    assert s["prediction_set"]["certain"] is True and s["prediction_set"]["labels"] == ["ransomware"]
    assert h["model_version"] == "health-fixture-1" and h["model_scored"] is True
    assert len(h["top_factors"]) == iv.MAX_TOP_FACTORS and h["top_factors_total"] == 10     # bounded
    assert {"feature", "value", "contribution"} <= set(h["top_factors"][0])
    assert any(f["contribution"] < 0 for f in h["top_factors"])                              # signed
    assert h["legacy"] == {} and s["legacy"] == {}
    assert "ci_width" not in h and "ci_width" not in s
    d = body["decision"]
    assert d["containment"] == {"label": "ransomware", "restore_after": True, "human_followup": False}
    assert d["rule_path"] is False and d["rule_reasons"] == [] and d["patch_fields"] == []
    assert d["security_fresh"] is True and d["models_ok"] is True


def test_not_certain_marker_for_several_labels_empty_set_and_uncertain_flag(client, harness):
    seed_v5_incident(harness, health_set='["benign", "degradation"]', sec_set="[]", sec_uncertain="true")
    sc = client.get(f"/api/incidents/{INC}").json()["scores"]
    assert sc["health"]["prediction_set"]["certain"] is False
    assert sc["security"]["prediction_set"]["certain"] is False and sc["security"]["prediction_set"]["labels"] == []
    page = client.get(f"/incidents/{INC}").text
    assert page.count("pset-uncertain") == 2 and "pset-certain" not in page
    assert "not certain: {benign, degradation} holds 2 labels" in page
    assert "not certain: the prediction set is empty" in page


def test_one_label_set_marked_uncertain_by_the_producer_is_not_certain(client, harness):
    seed_v5_incident(harness, health_set='["benign"]', health_uncertain="true")
    h = client.get(f"/api/incidents/{INC}").json()["scores"]["health"]
    assert h["prediction_set"]["certain"] is False and h["prediction_set"]["marked_uncertain"] is True


def test_rule_path_decision_shows_reasons_and_changed_fields(client, harness):
    seed_v5_incident(harness, decision="human_patch", containment=None, rule_path=True,
                     rule_reasons=["posture violation", "rollout failed"],
                     patch_fields=["spec.template.spec.containers[0].resources.limits.cpu"])
    d = client.get(f"/api/incidents/{INC}").json()["decision"]
    assert d["rule_path"] is True and d["rule_reasons"] == ["posture violation", "rollout failed"]
    assert d["patch_fields"] == ["spec.template.spec.containers[0].resources.limits.cpu"]
    assert d["containment"] is None
    page = client.get(f"/incidents/{INC}").text
    assert "Rule reasons" in page and "posture violation" in page and "rollout failed" in page
    assert "resources.limits.cpu" in page and "Decided by the rule path: yes" in page
    assert "Containment label" not in page


# ------------------------------------------------------------------ page

def test_v5_page_shows_set_marker_factors_and_containment_without_ci_boxes(client, harness):
    seed_v5_incident(harness)
    page = client.get(f"/incidents/{INC}").text
    assert "certain: {degradation}" in page and "pset-certain" in page
    assert "Top factors (TreeSHAP)" in page and "h_f9" in page and "-0.1000" in page and "+0.0900" in page and "+0.1000" not in page
    assert "Showing 8 of 10 factors" in page
    assert "Containment label: <strong>ransomware</strong>" in page and "restore after: yes" in page
    assert "human follow-up: no" in page
    assert "CI width" not in page and "ci_width" not in page and "Legacy" not in page
    assert "Legacy config field attribution" not in page and "Legacy syscall attribution" not in page
    assert "rule M2" in page and "model version health-fixture-1" in page
    assert re.findall(r"<script\b[^>]*>", page) == ['<script src="/static/admin.js">']


def test_page_marks_contain_decision_with_follow_up_and_no_restore(client, harness):
    seed_v5_incident(harness, sec_set='["exfiltration"]',
                     containment={"containment_label": "exfiltration", "restore_after": False,
                                  "human_followup": True})
    page = client.get(f"/incidents/{INC}").text
    assert "<strong>exfiltration</strong>; restore after: no; human follow-up: yes" in page


def test_v5_incident_text_is_escaped(client, harness):
    nasty = "<img src=x onerror=alert(1)>"
    seed_v5_incident(harness, rule_path=True, rule_reasons=[nasty], patch_fields=[nasty],
                     containment={"containment_label": nasty, "restore_after": True, "human_followup": True})
    harness.events[("health", HEALTH_EVENT)]["top_factors_json"] = json.dumps(
        [{"feature": nasty, "value": 1, "contribution": 0.5}])
    page = client.get(f"/incidents/{INC}").text
    assert "<img src=x" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


# ------------------------------------------------------------------ legacy tolerance

def test_legacy_incident_still_renders_and_marks_fields_as_legacy(client, harness):
    seed_incident(harness)
    page = client.get(f"/incidents/{INC}").text
    assert "CI width 0.2000" in page and "CI width 0.1000" in page
    assert "Legacy or compatibility fields" in page
    assert "Legacy config field attribution" in page and "resources.limits.cpu" in page
    assert "not certain: no prediction set was published" in page
    body = client.get(f"/api/incidents/{INC}").json()
    assert body["scores"]["health"]["legacy"]["ci_width"] == 0.2
    assert body["scores"]["health"]["top_factors"] == []


def test_v5_incident_with_stray_legacy_event_fields_still_renders(client, harness):
    seed_v5_incident(harness, events_have_legacy=True)
    r = client.get(f"/incidents/{INC}")
    assert r.status_code == 200 and "Legacy config field attribution" in r.text


@pytest.mark.parametrize("junk", [None, "", "not json", "[1, 2]", '"text"', "123", "{}", '{"a": "x"}',
                                  '{"a": NaN}', '{"a": Infinity}'])
def test_junk_in_every_removed_field_never_crashes(client, harness, junk):
    seed_incident(harness)
    for key in ("field_attribution_json", "health_ci_width", "top_field", "top_metric",
                "health_embedding_b64"):
        harness.events[("health", HEALTH_EVENT)][key] = junk
    for key in ("syscall_attribution_json", "sec_ci_width", "top_syscall", "security_embedding_b64"):
        harness.events[("security", SECURITY_EVENT)][key] = junk
    assert client.get(f"/api/incidents/{INC}").status_code == 200
    assert client.get(f"/incidents/{INC}").status_code == 200


def test_incident_with_no_score_fields_at_all_renders(client, harness):
    harness.ledger.append(INC, "detection", {"namespace": "staging", "deployment": "web"})
    harness.ledger.append(INC, "scores", {"health": {"health_risk": "0.5"}, "security": {}})
    harness.ledger.append(INC, "decision", {"decision": "observe"})
    body = client.get(f"/api/incidents/{INC}").json()
    assert body["scores"]["health"]["prediction_set"]["certain"] is False
    assert body["scores"]["security"] is None
    assert body["decision"]["containment"] is None and body["decision"]["rule_reasons"] == []
    assert client.get(f"/incidents/{INC}").status_code == 200


def test_scores_record_with_malformed_types_does_not_crash(client, harness):
    harness.ledger.append(INC, "detection", {"namespace": "staging", "deployment": "web"})
    harness.ledger.append(INC, "scores", {"health": {"health_prediction_set": 7, "top_factors_json": {"x": 1},
                                                     "model_scored": ["x"], "health_risk": "NaN"},
                                          "security": {"sec_prediction_set": {"a": 1}, "top_factors_json": 3}})
    harness.ledger.append(INC, "decision", {"decision": "observe", "rule_reasons": "oops", "patch_fields": 4,
                                            "containment_label": "ransomware", "restore_after": "maybe",
                                            "top_factors_json": "bad"})
    assert client.get(f"/api/incidents/{INC}").status_code == 200
    assert client.get(f"/incidents/{INC}").status_code == 200


def test_decision_record_is_the_fallback_for_sets_and_factors(client, harness):
    seed_v5_incident(harness, with_events=False)
    # drop the set and the factors from the scores record: the decision record still carries them
    for rec in harness.ledger.store.keys(f"incidents/{INC}/"):
        if rec.endswith("-scores.json"):
            data = json.loads(harness.ledger.store.objects[rec])
            for side in ("health", "security"):
                for k in list(data["payload"][side]):
                    if k.endswith("prediction_set") or k.endswith("uncertain") or k == "top_factors_json":
                        del data["payload"][side][k]
            harness.ledger.store.objects[rec] = json.dumps(data).encode()
    h = client.get(f"/api/incidents/{INC}").json()["scores"]["health"]
    assert h["prediction_set"]["labels"] == ["degradation"] and len(h["top_factors"]) == iv.MAX_TOP_FACTORS
