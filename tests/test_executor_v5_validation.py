"""V5-D6 and V5-D9: candidate fields from the spec diff, pre-patch validation (selector, posture) and the new
request fields (Fusion sends them, the Executor accepts and ledgers them)."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import remediation_fakes as fk
from agents.executor import drift
from agents.executor.config import ExecConfig
from agents.executor.main import ExecutorService
from agents.executor.validation import parse_request
from test_remediation_drift import CPU, ENV, Scenario, run

MEM = "template.spec.containers[0].resources.limits.memory"
IMAGE = "template.spec.containers[0].image"


# ---- candidate fields ----------------------------------------------------------------------------------
def test_every_candidate_that_really_differs_is_patched_and_nothing_else():
    s = Scenario()
    out = s.go(field=CPU, patch_fields=[CPU, MEM])
    assert out == "patched_kept"
    live = s.live_spec()["template"]["spec"]["containers"][0]["resources"]["limits"]
    assert live == {"cpu": "500m", "memory": "256Mi"}


def test_a_candidate_that_does_not_differ_is_skipped_and_the_others_still_patch():
    s = Scenario()
    plan = drift.build_patch(s.golden["spec"], s.live_before, [IMAGE, CPU])      # image equals the baseline
    assert plan.drifted and all("image" not in d for d in plan.drifted)
    assert any("cpu" in d for d in plan.drifted) and not any("memory" in d for d in plan.drifted)


def test_it_escalates_only_when_no_candidate_differs():
    s = Scenario()
    out = s.go(field=IMAGE, patch_fields=[IMAGE])
    assert out.startswith("escalated:no_drift_at_field")
    assert s.c.writes() == []


def test_a_model_attribution_is_never_needed_the_spec_diff_alone_decides():
    s = Scenario()
    out = s.go(field="", patch_fields=[MEM])           # no single field at all
    assert out == "patched_kept"
    limits = s.live_spec()["template"]["spec"]["containers"][0]["resources"]["limits"]
    assert limits["memory"] == "256Mi" and limits["cpu"] == "50m"      # only the named candidate was restored


# ---- selector and posture validation -------------------------------------------------------------------
def test_a_match_expressions_selector_always_escalates_before_any_write():
    s = Scenario()
    s.c.workloads[("Deployment", "web")]["spec"]["selector"] = {
        "matchExpressions": [{"key": "app", "operator": "In", "values": ["web"]}]}
    out = s.go(patch_fields=[CPU])
    assert out.startswith("escalated:selector_match_expressions")
    assert s.c.writes() == [] and "rollback_point_saved" not in s.steps()


def test_a_selector_the_template_cannot_satisfy_escalates_before_the_rollback_point_is_saved():
    s = Scenario()
    s.c.workloads[("Deployment", "web")]["spec"]["selector"] = {"matchLabels": {"app": "web", "tier": "x"}}
    out = s.go(patch_fields=[CPU])
    assert out.startswith("escalated:selector_mismatch")
    assert s.c.writes() == [] and "rollback_point_saved" not in s.steps()


def test_a_candidate_that_would_weaken_the_posture_escalates_before_any_write():
    s = Scenario()
    golden_container = s.golden["spec"]["template"]["spec"]["containers"][0]
    golden_container["securityContext"] = {"privileged": True}          # a baseline weaker than the live spec
    out = s.go(patch_fields=["template.spec.containers[0].securityContext"])
    assert out.startswith("escalated:patch_weakens_posture")
    assert s.c.writes() == [] and "rollback_point_saved" not in s.steps()


def test_a_match_labels_value_that_is_not_a_mapping_is_a_selector_error_not_a_crash():
    with pytest.raises(drift.PlanError, match="selector_missing"):
        drift.validate_patch_target({"selector": {"matchLabels": ["app"]}}, {}, {"template": {}})


def test_a_patched_template_that_would_lose_a_selector_label_escalates():
    live_view = {"template": {"metadata": {"labels": {"app": "web", "tier": "x"}},
                              "spec": {"containers": [{"name": "a"}]}}}
    raw = {"selector": {"matchLabels": {"app": "web", "tier": "x"}}}
    target = {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "a"}]}}}
    with pytest.raises(drift.PlanError, match="selector_mismatch"):
        drift.validate_patch_target(raw, live_view, target)


def test_a_patch_that_weakens_the_live_posture_escalates():
    live_view = {"template": {"metadata": {"labels": {"app": "web"}},
                              "spec": {"containers": [{"name": "a", "securityContext": {"privileged": False}}]}}}
    target = {"template": {"metadata": {"labels": {"app": "web"}},
                           "spec": {"containers": [{"name": "a", "securityContext": {"privileged": True}}]}}}
    raw = {"selector": {"matchLabels": {"app": "web"}}}
    with pytest.raises(drift.PlanError, match="patch_weakens_posture"):
        drift.validate_patch_target(raw, live_view, target)


def test_an_unreadable_spec_is_a_posture_error_that_escalates():
    raw = {"selector": {"matchLabels": {"app": "web"}}}
    target = {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": "not-a-list"}}}
    live_view = {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "a"}]}}}
    with pytest.raises(drift.PlanError, match="posture_unreadable"):
        drift.validate_patch_target(raw, live_view, target)


def test_a_restoring_patch_passes_validation():
    s = Scenario()
    raw = s.c.workloads[("Deployment", "web")]["spec"]
    plan = drift.build_patch(s.golden["spec"], s.live_before, [CPU])
    drift.validate_patch_target(raw, s.live_before, plan.target)         # raises on failure


# ---- request parsing ----------------------------------------------------------------------------------
def req(**kw):
    base = {"action": "patch", "namespace": "prod", "deployment": "web", "incident_id": "inc-1"}
    base.update(kw)
    return parse_request(base)


def test_patch_fields_json_is_accepted_and_the_first_becomes_patch_field():
    status, _why, r = req(patch_fields=json.dumps([CPU, MEM]), rule_path="true",
                          rule_reasons=json.dumps(["policy:cpu_cut_10x"]))
    assert status == "ok" and r.patch_fields == [CPU, MEM] and r.patch_field == CPU
    assert r.rule_path is True and r.rule_reasons == ["policy:cpu_cut_10x"]


def test_the_legacy_single_patch_field_still_works():
    status, _why, r = req(patch_field=CPU)
    assert status == "ok" and r.patch_fields == [CPU]


def test_no_candidate_at_all_or_only_unknown_escalates():
    assert req()[0] == "escalate"
    assert req(patch_field="unknown", patch_fields="[]")[0] == "escalate"


@pytest.mark.parametrize("bad", ["not json", '{"a": 1}', json.dumps([1, 2]), json.dumps(["x" * 300]),
                                 json.dumps(["ok"] * 65), json.dumps(["bad\nline"])])
def test_malformed_patch_fields_escalate_a_patch_to_a_human_and_never_guess(bad):
    status, why, r = req(patch_fields=bad)
    assert status == "escalate" and "patch_fields" in why and r is not None and r.patch_fields == []


def test_a_malformed_informational_list_never_stops_a_safety_action():
    base = {"action": "contain", "namespace": "prod", "deployment": "web", "pod": "web-abc-1",
            "incident_id": "inc-1"}
    for extra in ({"patch_fields": "not json"}, {"rule_reasons": "{"}, {"containment_label": "weird"}):
        status, _why, r = parse_request({**base, **extra})
        assert status == "ok" and r.action == "contain"
    assert parse_request({**base, "containment_label": "weird"})[2].containment_label == ""


def test_a_non_printable_or_oversized_single_patch_field_escalates():
    assert req(patch_field="badchar")[0] == "escalate"
    assert req(patch_field="x" * 300)[0] == "escalate"


def test_containment_fields_are_parsed_and_an_unknown_label_is_refused():
    base = {"action": "contain", "namespace": "prod", "deployment": "web", "pod": "web-abc-1",
            "incident_id": "inc-1"}
    status, _why, r = parse_request({**base, "containment_label": "Exfiltration", "restore_after": "false",
                                     "human_followup": "true"})
    assert status == "ok" and r.containment_label == "exfiltration"
    assert r.restore_after is False and r.human_followup is True
    status, _why, r = parse_request({**base, "containment_label": "suspicious"})     # not an automatic label
    assert status == "ok" and r.containment_label == ""


# ---- the ledger carries the new fields -----------------------------------------------------------------
def test_the_accepted_request_is_ledgered_with_every_new_field():
    s = Scenario()
    s.redis.store["kubeheal:baseline:prod:web"] = json.dumps(s.golden)
    steps = []
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(), metric_source=s.source,
                         cfg=ExecConfig(ENV), sleep=s.clock.sleep, clock=s.clock,
                         record_step=lambda i, st, p: steps.append((st, p)))
    run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "patch", "namespace": "prod", "deployment": "web", "incident_id": "inc-9",
        "patch_fields": json.dumps([CPU]), "rule_path": "true",
        "rule_reasons": json.dumps(["policy:cpu_cut_10x"]),
        "containment_label": "", "restore_after": "false", "human_followup": "false"}))
    accepted = dict(steps)["request_accepted"]
    assert accepted["patch_fields"] == [CPU] and accepted["rule_path"] is True
    assert accepted["rule_reasons"] == ["policy:cpu_cut_10x"]
    assert accepted["restore_after"] is False and accepted["human_followup"] is False
