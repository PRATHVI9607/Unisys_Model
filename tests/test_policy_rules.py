"""P6 policy rules (S-POL-1 .. S-POL-7): fail closed inputs, protected namespaces, breakers, burn-in, purity."""
import ast
import math
from pathlib import Path

import pytest

from agents.fusion_agent import decision_policy as dp
from agents.fusion_agent.decision_policy import (
    BURN_IN_SAMPLES, CB_CONTAIN_LIMIT_PER_HOUR, CB_PATCH_LIMIT_PER_HOUR, Decision, DecisionInput,
    make_decision,
)

OK = dict(models_ok=True, namespace_protected=False, metric_samples_seen=BURN_IN_SAMPLES, mode="enforce",
          namespace_tier="staging", health_label="drift", health_prediction_set=["drift"],
          sec_label="ransomware", sec_prediction_set=["ransomware"],
          changed_fields=["template.spec.containers[0].resources.limits.cpu"])
AUTO = (Decision.AUTO_CONTAIN, Decision.AUTO_PATCH)


def D(**kw):
    return make_decision(DecisionInput(**{**OK, **kw}))


# ---- S-POL-1: models_ok ------------------------------------------------------------------------
def test_models_ok_defaults_to_false_so_forgetting_it_fails_closed():
    out = make_decision(DecisionInput(sec_risk=0.99, namespace_tier="prod", namespace_protected=False,
                                      metric_samples_seen=BURN_IN_SAMPLES))
    assert DecisionInput().models_ok is False
    assert out.decision == Decision.HUMAN_CONTAIN and out.requires_incident_lock is False


@pytest.mark.parametrize("kw,expected", [
    (dict(sec_risk=0.99), Decision.HUMAN_CONTAIN),
    (dict(health_risk=0.99), Decision.HUMAN_PATCH),
    (dict(health_risk=0.95, sec_risk=0.95, compound_flag=True, correlation_score=0.9), Decision.HUMAN_CONTAIN),
    (dict(health_risk=0.10, sec_risk=0.10), Decision.HUMAN_CONTAIN),
])
def test_models_not_ok_is_human_for_every_score(kw, expected):
    out = D(models_ok=False, **kw)
    assert out.decision == expected and out.decision not in AUTO


@pytest.mark.parametrize("bad", [None, 1, "true", 0])
def test_only_exact_true_counts_as_models_ok(bad):
    assert D(models_ok=bad, sec_risk=0.99).decision not in AUTO


def test_models_ok_does_not_change_the_dry_run_flag():
    assert D(models_ok=False, sec_risk=0.99, mode="test").dry_run is True
    assert D(models_ok=False, sec_risk=0.99, mode="enforce").dry_run is False


# ---- events without a real model score never reach AUTO_* ---------------------------------------
# ---- M2: the prediction set must be exactly one label ------------------------------------------
BAD_SETS = [[], ["ransomware", "benign"], ["benign"], ["", ], [None], "ransomware", {"ransomware"}, 1, ("a", "b")]


@pytest.mark.parametrize("bad", BAD_SETS)
def test_a_set_that_is_not_one_matching_label_is_uncertain_on_the_security_side(bad):
    assert D(sec_risk=0.99, sec_prediction_set=bad).decision == Decision.HUMAN_CONTAIN
    # a bad set on the OTHER side also blocks (any side that has an event must be certain)
    assert D(sec_risk=0.99, health_prediction_set=bad).decision == Decision.HUMAN_CONTAIN


@pytest.mark.parametrize("bad", BAD_SETS)
def test_a_set_that_is_not_one_matching_label_is_uncertain_on_the_health_side(bad):
    assert D(health_risk=0.99, health_prediction_set=bad).decision == Decision.HUMAN_PATCH
    assert D(health_risk=0.99, sec_prediction_set=bad).decision == Decision.HUMAN_PATCH


def test_the_trigger_side_must_have_a_set_and_a_side_without_event_may_pass_none():
    assert D(sec_risk=0.99, sec_prediction_set=None).decision == Decision.HUMAN_CONTAIN
    assert D(health_risk=0.99, health_prediction_set=None).decision == Decision.HUMAN_PATCH
    assert D(sec_risk=0.99, health_prediction_set=None).decision == Decision.AUTO_CONTAIN
    assert D(health_risk=0.99, sec_prediction_set=None).decision == Decision.AUTO_PATCH


def test_one_label_set_matching_the_label_is_certain_case_and_space_insensitive():
    assert D(sec_risk=0.99, sec_prediction_set=[" Ransomware "]).decision == Decision.AUTO_CONTAIN
    assert D(sec_risk=0.99, sec_prediction_set=("ransomware",)).decision == Decision.AUTO_CONTAIN


def test_there_is_no_ci_width_guard_any_more():
    assert not hasattr(dp, "CI_WIDTH_LIMIT")
    assert not hasattr(DecisionInput(), "health_ci_width") and not hasattr(DecisionInput(), "sec_ci_width")
    assert dp.set_certain(["a"], "a") and not dp.set_certain([], "a") and dp.set_certain(None, "a")
    assert not dp.set_certain(None, "a", required=True)


@pytest.mark.parametrize("risk", [float("nan"), float("inf")])
def test_invalid_risk_is_human(risk):
    assert D(sec_risk=risk).decision not in AUTO
    assert D(health_risk=risk).decision not in AUTO


# ---- S-POL-6: protected namespace ---------------------------------------------------------------
def test_protected_namespace_never_gets_an_automatic_action():
    assert D(sec_risk=0.99, namespace_protected=True).decision == Decision.HUMAN_CONTAIN
    assert D(health_risk=0.99, namespace_protected=True).decision == Decision.HUMAN_PATCH
    comp = D(health_risk=0.9, sec_risk=0.95, compound_flag=True, correlation_score=0.9,
             namespace_protected=True)
    assert comp.decision == Decision.HUMAN_CONTAIN and "protected" in comp.rationale


def test_namespace_protected_defaults_to_true():
    assert DecisionInput().namespace_protected is True


@pytest.mark.parametrize("unknown", [None, "false", 0])
def test_only_exact_false_unblocks(unknown):
    assert D(sec_risk=0.99, namespace_protected=unknown).decision == Decision.HUMAN_CONTAIN


def test_protected_does_not_change_low_scores():
    assert D(sec_risk=0.5, namespace_protected=True).decision == Decision.OBSERVE
    assert D(sec_risk=0.1, namespace_protected=True).decision == Decision.BENIGN


def test_unprotected_namespace_still_gets_auto():
    assert D(sec_risk=0.99).decision == Decision.AUTO_CONTAIN
    assert D(health_risk=0.99).decision == Decision.AUTO_PATCH


# ---- S-POL-6: breakers ---------------------------------------------------------------------------
def test_breaker_counts_are_inputs_and_open_at_the_limit():
    assert D(sec_risk=0.99, circuit_breaker_containments=CB_CONTAIN_LIMIT_PER_HOUR - 1).decision \
        == Decision.AUTO_CONTAIN
    assert D(sec_risk=0.99, circuit_breaker_containments=CB_CONTAIN_LIMIT_PER_HOUR).decision \
        == Decision.HUMAN_CONTAIN
    assert D(health_risk=0.99, circuit_breaker_patches=CB_PATCH_LIMIT_PER_HOUR - 1).decision \
        == Decision.AUTO_PATCH
    assert D(health_risk=0.99, circuit_breaker_patches=CB_PATCH_LIMIT_PER_HOUR).decision \
        == Decision.HUMAN_PATCH


def test_the_spec_numbers():
    assert (CB_CONTAIN_LIMIT_PER_HOUR, CB_PATCH_LIMIT_PER_HOUR) == (3, 10)
    assert dp.TIER_MULTIPLIERS == {"prod": 1.20, "staging": 1.00, "dev": 0.70}
    assert dp.COMPOUND_ESCALATION == 1.15 and dp.BURN_IN_SAMPLES == 2000
    t = dp.Thresholds
    assert (t.AUTO_CONTAIN, t.AUTO_PATCH, t.HUMAN_APPROVAL, t.OBSERVE) == (0.85, 0.85, 0.65, 0.40)
    assert (t.BURN_IN_AUTO_CONTAIN, t.BURN_IN_AUTO_PATCH) == (0.95, 0.90)


@pytest.mark.parametrize("count", [None, -1, "3", 1.5, True])
def test_invalid_breaker_count_counts_as_open(count):
    assert D(sec_risk=0.99, circuit_breaker_containments=count).decision == Decision.HUMAN_CONTAIN
    assert D(health_risk=0.99, circuit_breaker_patches=count).decision == Decision.HUMAN_PATCH


# ---- S-POL-7: burn-in from a counter -------------------------------------------------------------
def test_burn_in_counter_below_and_above():
    # 0.90 passes the normal 0.85 threshold, not the burn-in 0.95
    below = D(sec_risk=0.90, metric_samples_seen=BURN_IN_SAMPLES - 1)
    at = D(sec_risk=0.90, metric_samples_seen=BURN_IN_SAMPLES)
    assert below.decision != Decision.AUTO_CONTAIN
    assert at.decision == Decision.AUTO_CONTAIN
    assert D(sec_risk=0.96, metric_samples_seen=0).decision == Decision.AUTO_CONTAIN


def test_burn_in_patch_threshold_from_counter():
    assert D(health_risk=0.88, metric_samples_seen=10).decision != Decision.AUTO_PATCH
    assert D(health_risk=0.91, metric_samples_seen=10).decision == Decision.AUTO_PATCH
    assert D(health_risk=0.88, metric_samples_seen=BURN_IN_SAMPLES).decision == Decision.AUTO_PATCH


def test_unknown_counter_means_burn_in():
    assert D(sec_risk=0.90, metric_samples_seen=None).decision != Decision.AUTO_CONTAIN
    assert DecisionInput().metric_samples_seen is None


def test_env_style_flag_can_only_force_burn_in_on():
    assert D(sec_risk=0.90, burn_in_mode=True, metric_samples_seen=10 * BURN_IN_SAMPLES).decision \
        != Decision.AUTO_CONTAIN
    # False does not switch burn-in off while the counter is low
    assert D(sec_risk=0.90, burn_in_mode=False, metric_samples_seen=5).decision != Decision.AUTO_CONTAIN


# ---- tiers, compound, observe ---------------------------------------------------------------------
def test_adjusted_score_uses_tier_and_compound_factors():
    assert D(sec_risk=0.5, namespace_tier="prod").adjusted_score == pytest.approx(0.5 * 1.20)
    assert D(sec_risk=0.5, namespace_tier="dev").adjusted_score == pytest.approx(0.5 * 0.70)
    out = D(health_risk=0.3, sec_risk=0.5, namespace_tier="staging", compound_flag=True)
    assert out.adjusted_score == pytest.approx(0.5 * 1.15)


def test_observe_decision_has_no_action_and_no_lock():
    out = D(sec_risk=0.5)
    assert out.decision == Decision.OBSERVE and out.requires_incident_lock is False


# ---- purity ---------------------------------------------------------------------------------------
FORBIDDEN = {"redis", "os", "time", "asyncio", "aiohttp", "datetime", "random", "socket", "subprocess",
             "requests", "logging", "uuid"}


def test_decision_policy_module_has_no_io_imports():
    src = Path(dp.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & FORBIDDEN), imported & FORBIDDEN
    assert imported <= {"math", "dataclasses", "enum", "typing"}


def test_policy_does_not_read_the_environment_or_clock_at_call_time():
    tree = ast.parse(Path(dp.__file__).read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not ({"open", "print", "input", "environ", "getenv"} & (names | attrs))
    assert not [n for n in ast.walk(tree) if isinstance(n, (ast.Await, ast.AsyncFunctionDef))]
    assert math.isfinite(D(sec_risk=0.5).adjusted_score)


# ---- Q2: automatic containment labels --------------------------------------------------------------
def test_ransomware_contains_automatically_and_restores():
    o = D(sec_risk=0.99)
    assert o.decision == Decision.AUTO_CONTAIN
    assert o.action_params["containment_label"] == "ransomware"
    assert o.action_params["restore_after"] is True and o.action_params["human_followup"] is False


def test_exfiltration_contains_automatically_without_restore_and_with_a_human_followup():
    o = D(sec_risk=0.99, sec_label="exfiltration", sec_prediction_set=["exfiltration"])
    assert o.decision == Decision.AUTO_CONTAIN and o.requires_incident_lock
    assert o.action_params["containment_label"] == "exfiltration"
    assert o.action_params["restore_after"] is False and o.action_params["human_followup"] is True


@pytest.mark.parametrize("label", ["suspicious", "benign", "", "ransom", None, 5])
def test_other_labels_never_contain_automatically(label):
    o = D(sec_risk=0.99, sec_label=label, sec_prediction_set=[label] if isinstance(label, str) else None)
    assert o.decision == Decision.HUMAN_CONTAIN and o.requires_incident_lock
    assert "never triggers automatic containment" in o.rationale or "prediction set" in o.rationale


def test_compound_containment_uses_the_same_label_gate():
    ok = D(health_risk=0.9, sec_risk=0.95, compound_flag=True, correlation_score=0.9)
    assert ok.decision == Decision.AUTO_CONTAIN and ok.action_params["compound"] is True
    no = D(health_risk=0.9, sec_risk=0.95, compound_flag=True, correlation_score=0.9,
           sec_label="suspicious", sec_prediction_set=["suspicious"])
    assert no.decision == Decision.HUMAN_CONTAIN


# ---- D2/Q1: rule-based rollback ----------------------------------------------------------------------
RULE = dict(rollback_reasons=["ImagePullBackOff"], spec_changed=True, has_baseline=True, security_fresh=True,
            sec_risk=0.1, health_prediction_set=None, sec_prediction_set=None, models_ok=False,
            metric_samples_seen=0, changed_fields=["image"])


def test_rule_path_rolls_back_without_the_health_model_set_or_burn_in():
    o = D(**RULE)
    assert o.decision == Decision.AUTO_PATCH and o.requires_incident_lock
    assert o.action_params["rule_path"] is True
    assert o.action_params["rule_reasons"] == ["ImagePullBackOff"]
    assert o.action_params["patch_fields"] == ["image"]
    assert D(**{**RULE, "health_prediction_set": ["a", "b"], "health_risk": 0.0}).decision == Decision.AUTO_PATCH


def test_rule_path_needs_a_fresh_security_response_else_a_human_decides():
    o = D(**{**RULE, "security_fresh": False})
    assert o.decision == Decision.HUMAN_PATCH and "Security Model" in o.rationale and o.requires_incident_lock
    assert o.action_params["rule_path"] is True
    assert DecisionInput().security_fresh is False
    for bad in (None, 1, "true"):
        assert D(**{**RULE, "security_fresh": bad}).decision == Decision.HUMAN_PATCH


@pytest.mark.parametrize("key,bad", [("namespace_protected", True), ("namespace_tier", "weird"),
                                     ("circuit_breaker_patches", CB_PATCH_LIMIT_PER_HOUR),
                                     ("circuit_breaker_patches", None), ("namespace_protected", None)])
def test_rule_path_still_respects_the_remaining_blockers(key, bad):
    assert D(**{**RULE, key: bad}).decision == Decision.HUMAN_PATCH


@pytest.mark.parametrize("key,bad", [("rollback_reasons", []), ("rollback_reasons", [""]),
                                     ("rollback_reasons", "ImagePullBackOff"), ("spec_changed", False),
                                     ("spec_changed", 1), ("has_baseline", False), ("has_baseline", None)])
def test_without_every_rule_input_there_is_no_rule_path(key, bad):
    o = D(**{**RULE, key: bad})
    assert o.decision not in AUTO and "rule_path" not in o.action_params


def test_rule_path_needs_the_raw_security_risk_below_the_ceiling():
    assert D(**{**RULE, "sec_risk": 0.39}).decision == Decision.AUTO_PATCH
    o = D(**{**RULE, "sec_risk": 0.40})
    assert o.decision not in AUTO and "rule_path" not in o.action_params
    assert D(**{**RULE, "sec_risk": float("nan")}).decision not in AUTO


def test_rule_path_is_a_dry_run_in_test_mode_and_the_policy_stays_pure():
    o = D(**{**RULE, "mode": "test"})
    assert o.decision == Decision.AUTO_PATCH and o.dry_run is True
    assert D(**RULE).dry_run is False


@pytest.mark.parametrize("risk", [-1.0, -0.01, 1.01])
def test_rule_path_does_not_trust_a_security_risk_outside_zero_one(risk):
    o = D(**{**RULE, "sec_risk": risk})
    if risk > 1:
        assert o.decision not in AUTO                       # at or above the ceiling: normal flow
    else:
        assert o.decision == Decision.HUMAN_PATCH and "outside [0, 1]" in o.rationale


@pytest.mark.parametrize("fields", [[], [""], None, "image"])
def test_rule_path_needs_a_changed_field_to_restore(fields):
    o = D(**{**RULE, "changed_fields": fields})
    assert o.decision == Decision.HUMAN_PATCH and "no changed field" in o.rationale
