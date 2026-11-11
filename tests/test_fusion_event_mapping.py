"""V5-D3: the mapping of Redis event dicts onto the correlation contract never raises and fails closed."""
import json
import math

import pytest

from fusion_helpers import health_event, ledger_steps, make_agent, run, sec_event
from agents.fusion_agent import event_mapping as em
from kubeheal.correlation import COMPOUND_THRESHOLD


def test_prediction_set_absent_event_is_none_and_present_event_is_never_silently_certain():
    assert em.prediction_set({}, "sec_prediction_set") is None
    assert em.prediction_set(None, "sec_prediction_set") is None
    assert em.prediction_set({"sec_prediction_set": '["ransomware"]'}, "sec_prediction_set") == ["ransomware"]
    assert em.prediction_set({"sec_prediction_set": "[]"}, "sec_prediction_set") == []
    for bad in (None, "", "[nope", '"ransomware"', "{}", "5"):
        ev = {"event_id": "x"} if bad is None else {"sec_prediction_set": bad}
        assert em.prediction_set(ev, "sec_prediction_set") == em.MALFORMED_SET


def test_the_marker_is_uncertain_for_the_policy():
    from agents.fusion_agent.decision_policy import set_certain
    assert set_certain(em.MALFORMED_SET, "ransomware", required=True) is False
    assert set_certain(em.MALFORMED_SET, "ransomware") is False


def test_string_list_and_safe_float():
    assert em.string_list('["a", "", 3, "b"]') == ["a", "b"]
    assert em.string_list(["a"]) == ["a"] and em.string_list("garbage") == [] and em.string_list(None) == []
    assert em.safe_float(None) == 0.0 and em.safe_float("") == 0.0 and em.safe_float("0.5") == 0.5
    assert math.isnan(em.safe_float("n/a"))


def test_top_factors_drop_unusable_rows_and_rank_by_size():
    raw = json.dumps([{"feature": "a", "value": 1, "contribution": 0.1},
                      {"feature": "b", "value": None, "contribution": -0.4},
                      {"feature": "c", "contribution": "x"}, "junk", {"contribution": 1.0}])
    assert [r["feature"] for r in em.top_factors(raw)] == ["b", "a"]
    assert em.top_factors("not json") == []


def test_events_map_with_optional_fields_missing():
    h = em.to_health_event({"health_risk": "0.7"}, "prod", "payments")
    s = em.to_security_event({"sec_risk": "0.9", "sec_label": "ransomware"}, "prod", "payments")
    assert h is not None and h.label == "benign" and h.spec_changed is False and h.has_baseline is False
    assert s is not None and s.label == "ransomware" and s.window_start_ms == 0


def test_events_that_cannot_be_mapped_are_none_not_an_exception():
    assert em.to_health_event({"health_risk": "n/a"}, "prod", "p") is None
    assert em.to_health_event({"health_risk": "1.5"}, "prod", "p") is None
    assert em.to_security_event({"sec_risk": "-0.1"}, "prod", "p") is None
    assert em.to_security_event({"sec_risk": "nan"}, "prod", "p") is None


def test_the_security_window_start_falls_back_to_t0():
    s = em.to_security_event(sec_event(t0_ms="123456"), "prod", "payments")
    assert s.window_start_ms == 123456
    s = em.to_security_event(sec_event(t0_ms="1", window_start_ms="99"), "prod", "payments")
    assert s.window_start_ms == 99


def test_correlate_flag_uses_the_correlation_module_threshold():
    h = em.to_health_event(health_event(), "prod", "payments")
    s = em.to_security_event(sec_event(), "prod", "payments")
    score, compound, reasons = em.correlate(h, s)
    assert compound == (score >= COMPOUND_THRESHOLD) and compound is True and reasons
    other = em.to_security_event(sec_event(), "prod", "elsewhere")
    assert em.correlate(h, other) == (0.0, False, [])


def test_the_local_summary_is_a_plain_sentence():
    h = em.to_health_event(health_event(top_factors_json=json.dumps(
        [{"feature": "cpu_limit_ratio", "value": 0.1, "contribution": 0.5}])), "prod", "payments")
    s = em.to_security_event(sec_event(), "prod", "payments")
    score, compound, reasons = em.correlate(h, s)
    text = em.local_summary(h, s, score, compound, reasons)
    assert text.endswith(".") and "cpu_limit_ratio" in text
    assert not any(ch in text for ch in (chr(0x2014), chr(0x2013)))      # no em or en dash
    assert em.local_summary(None, None, 0.0, False, []) == ""
    assert "Security signal" in em.local_summary(None, s, 0.0, False, [])
    assert "Health signal" in em.local_summary(h, None, 0.0, False, [])


def test_the_ledger_scores_carry_sets_uncertainty_and_factors_but_no_ci_width():
    a = make_agent()
    factors = json.dumps([{"feature": "files_written_per_s", "value": 40.0, "contribution": 0.3}])
    run(a._decide("prod:payments", None, sec_event(top_factors_json=factors, model_version="sec-1")))
    scores = next(r["payload"] for r in ledger_steps(a) if r["step"] == "scores")
    sec = scores["security"]
    assert sec["sec_prediction_set"] == '["ransomware"]' and sec["sec_uncertain"] == "false"
    assert sec["top_factors_json"] == factors and "sec_ci_width" not in sec
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    for key in ("sec_prediction_set", "health_prediction_set", "rule_path", "rule_reasons", "top_factors_json"):
        assert key in payload
    assert payload["rule_path"] is False and payload["health_prediction_set"] is None
    assert payload["sec_prediction_set"] == ["ransomware"]
    assert payload["attributions"]["security_top_factors"][0]["feature"] == "files_written_per_s"
