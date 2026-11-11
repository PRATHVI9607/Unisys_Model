"""V5-D3 through the Fusion Agent: the rule-based rollback path (owner decisions D2 and Q1), the freshness of the
Security Model score, and the containment labels (Q2): restore only after ransomware, a human follow-up after
exfiltration, suspicious never acts automatically.

Until V5-S2 (the Security Agent) writes the Redis hash `kubeheal:security:score:<namespace>:<workload>` there is
never a fresh Security score for a workload without a security event, so the rule path escalates to a human. That
is the intended fail-closed behaviour and the tests below pin it."""
import json

import pytest

from fusion_helpers import (NOW_MS, health_event, ledger_steps, make_agent, rule_health_event, run, sec_event,
                            security_score_key, set_security_score, stream)
from agents.executor.validation import parse_request
from agents.fusion_agent import agent as fusion
from agents.fusion_agent.config import FusionConfig

T0 = NOW_MS - 20_000


def decide(a, health=None, sec=None):
    run(a._decide("prod:payments", health, sec))


def decisions(a):
    return [r["payload"]["decision"] for r in ledger_steps(a) if r["step"] == "decision"]


def exec_requests(a):
    return stream(a.redis, fusion.EXEC_STREAM)


def restores(a):
    return [f for f in exec_requests(a) if f["action"] == "restore"]


def escalations(a):
    return stream(a.redis, fusion.ESCALATIONS_STREAM)


def contained(a, incident_id):
    entry = {"incident_id": incident_id, "action_type": "executed_contain", "outcome": "contained",
             "approved_by": "auto", "target": json.dumps({"namespace": "prod", "deployment": "payments",
                                                          "pod": "payments-abc-1"})}
    assert run(a._handle_entry(fusion.ACTIONS_STREAM, "9-0", entry)) is True


# ---- rule-based rollback (D2, Q1) ----------------------------------------------------------------------
def test_rule_path_with_a_fresh_security_key_auto_patches_and_carries_the_fields():
    a = make_agent()
    set_security_score(a, sec_risk="0.05")
    # the Health Model did not answer (model_unavailable): the event is still decided, not just escalated
    assert run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", rule_health_event())) is True
    assert decisions(a) == ["auto_patch"]
    [req] = exec_requests(a)
    assert req["action"] == "patch" and req["dry_run"] == "false" and req["approved_by"] == "auto"
    assert json.loads(req["patch_fields"]) == ["containers[0].image"]
    assert json.loads(req["rule_reasons"]) == ["ImagePullBackOff"] and req["rule_path"] == "true"
    assert req["patch_field"] == "containers[0].image"   # the rule path uses the diff, not the model top_field
    assert req["restore_after"] == "false" and req["human_followup"] == "false" and req["containment_label"] == ""
    assert escalations(a) == []                          # not the model_unavailable escalation
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["rule_path"] is True and payload["rule_reasons"] == ["ImagePullBackOff"]
    assert payload["security_fresh"] is True and payload["security_fresh_source"] == "hash"
    assert payload["models_ok"] is False                 # the Health Model did not answer: the rule path ignores it
    # a patch request still needs a field the Executor accepts
    assert parse_request(req)[0] == "ok"


def test_model_path_patch_keeps_the_top_field_as_the_patch_field():
    a = make_agent()
    decide(a, health=health_event())
    [req] = exec_requests(a)
    assert req["action"] == "patch" and req["patch_field"] == "spec.cpu" and req["rule_path"] == "false"


def test_rule_path_needs_no_burn_in_no_threshold_and_no_health_model():
    a = make_agent(burn_in_over=False)
    set_security_score(a)
    decide(a, health=rule_health_event(health_risk="0", health_label="benign"))
    assert decisions(a) == ["auto_patch"] and len(exec_requests(a)) == 1


def test_a_scored_security_event_in_the_decision_counts_as_fresh_and_supplies_the_raw_risk():
    a = make_agent()
    sec = sec_event(sec_risk="0.1", sec_label="benign", sec_prediction_set='["benign"]')
    decide(a, health=rule_health_event(), sec=sec)
    assert decisions(a) == ["auto_patch"]
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["security_fresh_source"] == "event"


def test_an_unscored_security_event_is_not_fresh():
    a = make_agent()
    set_security_score(a)                                # the event wins over the hash when it is present
    sec = sec_event(sec_risk="0.1", sec_label="benign", sec_prediction_set='["benign"]', model_scored="false")
    decide(a, health=rule_health_event(), sec=sec)
    assert decisions(a) == ["human_patch"] and exec_requests(a) == []


def test_a_security_risk_at_or_above_the_ceiling_leaves_the_rule_path():
    a = make_agent()
    set_security_score(a, sec_risk="0.5")                # >= 0.4: the normal flow handles it, no automatic patch
    decide(a, health=rule_health_event())
    assert decisions(a)[0].startswith("human_") and exec_requests(a) == []


# ---- Q1: without a fresh Security response a human decides --------------------------------------------------
@pytest.mark.parametrize("case", ["no_key", "stale", "not_scored", "bad_timestamp", "bad_risk", "redis_error",
                                  "future"])
def test_rule_path_without_a_fresh_security_score_goes_to_a_human(case):
    a = make_agent()
    now_ms = int(a.clock() * 1000)
    if case == "stale":
        set_security_score(a, ts_ms=now_ms - 31_000)     # older than SECURITY_FRESH_S (default 30 s)
    elif case == "not_scored":
        set_security_score(a, model_scored="false")
    elif case == "bad_timestamp":
        set_security_score(a, ts_ms="yesterday")
    elif case == "bad_risk":
        set_security_score(a, sec_risk="n/a")
    elif case == "future":
        set_security_score(a, ts_ms=now_ms + 60_000)
    elif case == "redis_error":
        set_security_score(a)
        real = a.redis.hgetall

        async def broken(key):
            if key == security_score_key():
                raise RuntimeError("redis down")
            return await real(key)
        a.redis.hgetall = broken
    decide(a, health=rule_health_event())
    assert decisions(a) == ["human_patch"] and exec_requests(a) == []
    steps = [r["step"] for r in ledger_steps(a)]
    assert "approval_requested" in steps                 # the human is asked, the incident is pending
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["security_fresh"] is False and "fresh Security Model response" in payload["rationale"]
    assert payload["rule_path"] is True


def test_the_freshness_window_is_configurable_and_the_edge_is_inclusive():
    a = make_agent(cfg=FusionConfig(security_fresh_s=10.0))
    now_ms = int(a.clock() * 1000)
    set_security_score(a, ts_ms=now_ms - 10_000)
    assert run(a._security_score("prod", "payments")) == (True, 0.05)
    set_security_score(a, ts_ms=now_ms - 10_001)
    assert run(a._security_score("prod", "payments")) == (False, None)
    assert FusionConfig.from_env({"SECURITY_FRESH_S": "12"}).security_fresh_s == 12.0
    assert FusionConfig.from_env({}).security_fresh_s == 30.0
    assert FusionConfig.from_env({"SECURITY_FRESH_S": "-5"}).security_fresh_s == 30.0


def test_the_fresh_score_ages_out_with_the_clock():
    class Clock:
        t = 1_000_000.0

        def __call__(self):
            return self.t
    clock = Clock()
    a = make_agent(clock=clock)
    set_security_score(a, sec_risk="0.2")
    assert run(a._security_score("prod", "payments")) == (True, 0.2)
    clock.t += 31
    assert run(a._security_score("prod", "payments")) == (False, None)


def test_the_hash_of_another_workload_is_not_used():
    a = make_agent()
    set_security_score(a, workload="other")
    assert run(a._security_score("prod", "payments")) == (False, None)


def test_rule_path_blocked_by_the_other_rules_still_goes_to_a_human():
    for kwargs, ev in ((dict(protected=True), {}), (dict(), {"has_baseline": "false"}),
                       (dict(), {"spec_changed": "false"})):
        a = make_agent(**kwargs)
        set_security_score(a)
        decide(a, health=rule_health_event(**ev))
        assert exec_requests(a) == [], (kwargs, ev)
        assert decisions(a)[0].startswith("human_")


def test_dry_run_rule_path_queues_a_dry_run_request_and_does_not_use_the_patch_budget():
    a = make_agent(enforce=False)
    set_security_score(a)
    decide(a, health=rule_health_event())
    [req] = exec_requests(a)
    assert req["dry_run"] == "true" and a.redis.zsets == {}


# ---- model_unavailable routing (item 4) -------------------------------------------------------------------
def test_model_unavailable_without_failure_reasons_is_still_only_an_escalation():
    a = make_agent()
    ev = rule_health_event()
    del ev["failure_reasons_json"]
    assert run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", ev)) is True
    assert decisions(a) == [] and exec_requests(a) == []
    [esc] = escalations(a)
    assert esc["reason"].startswith("health_model_unavailable")


@pytest.mark.parametrize("raw", ["[]", "", "not json", "{}", '[""]'])
def test_model_unavailable_with_empty_or_unreadable_failure_reasons_is_an_escalation(raw):
    a = make_agent()
    set_security_score(a)
    run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", rule_health_event(failure_reasons_json=raw)))
    assert decisions(a) == [] and exec_requests(a) == [] and len(escalations(a)) == 1


# ---- Q2: containment labels ----------------------------------------------------------------------------------
def exfil_event(**kw):
    ev = sec_event(sec_label="exfiltration", sec_prediction_set='["exfiltration"]', t0_ms=str(T0))
    ev.update(kw)
    return ev


def test_exfiltration_containment_requests_no_restore_and_escalates_once():
    a = make_agent()
    ev = exfil_event()
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    iid = fusion.derive_incident_id(ev)
    [req] = exec_requests(a)
    assert req["action"] == "contain" and req["containment_label"] == "exfiltration"
    assert req["restore_after"] == "false" and req["human_followup"] == "true"
    assert req["rule_path"] == "false" and json.loads(req["patch_fields"]) == []
    ctx = a.redis.hashes[fusion.INCIDENT_PREFIX + ":" + iid]
    assert ctx["restore_after"] == "0" and ctx["human_followup"] == "1" and ctx["containment_label"] == "exfiltration"
    assert escalations(a) == []                           # nothing before the Executor reports
    contained(a, iid)
    contained(a, iid)                                     # redelivery or a second replica
    assert restores(a) == []
    [esc] = escalations(a)
    assert esc["incident_id"] == iid and esc["required"] == "human"
    assert "containment done for exfiltration" in esc["reason"] and "human follow-up required" in esc["reason"]
    assert [r["step"] for r in ledger_steps(a)].count("fusion_escalation") == 1


def test_a_second_security_event_of_the_incident_does_not_escalate_the_follow_up_again():
    a = make_agent()
    ev = exfil_event()
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    iid = fusion.derive_incident_id(ev)
    contained(a, iid)
    complete = exfil_event(event_id="sec-2", entropy_phase="complete", t0_ms=str(T0 - 1000))
    assert run(a._handle_entry(fusion.SEC_STREAM, "2-0", complete)) is True      # same pid: the same incident
    assert restores(a) == [] and len(escalations(a)) == 1


def test_ransomware_containment_still_requests_the_restore():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0))
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    iid = fusion.derive_incident_id(ev)
    [req] = exec_requests(a)
    assert req["containment_label"] == "ransomware" and req["restore_after"] == "true"
    assert req["human_followup"] == "false"
    contained(a, iid)
    [restore] = restores(a)
    assert restore["t0_ms"] == str(T0) and restore["incident_id"] == iid
    assert escalations(a) == []


def test_a_context_without_the_restore_flag_never_requests_a_restore():
    a = make_agent()
    iid = "inc-20251109-000000-abcdef12"
    a.redis.hashes[fusion.INCIDENT_PREFIX + ":" + iid] = {
        "namespace": "prod", "deployment": "payments", "pod": "payments-abc-1", "workload_kind": "Deployment",
        "t0_ms": str(T0), "opened": "1"}
    contained(a, iid)
    assert restores(a) == [] and escalations(a) == []


def test_a_human_approved_exfiltration_containment_also_ends_in_a_follow_up_not_a_restore():
    a = make_agent()
    ev = exfil_event(model_scored="false")                # not scored: a human decides the containment
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    assert exec_requests(a) == []
    iid = fusion.derive_incident_id(ev)
    contained(a, iid)                                     # the dashboard queued it, the Executor contained
    assert restores(a) == [] and len(escalations(a)) == 1


def test_suspicious_never_triggers_an_automatic_containment():
    a = make_agent()
    decide(a, sec=sec_event(sec_label="suspicious", sec_prediction_set='["suspicious"]', sec_risk="0.99"))
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert "never triggers automatic containment" in payload["rationale"]


def test_a_human_approved_suspicious_containment_requests_neither_restore_nor_follow_up():
    a = make_agent()
    ev = sec_event(sec_label="suspicious", sec_prediction_set='["suspicious"]', t0_ms=str(T0))
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    contained(a, fusion.derive_incident_id(ev))
    assert restores(a) == [] and escalations(a) == []
