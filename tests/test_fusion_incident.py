"""P6-D7 and D6 wiring: two security events per incident, T0 in the records, restore request after a contain."""
import json

import pytest

from fusion_helpers import NOW_MS, emb, health_event, ledger_steps, make_agent, run, sec_event, stream
from agents.executor.validation import parse_request
from agents.fusion_agent import agent as fusion

T0 = NOW_MS - 20_000


def handle_sec(a, ev, entry="1-0"):
    assert run(a._handle_entry(fusion.SEC_STREAM, entry, ev)) is True


def incident_id_of(ev):
    return fusion.derive_incident_id(ev)


def contained(a, incident_id, approved_by="auto", outcome="contained"):
    entry = {"incident_id": incident_id, "action_type": "executed_contain", "outcome": outcome,
             "approved_by": approved_by, "target": json.dumps({"namespace": "prod", "deployment": "payments",
                                                               "pod": "payments-abc-1"})}
    assert run(a._handle_entry(fusion.ACTIONS_STREAM, "9-0", entry)) is True


def restores(a):
    return [f for f in stream(a.redis, fusion.EXEC_STREAM) if f["action"] == "restore"]


def escalations(a):
    return stream(a.redis, fusion.ESCALATIONS_STREAM)


# ---- two security events per incident -------------------------------------------------------------------
def test_initial_and_complete_security_events_share_one_incident():
    a = make_agent()
    initial = sec_event(event_id="sec-1", entropy_phase="initial", entropy_valid_samples="1")
    complete = sec_event(event_id="sec-2", entropy_phase="complete", entropy_valid_samples="5",
                         timestamp_ms=str(NOW_MS + 4000))
    handle_sec(a, initial, "1-0")
    handle_sec(a, complete, "2-0")
    iid = incident_id_of(initial)
    assert len({r["incident_id"] for r in ledger_steps(a)}) == 1
    steps = [r["step"] for r in ledger_steps(a)]
    assert steps.count("detection") == 1 and steps.count("incident_update") == 1
    update = next(r["payload"] for r in ledger_steps(a) if r["step"] == "incident_update")
    assert update["scores"]["security"]["entropy_phase"] == "complete"
    assert update["scores"]["security"]["entropy_valid_samples"] == "5"
    assert update["trigger_event_ids"]["security"] == "sec-2"
    # one automatic action for the incident, not two
    assert len(stream(a.redis, fusion.EXEC_STREAM)) == 1
    assert stream(a.redis, fusion.EXEC_STREAM)[0]["incident_id"] == iid
    assert len(a.redis.zsets["kubeheal:cbw:contain:prod"]) == 1


def test_a_different_process_is_a_different_incident():
    a = make_agent()
    handle_sec(a, sec_event(event_id="sec-1", pid_target="42"), "1-0")
    handle_sec(a, sec_event(event_id="sec-2", pid_target="43"), "2-0")
    assert len({r["incident_id"] for r in ledger_steps(a)}) == 2


def test_the_incident_window_expires():
    a = make_agent()
    handle_sec(a, sec_event(event_id="sec-1"), "1-0")
    a.redis.advance(a.cfg.incident_dedup_ttl_s + 1)
    handle_sec(a, sec_event(event_id="sec-2", entropy_phase="complete"), "2-0")
    assert len({r["incident_id"] for r in ledger_steps(a)}) == 2


def test_the_second_event_cannot_queue_an_action_when_an_approval_is_pending():
    a = make_agent()
    handle_sec(a, sec_event(event_id="sec-1", model_scored="false", sec_ci_width="1.0"), "1-0")    # human
    handle_sec(a, sec_event(event_id="sec-2", entropy_phase="complete"), "2-0")                  # would be auto
    steps = [r["step"] for r in ledger_steps(a)]
    assert steps.count("approval_requested") == 1 and "incident_update" in steps
    assert stream(a.redis, fusion.EXEC_STREAM) == []


def test_a_low_initial_event_can_be_followed_by_an_action_from_the_complete_one():
    a = make_agent()
    handle_sec(a, sec_event(event_id="sec-1", sec_risk="0.30"), "1-0")                           # benign
    handle_sec(a, sec_event(event_id="sec-2", entropy_phase="complete"), "2-0")
    assert len(stream(a.redis, fusion.EXEC_STREAM)) == 1
    steps = [r["step"] for r in ledger_steps(a)]
    assert steps.count("detection") == 1 and steps.count("incident_update") == 1


def test_the_state_is_in_redis_so_a_second_replica_sees_the_same_incident():
    a = make_agent()
    b = make_agent(redis=a.redis)
    handle_sec(a, sec_event(event_id="sec-1"), "1-0")
    handle_sec(b, sec_event(event_id="sec-2", entropy_phase="complete"), "2-0")
    assert len(stream(a.redis, fusion.EXEC_STREAM)) == 1
    assert [r["step"] for r in ledger_steps(b)] == ["incident_update"]


def test_events_without_a_phase_are_not_merged():
    a = make_agent()
    handle_sec(a, sec_event(event_id="sec-1", entropy_phase=""), "1-0")
    handle_sec(a, sec_event(event_id="sec-2", entropy_phase=""), "2-0")
    assert len({r["incident_id"] for r in ledger_steps(a)}) == 2


# ---- T0 in the records ------------------------------------------------------------------------------------
def test_t0_goes_into_detection_decision_and_the_actions_entry_when_known():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0))
    handle_sec(a, ev)
    recs = {r["step"]: r["payload"] for r in ledger_steps(a)}
    assert recs["detection"]["t0_ms"] == T0 and recs["decision"]["t0_ms"] == T0
    action = next(f for f in stream(a.redis, fusion.ACTIONS_STREAM) if f["action_type"] == "auto_contain")
    assert action["t0_ms"] == str(T0)
    chain = recs["decision"]["causal_chain"]
    assert chain[0].startswith("T0: attack onset") and f"t0_ms={T0}" in chain[0]
    assert any(line.startswith("T+20.0s:") and "security event sec-1" in line for line in chain)


def test_t0_is_absent_when_no_event_carries_it_and_the_publish_time_is_never_used():
    a = make_agent()
    handle_sec(a, sec_event())
    recs = {r["step"]: r["payload"] for r in ledger_steps(a)}
    assert "t0_ms" not in recs["detection"] and "t0_ms" not in recs["decision"]
    action = next(f for f in stream(a.redis, fusion.ACTIONS_STREAM) if f["action_type"] == "auto_contain")
    assert "t0_ms" not in action
    assert not any(line.startswith("T0:") for line in recs["decision"]["causal_chain"])


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "1.5e12", ""])
def test_an_invalid_t0_is_ignored(bad):
    a = make_agent()
    handle_sec(a, sec_event(t0_ms=bad))
    assert "t0_ms" not in next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")


def test_the_earliest_t0_of_the_incident_wins():
    a = make_agent()
    handle_sec(a, sec_event(event_id="sec-1", t0_ms=str(T0)), "1-0")
    handle_sec(a, sec_event(event_id="sec-2", entropy_phase="complete", t0_ms=str(T0 - 3000)), "2-0")
    assert a.redis.hashes[fusion.INCIDENT_PREFIX + ":" + incident_id_of(sec_event())]["t0_ms"] == str(T0 - 3000)


# ---- restore after a contain --------------------------------------------------------------------------
def test_restore_is_requested_after_a_successful_automatic_contain():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0))
    handle_sec(a, ev)
    iid = incident_id_of(ev)
    assert restores(a) == []                                   # nothing before the Executor reports
    contained(a, iid)
    [req] = restores(a)
    assert req["incident_id"] == iid and req["t0_ms"] == str(T0) and req["workload_kind"] == "Deployment"
    assert (req["namespace"], req["deployment"], req["pod"]) == ("prod", "payments", "payments-abc-1")
    assert req["approved_by"] == "auto" and req["dry_run"] == "false" and req["source"] == "fusion"
    # the Executor accepts the request as it is
    status, why, parsed = parse_request(req)
    assert status == "ok", why
    assert parsed.t0_ms == T0 and parsed.kind == "Deployment" and parsed.action == "restore"
    # recorded in the ledger and on kubeheal.actions
    rec = next(r["payload"] for r in ledger_steps(a) if r["step"] == "restore_requested")
    assert rec["t0_ms"] == T0 and rec["workload_kind"] == "Deployment"
    assert any(f["action_type"] == "restore_requested" and f["t0_ms"] == str(T0)
               for f in stream(a.redis, fusion.ACTIONS_STREAM))
    # the same containment result again (redelivery, second replica): still one restore
    contained(a, iid)
    assert len(restores(a)) == 1


def test_restore_after_human_approval_of_a_containment():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0), model_scored="false", sec_ci_width="1.0")       # human decision
    handle_sec(a, ev)
    iid = incident_id_of(ev)
    assert stream(a.redis, fusion.EXEC_STREAM) == []
    contained(a, iid, approved_by="admin-anna")                                    # the dashboard queued it
    [req] = restores(a)
    assert req["approved_by"] == "admin-anna" and req["t0_ms"] == str(T0)


def test_without_t0_no_restore_is_requested_and_the_incident_is_escalated_once():
    a = make_agent()
    ev = sec_event()
    handle_sec(a, ev)
    iid = incident_id_of(ev)
    contained(a, iid)
    contained(a, iid)
    assert restores(a) == []
    esc = escalations(a)
    assert len(esc) == 1 and esc[0]["reason"].startswith("restore_not_requested: t0_unknown")
    assert esc[0]["required"] == "human" and esc[0]["incident_id"] == iid
    assert any(r["step"] == "fusion_escalation" for r in ledger_steps(a))


def test_t0_learned_from_the_complete_event_triggers_the_restore_of_a_finished_containment():
    a = make_agent()
    initial = sec_event(event_id="sec-1")
    handle_sec(a, initial, "1-0")
    iid = incident_id_of(initial)
    contained(a, iid)                                         # contained, T0 still unknown: escalated
    assert restores(a) == [] and len(escalations(a)) == 1
    handle_sec(a, sec_event(event_id="sec-2", entropy_phase="complete", t0_ms=str(T0)), "2-0")
    [req] = restores(a)
    assert req["t0_ms"] == str(T0) and req["incident_id"] == iid


@pytest.mark.parametrize("outcome", ["DRY RUN: would have CONTAIN prod/payments-abc-1",
                                     "contained_with_gaps:no snapshot", "contain_failed:x",
                                     "escalated:preflight", "refused:bad"])
def test_only_a_clean_contained_outcome_triggers_a_restore(outcome):
    a = make_agent()
    ev = sec_event(t0_ms=str(T0))
    handle_sec(a, ev)
    contained(a, incident_id_of(ev), outcome=outcome)
    assert restores(a) == [] and escalations(a) == []


def test_results_of_other_actions_and_fusions_own_records_are_ignored():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0))
    handle_sec(a, ev)
    iid = incident_id_of(ev)
    for entry in ({"incident_id": iid, "action_type": "executed_patch", "outcome": "contained"},
                  {"incident_id": iid, "action_type": "auto_contain", "outcome": "contained"},
                  {"incident_id": iid, "action_type": "executed_restore", "outcome": "restored"}):
        assert run(a._handle_entry(fusion.ACTIONS_STREAM, "9-0", entry)) is True
    assert restores(a) == []


def test_workload_kind_pod_is_not_sent_to_the_executor():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0), workload_kind="Pod")                  # the Security Agent's fallback
    handle_sec(a, ev)
    contained(a, incident_id_of(ev))
    assert restores(a) == []
    assert "workload_kind_unsupported" in escalations(a)[0]["reason"]


def test_an_unknown_incident_is_escalated_not_restored():
    a = make_agent()
    contained(a, "inc-unknown-0001")
    assert restores(a) == [] and "no context" in escalations(a)[0]["reason"]


def test_in_test_mode_the_restore_request_is_a_dry_run():
    a = make_agent()
    ev = sec_event(t0_ms=str(T0))
    handle_sec(a, ev)
    a.mode.apply_configmap(type("C", (), {"data": {"mode": "test"}})())
    contained(a, incident_id_of(ev))
    assert restores(a)[0]["dry_run"] == "true"


def test_fusion_reads_the_p5_event_fields():
    a = make_agent()
    ev = sec_event(syscall_source="replay", entropy_valid_samples="3", entropy_phase="complete",
                   model_scored="true")
    handle_sec(a, ev)
    det = next(r["payload"] for r in ledger_steps(a) if r["step"] == "detection")
    assert det["syscall_source"] == "replay" and det["entropy_valid_samples"] == "3"
    assert det["model_scored"] == "true" and det["workload_kind"] == "Deployment"
    scores = next(r["payload"] for r in ledger_steps(a) if r["step"] == "scores")
    assert scores["security"]["model_scored"] == "true" and scores["security"]["syscall_source"] == "replay"


def test_a_health_event_paired_with_the_security_event_updates_that_incident():
    a = make_agent()
    sec = sec_event()
    handle_sec(a, sec)
    run(a._decide("prod:payments", health_event(health_embedding_b64=emb(seed=1)),
                  dict(sec, security_embedding_b64=emb(seed=2))))
    assert len({r["incident_id"] for r in ledger_steps(a)}) == 1
    assert len(stream(a.redis, fusion.EXEC_STREAM)) == 1
