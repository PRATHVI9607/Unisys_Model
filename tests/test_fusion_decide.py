"""P6-D1, D3, D4, D5 through the Fusion Agent: models_ok and deadlines, protected label, sliding breakers,
burn-in counter, redelivery idempotency."""
import asyncio

import pytest

import json

from fusion_helpers import (NOW_MS, StubInterp, emb, health_event, ledger_steps, make_agent, rule_health_event,
                            run, sec_event, security_score_key, set_security_score, stream)
from agents.fusion_agent import agent as fusion
from agents.fusion_agent import breakers
from agents.fusion_agent.breakers import BURN_IN_SEEN_KEY, BurnInCounter, SlidingWindowBreaker
from agents.fusion_agent.config import FusionConfig
from agents.fusion_agent.decision_policy import BURN_IN_SAMPLES, CB_CONTAIN_LIMIT_PER_HOUR
from agents.fusion_agent.interpretation_client import CorrelateResult


def decide(a, health=None, sec=None):
    run(a._decide("prod:payments", health, sec))


def decisions(a):
    return [r["payload"]["decision"] for r in ledger_steps(a) if r["step"] == "decision"]


def exec_requests(a):
    return stream(a.redis, fusion.EXEC_STREAM)


# ---- S-POL-1: models_ok ---------------------------------------------------------------------------
def test_scored_event_in_an_open_unprotected_namespace_is_contained_automatically():
    a = make_agent()
    decide(a, sec=sec_event())
    assert decisions(a) == ["auto_contain"]
    req = exec_requests(a)[0]
    assert req["action"] == "contain" and req["dry_run"] == "false" and req["pod"] == "payments-abc-1"


@pytest.mark.parametrize("fields", [
    {"model_scored": "false", "sec_uncertain": "true"},     # P5: heuristic only or no syscall window
    {"model_scored": "false"},
    {"model_scored": ""},
])
def test_security_event_the_model_did_not_score_is_human(fields):
    a = make_agent()
    ev = sec_event(**fields)
    decide(a, sec=ev)
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["models_ok"] is False and payload["model_issues"]


def test_event_without_a_model_scored_field_fails_closed():
    a = make_agent()
    ev = sec_event()
    del ev["model_scored"]
    decide(a, sec=ev)
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []


# ---- M2: a prediction set of more than one label blocks every automatic action end to end -----------------
def test_a_two_label_set_blocks_automatic_action_end_to_end():
    two = json.dumps(["ransomware", "exfiltration"])
    a = make_agent()
    decide(a, sec=sec_event(sec_prediction_set=two))
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []
    assert "one-label" in next(r["payload"]["rationale"] for r in ledger_steps(a) if r["step"] == "decision")
    a = make_agent()
    decide(a, health=health_event(health_prediction_set=json.dumps(["degradation", "critical"])))
    assert decisions(a) == ["human_patch"] and exec_requests(a) == []
    # a paired incident: the uncertain side blocks the compound containment too
    a = make_agent()
    decide(a, health=health_event(health_prediction_set=json.dumps(["degradation", "critical"])),
           sec=sec_event())
    assert decisions(a)[0].startswith("human_") and exec_requests(a) == []
    a = make_agent()
    decide(a, health=health_event(), sec=sec_event(sec_prediction_set=two))
    assert decisions(a)[0].startswith("human_") and exec_requests(a) == []


@pytest.mark.parametrize("bad", ["absent", "empty", "garbage", "not_a_list", "empty_list"])
def test_a_malformed_prediction_set_is_uncertain_and_never_acts(bad):
    for kind in ("security", "health"):
        a = make_agent()
        ev = sec_event() if kind == "security" else health_event()
        name = "sec_prediction_set" if kind == "security" else "health_prediction_set"
        if bad == "absent":
            del ev[name]
        else:
            ev[name] = {"empty": "", "garbage": "[not json", "not_a_list": '{"a": 1}', "empty_list": "[]"}[bad]
        decide(a, **({"sec": ev} if kind == "security" else {"health": ev}))
        assert decisions(a) == [("human_contain" if kind == "security" else "human_patch")]
        assert exec_requests(a) == []
        # the ledger records what Fusion saw, with the marker for the unusable value
        payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
        assert payload["health_prediction_set" if kind == "health" else "sec_prediction_set"] in (
            [], fusion.em.MALFORMED_SET)


def test_a_wrong_label_in_a_one_label_set_is_uncertain():
    a = make_agent()
    decide(a, sec=sec_event(sec_prediction_set='["exfiltration"]'))     # the label says ransomware
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []


def test_health_event_flagged_not_scored_is_human():
    a = make_agent()
    decide(a, health=health_event(model_scored="false"))
    assert decisions(a) == ["human_patch"] and exec_requests(a) == []


def pair(a, **dcm):
    result = CorrelateResult(True, {"correlation_score": 0.84, "compound_flag": True,
                                    "causal_chain": ["DCM line"], **dcm})
    a.interp = StubInterp(result)
    decide(a, health=health_event(health_embedding_b64=emb(seed=1)),
           sec=sec_event(security_embedding_b64=emb(seed=2)))


# ---- V5-D3: correlation is compound_score, no DCM call by default ------------------------------------------
def test_without_a_dcm_a_paired_incident_still_decides_with_compound_score():
    from kubeheal.correlation import COMPOUND_THRESHOLD
    a = make_agent()                                   # dcm_url is empty: no DCM, no explain call
    decide(a, health=health_event(), sec=sec_event())
    assert a.interp.calls == 0 and decisions(a) == ["auto_contain"]
    scores = next(r["payload"] for r in ledger_steps(a) if r["step"] == "scores")
    assert scores["compound"] is True and scores["correlation_score"] >= COMPOUND_THRESHOLD
    assert scores["correlation_reasons"] and "same workload" in scores["correlation_reasons"][0]
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["models_ok"] is True and payload["compound"] is True
    assert payload["causal_chain"] and any(line.startswith("Correlation: ") for line in payload["causal_chain"])
    assert stream(a.redis, fusion.DCM_STREAM) == []             # only a legacy DCM answer is published
    assert exec_requests(a)[0]["action"] == "contain"
    ent = next(f for f in stream(a.redis, fusion.ACTIONS_STREAM))
    assert ent["compound"] == "True" and ent["nl_summary"]
    assert "\u2014" not in ent["nl_summary"]                    # plain sentence, no em dash


def test_a_missing_dcm_no_longer_makes_models_ok_false():
    a = make_agent(interp=StubInterp(CorrelateResult(False, error="DCM down")))     # never called: dcm_url empty
    decide(a, sec=sec_event())
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["models_ok"] is True and payload["model_issues"] == []


def test_a_weak_pair_is_not_compound():
    a = make_agent()
    decide(a, health=health_event(health_risk="0.05", health_label="benign",
                                  health_prediction_set='["benign"]'),
           sec=sec_event(sec_risk="0.2", sec_label="benign", sec_prediction_set='["benign"]'))
    scores = next(r["payload"] for r in ledger_steps(a) if r["step"] == "scores")
    assert scores["compound"] is False and decisions(a) == ["benign"]


@pytest.mark.parametrize("ev_kind", ["security", "health"])
def test_a_malformed_event_makes_models_ok_false_and_never_raises(ev_kind):
    a = make_agent()
    if ev_kind == "security":
        decide(a, health=health_event(), sec=sec_event(sec_risk="not-a-number"))
    else:
        decide(a, health=health_event(health_risk="not-a-number"), sec=sec_event())
    assert decisions(a)[0].startswith("human_") and exec_requests(a) == []
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert payload["models_ok"] is False and any("malformed" in i for i in payload["model_issues"])


# ---- legacy DCM path (only when DCM_URL is set) ---------------------------------------------------------------
def test_paired_events_with_a_dcm_answer_are_compound_and_contained():
    a = make_agent(legacy_dcm=True)
    pair(a)
    assert decisions(a) == ["auto_contain"]
    assert exec_requests(a)[0]["action"] == "contain"
    assert len(stream(a.redis, fusion.DCM_STREAM)) == 1


def test_missing_or_late_dcm_answer_is_human_not_a_zero_score():
    a = make_agent(interp=StubInterp(CorrelateResult(False, error="DCM call exceeded its deadline of 5.0s")),
                   legacy_dcm=True)
    decide(a, health=health_event(health_embedding_b64=emb(seed=1)),
           sec=sec_event(security_embedding_b64=emb(seed=2)))
    assert decisions(a)[0].startswith("human_") and exec_requests(a) == []
    payload = next(r["payload"] for r in ledger_steps(a) if r["step"] == "decision")
    assert "deadline" in payload["model_issues"][0]
    assert stream(a.redis, fusion.DCM_STREAM) == []


def test_paired_events_without_an_embedding_cannot_ask_the_dcm_and_go_to_a_human():
    a = make_agent(legacy_dcm=True)
    decide(a, health=health_event(), sec=sec_event())
    assert decisions(a)[0].startswith("human_") and a.interp.calls == 0


def test_a_late_interpretation_step_is_human():
    async def slow(health, sec):
        await asyncio.sleep(1)
        return {}
    a = make_agent(interp=StubInterp(explainer=slow), cfg=FusionConfig(interpretation_deadline_s=0.02),
                   legacy_dcm=True)
    decide(a, sec=sec_event())
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []


def test_a_failing_interpretation_step_is_human():
    def broken(health, sec):
        raise RuntimeError("explainer crashed")
    a = make_agent(interp=StubInterp(explainer=broken), legacy_dcm=True)
    decide(a, sec=sec_event())
    assert decisions(a) == ["human_contain"]


def test_mode_watcher_start_failure_keeps_safe_test_mode(caplog):
    async def broken_start(_core_api):
        raise RuntimeError("watch startup failed")

    a = make_agent()
    from agents.common.killswitch import ModeWatcher
    a.mode = ModeWatcher()
    a.mode.start = broken_start
    run(a._start_mode_watcher(object()))
    assert a.mode.mode_for("prod") == "test"
    assert "mode stays 'test'" in caplog.text


def test_single_signal_incident_needs_no_dcm_call():
    a = make_agent()
    decide(a, sec=sec_event())
    assert a.interp.calls == 0


def test_deadlines_are_configurable_and_labelled_chosen():
    c = FusionConfig.from_env({"DCM_DEADLINE_S": "2.5", "INTERPRETATION_DEADLINE_S": "1.5",
                               "OBSERVE_PERIOD_S": "bad"})
    assert (c.dcm_deadline_s, c.interpretation_deadline_s, c.observe_period_s) == (2.5, 1.5, 300)
    from pathlib import Path
    assert "chosen, not measured" in Path(fusion.FusionConfig.__module__.replace(".", "/") + ".py").read_text(
        encoding="utf-8")


# ---- S-POL-6: protected namespaces ------------------------------------------------------------------
def test_protected_label_means_human():
    a = make_agent(protected=True)
    decide(a, sec=sec_event())
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []
    assert "protected" in next(r["payload"]["rationale"] for r in ledger_steps(a) if r["step"] == "decision")


def test_unreadable_label_state_is_protected():
    a = make_agent()
    a.mode.ns_readable = False
    decide(a, sec=sec_event())
    assert decisions(a) == ["human_contain"] and exec_requests(a) == []


def test_unknown_namespace_is_protected():
    a = make_agent(namespaces=("dev",))
    decide(a, sec=sec_event())
    assert decisions(a) == ["human_contain"]


@pytest.mark.parametrize("value,protected", [(None, False), ("true", True), ("True", True), ("yes", True),
                                              ("false", False), ("FALSE", False)])
def test_protected_label_values(value, protected):
    from agents.common.killswitch import ModeWatcher
    from types import SimpleNamespace as NS
    w = ModeWatcher()
    w.ns_readable = True
    labels = {} if value is None else {"kubeheal/protected": value}
    w.apply_namespace(NS(metadata=NS(name="prod", labels=labels)))
    assert w.protected_for("prod") is protected


def test_namespace_watcher_protected_state_follows_the_watch():
    from agents.common.killswitch import ModeWatcher
    from types import SimpleNamespace as NS
    w = ModeWatcher()
    assert w.protected_for("prod") is True                       # nothing read yet
    w.ns_readable = True
    w.apply_namespace(NS(metadata=NS(name="prod", labels={"kubeheal/protected": "true"})))
    assert w.protected_for("prod") is True
    w.apply_namespace(NS(metadata=NS(name="prod", labels={})))   # label removed
    assert w.protected_for("prod") is False
    w.apply_namespace(NS(metadata=NS(name="prod", labels={})), deleted=True)
    assert w.protected_for("prod") is True                       # unknown again
    w.apply_namespace(NS(metadata=NS(name="dev", labels={})))
    w.ns_readable = False                                        # watch broke
    assert w.protected_for("dev") is True
    assert w.protected_for("") is True


# ---- S-POL-6: sliding window breakers ---------------------------------------------------------------
class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_breaker_is_a_sliding_window_not_a_fixed_ttl_counter():
    async def go():
        a = make_agent()
        clock = Clock()
        b = SlidingWindowBreaker(a.redis, "k", clock=clock)
        for i, dt in enumerate((0, 1800, 100)):
            clock.t += dt
            await b.record(f"inc-{i}")
        assert await b.count() == 3
        clock.t += 1700                    # 3600 s after the first action: only that one has left the window
        assert await b.count() == 2
        clock.t += 1800                    # the second leaves, the third stays
        assert await b.count() == 1
        clock.t += 100
        assert await b.count() == 0
    run(go())


def test_breaker_counts_an_incident_once():
    async def go():
        a = make_agent()
        b = SlidingWindowBreaker(a.redis, "k")
        await b.record("inc-1")
        await b.record("inc-1")             # redelivery
        assert await b.count() == 1
    run(go())


def test_the_fourth_containment_in_an_hour_goes_to_a_human_and_recovers_after_the_window():
    clock = Clock()
    a = make_agent(clock=clock)
    for i in range(CB_CONTAIN_LIMIT_PER_HOUR):
        run(a._decide("prod:payments", None, sec_event(event_id=f"sec-{i}", pod_name=f"payments-abc-{i}",
                                                       pid_target=str(100 + i))))
        clock.t += 60
    assert decisions(a) == ["auto_contain"] * CB_CONTAIN_LIMIT_PER_HOUR
    run(a._decide("prod:payments", None, sec_event(event_id="sec-x", pod_name="payments-abc-x", pid_target="9")))
    assert decisions(a)[-1] == "human_contain"
    assert "circuit breaker" in next(r["payload"]["rationale"] for r in reversed(ledger_steps(a))
                                     if r["step"] == "decision")
    clock.t += 3600                         # the whole window passes
    run(a._decide("prod:payments", None, sec_event(event_id="sec-y", pod_name="payments-abc-y", pid_target="8")))
    assert decisions(a)[-1] == "auto_contain"


def test_patch_breaker_is_per_deployment_and_counts_only_enforced_actions():
    clock = Clock()
    a = make_agent(clock=clock)
    for i in range(10):
        run(a._decide("prod:payments", health_event(event_id=f"h{i}", sec_risk="0") and
                      health_event(event_id=f"h{i}"), None))
    assert decisions(a) == ["auto_patch"] * 10
    run(a._decide("prod:payments", health_event(event_id="h-last"), None))
    assert decisions(a)[-1] == "human_patch"
    run(a._decide("prod:other", health_event(event_id="h-o", deployment="other"), None))
    assert decisions(a)[-1] == "auto_patch"                     # another Deployment has its own breaker
    # dry run (test mode) never uses the budget
    d = make_agent(enforce=False)
    for i in range(12):
        run(d._decide("prod:payments", health_event(event_id=f"h{i}"), None))
    assert set(decisions(d)) == {"auto_patch"} and d.redis.zsets == {}


def test_breaker_is_recorded_after_the_request_is_queued():
    a = make_agent()
    order = []
    real_xadd = a.redis.xadd

    async def spy_xadd(stream_name, fields, **kw):
        order.append(("xadd", stream_name))
        return await real_xadd(stream_name, fields, **kw)

    real_zadd = a.redis.zadd

    async def spy_zadd(key, mapping):
        order.append(("zadd", key))
        return await real_zadd(key, mapping)

    a.redis.xadd, a.redis.zadd = spy_xadd, spy_zadd
    decide(a, sec=sec_event())
    assert order.index(("xadd", fusion.EXEC_STREAM)) < order.index(("zadd", "kubeheal:cbw:contain:prod"))


# ---- S-POL-7: burn-in -------------------------------------------------------------------------------
def test_burn_in_counter_counts_each_health_sample_once_and_is_shared():
    async def go():
        a, b = make_agent(burn_in_over=False), make_agent(burn_in_over=False)
        b.redis = a.redis                                   # the second replica uses the same Redis
        for ev in ("h1", "h2", "h2", "h3"):                 # h2 delivered twice
            await fusion.BurnInCounter(a.redis).observe(ev)
        await fusion.BurnInCounter(b.redis).observe("h1")
        assert await BurnInCounter(a.redis).seen() == 3
        await BurnInCounter(a.redis).observe(None)
        assert await BurnInCounter(a.redis).seen() == 3
    run(go())


def test_the_counter_stops_growing_at_the_burn_in_limit():
    async def go():
        a = make_agent(burn_in_over=True)
        await BurnInCounter(a.redis).observe("one-more")
        assert await BurnInCounter(a.redis).seen() == BURN_IN_SAMPLES
    run(go())


def test_health_events_feed_the_counter_through_the_consume_path():
    a = make_agent(burn_in_over=False)
    for i in range(3):
        run(a._handle_entry(fusion.HEALTH_STREAM, f"{i}-0", health_event(event_id=f"h{i}", health_risk="0.1")))
    run(a._handle_entry(fusion.HEALTH_STREAM, "1-0", health_event(event_id="h1", health_risk="0.1")))
    assert len(a.redis.sets[BURN_IN_SEEN_KEY]) == 3


def test_decision_thresholds_follow_the_counter_not_only_the_env_var():
    # staging, sec_risk 0.90: above 0.85 but below the burn-in 0.95
    def contained(samples, forced=False):
        a = make_agent(burn_in_over=False, cfg=FusionConfig(burn_in_forced=forced))
        a.redis.sets[BURN_IN_SEEN_KEY] = {f"s{i}" for i in range(samples)}
        run(a._decide("staging:payments", None, sec_event(namespace="staging", namespace_tier="staging",
                                                           sec_risk="0.90")))
        return decisions(a)[-1]
    assert contained(BURN_IN_SAMPLES - 1) == "human_contain"
    assert contained(BURN_IN_SAMPLES) == "auto_contain"
    assert contained(10 * BURN_IN_SAMPLES, forced=True) == "human_contain"    # env var forces burn-in on


def test_unreadable_counter_means_burn_in():
    a = make_agent(burn_in_over=True)
    a.redis.fail["scard"] = RuntimeError("redis down")
    assert run(BurnInCounter(a.redis).seen()) is None
    run(a._decide("staging:payments", None, sec_event(namespace="staging", namespace_tier="staging",
                                                       sec_risk="0.90")))
    assert decisions(a)[-1] == "human_contain"


# ---- redelivery -------------------------------------------------------------------------------------
def test_incident_ids_are_deterministic_dns_labels():
    import re
    ev = sec_event()
    assert fusion.derive_incident_id(ev) == fusion.derive_incident_id(dict(ev))
    assert fusion.derive_incident_id(ev) != fusion.derive_incident_id(sec_event(event_id="sec-2"))
    iid = fusion.derive_incident_id(ev)
    assert re.match(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", iid) and len(iid) <= 63 and iid.startswith("inc-")


def test_a_replayed_entry_queues_one_request_and_counts_one_action():
    a = make_agent()
    ev = sec_event()
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    assert run(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True       # delivered again
    assert len(exec_requests(a)) == 1
    assert len(a.redis.zsets["kubeheal:cbw:contain:prod"]) == 1
    steps = [r["step"] for r in ledger_steps(a)]
    assert steps.count("detection") == 1 and steps.count("incident_update") == 1


def test_an_absent_partner_event_does_not_make_the_incident_uncertain():
    a = make_agent()
    decide(a, sec=sec_event())                 # no health event at all: its prediction set is not an input
    assert decisions(a) == ["auto_contain"]
