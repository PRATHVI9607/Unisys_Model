"""V5-D4: the fields the Health Agent PUBLISHES are exactly what Fusion READS.

The events below are built by the real agent (fakes only for Kubernetes, Redis, Prometheus and the inference
service) and then run through agents/fusion_agent/event_mapping.to_health_event and the Fusion Agent itself."""
import asyncio
import json

from health_helpers import KEY, Env, dep, prediction
from fusion_helpers import health_event, make_agent, rule_health_event, set_security_score, stream
from fusion_helpers import ledger_steps
from agents.executor.validation import parse_request
from agents.fusion_agent import agent as fusion
from agents.fusion_agent import event_mapping as em


def run(coro):
    return asyncio.run(coro)


async def _published(change, result="scored", **env_kw):
    env = Env(**env_kw)
    env.result = prediction("degradation", 0.7) if result == "scored" else None
    await env.send("ADDED", dep())
    await env.send("MODIFIED", dep(**change))
    await env.tick(60 if "cpu" not in change else 0)
    await env.agent.stop()
    assert len(env.events) == 1
    return env.events[0]


def scored_event():
    return run(_published({"image": "img:2"}))


def rule_event():
    return run(_published({"cpu": "50m"}, result="down"))          # posture violation, no score


def notice_event():
    return run(_published({"image": "img:2"}, result="down"))      # no score, no rule evidence


def test_a_scored_event_maps_onto_the_health_event_contract():
    f = scored_event()
    ev = em.to_health_event(f, "prod", "victim-app")
    assert ev is not None
    assert (ev.label, ev.risk, ev.uncertain) == ("degradation", 0.7, False)
    assert ev.model_version == "test-bundle-1" and ev.event_id == f["event_id"] and ev.workload == "victim-app"
    assert ev.spec_changed is True and ev.has_baseline is True and ev.failure_reasons == []
    assert ev.changed_fields == ["template.spec.containers[0].image"]
    assert [x.feature for x in ev.top_factors] == ["cpu_limit_ratio"]
    assert json.loads(f["health_prediction_set"]) == ["degradation"]
    assert f["model_scored"] == "true" and f["health_uncertain"] == "false"
    assert f["top_field"] == "template.spec.containers[0].image"      # first changed field, not a model feature
    assert em.prediction_set(f, "health_prediction_set") == ["degradation"]


def test_a_rule_event_without_a_score_maps_and_says_model_unavailable():
    f = rule_event()
    ev = em.to_health_event(f, "prod", "victim-app")
    assert ev is not None and ev.failure_reasons == ["policy:cpu_cut_10x"]
    assert ev.spec_changed and ev.has_baseline and ev.risk == 0.0
    assert f["model_unavailable"] == "true" and f["model_scored"] == "false"
    assert em.prediction_set(f, "health_prediction_set") == []


def test_every_field_of_the_fusion_test_events_is_published():
    scored, rule = scored_event(), rule_event()
    assert set(health_event()) <= set(scored)
    # the rule helper carries the rule fields; the real rule event has all of them as well
    assert set(rule_health_event()) <= set(rule) | {"health_risk"}
    # every value is a string (Redis stream fields)
    for f in (scored, rule, notice_event()):
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in f.items())


def test_the_notice_has_no_score_and_no_rule_evidence():
    f = notice_event()
    assert f["model_unavailable"] == "true" and f["model_scored"] == "false"
    assert "health_risk" not in f and "failure_reasons_json" not in f and "health_embedding_b64" not in f
    assert f["health_prediction_set"] == "[]"


def test_the_outage_notice_reaches_a_human_through_fusion():
    f = notice_event()
    fa = make_agent()
    assert run(fa._handle_entry(fusion.HEALTH_STREAM, "1-0", f)) is True
    esc = stream(fa.redis, fusion.ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human" and esc[0]["deployment"] == "victim-app"
    assert stream(fa.redis, fusion.EXEC_STREAM) == []


def test_the_rule_event_reaches_an_executor_request_through_the_d3_rule_path():
    f = rule_event()
    fa = make_agent()
    set_security_score(fa, workload="victim-app", sec_risk="0.05")
    assert run(fa._handle_entry(fusion.HEALTH_STREAM, "1-0", f)) is True
    steps = ledger_steps(fa)
    decision = next(r["payload"] for r in steps if r["step"] == "decision")
    assert decision["decision"] == "auto_patch" and decision["rule_path"] is True
    assert decision["rule_reasons"] == ["policy:cpu_cut_10x"]
    [req] = stream(fa.redis, fusion.EXEC_STREAM)
    assert req["action"] == "patch" and req["rule_path"] == "true"
    assert json.loads(req["patch_fields"]) == ["template.spec.containers[0].resources.limits.cpu"]
    assert req["patch_field"] == "template.spec.containers[0].resources.limits.cpu"
    assert stream(fa.redis, fusion.ESCALATIONS_STREAM) == []


def test_a_scored_event_passes_fusions_model_scored_check_and_the_set_gate():
    f = scored_event()
    fa = make_agent()
    run(fa._decide("prod:victim-app", dict(f), None))
    decision = next(r["payload"] for r in ledger_steps(fa) if r["step"] == "decision")
    assert decision["models_ok"] is True and decision["model_issues"] == []
    assert decision["health_prediction_set"] == ["degradation"]


def test_a_two_label_set_is_uncertain_for_fusion():
    async def go():
        env = Env()
        env.result = prediction("degradation", 0.95, pset=["degradation", "critical"], uncertain=True)
        await env.send("ADDED", dep())
        await env.send("MODIFIED", dep(image="img:2"))
        await env.tick(60)
        await env.agent.stop()
        return env.events[0]
    f = run(go())
    assert f["health_uncertain"] == "true"
    fa = make_agent()
    run(fa._decide("prod:victim-app", dict(f), None))
    decision = next(r["payload"] for r in ledger_steps(fa) if r["step"] == "decision")
    assert decision["decision"] not in ("auto_patch",)


def test_a_follow_up_event_maps_with_the_late_failure_reasons():
    from health_helpers import failing_pod

    async def go():
        env = Env()
        await env.send("ADDED", dep())
        await env.send("MODIFIED", dep(image="img:2", rolled_out=False))
        await env.tick(60)
        env.core.pods = [failing_pod(env.clock.wall() - 30)]
        await env.tick(2)
        await env.tick(2)
        await env.agent.stop()
        return env.events
    first, follow = run(go())
    ev = em.to_health_event(follow, "prod", "victim-app")
    assert ev is not None and ev.failure_reasons == ["ImagePullBackOff"] and ev.event_id != first["event_id"]
    assert ev.risk == em.to_health_event(first, "prod", "victim-app").risk
