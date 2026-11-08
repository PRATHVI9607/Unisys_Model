from kubeheal.contracts import (
    ActionEvent,
    Decision,
    Factor,
    HealthEvent,
    SecurityEvent,
    new_event_id,
)


def _roundtrip(ev):
    fields = ev.to_fields()
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in fields.items())
    # Redis returns bytes
    back = type(ev).from_fields({k.encode(): v.encode() for k, v in fields.items()})
    assert back == ev
    return back


def test_health_event_roundtrip():
    _roundtrip(HealthEvent(
        event_id=new_event_id("h"), namespace="shop-prod", workload="web",
        label="critical", risk=0.91, uncertain=True,
        probabilities={"benign": 0.05, "degradation": 0.04, "critical": 0.91},
        top_factors=[Factor(feature="cpu_limit_ratio", value=0.1, contribution=1.2)],
        features={"cpu_limit_ratio": 0.1, "latency_p99_max_s": None},
        changed_fields=["spec.template.spec.containers[0].resources.limits.cpu"],
        has_baseline=True, failure_reasons=["CrashLoopBackOff", "OOMKilled"],
    ))
    # Additive field: an event from an older agent (no failure_reasons) still decodes.
    old = HealthEvent(event_id="h-0", namespace="a", workload="b", label="benign", risk=0.1).to_fields()
    del old["failure_reasons"]
    assert HealthEvent.from_fields(old).failure_reasons == []


def test_security_and_action_roundtrip():
    s = _roundtrip(SecurityEvent(event_id="s-1", namespace="dev", workload="api", pod="api-7d9-x",
                                 label="ransomware", risk=0.97, n_events=212))
    assert s.uncertain is False
    a = _roundtrip(ActionEvent(event_id="a-1", namespace="dev", workload="api", decision=Decision.AUTO_KILL,
                               mode="observe", outcome="would_kill", score=0.97, rationale="r"))
    assert a.decision is Decision.AUTO_KILL
