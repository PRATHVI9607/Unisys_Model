from kubeheal.contracts import HealthEvent, SecurityEvent
from kubeheal.correlation import COMPOUND_THRESHOLD, CORRELATION_WINDOW_S, compound_score

T0 = 1_800_000_000_000


def health(**kw) -> HealthEvent:
    base = dict(event_id="h1", namespace="shop-prod", workload="api", timestamp_ms=T0, label="degradation", risk=0.6,
                changed_fields=["template.metadata.annotations.note"],
                features={"cpu_util_max": 0.95, "mem_util_max": 0.4})
    return HealthEvent(**(base | kw))


def security(**kw) -> SecurityEvent:
    base = dict(event_id="s1", namespace="shop-prod", workload="api", pod="api-1", timestamp_ms=T0 + 30_000,
                window_start_ms=T0 - 20_000, label="ransomware", risk=0.95, features={"files_written_per_s": 12.0})
    return SecurityEvent(**(base | kw))


def test_compound_attack_crosses_threshold_with_reasons():
    score, reasons = compound_score(health(), security())
    assert score >= COMPOUND_THRESHOLD
    assert any("not explained" in r for r in reasons) and any("started before" in r for r in reasons)


def test_deterministic():
    assert compound_score(health(), security()) == compound_score(health(), security())


def test_different_workload_or_far_apart_is_zero():
    assert compound_score(health(), security(workload="db")) == (0.0, [])
    assert compound_score(health(), security(namespace="other")) == (0.0, [])
    far = T0 + (CORRELATION_WINDOW_S + 1) * 1000
    assert compound_score(health(), security(timestamp_ms=far)) == (0.0, [])


def test_one_strong_signal_alone_never_compounds():
    benign_health = health(label="benign", risk=0.05)
    assert compound_score(benign_health, security())[0] < COMPOUND_THRESHOLD
    quiet_security = security(label="benign", risk=0.05, features={})
    assert compound_score(health(risk=0.95, label="critical"), quiet_security)[0] < COMPOUND_THRESHOLD


def test_config_explained_degradation_scores_lower():
    explained = health(changed_fields=["template.spec.containers[0].resources.limits.cpu"])
    assert compound_score(explained, security())[0] < compound_score(health(), security())[0]
