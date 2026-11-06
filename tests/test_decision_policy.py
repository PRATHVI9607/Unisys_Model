"""Decision policy table (docs/architecture.md, "Decision policy"). Thresholds live in decision_policy.py."""

import pytest

from agents.fusion_agent.decision_policy import adjusted_score, decide
from kubeheal.contracts import Decision, HealthEvent, SecurityEvent

D = Decision


def h(risk, label="critical", ns="staging", uncertain=False, has_baseline=True, failures=(), spec_changed=True):
    return HealthEvent(event_id="h1", namespace=ns, workload="web", label=label, risk=risk,
                       uncertain=uncertain, has_baseline=has_baseline, failure_reasons=list(failures),
                       spec_changed=spec_changed)


F = ("ImagePullBackOff",)
P = ("policy:privileged_added",)


def s(risk, label="ransomware", ns="staging", uncertain=False):
    return SecurityEvent(event_id="s1", namespace=ns, workload="web", pod="web-1", label=label, risk=risk,
                         uncertain=uncertain)


@pytest.mark.parametrize("health,security,compound,expected", [
    # AUTO_KILL
    (None, s(0.85), False, D.AUTO_KILL),                                  # boundary: adj == 0.85
    (None, s(0.80, ns="prod-shop"), False, D.AUTO_KILL),                  # tier prod 0.8*1.2 = 0.96
    (None, s(0.90, label="exfiltration"), False, D.AUTO_KILL),
    (h(0.9), s(0.80), True, D.AUTO_KILL),                                 # compound 0.8*1.15 = 0.92
    (None, s(0.80), False, D.HUMAN),                                      # same without compound
    (None, s(0.95, uncertain=True), False, D.HUMAN),                      # uncertain never auto-kills
    (None, s(0.95, label="suspicious"), False, D.HUMAN),                  # label not kill-eligible
    (None, s(0.95, ns="dev"), False, D.HUMAN),                            # tier dev 0.95*0.7 = 0.665
    # AUTO_PATCH
    (h(0.90), None, False, D.AUTO_PATCH),
    (h(0.90), s(0.30, label="benign"), False, D.AUTO_PATCH),              # security risk < 0.4
    (h(0.90), s(0.50, label="suspicious"), False, D.HUMAN),               # security risk >= 0.4 blocks patch
    (h(0.90, has_baseline=False), None, False, D.HUMAN),                  # nothing to restore
    (h(0.90, uncertain=True), None, False, D.HUMAN),
    (h(0.90, label="benign"), None, False, D.HUMAN),
    # AUTO_PATCH by rule: failed rollout, any tier, any model certainty/label
    (h(0.10, label="benign", ns="dev", failures=F), None, False, D.AUTO_PATCH),
    (h(0.50, uncertain=True, ns="default", failures=F), None, False, D.AUTO_PATCH),
    (h(0.30, ns="prod-shop", failures=F), s(0.39, label="benign"), False, D.AUTO_PATCH),
    (h(0.30, failures=F), s(0.40, label="suspicious"), False, D.OBSERVE),   # security risk >= 0.4 blocks
    (h(0.30, failures=F, has_baseline=False), None, False, D.BENIGN),         # nothing to restore
    (h(0.30, failures=F, spec_changed=False), None, False, D.BENIGN),         # not caused by a change
    (h(0.90, failures=F), s(0.95), False, D.AUTO_KILL),                       # kill still wins
    # AUTO_PATCH by rule: posture policy violation, same rails as a failed rollout
    (h(0.05, label="benign", ns="dev", failures=P), None, False, D.AUTO_PATCH),
    (h(0.50, uncertain=True, ns="prod-shop", failures=P), None, False, D.AUTO_PATCH),
    (h(0.30, failures=P), s(0.40, label="suspicious"), False, D.OBSERVE),   # security risk >= 0.4 blocks
    (h(0.30, failures=P, has_baseline=False), None, False, D.BENIGN),         # nothing to restore
    (h(0.30, failures=P, spec_changed=False), None, False, D.BENIGN),         # not caused by a change
    (h(0.30, failures=P), s(0.95), False, D.AUTO_KILL),                       # kill still wins
    # HUMAN / OBSERVE / BENIGN
    (h(0.70, label="degradation"), None, False, D.HUMAN),                 # >= 0.65
    (h(0.50, label="degradation", uncertain=True), None, False, D.HUMAN),  # uncertain and >= 0.4
    (h(0.30, label="degradation", uncertain=True), None, False, D.BENIGN),  # uncertain but < 0.4
    (h(0.50, label="degradation"), None, False, D.OBSERVE),
    (None, s(0.45, label="suspicious"), False, D.OBSERVE),
    (h(0.10, label="benign"), s(0.05, label="benign"), False, D.BENIGN),
])
def test_policy_table(health, security, compound, expected):
    r = decide(health, security, compound=compound)
    assert r.decision is expected, r.rationale
    assert r.rationale.startswith(expected.value + ":")
    assert 0.0 <= r.score <= 1.0


def test_score_capped_at_one():
    assert adjusted_score(0.95, "prod", compound=True) == 1.0          # 0.95*1.2*1.15 = 1.31
    assert decide(None, s(0.95, ns="prod"), compound=True).score == 1.0


def test_tier_multipliers():
    assert adjusted_score(0.5, "prod-eu", False) == pytest.approx(0.6)
    assert adjusted_score(0.5, "staging", False) == pytest.approx(0.5)
    assert adjusted_score(0.5, "default", False) == pytest.approx(0.35)


def test_tier_override_beats_the_name():
    assert decide(None, s(0.95, ns="demo")).decision is D.HUMAN                      # name → dev, 0.665
    r = decide(None, s(0.95, ns="demo"), tier="prod")                                # labelled prod
    assert r.decision is D.AUTO_KILL and "tier prod" in r.rationale


def test_rationale_explains_branch():
    r = decide(h(0.5, label="degradation", uncertain=True), None)
    assert "uncertain" in r.rationale and "0.4" in r.rationale
    r = decide(h(0.9), s(0.8), compound=True)
    assert "compound x1.15" in r.rationale and "tier staging" in r.rationale


def test_failed_rollout_rationale_names_the_reasons():
    r = decide(h(0.2, label="benign", uncertain=True, failures=("CrashLoopBackOff", "OOMKilled")), None)
    assert r.rationale.startswith("AUTO_PATCH: rule: failed rollout (CrashLoopBackOff, OOMKilled)")


@pytest.mark.parametrize("failures,expected", [
    (("policy:privileged_added", "policy:host_path_added"),
     "AUTO_PATCH: rule: policy violation (privileged_added, host_path_added), "),
    (("OOMKilled", "policy:root_user_added"),
     "AUTO_PATCH: rule: failed rollout (OOMKilled) + policy violation (root_user_added), "),
])
def test_policy_violation_rationale_says_policy_not_failed_rollout(failures, expected):
    assert decide(h(0.1, label="benign", failures=failures), None).rationale.startswith(expected)


def test_needs_an_event():
    with pytest.raises(ValueError):
        decide(None, None)

