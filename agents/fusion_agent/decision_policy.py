"""Fusion decision policy (docs/architecture.md, "Decision policy"). Pure: no I/O, no env.

Every threshold is a module constant; change them here and in
tests/test_decision_policy.py together.
"""

from __future__ import annotations

from dataclasses import dataclass

from kubeheal.contracts import POLICY_REASON_PREFIX, Decision, HealthEvent, SecurityEvent, namespace_tier

TIER_MULTIPLIER = {"prod": 1.2, "staging": 1.0, "dev": 0.7}
COMPOUND_MULTIPLIER = 1.15
KILL_MIN_SCORE = 0.85
KILL_LABELS = frozenset({"ransomware", "exfiltration"})
PATCH_MIN_SCORE = 0.85
PATCH_MAX_SECURITY_RISK = 0.4
HUMAN_MIN_SCORE = 0.65
UNCERTAIN_HUMAN_MIN_SCORE = 0.4
OBSERVE_MIN_SCORE = 0.4


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    score: float          # adjusted score that drove the decision, ≤ 1.0
    rationale: str


def adjusted_score(risk: float, namespace: str, compound: bool, tier: str | None = None) -> float:
    mult = TIER_MULTIPLIER[tier or namespace_tier(namespace)] * (COMPOUND_MULTIPLIER if compound else 1.0)
    return min(1.0, risk * mult)


def _describe(kind: str, ev, adj: float) -> str:
    flags = " uncertain" if ev.uncertain else ""
    if isinstance(ev, HealthEvent) and not ev.has_baseline:
        flags += " no-baseline"
    return f"{kind} {ev.label} risk {ev.risk:.2f} adj {adj:.2f}{flags}"


def decide(health: HealthEvent | None, security: SecurityEvent | None, compound: bool = False,
           tier: str | None = None) -> PolicyResult:
    """Decide on one event, or on a health+security pair of the same workload.

    tier: the namespace's tier when the caller knows it (namespace label); default: from the name.
    """
    if health is None and security is None:
        raise ValueError("decide() needs at least one event")
    ns = (health or security).namespace
    tier = tier or namespace_tier(ns)
    h_adj = adjusted_score(health.risk, ns, compound, tier) if health else 0.0
    s_adj = adjusted_score(security.risk, ns, compound, tier) if security else 0.0
    score = max(h_adj, s_adj)
    uncertain = any(e.uncertain for e in (health, security) if e is not None)

    signals = [_describe(k, e, a) for k, e, a in (("security", security, s_adj), ("health", health, h_adj)) if e]
    context = f"{'; '.join(signals)}; tier {tier} x{TIER_MULTIPLIER[tier]}"
    if compound:
        context += f", compound x{COMPOUND_MULTIPLIER}"

    def result(decision: Decision, s: float, why: str) -> PolicyResult:
        return PolicyResult(decision, round(s, 4), f"{decision.value}: {why} ({context})")

    if security and s_adj >= KILL_MIN_SCORE and security.label in KILL_LABELS and not security.uncertain:
        return result(Decision.AUTO_KILL, s_adj,
                      f"certain {security.label} with security adj {s_adj:.2f} >= {KILL_MIN_SCORE}")
    sec_risk = security.risk if security else 0.0
    # Kubernetes itself says the new spec cannot run, or the spec newly weakens security posture:
    # roll back in every tier, whatever the model's certainty.
    if (health and health.failure_reasons and health.spec_changed and health.has_baseline
            and sec_risk < PATCH_MAX_SECURITY_RISK):
        policy = [r.removeprefix(POLICY_REASON_PREFIX) for r in health.failure_reasons
                  if r.startswith(POLICY_REASON_PREFIX)]
        failed = [r for r in health.failure_reasons if not r.startswith(POLICY_REASON_PREFIX)]
        why = [f"{kind} ({', '.join(rs)})" for kind, rs in (("failed rollout", failed), ("policy violation", policy))
               if rs]
        return result(Decision.AUTO_PATCH, h_adj,
                      f"rule: {' + '.join(why)}, "
                      f"security risk {sec_risk:.2f} < {PATCH_MAX_SECURITY_RISK}, baseline available")
    if (health and h_adj >= PATCH_MIN_SCORE and health.label != "benign" and not health.uncertain
            and sec_risk < PATCH_MAX_SECURITY_RISK and health.has_baseline):
        return result(Decision.AUTO_PATCH, h_adj,
                      f"certain {health.label} drift with health adj {h_adj:.2f} >= {PATCH_MIN_SCORE}, "
                      f"security risk {sec_risk:.2f} < {PATCH_MAX_SECURITY_RISK}, baseline available")
    if score >= HUMAN_MIN_SCORE:
        return result(Decision.HUMAN, score,
                      f"max adj {score:.2f} >= {HUMAN_MIN_SCORE} but automatic-action conditions not met")
    if uncertain and score >= UNCERTAIN_HUMAN_MIN_SCORE:
        return result(Decision.HUMAN, score,
                      f"model uncertain (conformal set is not one label) with max adj {score:.2f} "
                      f">= {UNCERTAIN_HUMAN_MIN_SCORE}")
    if score >= OBSERVE_MIN_SCORE:
        return result(Decision.OBSERVE, score, f"max adj {score:.2f} >= {OBSERVE_MIN_SCORE}")
    return result(Decision.BENIGN, score, f"max adj {score:.2f} < {OBSERVE_MIN_SCORE}")
