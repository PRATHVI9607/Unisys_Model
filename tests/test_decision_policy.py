"""
Decision policy unit tests — KubeHeal v4 (PRD Section 07 mandates 20+ cases,
full branch coverage over thresholds, tiers, compound, burn-in, circuit breakers).
Run: PYTHONPATH=. pytest tests/test_decision_policy.py -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.fusion_agent.decision_policy import (
    make_decision, DecisionInput, Decision,
    Thresholds, TIER_MULTIPLIERS, COMPOUND_ESCALATION,
    CB_CONTAIN_LIMIT_PER_HOUR, CB_PATCH_LIMIT_PER_HOUR, BURN_IN_SAMPLES,
)

# P6: the policy fails closed on missing inputs, so the base case states them explicitly: all models
# answered, namespace known to be unprotected, burn-in over. Tests for the new rules live in
# tests/test_policy_rules.py.
OK = dict(models_ok=True, namespace_protected=False, metric_samples_seen=BURN_IN_SAMPLES,
          namespace_tier="staging")


def D(**kw):
    return make_decision(DecisionInput(**{**OK, **kw}))


# ── BENIGN / OBSERVE ────────────────────────────────────────
def test_benign_all_low():
    assert D(health_risk=0.1, sec_risk=0.1).decision == Decision.BENIGN

def test_observe_low_band():
    o = D(health_risk=0.45, sec_risk=0.0, namespace_tier="staging")
    assert o.decision == Decision.OBSERVE

def test_benign_boundary_just_under_observe():
    assert D(health_risk=0.39, sec_risk=0.0).decision == Decision.BENIGN


# ── HUMAN APPROVAL ZONE ─────────────────────────────────────
def test_human_zone_health_leaning():
    o = D(health_risk=0.70, sec_risk=0.0, namespace_tier="staging")
    assert o.decision == Decision.HUMAN_PATCH

def test_human_zone_security_leaning():
    o = D(health_risk=0.0, sec_risk=0.70, namespace_tier="staging")
    assert o.decision == Decision.HUMAN_CONTAIN


# ── HEALTH-ONLY AUTO-PATCH ──────────────────────────────────
def test_health_auto_patch_prod():
    o = D(health_risk=0.79, sec_risk=0.11, namespace_tier="prod", health_field_top="cpu")
    assert o.decision == Decision.AUTO_PATCH
    assert o.action_params.get("patch_field") == "cpu"

def test_health_no_autopatch_when_sec_elevated():
    # sec_risk >= 0.4 blocks the health-only path → falls to human zone
    o = D(health_risk=0.95, sec_risk=0.45, namespace_tier="prod")
    assert o.decision in (Decision.HUMAN_PATCH, Decision.HUMAN_CONTAIN)

def test_health_patch_cb_limit_escalates():
    o = D(health_risk=0.95, sec_risk=0.0, namespace_tier="prod",
          circuit_breaker_patches=CB_PATCH_LIMIT_PER_HOUR)
    assert o.decision == Decision.HUMAN_PATCH

def test_health_patch_wide_ci_escalates():
    o = D(health_risk=0.95, sec_risk=0.0, namespace_tier="prod", health_ci_width=0.2)
    assert o.decision == Decision.HUMAN_PATCH


# ── SECURITY-ONLY AUTO-CONTAIN ─────────────────────────────────
def test_security_auto_contain():
    o = D(sec_risk=0.90, namespace_tier="staging")
    assert o.decision == Decision.AUTO_CONTAIN
    assert o.action_params.get("compound") is False

def test_security_contain_cb_limit_escalates():
    o = D(sec_risk=0.95, namespace_tier="prod", circuit_breaker_containments=CB_CONTAIN_LIMIT_PER_HOUR)
    assert o.decision == Decision.HUMAN_CONTAIN

def test_security_contain_wide_ci_escalates():
    o = D(sec_risk=0.95, namespace_tier="prod", sec_ci_width=0.3)
    assert o.decision == Decision.HUMAN_CONTAIN


# ── COMPOUND ────────────────────────────────────────────────
def test_compound_auto_contain():
    o = D(health_risk=0.88, sec_risk=0.93, correlation_score=0.84,
          compound_flag=True, namespace_tier="prod")
    assert o.decision == Decision.AUTO_CONTAIN
    assert o.action_params.get("compound") is True
    # 0.93 * 1.20 * 1.15 ≈ 1.28
    assert o.adjusted_score > 1.2

def test_compound_escalation_applied():
    base = D(sec_risk=0.80, namespace_tier="staging", compound_flag=False)
    comp = D(sec_risk=0.80, namespace_tier="staging", compound_flag=True, correlation_score=0.7)
    assert comp.adjusted_score > base.adjusted_score

def test_compound_wide_ci_human():
    o = D(health_risk=0.88, sec_risk=0.93, compound_flag=True,
          correlation_score=0.84, namespace_tier="prod", sec_ci_width=0.25)
    assert o.decision == Decision.HUMAN_CONTAIN

def test_compound_cb_limit_human():
    o = D(health_risk=0.88, sec_risk=0.93, compound_flag=True, correlation_score=0.84,
          namespace_tier="prod", circuit_breaker_containments=CB_CONTAIN_LIMIT_PER_HOUR)
    assert o.decision == Decision.HUMAN_CONTAIN


# ── TIER MULTIPLIERS ────────────────────────────────────────
def test_dev_tier_dampens():
    o = D(health_risk=0.72, sec_risk=0.0, namespace_tier="dev")
    # 0.72 * 0.70 = 0.504 → observe, not auto-patch
    assert o.decision == Decision.OBSERVE

def test_prod_tier_amplifies_to_autocontain():
    # 0.72 * 1.20 = 0.864 ≥ 0.85 auto-contain
    o = D(sec_risk=0.72, namespace_tier="prod")
    assert o.decision == Decision.AUTO_CONTAIN

def test_unknown_tier_is_scored_with_the_highest_multiplier_but_never_acts():
    for tier in ("weird", "production", "unknown", "", None):
        o = D(sec_risk=0.80, namespace_tier=tier)
        assert o.adjusted_score == pytest.approx(0.80 * max(TIER_MULTIPLIERS.values()))
        assert o.decision == Decision.HUMAN_CONTAIN and o.requires_incident_lock
        assert "tier is unknown" in o.rationale
    # the same score on a known tier acts automatically only when the tier is "prod" or "staging"
    assert D(sec_risk=0.86, namespace_tier="staging").decision == Decision.AUTO_CONTAIN
    # a health incident of an unknown tier is also at most a human patch
    h = D(health_risk=0.80, namespace_tier="weird")
    assert h.decision == Decision.HUMAN_PATCH and "tier is unknown" in h.rationale


def test_a_missing_tier_defaults_to_unknown_not_to_staging():
    assert DecisionInput().namespace_tier == "unknown"
    o = make_decision(DecisionInput(sec_risk=0.99, models_ok=True, namespace_protected=False,
                                    metric_samples_seen=BURN_IN_SAMPLES, mode="enforce"))
    assert o.decision == Decision.HUMAN_CONTAIN


def test_prod_and_production_no_longer_differ_silently():
    prod = D(sec_risk=0.80, namespace_tier="prod")
    production = D(sec_risk=0.80, namespace_tier="production")
    assert prod.decision == Decision.AUTO_CONTAIN
    assert production.decision == Decision.HUMAN_CONTAIN        # unknown: scored at 1.20 but never automatic
    assert production.adjusted_score == pytest.approx(prod.adjusted_score)


# ── BURN-IN MODE ────────────────────────────────────────────
def test_burn_in_raises_kill_threshold():
    # 0.90 * 1.0 = 0.90 < 0.95 burn-in kill threshold → not auto-contain
    o = D(sec_risk=0.90, namespace_tier="staging", burn_in_mode=True)
    assert o.decision != Decision.AUTO_CONTAIN

def test_burn_in_kill_above_threshold():
    o = D(sec_risk=0.97, namespace_tier="staging", burn_in_mode=True)
    assert o.decision == Decision.AUTO_CONTAIN

def test_burn_in_patch_threshold():
    # 0.88 < 0.90 burn-in patch threshold
    o = D(health_risk=0.88, sec_risk=0.0, namespace_tier="staging", burn_in_mode=True)
    assert o.decision != Decision.AUTO_PATCH


# ── RATIONALE + LOCK FLAGS ──────────────────────────────────
def test_rationale_present_everywhere():
    for kw in [dict(health_risk=0.1, sec_risk=0.1),
               dict(sec_risk=0.9),
               dict(health_risk=0.9, sec_risk=0.0),
               dict(health_risk=0.5)]:
        assert D(**kw).rationale

def test_autocontain_requires_lock():
    assert D(sec_risk=0.9).requires_incident_lock is True

def test_observe_no_lock():
    assert D(health_risk=0.45).requires_incident_lock is False
