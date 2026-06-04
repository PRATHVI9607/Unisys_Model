"""
Decision policy unit tests — KubeHeal v4 (PRD Section 07 mandates 20+ cases,
full branch coverage over thresholds, tiers, compound, burn-in, circuit breakers).
Run: PYTHONPATH=. pytest tests/test_decision_policy.py -q
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.fusion_agent.decision_policy import (
    make_decision, DecisionInput, Decision,
    Thresholds, TIER_MULTIPLIERS, COMPOUND_ESCALATION,
    CB_KILL_LIMIT_PER_HOUR, CB_PATCH_LIMIT_PER_HOUR,
)


def D(**kw):
    return make_decision(DecisionInput(**kw))


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
    assert o.decision == Decision.HUMAN_KILL


# ── HEALTH-ONLY AUTO-PATCH ──────────────────────────────────
def test_health_auto_patch_prod():
    o = D(health_risk=0.79, sec_risk=0.11, namespace_tier="prod", health_field_top="cpu")
    assert o.decision == Decision.AUTO_PATCH
    assert o.action_params.get("patch_field") == "cpu"

def test_health_no_autopatch_when_sec_elevated():
    # sec_risk >= 0.4 blocks the health-only path → falls to human zone
    o = D(health_risk=0.95, sec_risk=0.45, namespace_tier="prod")
    assert o.decision in (Decision.HUMAN_PATCH, Decision.HUMAN_KILL)

def test_health_patch_cb_limit_escalates():
    o = D(health_risk=0.95, sec_risk=0.0, namespace_tier="prod",
          circuit_breaker_patches=CB_PATCH_LIMIT_PER_HOUR)
    assert o.decision == Decision.HUMAN_PATCH

def test_health_patch_wide_ci_escalates():
    o = D(health_risk=0.95, sec_risk=0.0, namespace_tier="prod", health_ci_width=0.2)
    assert o.decision == Decision.HUMAN_PATCH


# ── SECURITY-ONLY AUTO-KILL ─────────────────────────────────
def test_security_auto_kill():
    o = D(sec_risk=0.90, namespace_tier="staging")
    assert o.decision == Decision.AUTO_KILL
    assert o.action_params.get("compound") is False

def test_security_kill_cb_limit_escalates():
    o = D(sec_risk=0.95, namespace_tier="prod", circuit_breaker_kills=CB_KILL_LIMIT_PER_HOUR)
    assert o.decision == Decision.HUMAN_KILL

def test_security_kill_wide_ci_escalates():
    o = D(sec_risk=0.95, namespace_tier="prod", sec_ci_width=0.3)
    assert o.decision == Decision.HUMAN_KILL


# ── COMPOUND ────────────────────────────────────────────────
def test_compound_auto_kill():
    o = D(health_risk=0.88, sec_risk=0.93, correlation_score=0.84,
          compound_flag=True, namespace_tier="prod")
    assert o.decision == Decision.AUTO_KILL
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
    assert o.decision == Decision.HUMAN_KILL

def test_compound_cb_limit_human():
    o = D(health_risk=0.88, sec_risk=0.93, compound_flag=True, correlation_score=0.84,
          namespace_tier="prod", circuit_breaker_kills=CB_KILL_LIMIT_PER_HOUR)
    assert o.decision == Decision.HUMAN_KILL


# ── TIER MULTIPLIERS ────────────────────────────────────────
def test_dev_tier_dampens():
    o = D(health_risk=0.72, sec_risk=0.0, namespace_tier="dev")
    # 0.72 * 0.70 = 0.504 → observe, not auto-patch
    assert o.decision == Decision.OBSERVE

def test_prod_tier_amplifies_to_autokill():
    # 0.72 * 1.20 = 0.864 ≥ 0.85 auto-kill
    o = D(sec_risk=0.72, namespace_tier="prod")
    assert o.decision == Decision.AUTO_KILL

def test_unknown_tier_defaults_to_1x():
    o = D(sec_risk=0.86, namespace_tier="weird")
    assert o.decision == Decision.AUTO_KILL


# ── BURN-IN MODE ────────────────────────────────────────────
def test_burn_in_raises_kill_threshold():
    # 0.90 * 1.0 = 0.90 < 0.95 burn-in kill threshold → not auto-kill
    o = D(sec_risk=0.90, namespace_tier="staging", burn_in_mode=True)
    assert o.decision != Decision.AUTO_KILL

def test_burn_in_kill_above_threshold():
    o = D(sec_risk=0.97, namespace_tier="staging", burn_in_mode=True)
    assert o.decision == Decision.AUTO_KILL

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
        assert make_decision(DecisionInput(**kw)).rationale

def test_autokill_requires_lock():
    assert D(sec_risk=0.9).requires_incident_lock is True

def test_observe_no_lock():
    assert D(health_risk=0.45).requires_incident_lock is False
