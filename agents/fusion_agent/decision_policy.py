"""
Fusion Agent v4 — Three-Signal Decision Policy (PRD Section 07)
===============================================================
Pure function: (health_risk, sec_risk, correlation_score, context) → Decision.
No side effects, no I/O — fully testable and auditable. Single source of truth
for every KubeHeal action.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Decision(Enum):
    AUTO_KILL = "auto_kill"
    AUTO_PATCH = "auto_patch"
    HUMAN_KILL = "human_kill"
    HUMAN_PATCH = "human_patch"
    OBSERVE = "observe"
    BENIGN = "benign"


@dataclass
class DecisionInput:
    health_risk: float = 0.0
    health_label: str = "benign"
    health_ci_width: float = 0.0
    health_field_top: str = ""

    sec_risk: float = 0.0
    sec_label: str = "benign"
    sec_ci_width: float = 0.0
    sec_syscall_top: str = ""

    correlation_score: float = 0.0
    compound_flag: bool = False

    namespace_tier: str = "staging"
    circuit_breaker_kills: int = 0
    circuit_breaker_patches: int = 0

    burn_in_mode: bool = False
    nl_summary: Optional[str] = None


@dataclass
class DecisionOutput:
    decision: Decision
    adjusted_score: float
    rationale: str
    requires_incident_lock: bool
    action_params: dict = field(default_factory=dict)


TIER_MULTIPLIERS = {"prod": 1.20, "staging": 1.00, "dev": 0.70}
COMPOUND_ESCALATION = 1.15
CB_KILL_LIMIT_PER_HOUR = 3
CB_PATCH_LIMIT_PER_HOUR = 10


class Thresholds:
    RANSOMWARE_DIRECT_KILL = 0.98
    AUTO_KILL = 0.85
    AUTO_PATCH = 0.85
    HUMAN_APPROVAL = 0.65
    OBSERVE = 0.40
    BURN_IN_AUTO_KILL = 0.95
    BURN_IN_AUTO_PATCH = 0.90


def make_decision(inp: DecisionInput) -> DecisionOutput:
    t = Thresholds()
    tier_mult = TIER_MULTIPLIERS.get(inp.namespace_tier, 1.00)

    health_adjusted = inp.health_risk * tier_mult
    sec_adjusted = inp.sec_risk * tier_mult

    if inp.compound_flag:
        health_adjusted *= COMPOUND_ESCALATION
        sec_adjusted *= COMPOUND_ESCALATION

    auto_kill_t = t.BURN_IN_AUTO_KILL if inp.burn_in_mode else t.AUTO_KILL
    auto_patch_t = t.BURN_IN_AUTO_PATCH if inp.burn_in_mode else t.AUTO_PATCH

    ci_uncertain = (inp.health_ci_width > 0.15 or inp.sec_ci_width > 0.15)
    params = {"nl_summary": inp.nl_summary}

    # ── COMPOUND INCIDENT ───────────────────────────────────
    if inp.compound_flag and sec_adjusted >= auto_kill_t:
        if ci_uncertain:
            return DecisionOutput(Decision.HUMAN_KILL, sec_adjusted,
                f"Compound incident but CI too wide (health_ci={inp.health_ci_width:.2f}, "
                f"sec_ci={inp.sec_ci_width:.2f}). Human approval required.", True, params)
        if inp.circuit_breaker_kills >= CB_KILL_LIMIT_PER_HOUR:
            return DecisionOutput(Decision.HUMAN_KILL, sec_adjusted,
                f"Compound incident. Circuit breaker: {inp.circuit_breaker_kills} kills this "
                f"hour, limit {CB_KILL_LIMIT_PER_HOUR}. Human approval required.", True, params)
        return DecisionOutput(Decision.AUTO_KILL, sec_adjusted,
            f"Compound incident (DCM corr={inp.correlation_score:.2f}): "
            f"sec_risk={inp.sec_risk:.2f}, health_risk={inp.health_risk:.2f}. "
            f"Tier={inp.namespace_tier}. AUTO-KILL.", True,
            {"compound": True, "nl_summary": inp.nl_summary})

    # ── SECURITY-ONLY ───────────────────────────────────────
    if sec_adjusted >= auto_kill_t and not inp.compound_flag:
        if ci_uncertain or inp.circuit_breaker_kills >= CB_KILL_LIMIT_PER_HOUR:
            return DecisionOutput(Decision.HUMAN_KILL, sec_adjusted,
                "Security incident. CI uncertainty or CB limit. Human approval.", True, params)
        return DecisionOutput(Decision.AUTO_KILL, sec_adjusted,
            f"Security incident. sec_risk={inp.sec_risk:.2f}, label={inp.sec_label}. AUTO-KILL.",
            True, {"compound": False, "nl_summary": inp.nl_summary})

    # ── HEALTH-ONLY (security calm) ─────────────────────────
    if health_adjusted >= auto_patch_t and inp.sec_risk < 0.4:
        if ci_uncertain or inp.circuit_breaker_patches >= CB_PATCH_LIMIT_PER_HOUR:
            return DecisionOutput(Decision.HUMAN_PATCH, health_adjusted,
                "Health incident. CI uncertainty or CB limit. Human approval.", True, params)
        return DecisionOutput(Decision.AUTO_PATCH, health_adjusted,
            f"Health incident. health_risk={inp.health_risk:.2f}, "
            f"top_field={inp.health_field_top}. AUTO-PATCH.", True,
            {"patch_field": inp.health_field_top, "nl_summary": inp.nl_summary})

    # ── HUMAN APPROVAL ZONE ─────────────────────────────────
    if max(health_adjusted, sec_adjusted) >= t.HUMAN_APPROVAL:
        dec = Decision.HUMAN_PATCH if health_adjusted > sec_adjusted else Decision.HUMAN_KILL
        return DecisionOutput(dec, max(health_adjusted, sec_adjusted),
            f"Medium confidence. health_adj={health_adjusted:.2f}, "
            f"sec_adj={sec_adjusted:.2f}. Human approval.", False, params)

    # ── OBSERVE ─────────────────────────────────────────────
    if max(health_adjusted, sec_adjusted) >= t.OBSERVE:
        return DecisionOutput(Decision.OBSERVE, max(health_adjusted, sec_adjusted),
            f"Low signal. Increasing monitoring x3. health_adj={health_adjusted:.2f}, "
            f"sec_adj={sec_adjusted:.2f}.", False, {})

    # ── BENIGN ──────────────────────────────────────────────
    return DecisionOutput(Decision.BENIGN, max(health_adjusted, sec_adjusted),
        "Benign signal. XACK and continue.", False, {})
