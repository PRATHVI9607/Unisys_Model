"""
Fusion Agent v4 - Three-Signal Decision Policy (spec section 2, S-POL-1 .. S-POL-7)
==================================================================================
Pure function: DecisionInput -> DecisionOutput. No I/O, no clock, no Redis, no environment: time based
facts (circuit breaker counts, the burn-in sample counter, the kill-switch mode, the namespace label state,
whether the models answered in time) are computed by the caller and come in as inputs.

Fail closed: every input that is missing, unknown or invalid leads to HUMAN, never to an automatic action.
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Decision(Enum):
    AUTO_CONTAIN = "auto_contain"
    AUTO_PATCH = "auto_patch"
    HUMAN_CONTAIN = "human_contain"
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
    # Circuit breaker counts (S-POL-6): enforced actions inside the last hour. The caller counts them
    # with a sliding window; the policy never reads a clock.
    circuit_breaker_containments: int = 0
    circuit_breaker_patches: int = 0

    # S-POL-1: True only when EVERY model response this decision needs arrived inside its deadline.
    # The default is False so that a caller that forgets to set it gets HUMAN, never an automatic action.
    models_ok: bool = False

    # S-POL-6: namespace label kubeheal/protected. The default is True (unknown means protected); the
    # caller passes False only when the label state was read and the namespace is not protected.
    namespace_protected: bool = True

    # S-POL-7: burn-in lasts until BURN_IN_SAMPLES metric samples were seen. The caller passes the real
    # counter. None (counter unreadable or not supplied) means burn-in, the stricter thresholds.
    # `burn_in_mode` can only force burn-in on, never off.
    metric_samples_seen: Optional[int] = None
    burn_in_mode: bool = False
    nl_summary: Optional[str] = None

    # Kill switch (P3): the mode is an input, the policy stays pure. Anything other than
    # exactly "enforce" is a dry run, so the safe value is also the default.
    mode: str = "test"


@dataclass
class DecisionOutput:
    decision: Decision
    adjusted_score: float
    rationale: str
    requires_incident_lock: bool
    action_params: dict = field(default_factory=dict)
    dry_run: bool = True


TIER_MULTIPLIERS = {"prod": 1.20, "staging": 1.00, "dev": 0.70}
COMPOUND_ESCALATION = 1.15
CB_CONTAIN_LIMIT_PER_HOUR = 3
CB_PATCH_LIMIT_PER_HOUR = 10
CI_WIDTH_LIMIT = 0.15             # S-POL-6: both CI widths must be <= this for an automatic action
BURN_IN_SAMPLES = 2000            # S-POL-7
RAW_SEC_RISK_PATCH_CEILING = 0.4  # S-POL-4: a health patch needs the raw security risk below this


class Thresholds:
    AUTO_CONTAIN = 0.85
    AUTO_PATCH = 0.85
    HUMAN_APPROVAL = 0.65
    OBSERVE = 0.40
    BURN_IN_AUTO_CONTAIN = 0.95
    BURN_IN_AUTO_PATCH = 0.90


def make_decision(inp: DecisionInput) -> DecisionOutput:
    """Pure. The decision itself does not depend on the mode (Sense, Score and Decide always run);
    the result carries `dry_run` so every later step knows no write may happen."""
    out = _decide(inp)
    out.dry_run = str(inp.mode).strip().lower() != "enforce"
    return out


def _finite(*values) -> bool:
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            return False
    return True


def burn_in_active(inp: DecisionInput) -> bool:
    """True until BURN_IN_SAMPLES samples were seen. The flag can only force burn-in on."""
    n = inp.metric_samples_seen
    if inp.burn_in_mode or n is None or isinstance(n, bool) or not isinstance(n, int):
        return True
    return n < BURN_IN_SAMPLES


def _ci_ok(width) -> bool:
    """NaN, negative and non-numeric widths count as uncertain (a plain `width > limit` accepts NaN)."""
    return _finite(width) and 0.0 <= width <= CI_WIDTH_LIMIT


def _breaker_closed(count, limit: int) -> bool:
    """A count that is not a non-negative int is treated as an open breaker."""
    return isinstance(count, int) and not isinstance(count, bool) and 0 <= count < limit


def _decide(inp: DecisionInput) -> DecisionOutput:
    t = Thresholds()
    tier_mult = TIER_MULTIPLIERS.get(inp.namespace_tier, 1.00)

    # Invalid numeric input is never trusted.
    if not _finite(inp.health_risk, inp.sec_risk):
        return DecisionOutput(Decision.HUMAN_CONTAIN, 0.0,
            "Invalid risk input (not a finite number). Human approval required.", False, {})

    health_adjusted = inp.health_risk * tier_mult
    sec_adjusted = inp.sec_risk * tier_mult
    if inp.compound_flag:
        health_adjusted *= COMPOUND_ESCALATION
        sec_adjusted *= COMPOUND_ESCALATION

    params = {"nl_summary": inp.nl_summary}
    top = max(health_adjusted, sec_adjusted)

    # S-POL-1: a missing or late model response means a human decides, whatever the scores say.
    if inp.models_ok is not True:
        dec = Decision.HUMAN_PATCH if health_adjusted > sec_adjusted else Decision.HUMAN_CONTAIN
        return DecisionOutput(dec, top,
            "A model response is missing or late (models_ok is not true). Fail closed: human "
            "approval required.", False, params)

    burn_in = burn_in_active(inp)
    auto_contain_t = t.BURN_IN_AUTO_CONTAIN if burn_in else t.AUTO_CONTAIN
    auto_patch_t = t.BURN_IN_AUTO_PATCH if burn_in else t.AUTO_PATCH

    ci_uncertain = not (_ci_ok(inp.health_ci_width) and _ci_ok(inp.sec_ci_width))
    protected = inp.namespace_protected is not False

    def blockers(breaker_closed: bool, breaker_text: str):
        why = []
        if ci_uncertain:
            why.append(f"CI too wide or invalid (health_ci={inp.health_ci_width}, "
                       f"sec_ci={inp.sec_ci_width}, limit {CI_WIDTH_LIMIT})")
        if not breaker_closed:
            why.append(breaker_text)
        if protected:
            why.append("namespace is protected (kubeheal/protected) or its label state is unknown")
        return why

    # ── SECURITY: CONTAIN candidate (compound or security-only) ──
    if sec_adjusted >= auto_contain_t:
        why = blockers(_breaker_closed(inp.circuit_breaker_containments, CB_CONTAIN_LIMIT_PER_HOUR),
                       f"circuit breaker open: {inp.circuit_breaker_containments} containments this "
                       f"hour, limit {CB_CONTAIN_LIMIT_PER_HOUR}")
        kind = "Compound incident" if inp.compound_flag else "Security incident"
        if why:
            return DecisionOutput(Decision.HUMAN_CONTAIN, sec_adjusted,
                f"{kind}. Automatic action blocked: {'; '.join(why)}. Human approval required.",
                True, params)
        if inp.compound_flag:
            return DecisionOutput(Decision.AUTO_CONTAIN, sec_adjusted,
                f"Compound incident (DCM corr={inp.correlation_score:.2f}): "
                f"sec_risk={inp.sec_risk:.2f}, health_risk={inp.health_risk:.2f}. "
                f"Tier={inp.namespace_tier}. AUTO-CONTAIN.", True,
                {"compound": True, "nl_summary": inp.nl_summary})
        return DecisionOutput(Decision.AUTO_CONTAIN, sec_adjusted,
            f"Security incident. sec_risk={inp.sec_risk:.2f}, label={inp.sec_label}. AUTO-CONTAIN.",
            True, {"compound": False, "nl_summary": inp.nl_summary})

    # ── HEALTH-ONLY (security calm): PATCH candidate ──
    if health_adjusted >= auto_patch_t and inp.sec_risk < RAW_SEC_RISK_PATCH_CEILING:
        why = blockers(_breaker_closed(inp.circuit_breaker_patches, CB_PATCH_LIMIT_PER_HOUR),
                       f"circuit breaker open: {inp.circuit_breaker_patches} patches for this Deployment "
                       f"this hour, limit {CB_PATCH_LIMIT_PER_HOUR}")
        if why:
            return DecisionOutput(Decision.HUMAN_PATCH, health_adjusted,
                f"Health incident. Automatic action blocked: {'; '.join(why)}. Human approval required.",
                True, params)
        return DecisionOutput(Decision.AUTO_PATCH, health_adjusted,
            f"Health incident. health_risk={inp.health_risk:.2f}, "
            f"top_field={inp.health_field_top}. AUTO-PATCH.", True,
            {"patch_field": inp.health_field_top, "nl_summary": inp.nl_summary})

    # ── HUMAN APPROVAL ZONE ──
    if top >= t.HUMAN_APPROVAL:
        dec = Decision.HUMAN_PATCH if health_adjusted > sec_adjusted else Decision.HUMAN_CONTAIN
        return DecisionOutput(dec, top,
            f"Medium confidence. health_adj={health_adjusted:.2f}, "
            f"sec_adj={sec_adjusted:.2f}. Human approval.", False, params)

    # ── OBSERVE (the caller triples sampling for a bounded period) ──
    if top >= t.OBSERVE:
        return DecisionOutput(Decision.OBSERVE, top,
            f"Low signal. Increasing monitoring x3. health_adj={health_adjusted:.2f}, "
            f"sec_adj={sec_adjusted:.2f}.", False, {})

    # ── BENIGN ──
    return DecisionOutput(Decision.BENIGN, top, "Benign signal. XACK and continue.", False, {})
