"""
Fusion Agent v4 - Three-Signal Decision Policy (spec section 2, S-POL-1 .. S-POL-7)
==================================================================================
Pure function: DecisionInput -> DecisionOutput. No I/O, no clock, no Redis, no environment: time based
facts (circuit breaker counts, the burn-in sample counter, the kill-switch mode, the namespace label state,
whether the models answered in time) are computed by the caller and come in as inputs.

Fail closed: every input that is missing, unknown or invalid leads to HUMAN, never to an automatic action.

V5-D3 (owner decisions M2, D2, Q1, Q2 in docs/kubeheal/V5_INTEGRATION_PLAN.md section 11):
  * M2: an automatic action needs a conformal prediction set of exactly ONE label on each side that has an event
    (replaces the old CI-width guard). The trigger side must have a set; a side with no event passes `None`.
  * D2/Q1: a rule-based rollback (the Health Agent's failure_reasons or a posture violation) skips only the set
    gate, burn-in, the score threshold and the Health Model response. It still needs the kill switch (dry_run),
    an unprotected namespace, a known tier, a closed patch breaker, an incident lock, has_baseline, a raw security
    risk below 0.4 AND a fresh Security Model response (`security_fresh`); with no fresh Security response a human
    decides.
  * Q2: automatic containment only for the labels `ransomware` and `exfiltration`; `suspicious` and anything else
    never acts automatically. The restore step is for `ransomware` only; after `exfiltration` a human follows up.
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
    # Conformal prediction set of the Health Model, a list of labels. None = this side has no event (counts as
    # certain unless it triggers the action). Exactly one label equal to health_label = certain; anything else
    # (empty, several labels, a different label, wrong type) = uncertain, fail closed.
    health_prediction_set: Optional[list] = None

    sec_risk: float = 0.0
    sec_label: str = "benign"
    sec_prediction_set: Optional[list] = None
    sec_syscall_top: str = ""

    correlation_score: float = 0.0
    compound_flag: bool = False

    # "prod", "staging", "dev" or "unknown". Anything else (a missing value, a typo, "production") is treated
    # as "unknown": the highest multiplier for the score, but never an automatic action.
    namespace_tier: str = "unknown"
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

    # Rule-based rollback inputs (D2). `rollback_reasons` are the Health Agent's failure_reasons (policy:* included).
    # `changed_fields` is the spec diff against the baseline (the fields the Executor may restore).
    rollback_reasons: list = field(default_factory=list)
    spec_changed: bool = False
    has_baseline: bool = False
    changed_fields: list = field(default_factory=list)
    # Q1: True only when a FRESH Security Model response arrived inside its deadline. Default False: fail closed.
    security_fresh: bool = False

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
# An unknown tier uses the HIGHEST multiplier for the score (a larger multiplier makes a human review more
# likely, and never makes an automatic action easier because an unknown tier can never act automatically).
UNKNOWN_TIER_MULTIPLIER = max(TIER_MULTIPLIERS.values())
COMPOUND_ESCALATION = 1.15
CB_CONTAIN_LIMIT_PER_HOUR = 3
CB_PATCH_LIMIT_PER_HOUR = 10
# Q2: the only labels that may trigger an automatic containment, and the one that also gets the restore step.
AUTO_CONTAIN_LABELS = ("ransomware", "exfiltration")
RESTORE_LABEL = "ransomware"
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


def _label(value) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def set_certain(prediction_set, label, required: bool = False) -> bool:
    """M2. None = no event on this side: certain unless `required` (the side that triggers the action).
    Otherwise the set must be a list or tuple with exactly one non-empty string equal to `label`."""
    if prediction_set is None:
        return not required
    if not isinstance(prediction_set, (list, tuple)):
        return False
    if len(prediction_set) != 1:
        return False
    only = _label(prediction_set[0])
    return bool(only) and only == _label(label)


def _clean_list(value) -> list:
    if not isinstance(value, (list, tuple)):
        return []
    return [v for v in value if isinstance(v, str) and v.strip()]


def _breaker_closed(count, limit: int) -> bool:
    """A count that is not a non-negative int is treated as an open breaker."""
    return isinstance(count, int) and not isinstance(count, bool) and 0 <= count < limit


def _tier(value) -> Optional[str]:
    """The known tier name, or None for anything else (missing, wrong type, unrecognised, "unknown")."""
    if isinstance(value, str) and value.strip().lower() in TIER_MULTIPLIERS:
        return value.strip().lower()
    return None


def _rule_path(inp, reasons, tier, health_adjusted):
    """The rule-based rollback candidate (D2, Q1). Returns None when the raw security risk is not below the
    ceiling (the normal flow then handles the event), otherwise AUTO_PATCH or HUMAN_PATCH."""
    if inp.sec_risk >= RAW_SEC_RISK_PATCH_CEILING:
        return None
    rule_params = {"rule_path": True, "rule_reasons": reasons, "patch_fields": _clean_list(inp.changed_fields),
                   "nl_summary": inp.nl_summary}
    why = []
    if inp.security_fresh is not True:
        why.append("no fresh Security Model response to confirm security risk below "
                   f"{RAW_SEC_RISK_PATCH_CEILING} (Q1: escalate to a human)")
    if not 0.0 <= inp.sec_risk <= 1.0:
        why.append(f"raw security risk {inp.sec_risk} is outside [0, 1], so it is not a trusted Security Model "
                   "answer (Q1: escalate to a human)")
    if not rule_params["patch_fields"]:
        why.append("no changed field to restore (changed_fields is empty), so there is nothing the Executor "
                   "could patch automatically")
    if not _breaker_closed(inp.circuit_breaker_patches, CB_PATCH_LIMIT_PER_HOUR):
        why.append(f"circuit breaker open: {inp.circuit_breaker_patches} patches for this Deployment this hour, "
                   f"limit {CB_PATCH_LIMIT_PER_HOUR}")
    if inp.namespace_protected is not False:
        why.append("namespace is protected (kubeheal/protected) or its label state is unknown")
    if tier is None:
        why.append(f"namespace tier is unknown ({inp.namespace_tier!r}): no automatic action for an unknown tier")
    if why:
        return DecisionOutput(Decision.HUMAN_PATCH, health_adjusted,
            f"Rule-based rollback candidate ({', '.join(reasons)}). Automatic action blocked: "
            f"{'; '.join(why)}. Human approval required.", True, rule_params)
    return DecisionOutput(Decision.AUTO_PATCH, health_adjusted,
        f"Rule-based rollback ({', '.join(reasons)}) of {len(rule_params['patch_fields'])} changed field(s); "
        f"raw security risk {inp.sec_risk:.2f} is below {RAW_SEC_RISK_PATCH_CEILING}. AUTO-PATCH.",
        True, rule_params)


def _decide(inp: DecisionInput) -> DecisionOutput:
    t = Thresholds()
    tier = _tier(inp.namespace_tier)
    tier_mult = TIER_MULTIPLIERS[tier] if tier else UNKNOWN_TIER_MULTIPLIER

    # Invalid numeric input is never trusted.
    if not _finite(inp.health_risk, inp.sec_risk):
        return DecisionOutput(Decision.HUMAN_CONTAIN, 0.0,
            "Invalid risk input (not a finite number). Human approval required.", False, {})

    health_adjusted = inp.health_risk * tier_mult
    sec_adjusted = inp.sec_risk * tier_mult
    if inp.compound_flag:
        health_adjusted *= COMPOUND_ESCALATION
        sec_adjusted *= COMPOUND_ESCALATION

    params = {"nl_summary": inp.nl_summary, "patch_fields": _clean_list(inp.changed_fields)}
    top = max(health_adjusted, sec_adjusted)

    # D2/Q1: rule-based rollback. Evaluated BEFORE the model-response gate because it does not need the Health
    # Model (and, by owner decision, skips the set gate, burn-in and score threshold). It needs a fresh Security
    # response to confirm the raw security risk is below the ceiling.
    reasons = _clean_list(inp.rollback_reasons)
    if reasons and inp.spec_changed is True and inp.has_baseline is True:
        rule = _rule_path(inp, reasons, tier, health_adjusted)
        if rule is not None:
            return rule

    # S-POL-1: a missing or late model response means a human decides, whatever the scores say.
    if inp.models_ok is not True:
        dec = Decision.HUMAN_PATCH if health_adjusted > sec_adjusted else Decision.HUMAN_CONTAIN
        return DecisionOutput(dec, top,
            "A model response is missing or late (models_ok is not true). Fail closed: human "
            "approval required.", False, params)

    burn_in = burn_in_active(inp)
    auto_contain_t = t.BURN_IN_AUTO_CONTAIN if burn_in else t.AUTO_CONTAIN
    auto_patch_t = t.BURN_IN_AUTO_PATCH if burn_in else t.AUTO_PATCH

    protected = inp.namespace_protected is not False

    def blockers(breaker_closed: bool, breaker_text: str, trigger: str):
        why = []
        if not (set_certain(inp.health_prediction_set, inp.health_label, required=trigger == "health")
                and set_certain(inp.sec_prediction_set, inp.sec_label, required=trigger == "security")):
            why.append(f"prediction set is not exactly one label (health_set={inp.health_prediction_set!r}, "
                       f"sec_set={inp.sec_prediction_set!r}); an automatic action needs a one-label set")
        if not breaker_closed:
            why.append(breaker_text)
        if protected:
            why.append("namespace is protected (kubeheal/protected) or its label state is unknown")
        if tier is None:
            why.append(f"namespace tier is unknown ({inp.namespace_tier!r}): no automatic action for an "
                       "unknown tier, scored with the highest tier multiplier")
        return why

    # ── SECURITY: CONTAIN candidate (compound or security-only) ──
    if sec_adjusted >= auto_contain_t:
        why = blockers(_breaker_closed(inp.circuit_breaker_containments, CB_CONTAIN_LIMIT_PER_HOUR),
                       f"circuit breaker open: {inp.circuit_breaker_containments} containments this "
                       f"hour, limit {CB_CONTAIN_LIMIT_PER_HOUR}", "security")
        sec_label = _label(inp.sec_label)
        if sec_label not in AUTO_CONTAIN_LABELS:
            why.append(f"label {inp.sec_label!r} never triggers automatic containment "
                       f"(only {' and '.join(AUTO_CONTAIN_LABELS)})")
        contain_extra = {"containment_label": sec_label, "restore_after": sec_label == RESTORE_LABEL,
                         "human_followup": sec_label != RESTORE_LABEL}
        kind = "Compound incident" if inp.compound_flag else "Security incident"
        if why:
            return DecisionOutput(Decision.HUMAN_CONTAIN, sec_adjusted,
                f"{kind}. Automatic action blocked: {'; '.join(why)}. Human approval required.",
                True, params)
        if inp.compound_flag:
            return DecisionOutput(Decision.AUTO_CONTAIN, sec_adjusted,
                f"Compound incident (correlation={inp.correlation_score:.2f}): "
                f"sec_risk={inp.sec_risk:.2f}, health_risk={inp.health_risk:.2f}. "
                f"Tier={tier}. AUTO-CONTAIN.", True,
                {"compound": True, "nl_summary": inp.nl_summary, **contain_extra})
        return DecisionOutput(Decision.AUTO_CONTAIN, sec_adjusted,
            f"Security incident. sec_risk={inp.sec_risk:.2f}, label={inp.sec_label}. AUTO-CONTAIN.",
            True, {"compound": False, "nl_summary": inp.nl_summary, **contain_extra})

    # ── HEALTH-ONLY (security calm): PATCH candidate ──
    if health_adjusted >= auto_patch_t and inp.sec_risk < RAW_SEC_RISK_PATCH_CEILING:
        why = blockers(_breaker_closed(inp.circuit_breaker_patches, CB_PATCH_LIMIT_PER_HOUR),
                       f"circuit breaker open: {inp.circuit_breaker_patches} patches for this Deployment "
                       f"this hour, limit {CB_PATCH_LIMIT_PER_HOUR}", "health")
        candidate_fields = _clean_list(inp.changed_fields)
        if not candidate_fields:      # V5-D9: candidates come from the spec diff, never from a model attribution
            why.append("no changed field to restore (changed_fields is empty), so there is nothing the "
                       "Executor could patch automatically")
        if why:
            return DecisionOutput(Decision.HUMAN_PATCH, health_adjusted,
                f"Health incident. Automatic action blocked: {'; '.join(why)}. Human approval required.",
                True, params)
        return DecisionOutput(Decision.AUTO_PATCH, health_adjusted,
            f"Health incident. health_risk={inp.health_risk:.2f}, {len(candidate_fields)} changed field(s) "
            f"from the spec diff. AUTO-PATCH.", True,
            {"patch_field": candidate_fields[0], "patch_fields": candidate_fields,
             "nl_summary": inp.nl_summary})

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
