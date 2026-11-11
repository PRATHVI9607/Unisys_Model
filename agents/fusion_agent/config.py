"""
Fusion Agent settings. Every number here that is not in the spec is chosen, not measured, documented and
configurable through the environment. The spec numbers (tiers, thresholds, the one-label prediction-set gate, breaker limits,
burn-in samples, 3x sampling) live in decision_policy.py and agents/common/sampling.py, not here.
"""

import logging
import math
import os
from dataclasses import dataclass
from typing import Mapping, Optional

logger = logging.getLogger(__name__)


def _num(env: Mapping[str, str], name: str, default, cast=float):
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        value = cast(raw)
    except ValueError:
        logger.warning(f"{name}={raw!r} is not a number; using {default}")
        return default
    if not math.isfinite(value) or value <= 0:
        logger.warning(f"{name}={raw!r} must be a finite positive number; using {default}")
        return default
    return value


@dataclass(frozen=True)
class FusionConfig:
    # chosen, not measured (the first two are the values the code already used before P6)
    dcm_deadline_s: float = 5.0            # DCM_DEADLINE_S: a DCM answer later than this counts as missing
    interpretation_deadline_s: float = 4.0  # INTERPRETATION_DEADLINE_S: same for the interpretation step
    observe_period_s: int = 300            # OBSERVE_PERIOD_S: how long OBSERVE keeps sampling at 3x
    incident_dedup_ttl_s: int = 600        # INCIDENT_DEDUP_TTL_S: a second security event for the same pod and
    #                                        process inside this window updates the incident
    incident_context_ttl_s: int = 86400    # INCIDENT_CONTEXT_TTL_S: how long incident context (for the restore
    #                                        trigger) is kept in Redis
    model_unavailable_dedup_ttl_s: int = 300  # MODEL_UNAVAILABLE_DEDUP_TTL_S: one escalation per workload for a
    #                                        Health Model outage inside this window (chosen default, not measured)
    security_fresh_s: float = 30.0         # SECURITY_FRESH_S: a Security Model score (Redis hash written by the
    #                                        Security Agent) older than this is not "fresh" for the rule-based
    #                                        rollback (Q1). A configuration default, not a measurement.
    burn_in_forced: bool = False           # BURN_IN_MODE=true forces burn-in on. It can never force it off.

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "FusionConfig":
        env = os.environ if env is None else env
        return cls(
            dcm_deadline_s=_num(env, "DCM_DEADLINE_S", 5.0),
            interpretation_deadline_s=_num(env, "INTERPRETATION_DEADLINE_S", 4.0),
            observe_period_s=_num(env, "OBSERVE_PERIOD_S", 300, int),
            incident_dedup_ttl_s=_num(env, "INCIDENT_DEDUP_TTL_S", 600, int),
            incident_context_ttl_s=_num(env, "INCIDENT_CONTEXT_TTL_S", 86400, int),
            model_unavailable_dedup_ttl_s=_num(env, "MODEL_UNAVAILABLE_DEDUP_TTL_S", 300, int),
            security_fresh_s=_num(env, "SECURITY_FRESH_S", 30.0),
            burn_in_forced=str(env.get("BURN_IN_MODE", "false")).strip().lower() == "true",
        )
