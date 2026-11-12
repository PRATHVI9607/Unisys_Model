"""Namespace to risk tier (prod / staging / dev / unknown), shared by the Health and Security agents.

Two rules, in this order:
1. An explicit mapping from the environment variable NAMESPACE_TIER_MAP, for example "demo=dev,lab=staging"
   (exact namespace name, case-insensitive; the value must be prod, staging or dev, anything else is ignored).
   The chart sets it from the value `namespaceTierMap`; it is empty by default.
2. The name rule: a name containing "prod", "stag" or "dev".

Everything else is "unknown": the decision policy scores an unknown tier with the highest multiplier and never
acts on it automatically (human review). The `kubeheal/tier` namespace label is not read by any agent.
"""
import os
from typing import Dict, Mapping, Optional

TIERS = ("prod", "staging", "dev")


def parse_tier_map(raw: Optional[str]) -> Dict[str, str]:
    """`ns=tier,ns2=tier2` to {ns: tier}. Malformed pairs and unknown tiers are dropped (they stay unknown)."""
    result: Dict[str, str] = {}
    for pair in (raw or "").split(","):
        name, sep, tier = pair.partition("=")
        name, tier = name.strip().lower(), tier.strip().lower()
        if sep and name and tier in TIERS:
            result[name] = tier
    return result


def namespace_tier(namespace: str, overrides: Optional[Mapping[str, str]] = None) -> str:
    n = (namespace or "").strip().lower()
    mapping = parse_tier_map(os.environ.get("NAMESPACE_TIER_MAP")) if overrides is None else overrides
    if n in mapping:
        return mapping[n]
    if "prod" in n:
        return "prod"
    if "stag" in n:
        return "staging"
    if "dev" in n:
        return "dev"
    return "unknown"
