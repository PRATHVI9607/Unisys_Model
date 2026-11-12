import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from agents.common import tiers
from agents.health_agent import agent as health
from agents.security_agent import agent as security


@pytest.mark.parametrize("name,expected", [
    ("prod", "prod"), ("my-prod-eu", "prod"), ("staging", "staging"), ("dev", "dev"),
    ("demo", "unknown"), ("default", "unknown"), ("", "unknown"), (None, "unknown"),
])
def test_the_name_rule_without_a_map(monkeypatch, name, expected):
    monkeypatch.delenv("NAMESPACE_TIER_MAP", raising=False)
    assert tiers.namespace_tier(name) == expected
    assert health.namespace_tier(name) == expected and security.namespace_tier(name) == expected


def test_an_explicit_map_decides_before_the_name_rule(monkeypatch):
    monkeypatch.setenv("NAMESPACE_TIER_MAP", "demo=dev, Lab = staging ,prod-sandbox=dev")
    assert health.namespace_tier("demo") == "dev" and security.namespace_tier("demo") == "dev"
    assert health.namespace_tier("lab") == "staging"
    assert health.namespace_tier("prod-sandbox") == "dev"           # the map wins over the "prod" substring
    assert health.namespace_tier("prod") == "prod"                  # others keep the name rule
    assert health.namespace_tier("other") == "unknown"              # unmapped and unnamed stays human review


def test_malformed_pairs_and_unknown_tiers_stay_unknown(monkeypatch):
    monkeypatch.setenv("NAMESPACE_TIER_MAP", "demo=gold,=dev,noequals,x=PROD,y=")
    assert tiers.parse_tier_map(os.environ["NAMESPACE_TIER_MAP"]) == {"x": "prod"}
    assert health.namespace_tier("demo") == "unknown"
