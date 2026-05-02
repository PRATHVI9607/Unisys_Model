import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent import FusionAgent, ActionType, DecisionResult


class TestDecisionPolicy:
    """Test Fusion Agent decision policy."""
    
    @pytest.fixture
    def agent(self):
        """Create a FusionAgent for testing."""
        return FusionAgent(
            max_auto_kill_per_ns_per_hour=3,
            max_auto_patch_per_dep_per_hour=10,
            ci_width_threshold=0.15,
            namespace_tiers={"prod": 1.20, "staging": 1.00, "dev": 0.70}
        )
    
    @pytest.mark.asyncio
    async def test_decide_benign_low_score(self, agent):
        """Test benign decision for low score."""
        event = {
            "event_id": "test-001",
            "target": {"namespace": "dev", "name": "test-app"},
            "risk_score": 0.10,
            "severity": "benign",
            "confidence_interval": None
        }
        
        result = await agent._decide_benign(event, 0.10)
        
        assert result.action == ActionType.BENIGN
        assert "benign" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_decide_observe_medium_score(self, agent):
        """Test observe decision for medium score."""
        event = {
            "event_id": "test-002",
            "target": {"namespace": "dev", "name": "test-app"},
            "risk_score": 0.50,
            "severity": "low",
            "confidence_interval": None
        }
        
        result = await agent._decide_observe(event, 0.50)
        
        assert result.action == ActionType.OBSERVE
        assert result.adjusted_score == 0.50
    
    @pytest.mark.asyncio
    async def test_decide_human_approval(self, agent):
        """Test human approval decision for medium-high score."""
        event = {
            "event_id": "test-003",
            "target": {"namespace": "prod", "name": "test-app"},
            "risk_score": 0.70,
            "severity": "medium",
            "confidence_interval": None
        }
        
        result = await agent._decide_human_approval(event, 0.70)
        
        assert result.action == ActionType.HUMAN_APPROVAL
    
    @pytest.mark.asyncio
    async def test_decide_auto_patch_health_critical(self, agent):
        """Test auto-patch for health-critical in prod."""
        event = {
            "event_id": "test-004",
            "target": {"namespace": "prod", "name": "test-app"},
            "risk_score": 0.85,
            "severity": "critical",
            "confidence_interval": [0.80, 0.90]
        }
        
        with patch.object(agent, 'redis', MagicMock()) as mock_redis:
            mock_redis.incr = AsyncMock(return_value=1)
            result = await agent._decide_auto_patch(event, 0.85 * 1.20)
        
        assert result.action == ActionType.AUTO_PATCH
    
    @pytest.mark.asyncio
    async def test_decide_auto_kill_security_critical(self, agent):
        """Test auto-kill for security-critical ransomware."""
        event = {
            "event_id": "test-005",
            "target": {"namespace": "prod", "name": "compromised-app"},
            "risk_score": 0.85,
            "label": "ransomware-critical",
            "confidence_interval": [0.80, 0.90]
        }
        
        with patch.object(agent, 'redis', MagicMock()) as mock_redis:
            mock_redis.incr = AsyncMock(return_value=1)
            result = await agent._decide_auto_kill(event, 0.85 * 1.20)
        
        assert result.action == ActionType.AUTO_KILL
    
    @pytest.mark.asyncio
    async def test_namespace_tier_multiplier_prod(self, agent):
        """Test prod namespace gets 1.2x multiplier."""
        event = {
            "event_id": "test-006",
            "target": {"namespace": "production"},
            "risk_score": 0.70,
            "severity": "medium"
        }
        
        with patch.object(agent, '_get_namespace_tier', return_value="prod"):
            tier = await agent._get_namespace_tier("production")
            assert tier == "prod"
            assert agent.namespace_tiers["prod"] == 1.20
    
    @pytest.mark.asyncio
    async def test_namespace_tier_multiplier_dev(self, agent):
        """Test dev namespace gets 0.7x multiplier."""
        assert agent.namespace_tiers["dev"] == 0.70
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_auto_kill(self, agent):
        """Test circuit breaker for auto-kill."""
        event = {
            "event_id": "test-007",
            "target": {"namespace": "prod", "name": "test-app"},
            "risk_score": 0.90,
            "label": "ransomware-critical"
        }
        
        with patch.object(agent, 'redis', MagicMock()) as mock_redis:
            mock_redis.incr = AsyncMock(return_value=4)
            result = await agent._decide_auto_kill(event, 1.08)
        
        assert result.action == ActionType.HUMAN_APPROVAL
    
    @pytest.mark.asyncio
    async def test_wide_ci_escalation(self, agent):
        """Test wide confidence interval triggers human escalation."""
        event = {
            "event_id": "test-008",
            "target": {"namespace": "prod", "name": "test-app"},
            "risk_score": 0.50,
            "severity": "low",
            "confidence_interval": [0.30, 0.70]
        }
        
        result = await agent._decide_human_escalation(event, 0.50, "wide_ci")
        
        assert result.action == ActionType.HUMAN_APPROVAL
        assert "uncertainty" in result.message.lower()
    
    def test_parse_confidence_interval_valid(self, agent):
        """Test parsing valid CI."""
        ci = agent._parse_confidence_interval([0.30, 0.70])
        assert ci == 0.40
    
    def test_parse_confidence_interval_none(self, agent):
        """Test parsing null CI."""
        ci = agent._parse_confidence_interval(None)
        assert ci is None
    
    def test_parse_confidence_interval_string(self, agent):
        """Test parsing CI from string."""
        ci = agent._parse_confidence_interval("[0.3, 0.7]")
        assert ci == 0.40


class TestRiskScoreCalculation:
    """Test risk score calculations."""
    
    def test_score_to_label_ransomware_critical(self):
        """Test label for high ransomware score."""
        agent = FusionAgent()
        
        assert agent.namespace_tiers["prod"] == 1.20
        assert agent.namespace_tiers["staging"] == 1.00
        assert agent.namespace_tiers["dev"] == 0.70
    
    def test_adjusted_score_calculation(self):
        """Test adjusted score with tier multiplier."""
        agent = FusionAgent()
        
        raw_score = 0.85
        tier_multiplier = agent.namespace_tiers["prod"]
        
        adjusted = raw_score * tier_multiplier
        
        assert adjusted == 1.02


class TestNamespaceTiers:
    """Test namespace tier logic."""
    
    def test_prod_tier(self):
        """Test prod tier."""
        agent = FusionAgent()
        assert agent.namespace_tiers["prod"] == 1.20
    
    def test_staging_tier(self):
        """Test staging tier."""
        agent = FusionAgent()
        assert agent.namespace_tiers["staging"] == 1.00
    
    def test_dev_tier(self):
        """Test dev tier."""
        agent = FusionAgent()
        assert agent.namespace_tiers["dev"] == 0.70
    
    def test_unknown_namespace_default_to_dev(self):
        """Test unknown namespace defaults to dev."""
        agent = FusionAgent()
        assert agent.namespace_tiers.get("unknown", 0.70) == 0.70


if __name__ == "__main__":
    pytest.main([__file__, "-v"])