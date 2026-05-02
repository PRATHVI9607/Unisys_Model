"""Unit tests for Health Agent core functionality."""

import pytest
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent import HealthAgent, HealthAssessment, SeverityLevel


@pytest.mark.asyncio
async def test_cooldown_check(mock_redis):
    """Test cooldown period check."""
    agent = HealthAgent(redis_url="redis://localhost:6379")
    agent.redis = mock_redis

    # First check - not in cooldown
    mock_redis.exists = AsyncMock(return_value=False)
    result = await agent._check_cooldown("default", "test-app")
    assert result is False

    # Second check - in cooldown
    mock_redis.exists = AsyncMock(return_value=True)
    result = await agent._check_cooldown("default", "test-app")
    assert result is True


@pytest.mark.asyncio
async def test_set_cooldown(mock_redis):
    """Test setting cooldown period."""
    agent = HealthAgent(redis_url="redis://localhost:6379")
    agent.redis = mock_redis

    await agent._set_cooldown("default", "test-app")

    assert mock_redis.setex.called


def test_score_to_severity():
    """Test risk score to severity conversion."""
    agent = HealthAgent()

    assert agent._score_to_severity(0.05) == SeverityLevel.BENIGN
    assert agent._score_to_severity(0.25) == SeverityLevel.LOW
    assert agent._score_to_severity(0.50) == SeverityLevel.MEDIUM
    assert agent._score_to_severity(0.70) == SeverityLevel.HIGH
    assert agent._score_to_severity(0.90) == SeverityLevel.CRITICAL


def test_local_assessment_low_cpu():
    """Test local assessment detects low CPU limit."""
    agent = HealthAgent()

    spec = {
        "template": {
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "50m"}}}]
            }
        }
    }

    result = agent._local_assessment(spec, {})

    assert result["risk_score"] >= 0.85
    assert result["patch_proposal"] is not None


def test_local_assessment_normal_cpu():
    """Test local assessment with normal CPU limit."""
    agent = HealthAgent()

    spec = {
        "template": {
            "spec": {
                "containers": [
                    {"name": "app", "resources": {"limits": {"cpu": "500m"}}}
                ]
            }
        }
    }

    result = agent._local_assessment(spec, {})

    assert result["risk_score"] == 0.0


def test_local_assessment_no_containers():
    """Test local assessment with no containers."""
    agent = HealthAgent()

    spec = {"template": {"spec": {}}}
    result = agent._local_assessment(spec, {})

    assert result["risk_score"] == 0.0


@pytest.mark.asyncio
async def test_publish_assessment(mock_redis):
    """Test publishing health assessment."""
    agent = HealthAgent(redis_url="redis://localhost:6379")
    agent.redis = mock_redis

    assessment = HealthAssessment(
        event_id="test-001",
        target={"namespace": "default", "name": "test-app", "kind": "Deployment"},
        risk_score=0.75,
        severity=SeverityLevel.HIGH,
        blast_radius="High",
    )

    await agent._publish_assessment(assessment)

    # Should call hset and xadd
    assert mock_redis.hset.called
    assert mock_redis.xadd.called


@pytest.mark.asyncio
async def test_handle_deployment_event_in_cooldown(mock_redis, mock_apps_api):
    """Test event handling when in cooldown."""
    agent = HealthAgent(redis_url="redis://localhost:6379")
    agent.redis = mock_redis
    agent.apps_api = mock_apps_api

    mock_redis.exists = AsyncMock(return_value=True)

    deployment = {
        "metadata": {"name": "test-app", "namespace": "default", "generation": 1},
        "status": {"observedGeneration": 1},
        "spec": {},
    }

    await agent.handle_deployment_event("MODIFIED", deployment)

    # Should not proceed due to cooldown
    assert not mock_apps_api.read_namespaced_deployment.called
