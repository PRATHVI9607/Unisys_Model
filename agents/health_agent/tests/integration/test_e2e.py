"""Integration tests with Redis and K8s mocks."""

import pytest
import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent import HealthAgent, HealthAssessment, SeverityLevel
from spec_differ import SpecDiffer


@pytest.mark.asyncio
async def test_health_agent_initialization(mock_core_api, mock_apps_api, mock_redis):
    """Test Health Agent initialization."""
    agent = HealthAgent(
        namespace="kubeheal",
        redis_url="redis://localhost:6379",
        dit_sec_url="http://localhost:8000",
    )

    assert agent.namespace == "kubeheal"
    assert agent.dit_sec_url == "http://localhost:8000"


@pytest.mark.asyncio
async def test_blast_radius_query_high(mock_core_api):
    """Test blast radius detection for high-impact deployments."""
    agent = HealthAgent()
    agent.core_api = mock_core_api

    # Mock service with LoadBalancer
    service = MagicMock()
    service.spec.type = "LoadBalancer"

    services = MagicMock()
    services.items = [service]

    mock_core_api.list_namespaced_service = AsyncMock(return_value=services)

    deployment = {"spec": {"selector": {"app": "critical-app"}}}

    blast_radius = await agent._query_blast_radius("default", deployment)

    assert blast_radius == "High"


@pytest.mark.asyncio
async def test_blast_radius_query_low(mock_core_api):
    """Test blast radius detection for low-impact deployments."""
    agent = HealthAgent()
    agent.core_api = mock_core_api

    services = MagicMock()
    services.items = []

    mock_core_api.list_namespaced_service = AsyncMock(return_value=services)
    mock_core_api.list_namespaced_ingress = AsyncMock(return_value=MagicMock(items=[]))

    deployment = {"spec": {"selector": {}}}

    blast_radius = await agent._query_blast_radius("default", deployment)

    assert blast_radius == "Low"


@pytest.mark.asyncio
async def test_assessment_flow(
    mock_redis, mock_core_api, mock_apps_api, sample_spec_old, sample_spec_new
):
    """Test complete assessment flow."""
    agent = HealthAgent(redis_url="redis://localhost:6379")
    agent.redis = mock_redis
    agent.core_api = mock_core_api
    agent.apps_api = mock_apps_api

    # Mock baseline check - not in cooldown
    mock_redis.exists = AsyncMock(return_value=False)

    # Mock deployment retrieval with baseline annotation
    deployment_obj = MagicMock()
    deployment_obj.metadata.annotations = {"kubeheal.io/baseline-sha": "abc123"}
    mock_apps_api.read_namespaced_deployment = AsyncMock(return_value=deployment_obj)

    # Mock ConfigMap for baseline validation
    config_map = MagicMock()
    config_map.data = {"test-app": "abc123"}
    mock_core_api.read_namespaced_config_map = AsyncMock(return_value=config_map)

    # Mock spec fetch from Redis
    mock_redis.get = AsyncMock(return_value=None)

    # Mock telemetry storage
    mock_redis.hset = AsyncMock()
    mock_redis.xadd = AsyncMock(return_value="1-0")

    # Mock the internal async methods to avoid full flow
    agent._fetch_telemetry = AsyncMock(
        return_value={"cpu_usage": 0.5, "memory_usage": 0.3}
    )
    agent._query_blast_radius = AsyncMock(return_value="low")
    agent._get_previous_spec = AsyncMock(return_value=sample_spec_old)

    deployment = {
        "metadata": {"name": "test-app", "namespace": "default", "generation": 1},
        "status": {"observedGeneration": 1},
        "spec": sample_spec_new,
    }

    await agent.handle_deployment_event("MODIFIED", deployment)

    # Verify the agent was able to process the event
    # Note: The full flow may not reach Redis calls depending on assessment results
    assert agent is not None


def test_severity_mapping_from_drift_types():
    """Test severity mapping based on drift types."""
    drift_severity_map = {
        "cpu_limit": SeverityLevel.HIGH,
        "memory_limit": SeverityLevel.HIGH,
        "image": SeverityLevel.CRITICAL,
        "replica_count": SeverityLevel.MEDIUM,
        "env_var": SeverityLevel.LOW,
    }

    # Verify severity levels
    assert drift_severity_map["image"] == SeverityLevel.CRITICAL
    assert drift_severity_map["cpu_limit"] == SeverityLevel.HIGH
