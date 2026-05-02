"""Pytest configuration and fixtures for Health Agent tests."""

import pytest
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
import aioredis


@pytest.fixture
def mock_k8s_deployment():
    """Create a mock Kubernetes Deployment."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "test-app",
            "namespace": "default",
            "generation": 5,
            "annotations": {
                "kubeheal.io/baseline-sha": "abc123",
                "kubeheal.io/baseline-date": datetime.utcnow().isoformat() + "Z",
            },
        },
        "status": {
            "observedGeneration": 5,
            "replicas": 3,
            "updatedReplicas": 3,
            "readyReplicas": 3,
        },
        "spec": {
            "replicas": 3,
            "selector": {"matchLabels": {"app": "test-app"}},
            "template": {
                "metadata": {"labels": {"app": "test-app"}},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "test-app:1.0",
                            "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
                        }
                    ]
                },
            },
        },
    }


@pytest.fixture
def mock_core_api():
    """Create a mock Kubernetes Core API."""
    return AsyncMock()


@pytest.fixture
def mock_apps_api():
    """Create a mock Kubernetes Apps API."""
    return AsyncMock()


@pytest.fixture
def mock_custom_api():
    """Create a mock Kubernetes Custom API."""
    return AsyncMock()


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    redis = AsyncMock(spec=aioredis.Redis)
    redis.exists = AsyncMock(return_value=False)
    redis.setex = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.hset = AsyncMock()
    redis.xadd = AsyncMock(return_value="1-0")
    redis.close = AsyncMock()
    redis.wait_closed = AsyncMock()
    return redis


@pytest.fixture
def sample_spec_old():
    """Sample old deployment spec."""
    return {
        "replicas": 3,
        "selector": {"matchLabels": {"app": "test"}},
        "template": {
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "app:1.0",
                        "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
                    }
                ]
            }
        },
    }


@pytest.fixture
def sample_spec_new():
    """Sample new deployment spec with changes."""
    return {
        "replicas": 5,
        "selector": {"matchLabels": {"app": "test"}},
        "template": {
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "app:2.0",
                        "resources": {"limits": {"cpu": "250m", "memory": "512Mi"}},
                    }
                ]
            }
        },
    }
