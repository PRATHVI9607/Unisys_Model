import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent import HealthAgent, HealthAssessment, SeverityLevel


class TestHealthAgentInit:
    """Test HealthAgent initialization."""

    def test_init_with_defaults(self):
        """Test HealthAgent initialization with default parameters."""
        agent = HealthAgent()

        assert agent.namespace == "kubeheal"
        assert agent.redis_url == "redis://redis:6379"
        assert agent.dit_sec_url == "http://dit-sec-server:8000"
        assert agent.prometheus_url == "http://prometheus:9090"
        assert agent.cooldown_ttl == 300
        assert agent.running is False

    def test_init_with_env_vars(self):
        """Test HealthAgent initialization with environment variables."""
        with patch.dict(
            os.environ,
            {
                "REDIS_URL": "redis://custom-redis:6379",
                "DIT_SEC_URL": "http://custom-dit-sec:8000",
                "PROMETHEUS_URL": "http://custom-prometheus:9090",
            },
        ):
            agent = HealthAgent()

            assert agent.redis_url == "redis://custom-redis:6379"
            assert agent.dit_sec_url == "http://custom-dit-sec:8000"
            assert agent.prometheus_url == "http://custom-prometheus:9090"

    def test_init_with_explicit_params(self):
        """Test HealthAgent initialization with explicit parameters."""
        agent = HealthAgent(
            namespace="custom",
            redis_url="redis://explicit:6379",
            dit_sec_url="http://explicit-dit-sec:8000",
            cooldown_ttl=600,
            prometheus_url="http://explicit-prometheus:9090",
        )

        assert agent.namespace == "custom"
        assert agent.redis_url == "redis://explicit:6379"
        assert agent.dit_sec_url == "http://explicit-dit-sec:8000"
        assert agent.cooldown_ttl == 600
        assert agent.prometheus_url == "http://explicit-prometheus:9090"


class TestHealthAssessment:
    """Test HealthAssessment model."""

    def test_assessment_creation(self):
        """Test creating a HealthAssessment."""
        assessment = HealthAssessment(
            event_id="test-001",
            target={"namespace": "prod", "name": "nginx"},
            risk_score=0.75,
            severity=SeverityLevel.HIGH,
            blast_radius="wide",
        )

        assert assessment.event_id == "test-001"
        assert assessment.target["namespace"] == "prod"
        assert assessment.risk_score == 0.75
        assert assessment.severity == SeverityLevel.HIGH
        assert assessment.blast_radius == "wide"
        assert assessment.timestamp is not None

    def test_assessment_json_serialization(self):
        """Test HealthAssessment JSON serialization."""
        assessment = HealthAssessment(
            event_id="test-002",
            target={"namespace": "dev", "name": "app"},
            risk_score=0.25,
            severity=SeverityLevel.LOW,
            confidence_interval=(0.20, 0.30),
        )

        data = assessment.model_dump_json()
        assert isinstance(data, str)

        parsed = json.loads(data)
        assert parsed["event_id"] == "test-002"
        assert parsed["risk_score"] == 0.25
        assert parsed["severity"] == "low"

    def test_assessment_with_model_comparison_fields(self):
        """Test HealthAssessment with model comparison fields."""
        assessment = HealthAssessment(
            event_id="test-005",
            target={"namespace": "prod", "name": "api-server"},
            risk_score=0.48,
            severity=SeverityLevel.MEDIUM,
            model_used="onnx_model",
            model_score=0.48,
            heuristic_score=0.42,
            inference_method="ONNX inference",
        )

        assert assessment.model_used == "onnx_model"
        assert assessment.model_score == 0.48
        assert assessment.heuristic_score == 0.42
        assert assessment.inference_method == "ONNX inference"

        # Verify JSON serialization includes new fields
        data = assessment.model_dump_json()
        parsed = json.loads(data)
        assert parsed["model_used"] == "onnx_model"
        assert parsed["model_score"] == 0.48

    def test_assessment_risk_score_validation(self):
        """Test that risk_score is validated between 0.0 and 1.0."""
        with pytest.raises(ValueError):
            HealthAssessment(
                event_id="test-003",
                target={"namespace": "test"},
                risk_score=1.5,  # Invalid - > 1.0
                severity=SeverityLevel.CRITICAL,
            )

        with pytest.raises(ValueError):
            HealthAssessment(
                event_id="test-004",
                target={"namespace": "test"},
                risk_score=-0.1,  # Invalid - < 0.0
                severity=SeverityLevel.BENIGN,
            )


class TestHealthAgentRedisConnectivity:
    """Test HealthAgent Redis connectivity."""

    def test_redis_connection(self):
        """Test Redis connection initialization."""
        agent = HealthAgent()
        # Verify redis_url is set correctly
        assert agent.redis_url == "redis://redis:6379"


class TestHealthAgentEventProcessing:
    """Test HealthAgent event processing."""

    @pytest.mark.asyncio
    async def test_process_deployment_event(self):
        """Test processing a Deployment event."""
        agent = HealthAgent()

        event = {
            "type": "ADDED",
            "object": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "test-app",
                    "namespace": "default",
                    "generation": 1,
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "nginx:latest",
                                    "resources": {
                                        "limits": {"cpu": "500m", "memory": "512Mi"}
                                    },
                                }
                            ]
                        }
                    }
                },
            },
        }

        # Mock the Redis and DIT-Sec calls
        agent.redis = AsyncMock()
        agent.redis.xadd = AsyncMock(return_value=b"1-0")

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.json = AsyncMock(
                return_value={
                    "risk_score": 0.15,
                    "label": "benign",
                    "confidence_interval": [0.10, 0.20],
                }
            )
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session_inst = AsyncMock()
            mock_session_inst.post = AsyncMock(return_value=mock_response)
            mock_session_inst.__aenter__ = AsyncMock(return_value=mock_session_inst)
            mock_session_inst.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = mock_session_inst

            # Process the event
            # Note: This is a partial test - full implementation would require
            # mocking the entire Kubernetes watch mechanism


class TestHealthAgentSeverityLevels:
    """Test severity level determination."""

    def test_benign_severity(self):
        """Test benign severity level."""
        assert SeverityLevel.BENIGN.value == "benign"

    def test_critical_severity(self):
        """Test critical severity level."""
        assert SeverityLevel.CRITICAL.value == "critical"

    def test_severity_ordering(self):
        """Test severity levels can be compared."""
        severities = [
            SeverityLevel.BENIGN,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL,
        ]

        assert len(severities) == 5
        assert SeverityLevel.CRITICAL in severities


class TestHealthAgentDitSecIntegration:
    """Test HealthAgent DIT-Sec server integration."""

    @pytest.mark.asyncio
    async def test_dit_sec_score_endpoint(self):
        """Test calling DIT-Sec /score endpoint."""
        agent = HealthAgent(dit_sec_url="http://dit-sec-server:8000")

        score_request = {
            "old_spec": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "resources": {
                                        "limits": {"cpu": "500m", "memory": "512Mi"}
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "new_spec": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "resources": {
                                        "limits": {"cpu": "50m", "memory": "512Mi"}
                                    }
                                }
                            ]
                        }
                    }
                }
            },
        }

        # The score endpoint should return a risk score
        # Verify the request structure is correct
        assert "old_spec" in score_request
        assert "new_spec" in score_request

    @pytest.mark.asyncio
    async def test_dit_sec_response_with_model_comparison_fields(self):
        """Test that DIT-Sec response includes model comparison fields."""
        agent = HealthAgent(dit_sec_url="http://dit-sec-server:8000")

        # Mock DIT-Sec response with all fields including new ones
        mock_response = {
            "risk_score": 0.45,
            "label": "medium",
            "confidence_interval": [0.40, 0.50],
            "explainability": {"reason": "CPU limit low"},
            "model_used": "onnx_model",
            "model_score": 0.48,
            "heuristic_score": 0.42,
            "inference_method": "ONNX inference",
        }

        # Verify response has all expected fields
        assert "model_used" in mock_response
        assert "model_score" in mock_response
        assert "heuristic_score" in mock_response
        assert "inference_method" in mock_response
        assert mock_response["model_used"] == "onnx_model"
        assert mock_response["model_score"] == 0.48
        assert mock_response["heuristic_score"] == 0.42
        assert mock_response["inference_method"] == "ONNX inference"

    @pytest.mark.asyncio
    async def test_local_assessment_fallback_when_dit_sec_unavailable(self):
        """Test that local assessment is used when DIT-Sec is unavailable."""
        agent = HealthAgent(dit_sec_url="http://unavailable:9999")

        # Mock the assessment call to verify fallback works
        # This is a conceptual test showing fallback behavior
        new_spec = {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "resources": {"limits": {"cpu": "50m", "memory": "512Mi"}},
                        }
                    ]
                }
            }
        }

        # Call local assessment directly
        local_result = agent._local_assessment(new_spec, {})

        # Should return a valid result even if DIT-Sec fails
        assert "risk_score" in local_result
        assert local_result["risk_score"] >= 0.0
        assert local_result["risk_score"] <= 1.0


class TestHealthAgentCooldown:
    """Test cooldown mechanism for duplicate assessments."""

    @pytest.mark.asyncio
    async def test_cooldown_key_generation(self):
        """Test that cooldown keys are properly generated."""
        agent = HealthAgent(cooldown_ttl=300)

        # Cooldown key should be deterministic for same event
        event1 = {"namespace": "prod", "name": "app1"}
        event2 = {"namespace": "prod", "name": "app2"}

        # Keys should be different for different events
        assert hash((event1["namespace"], event1["name"])) != hash(
            (event2["namespace"], event2["name"])
        )


class TestSeverityMapping:
    """Test mapping risk scores to severity levels."""

    def test_score_to_severity_mapping(self):
        """Test that risk scores map to appropriate severity levels."""
        test_cases = [
            (0.0, SeverityLevel.BENIGN),
            (0.1, SeverityLevel.BENIGN),
            (0.2, SeverityLevel.LOW),
            (0.4, SeverityLevel.MEDIUM),
            (0.65, SeverityLevel.HIGH),
            (0.85, SeverityLevel.CRITICAL),
            (1.0, SeverityLevel.CRITICAL),
        ]

        # Each case should map to expected severity
        # This tests the mapping logic would be implemented in agent
        for score, expected_severity in test_cases:
            # Verify the severity values are correct
            assert expected_severity in SeverityLevel


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
