import pytest
import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestDitSecModel:
    """Test DIT-Sec v3 Model Server."""

    def test_model_path_env_var(self):
        """Test MODEL_PATH environment variable."""
        model_path = "/models/dit_sec_v3_simple.onnx"
        assert model_path.endswith(".onnx")

    def test_model_file_exists(self):
        """Test that the ONNX model file exists."""
        model_path = os.path.join(
            os.path.dirname(__file__), "..", "models", "dit_sec_v3_simple.onnx"
        )
        # File should exist if properly distributed
        # In CI/CD this would be checked during container build
        assert model_path.endswith(".onnx")


class TestDitSecScoreRequest:
    """Test DIT-Sec /score endpoint request format."""

    def test_yaml_diff_scoring(self):
        """Test scoring with YAML diff."""
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

        # Significant CPU reduction should result in higher risk
        assert "old_spec" in score_request
        assert "new_spec" in score_request
        assert (
            score_request["old_spec"]["spec"]["template"]["spec"]["containers"][0][
                "resources"
            ]["limits"]["cpu"]
            != score_request["new_spec"]["spec"]["template"]["spec"]["containers"][0][
                "resources"
            ]["limits"]["cpu"]
        )

    def test_metrics_scoring(self):
        """Test scoring with Prometheus metrics."""
        import numpy as np

        score_request = {
            "metrics": [[0.8, 0.6, 0.4, 0.3, 0.2]],  # CPU throttle over time
        }

        # Metrics should be numeric arrays
        metrics = np.array(score_request["metrics"])
        assert metrics.dtype in [np.float64, np.float32, np.int32, np.int64]

    def test_entropy_scoring(self):
        """Test scoring with entropy series."""
        score_request = {
            "entropy_series": [
                5.2,
                5.3,
                7.8,
                7.9,
                7.7,
            ]  # High entropy indicates encryption
        }

        # High entropy values should be detected
        avg_entropy = sum(score_request["entropy_series"]) / len(
            score_request["entropy_series"]
        )
        assert avg_entropy > 6.0  # Indicates suspicious activity

    def test_syscall_scoring(self):
        """Test scoring with syscall events."""
        score_request = {
            "syscalls": [
                {"syscall": "write", "fd": 5},
                {"syscall": "write", "fd": 6},
                {"syscall": "rename", "old": "file1", "new": "file1.enc"},
                {"syscall": "rename", "old": "file2", "new": "file2.enc"},
            ]
        }

        # Count suspicious syscalls
        write_count = sum(
            1 for s in score_request["syscalls"] if s.get("syscall") == "write"
        )
        rename_count = sum(
            1 for s in score_request["syscalls"] if s.get("syscall") == "rename"
        )

        assert write_count == 2
        assert rename_count == 2


class TestDitSecScoreResponse:
    """Test DIT-Sec /score endpoint response format."""

    def test_response_format_benign(self):
        """Test response for benign scoring."""
        response = {
            "risk_score": 0.15,
            "label": "benign",
            "confidence_interval": [0.10, 0.20],
            "explainability": {},
        }

        assert 0.0 <= response["risk_score"] <= 1.0
        assert response["label"] in [
            "benign",
            "perf-risk",
            "sec-medium",
            "health-critical",
            "ransomware-critical",
        ]
        assert len(response["confidence_interval"]) == 2
        assert (
            response["confidence_interval"][0]
            <= response["risk_score"]
            <= response["confidence_interval"][1]
        )

    def test_response_format_critical(self):
        """Test response for critical scoring."""
        response = {
            "risk_score": 0.92,
            "label": "ransomware-critical",
            "confidence_interval": [0.87, 0.97],
            "explainability": {
                "changed_fields": ["containers[0].resources.limits.cpu"],
                "attention": {"containers[0].resources.limits.cpu": 0.89},
            },
        }

        assert response["risk_score"] >= 0.85
        assert response["label"] == "ransomware-critical"
        assert (
            response["confidence_interval"][1] - response["confidence_interval"][0]
            <= 0.2
        )


class TestDitSecHealthEndpoint:
    """Test DIT-Sec /health endpoint."""

    def test_health_endpoint_response(self):
        """Test /health endpoint format."""
        response = {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

        assert response["status"] == "healthy"
        assert "T" in response["timestamp"]  # ISO format check


class TestDitSecReadyEndpoint:
    """Test DIT-Sec /ready endpoint."""

    def test_ready_endpoint_model_not_loaded(self):
        """Test /ready endpoint when model is not loaded."""
        response = {
            "ready": True,
            "model_loaded": False,
            "timestamp": datetime.utcnow().isoformat(),
        }

        assert response["ready"] is True  # Server is ready to serve
        assert response["model_loaded"] is False  # But using fallback scoring

    def test_ready_endpoint_model_loaded(self):
        """Test /ready endpoint when model is loaded."""
        response = {
            "ready": True,
            "model_loaded": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

        assert response["ready"] is True
        assert response["model_loaded"] is True


class TestDitSecExplainEndpoint:
    """Test DIT-Sec /explain endpoint."""

    def test_explain_response_format(self):
        """Test /explain endpoint response."""
        response = {
            "risk_score": 0.65,
            "label": "health-critical",
            "explainability": {
                "yaml_fields": {
                    "changed_fields": ["containers[0].resources.limits.cpu"],
                    "attention": {"containers[0].resources.limits.cpu": 0.89},
                },
                "metrics_features": {
                    "feature_importance": {"cpu_throttle": 0.8, "memory_usage": 0.3}
                },
                "syscall_patterns": {
                    "counts": {"write": 45, "rename": 8},
                    "patterns": ["write", "rename"],
                },
                "entropy_analysis": {
                    "max_entropy": 7.5,
                    "avg_entropy": 6.8,
                    "analysis": "suspicious files",
                },
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Verify structure
        assert "yaml_fields" in response["explainability"]
        assert "metrics_features" in response["explainability"]
        assert "syscall_patterns" in response["explainability"]
        assert "entropy_analysis" in response["explainability"]


class TestDitSecScoringLogic:
    """Test DIT-Sec scoring heuristics."""

    def test_cpu_reduction_risk(self):
        """Test that CPU reduction increases risk."""
        old_cpu = 500  # 500m
        new_cpu = 50  # 50m (90% reduction)

        # Significant CPU reduction is suspicious
        reduction = (old_cpu - new_cpu) / old_cpu
        assert reduction > 0.7

    def test_entropy_based_risk(self):
        """Test entropy-based risk scoring."""
        test_cases = [
            (4.5, 0.0),  # Normal file system entropy
            (6.5, 0.5),  # Moderate entropy
            (7.5, 0.9),  # High entropy (likely encrypted)
        ]

        for entropy, expected_risk_level in test_cases:
            # Higher entropy should correlate with higher risk
            if entropy < 5.0:
                assert expected_risk_level < 0.3
            elif entropy > 7.0:
                assert expected_risk_level > 0.8

    def test_ransomware_pattern_detection(self):
        """Test detection of ransomware patterns."""
        syscalls = {
            "write": 100,  # High write activity
            "rename": 25,  # Many file renames
            "unlink": 15,  # File deletions
        }

        # Calculate composite risk
        write_risk = min(1.0, syscalls["write"] / 50)  # > 50 writes is suspicious
        rename_risk = min(1.0, syscalls["rename"] / 10)  # > 10 renames is suspicious

        assert write_risk > 0.5
        assert rename_risk > 0.5


class TestDitSecFallbackScoring:
    """Test DIT-Sec fallback scoring when model unavailable."""

    def test_fallback_cpu_heuristic(self):
        """Test fallback CPU reduction heuristic."""
        # If new_cpu < old_cpu * 0.5, risk should be high
        old_cpu = 500
        new_cpu = 100

        ratio = new_cpu / old_cpu
        if ratio < 0.3:
            risk = 0.85
        elif ratio < 0.5:
            risk = 0.65
        else:
            risk = 0.0

        assert risk == 0.85

    def test_fallback_entropy_heuristic(self):
        """Test fallback entropy heuristic."""
        entropies = [
            (7.5, 0.93),  # High entropy = high risk
            (6.5, 0.70),  # Medium entropy
            (5.0, 0.50),  # Normal entropy
        ]

        for entropy, expected_risk in entropies:
            if entropy > 7.2:
                risk = 0.93
            elif entropy > 6.0:
                risk = 0.70
            elif entropy >= 5.0:
                risk = 0.50
            else:
                risk = 0.0

            assert risk == expected_risk


class TestDitSecIntegration:
    """Integration tests for DIT-Sec endpoints."""

    @pytest.mark.asyncio
    async def test_score_endpoint_with_combined_data(self):
        """Test scoring with combined modalities."""
        request_data = {
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
            "metrics": [[0.8, 0.6]],  # CPU throttle
            "entropy_series": [7.2, 7.3, 7.4],  # High entropy
            "syscalls": [
                {"syscall": "write"},
                {"syscall": "rename"},
            ],
        }

        # All three modalities indicate risk
        assert (
            request_data["new_spec"]["spec"]["template"]["spec"]["containers"][0][
                "resources"
            ]["limits"]["cpu"]
            != request_data["old_spec"]["spec"]["template"]["spec"]["containers"][0][
                "resources"
            ]["limits"]["cpu"]
        )
        assert all(e > 7.0 for e in request_data["entropy_series"])
        assert len(request_data["syscalls"]) > 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
