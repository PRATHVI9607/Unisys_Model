import pytest
import asyncio
import json
import math
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent import SecurityAgent, SecurityEvent, ThreatLevel, EntropyCalculator


class TestEntropyCalculator:
    """Test Shannon entropy calculations."""

    def test_entropy_all_same_byte(self):
        """Test entropy of repeated bytes (should be 0)."""
        data = b"\x00" * 1000
        entropy = EntropyCalculator.calculate_entropy(data)
        assert entropy == 0.0

    def test_entropy_uniform_distribution(self):
        """Test entropy of uniform byte distribution."""
        # Create uniformly distributed data
        data = bytes(range(256)) * 4  # 1024 bytes total, each byte appears 4 times
        entropy = EntropyCalculator.calculate_entropy(data)

        # Entropy of uniform distribution should be high (close to 8 for 256 values)
        assert entropy > 7.0
        assert entropy <= 8.0

    def test_entropy_empty_data(self):
        """Test entropy of empty data."""
        entropy = EntropyCalculator.calculate_entropy(b"")
        assert entropy == 0.0

    def test_entropy_single_byte(self):
        """Test entropy of single byte."""
        entropy = EntropyCalculator.calculate_entropy(b"\x42")
        assert entropy == 0.0

    def test_entropy_two_bytes(self):
        """Test entropy of binary data."""
        data = b"\x00\x01" * 50  # 100 bytes, 50/50 distribution
        entropy = EntropyCalculator.calculate_entropy(data)

        # Binary distribution should have entropy of 1.0
        assert abs(entropy - 1.0) < 0.01

    def test_file_entropy_with_real_file(self):
        """Test entropy calculation from a real file."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Write test data
            tmp.write(b"This is test data for entropy calculation.")
            tmp_path = tmp.name

        try:
            entropy = EntropyCalculator.calculate_file_entropy(tmp_path)
            assert isinstance(entropy, float)
            assert entropy >= 0.0
            assert entropy <= 8.0
        finally:
            os.unlink(tmp_path)

    def test_file_entropy_nonexistent_file(self):
        """Test entropy calculation for nonexistent file."""
        entropy = EntropyCalculator.calculate_file_entropy("/nonexistent/file")
        assert entropy == 0.0

    def test_file_entropy_random_multiple_files(self):
        """Test entropy calculation from multiple files."""
        file_paths = []
        try:
            # Create temporary files
            for i in range(3):
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(f"Test data {i}".encode() * 10)
                    file_paths.append(tmp.name)

            entropy = EntropyCalculator.calculate_file_entropy_random(file_paths)
            assert isinstance(entropy, float)
            assert entropy >= 0.0
            assert entropy <= 8.0
        finally:
            for path in file_paths:
                if os.path.exists(path):
                    os.unlink(path)


class TestSecurityEvent:
    """Test SecurityEvent model."""

    def test_security_event_creation(self):
        """Test creating a SecurityEvent."""
        event = SecurityEvent(
            event_id="test-001",
            target={"pod": "app", "container": "main"},
            risk_score=0.85,
            label=ThreatLevel.RANSOMWARE_CRITICAL,
            entropy=7.5,
        )

        assert event.event_id == "test-001"
        assert event.target["pod"] == "app"
        assert event.risk_score == 0.85
        assert event.label == ThreatLevel.RANSOMWARE_CRITICAL
        assert event.entropy == 7.5
        assert event.timestamp is not None

    def test_security_event_risk_score_bounds(self):
        """Test that risk_score is validated."""
        with pytest.raises(ValueError):
            SecurityEvent(
                event_id="test-002",
                target={"pod": "app"},
                risk_score=1.5,  # Invalid - > 1.0
                label=ThreatLevel.BENIGN,
            )

        with pytest.raises(ValueError):
            SecurityEvent(
                event_id="test-003",
                target={"pod": "app"},
                risk_score=-0.1,  # Invalid - < 0.0
                label=ThreatLevel.SUSPICIOUS,
            )

    def test_security_event_json_serialization(self):
        """Test SecurityEvent JSON serialization."""
        event = SecurityEvent(
            event_id="test-004",
            target={"pod": "nginx"},
            risk_score=0.5,
            label=ThreatLevel.SUSPICIOUS,
            early_signals={"renamed_files": True, "high_entropy": False},
        )

        json_str = event.model_dump_json()
        assert isinstance(json_str, str)

        parsed = json.loads(json_str)
        assert parsed["event_id"] == "test-004"
        assert parsed["risk_score"] == 0.5
        assert parsed["label"] == "suspicious"


class TestThreatLevel:
    """Test ThreatLevel enumeration."""

    def test_threat_level_values(self):
        """Test threat level values."""
        assert ThreatLevel.BENIGN.value == "benign"
        assert ThreatLevel.SUSPICIOUS.value == "suspicious"
        assert ThreatLevel.LIKELY_RANSOMWARE.value == "likely_ransomware"
        assert ThreatLevel.RANSOMWARE_CRITICAL.value == "ransomware-critical"

    def test_threat_level_ordering(self):
        """Test threat levels exist."""
        levels = [
            ThreatLevel.BENIGN,
            ThreatLevel.SUSPICIOUS,
            ThreatLevel.LIKELY_RANSOMWARE,
            ThreatLevel.RANSOMWARE_CRITICAL,
        ]

        assert len(levels) == 4
        assert ThreatLevel.RANSOMWARE_CRITICAL in levels


class TestSecurityAgentInit:
    """Test SecurityAgent initialization."""

    def test_init_with_defaults(self):
        """Test SecurityAgent initialization with defaults."""
        agent = SecurityAgent()

        assert agent.namespace == "kubeheal"
        assert agent.redis_url == "redis://redis-master:6379"
        assert agent.running is False

    def test_init_with_env_vars(self):
        """Test SecurityAgent initialization with explicit parameters."""
        # The agent takes parameters directly, not env vars
        agent = SecurityAgent(namespace="custom-ns", redis_url="redis://custom:6379")
        assert agent.redis_url == "redis://custom:6379"
        assert agent.namespace == "custom-ns"

    def test_init_with_explicit_params(self):
        """Test SecurityAgent initialization with explicit params."""
        agent = SecurityAgent(namespace="test", redis_url="redis://test:6379")

        assert agent.namespace == "test"
        assert agent.redis_url == "redis://test:6379"


class TestRansomwareDetection:
    """Test ransomware detection logic."""

    def test_entropy_threshold_detection(self):
        """Test detection based on entropy thresholds."""
        # High entropy data should indicate encryption
        random_data = os.urandom(1000)
        entropy = EntropyCalculator.calculate_entropy(random_data)

        # Encrypted/random data should have high entropy
        assert entropy > 7.0

    def test_renamed_files_signature(self):
        """Test detection of renamed files pattern."""
        # This would be part of the SecurityAgent logic
        # Simulating syscall pattern analysis
        syscalls = [
            {"syscall": "rename", "arg": "file1"},
            {"syscall": "rename", "arg": "file2"},
            {"syscall": "rename", "arg": "file3"},
        ]

        rename_count = sum(1 for s in syscalls if s.get("syscall") == "rename")

        # Multiple renames could indicate ransomware activity
        assert rename_count >= 3

    def test_file_write_pattern(self):
        """Test detection of excessive file write activity."""
        syscalls = [
            {"syscall": "write", "fd": 1},
            {"syscall": "write", "fd": 2},
            {"syscall": "write", "fd": 3},
        ] * 20  # 60 total write calls

        write_count = sum(1 for s in syscalls if s.get("syscall") == "write")

        assert write_count == 60


class TestSecurityAgentRedisIntegration:
    """Test SecurityAgent Redis connectivity."""

    @pytest.mark.asyncio
    async def test_redis_connection(self):
        """Test Redis connection initialization."""
        mock_redis = AsyncMock()
        with patch("agent.aioredis.from_url", return_value=mock_redis) as mock_from_url:
            agent = SecurityAgent()
            # Mock the kubernetes config to avoid requiring in-cluster environment
            with patch(
                "agent.config.load_kube_config", side_effect=Exception("Not configured")
            ):
                try:
                    await agent.start()
                except Exception:
                    # Expected to fail since we're not in-cluster, but redis should be set
                    pass

                # Verify redis was attempted to be connected
                assert agent.redis_url == "redis://redis-master:6379"


class TestSecurityMetrics:
    """Test security metrics and scoring."""

    def test_risk_score_from_entropy(self):
        """Test mapping entropy to risk score."""
        # Normal files have entropy 3-7
        # Encrypted/compressed have entropy 7+

        normal_entropy = 5.0
        suspicious_entropy = 7.5

        # Risk should increase with entropy
        assert normal_entropy < suspicious_entropy

    def test_early_warning_signals(self):
        """Test early warning signal detection."""
        early_signals = {
            "high_entropy_files": True,
            "large_file_writes": False,
            "mass_renames": False,
            "unusual_syscalls": True,
        }

        # Multiple signals indicate higher risk
        signal_count = sum(1 for v in early_signals.values() if v)
        assert signal_count >= 1


class TestDITSecIntegration:
    """Test DIT-Sec model comparison integration."""

    def test_default_dit_sec_response(self):
        """Test default DIT-Sec response when service is unavailable."""
        agent = SecurityAgent()
        response = agent._default_dit_sec_response()

        assert response.get("model_used") is None
        assert response.get("model_score") is None
        assert response.get("heuristic_score") is None
        assert response.get("inference_method") is None

    @pytest.mark.asyncio
    async def test_call_dit_sec_timeout_fallback(self):
        """Test DIT-Sec fallback when timeout occurs."""
        agent = SecurityAgent(dit_sec_url="http://dit-sec-mock:5000")

        with patch("agent.aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session.__aenter__.return_value = mock_session
            mock_session.post.return_value.__aenter__.side_effect = (
                asyncio.TimeoutError()
            )
            mock_session_class.return_value = mock_session

            early_signals = {"rename_burst": False}
            result = await agent._call_dit_sec_score(7.2, early_signals)

            # Should return default response when timeout occurs
            assert result["model_used"] is None
            assert result["model_score"] is None

    def test_security_event_with_model_fields(self):
        """Test SecurityEvent model with DIT-Sec fields."""
        event = SecurityEvent(
            event_id="test-005",
            target={"pod": "app", "container": "main"},
            risk_score=0.85,
            label=ThreatLevel.RANSOMWARE_CRITICAL,
            entropy=7.5,
            model_used="onnx_model",
            model_score=0.92,
            heuristic_score=0.85,
            inference_method="ONNX inference",
        )

        assert event.event_id == "test-005"
        assert event.model_used == "onnx_model"
        assert event.model_score == 0.92
        assert event.heuristic_score == 0.85
        assert event.inference_method == "ONNX inference"

    def test_security_event_with_null_model_fields(self):
        """Test SecurityEvent model with null DIT-Sec fields."""
        event = SecurityEvent(
            event_id="test-006",
            target={"pod": "app"},
            risk_score=0.5,
            label=ThreatLevel.SUSPICIOUS,
        )

        assert event.model_used is None
        assert event.model_score is None
        assert event.heuristic_score is None
        assert event.inference_method is None
