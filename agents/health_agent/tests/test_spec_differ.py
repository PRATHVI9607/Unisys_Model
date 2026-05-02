"""Unit tests for spec_differ module."""

import pytest
from datetime import datetime

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spec_differ import SpecDiffer, SpecChange


def test_compute_spec_hash():
    """Test spec hash computation."""
    spec = {"replicas": 3, "image": "app:1.0"}
    hash1 = SpecDiffer.compute_spec_hash(spec)
    hash2 = SpecDiffer.compute_spec_hash(spec)

    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex is 64 chars


def test_compute_spec_hash_differs():
    """Test that different specs produce different hashes."""
    spec1 = {"replicas": 3}
    spec2 = {"replicas": 5}

    hash1 = SpecDiffer.compute_spec_hash(spec1)
    hash2 = SpecDiffer.compute_spec_hash(spec2)

    assert hash1 != hash2


def test_diff_no_changes(sample_spec_old):
    """Test diff with identical specs."""
    diff = SpecDiffer.diff(sample_spec_old, sample_spec_old)

    assert diff.change_count == 0
    assert not diff.has_breaking_changes
    assert "No spec changes" in diff.summary


def test_diff_single_change(sample_spec_old, sample_spec_new):
    """Test diff with multiple changes."""
    diff = SpecDiffer.diff(sample_spec_old, sample_spec_new)

    assert diff.change_count > 0
    assert diff.has_breaking_changes
    assert any("replicas" in c.path for c in diff.changes)


def test_diff_image_change():
    """Test diff detects image changes as critical."""
    old = {"template": {"spec": {"containers": [{"image": "app:1.0"}]}}}
    new = {"template": {"spec": {"containers": [{"image": "app:2.0"}]}}}

    diff = SpecDiffer.diff(old, new)

    assert diff.change_count > 0
    image_changes = [c for c in diff.changes if "image" in c.path]
    assert all(c.severity == "critical" for c in image_changes)


def test_diff_cpu_limit_change():
    """Test diff detects CPU limit changes as high severity."""
    old = {
        "template": {
            "spec": {"containers": [{"resources": {"limits": {"cpu": "500m"}}}]}
        }
    }
    new = {
        "template": {
            "spec": {"containers": [{"resources": {"limits": {"cpu": "250m"}}}]}
        }
    }

    diff = SpecDiffer.diff(old, new)

    cpu_changes = [c for c in diff.changes if "cpu" in c.path]
    assert any(c.severity in ("high", "critical") for c in cpu_changes)


def test_diff_replicas_change():
    """Test diff detects replica count changes."""
    old = {"replicas": 3}
    new = {"replicas": 5}

    diff = SpecDiffer.diff(old, new)

    assert diff.change_count > 0
    assert any(c.severity == "high" for c in diff.changes)


def test_diff_from_none():
    """Test diff with None as old spec."""
    new = {"replicas": 3, "image": "app:1.0"}

    diff = SpecDiffer.diff(None, new)

    assert diff.change_count > 0


def test_summary_generation():
    """Test summary generation."""
    old = {"replicas": 3, "image": "app:1.0"}
    new = {"replicas": 5, "image": "app:2.0"}

    diff = SpecDiffer.diff(old, new)

    assert "modified" in diff.summary.lower()


def test_assess_severity():
    """Test severity assessment."""
    assert SpecDiffer._assess_severity("spec.image") == "critical"
    assert SpecDiffer._assess_severity("spec.securityContext") == "critical"
    assert SpecDiffer._assess_severity("spec.resources.limits.cpu") == "high"
    assert SpecDiffer._assess_severity("spec.replicas") == "high"
    assert SpecDiffer._assess_severity("spec.labels") == "medium"
    assert SpecDiffer._assess_severity("spec.unknown") == "low"
