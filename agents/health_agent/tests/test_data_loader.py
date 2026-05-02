"""Unit tests for data_loader module."""

import pytest
import json
import tempfile
import pandas as pd
from pathlib import Path

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data_loader import HealthDataLoader
from exceptions import DataLoaderError


@pytest.fixture
def sample_csv_dataset(tmp_path):
    """Create sample CSV dataset matching the real format."""
    data = pd.DataFrame(
        {
            "namespace": ["demo", "demo", "prod"],
            "deployment": ["drift-lab", "drift-lab", "critical-app"],
            "severity": [1, 3, 5],
            "operational_label": ["Benign", "Medium_Risk", "Critical"],
            "drift_type": ["cpu_limit", "memory_limit", "image"],
            "magnitude": ["tiny", "small", "large"],
            "baseline_json": ["{}", "{}", "{}"],
            "live_json": ["{}", "{}", "{}"],
            "request_rate": [1.0, 2.5, 5.0],
            "error_rate_5xx": [0.0, 0.01, 0.1],
            "latency_p99": [0.005, 0.01, 0.05],
            "cpu_usage_cores": [0.1, 0.2, 0.5],
            "memory_working_set_bytes": [300000000, 500000000, 1000000000],
            "cpu_limit": [0.5, 0.5, 1.0],
            "memory_limit": [256, 512, 1024],
            "desired_replicas": [3, 3, 5],
            "ready_replicas": [3, 3, 5],
            "restart_count": [0, 1, 5],
        }
    )

    csv_path = tmp_path / "test_dataset.csv"
    data.to_csv(csv_path, index=False)
    return str(csv_path)


@pytest.fixture
def sample_json_dataset(tmp_path):
    """Create sample JSON dataset."""
    data = [
        {
            "namespace": "demo",
            "deployment": "app-1",
            "severity": 1,
            "operational_label": "Benign",
        },
        {
            "namespace": "prod",
            "deployment": "critical-app",
            "severity": 5,
            "operational_label": "Critical",
        },
    ]

    json_path = tmp_path / "test_dataset.json"
    with open(json_path, "w") as f:
        json.dump(data, f)
    return str(json_path)


@pytest.fixture
def sample_json_dataset():
    """Create sample JSON dataset."""
    data = [
        {
            "namespace": "demo",
            "deployment": "app-1",
            "severity": 1,
            "operational_label": "Benign",
        },
        {
            "namespace": "prod",
            "deployment": "critical-app",
            "severity": 5,
            "operational_label": "Critical",
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        yield f.name

    os.unlink(f.name)


def test_load_csv(sample_csv_dataset):
    """Test loading CSV dataset."""
    loader = HealthDataLoader(sample_csv_dataset)
    df = loader.load()

    assert len(df) == 3
    assert "namespace" in df.columns
    assert "deployment" in df.columns


def test_load_json(tmp_path):
    """Test loading JSON dataset."""
    data = [
        {"namespace": "demo", "deployment": "app-1", "severity": 1},
        {"namespace": "prod", "deployment": "app-2", "severity": 5},
    ]

    json_path = tmp_path / "test.json"
    with open(json_path, "w") as f:
        json.dump(data, f)

    loader = HealthDataLoader(str(json_path))
    df = loader.load()

    assert len(df) == 2


def test_load_nonexistent():
    """Test loading nonexistent file."""
    with pytest.raises(DataLoaderError):
        HealthDataLoader("/nonexistent/path/file.csv")


def test_validate_csv(sample_csv_dataset):
    """Test dataset validation."""
    loader = HealthDataLoader(sample_csv_dataset)
    df = loader.load()
    df, warnings = loader.validate(df)

    assert len(df) > 0


def test_to_model_format(sample_csv_dataset):
    """Test conversion to model format."""
    loader = HealthDataLoader(sample_csv_dataset)
    df = loader.load()
    df, _ = loader.validate(df)
    samples = loader.to_model_format(df)

    assert len(samples) == len(df)
    assert all("event_id" in s for s in samples)
    assert all("target" in s for s in samples)
    assert all("telemetry" in s for s in samples)
    assert all("old_spec" in s for s in samples)


def test_compute_statistics(sample_csv_dataset):
    """Test statistics computation."""
    loader = HealthDataLoader(sample_csv_dataset)
    df = loader.load()
    df, _ = loader.validate(df)
    stats = loader.compute_statistics(df)

    assert stats["total_samples"] == len(df)
    assert "namespace_count" in stats
    assert "deployment_count" in stats


def test_load_and_validate(sample_csv_dataset):
    """Test complete load and validate flow."""
    loader = HealthDataLoader(sample_csv_dataset)
    samples, stats = loader.load_and_validate()

    assert len(samples) > 0
    assert stats["total_samples"] > 0

    # Verify sample structure
    sample = samples[0]
    assert sample["target"]["namespace"]
    assert sample["telemetry"]["cpu_cores"] >= 0
