"""Unit tests for training_pipeline module."""

import pytest
import tempfile
import json
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from training_pipeline import TrainingPipeline


@pytest.fixture
def sample_csv_file():
    """Create a temporary CSV file with sample training data."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(
            """namespace,deployment,severity,operational_label,cpu_usage,memory_usage,latency_p99,error_rate
demo,drift-lab,low,normal,0.25,0.30,100,0.01
demo,drift-lab,medium,drift,0.55,0.70,250,0.05
demo,cpu_app,high,anomalous,0.85,0.50,500,0.10
demo,drift-lab,benign,normal,0.15,0.20,50,0.005
demo,cpu_app,critical,drift,0.95,0.85,750,0.20
"""
        )
        fname = f.name
    # File is now closed, but still exists
    yield fname
    # Clean up after test
    Path(fname).unlink(missing_ok=True)


def test_training_pipeline_load(sample_csv_file):
    """Test training pipeline load."""
    pipeline = TrainingPipeline(sample_csv_file)
    assert pipeline.loader is not None
    assert pipeline.raw_data is None


def test_training_pipeline_run(sample_csv_file):
    """Test complete training pipeline."""
    pipeline = TrainingPipeline(sample_csv_file)
    processed_data, stats = pipeline.run()

    assert processed_data is not None
    assert len(processed_data) == 5
    assert "severity_score" in processed_data.columns
    assert "label_encoded" in processed_data.columns

    assert stats is not None
    assert stats["total_samples"] == 5
    assert "severity_distribution" in stats
    assert "label_distribution" in stats


def test_training_pipeline_statistics(sample_csv_file):
    """Test statistics computation."""
    pipeline = TrainingPipeline(sample_csv_file)
    processed_data, stats = pipeline.run()

    # Check distributions
    assert "severity_distribution" in stats
    assert "label_distribution" in stats

    # Check feature statistics
    assert "feature_statistics" in stats
    assert "cpu_usage" in stats["feature_statistics"]
    assert "memory_usage" in stats["feature_statistics"]

    # Verify feature stats have required keys
    cpu_stats = stats["feature_statistics"]["cpu_usage"]
    assert "mean" in cpu_stats
    assert "std" in cpu_stats
    assert "min" in cpu_stats
    assert "max" in cpu_stats


def test_training_pipeline_save_artifacts(sample_csv_file):
    """Test saving training artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pipeline = TrainingPipeline(sample_csv_file, output_dir=tmpdir)
        processed_data, stats = pipeline.run()

        # Verify output files were created
        output_dir = Path(tmpdir)
        assert (output_dir / "processed_data.csv").exists()
        assert (output_dir / "statistics.json").exists()
        assert (output_dir / "feature_names.json").exists()

        # Verify statistics file content
        with open(output_dir / "statistics.json") as f:
            saved_stats = json.load(f)
        assert saved_stats["total_samples"] == 5


def test_training_pipeline_train_test_split(sample_csv_file):
    """Test train/test split generation."""
    pipeline = TrainingPipeline(sample_csv_file)
    processed_data, stats = pipeline.run()

    (X_train, X_test), (y_train, y_test) = pipeline.get_train_test_split(
        test_size=0.2, random_state=42
    )

    assert len(X_train) + len(X_test) == 5
    assert len(y_train) + len(y_test) == 5
    assert X_train.shape[1] > 0  # Has features
    assert y_train.shape[0] > 0  # Has labels


def test_training_pipeline_no_run_error(sample_csv_file):
    """Test that get_train_test_split fails if run() not called."""
    pipeline = TrainingPipeline(sample_csv_file)

    with pytest.raises(ValueError, match="Must call run"):
        pipeline.get_train_test_split()
