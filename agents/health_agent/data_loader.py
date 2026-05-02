"""Data loader for training dataset."""

import json
import logging
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

try:
    from .exceptions import DataLoaderError
except ImportError:
    from exceptions import DataLoaderError

logger = logging.getLogger(__name__)


class HealthDataLoader:
    """Load and validate training dataset for Health Agent."""

    REQUIRED_FIELDS = {"namespace", "deployment", "severity", "operational_label"}

    def __init__(self, dataset_path: str):
        """Initialize data loader."""
        self.dataset_path = Path(dataset_path)

        if not self.dataset_path.exists():
            raise DataLoaderError(f"Dataset path does not exist: {dataset_path}")

    def load(self) -> pd.DataFrame:
        """Load dataset from CSV or JSON."""
        try:
            if self.dataset_path.suffix == ".csv":
                df = pd.read_csv(self.dataset_path)
            elif self.dataset_path.suffix in (".json", ".jsonl"):
                if self.dataset_path.suffix == ".jsonl":
                    df = pd.read_json(self.dataset_path, lines=True)
                else:
                    with open(self.dataset_path) as f:
                        data = json.load(f)
                    df = pd.DataFrame(data)
            else:
                raise DataLoaderError(
                    f"Unsupported file format: {self.dataset_path.suffix}"
                )

            logger.info(f"Loaded {len(df)} samples from {self.dataset_path}")
            return df

        except Exception as e:
            raise DataLoaderError(f"Failed to load dataset: {e}")

    def validate(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
        """Validate dataset and return clean data + warnings."""
        warnings = []

        # Check required fields
        missing_fields = self.REQUIRED_FIELDS - set(df.columns)
        if missing_fields:
            logger.warning(
                f"Missing fields: {missing_fields}. Will continue with available fields."
            )

        # Check for null values in key fields
        for field in ["namespace", "deployment", "severity"]:
            if field in df.columns:
                null_count = df[field].isnull().sum()
                if null_count > 0:
                    warnings.append(f"Found {null_count} null values in {field}")
                    df = df[df[field].notnull()]

        # Validate severity values if present
        if "severity" in df.columns:
            valid_severities = {
                1,
                2,
                3,
                4,
                5,
                "benign",
                "low",
                "medium",
                "high",
                "critical",
            }
            invalid_severities = set(df["severity"].unique()) - valid_severities
            if invalid_severities:
                warnings.append(f"Invalid severity values: {invalid_severities}")

        logger.info(
            f"Validation complete: {len(df)} valid samples, {len(warnings)} warnings"
        )

        return df, warnings

    def to_model_format(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Convert dataset to model training format."""
        samples = []

        for idx, row in df.iterrows():
            # Parse JSON specs
            baseline_json = row.get("baseline_json")
            live_json = row.get("live_json")

            old_spec = None
            new_spec = None

            if isinstance(baseline_json, str):
                try:
                    old_spec = json.loads(baseline_json)
                except:
                    old_spec = None

            if isinstance(live_json, str):
                try:
                    new_spec = json.loads(live_json)
                except:
                    new_spec = None

            # Map severity to numeric if string
            severity = row.get("severity", 1)
            if isinstance(severity, str):
                severity_map = {
                    "benign": 1,
                    "low": 2,
                    "medium": 3,
                    "high": 4,
                    "critical": 5,
                }
                severity = severity_map.get(severity.lower(), 1)

            sample = {
                "event_id": f"train-{idx}",
                "target": {
                    "namespace": str(row.get("namespace", "default")),
                    "name": str(row.get("deployment", f"app-{idx}")),
                    "kind": "Deployment",
                },
                "old_spec": old_spec or {},
                "new_spec": new_spec or {},
                "drift_type": row.get("drift_type", "unknown"),
                "drift_magnitude": row.get("magnitude", "unknown"),
                "severity": int(severity),
                "operational_label": row.get("operational_label", "unknown"),
                "blast_radius": "High"
                if any(
                    x in str(row.get("operational_label", "")).lower()
                    for x in ["critical", "high"]
                )
                else "Low",
                "telemetry": {
                    "request_rate": float(row.get("request_rate", 0)),
                    "error_rate": float(row.get("error_rate_5xx", 0)),
                    "latency_p99": float(row.get("latency_p99", 0)),
                    "cpu_cores": float(row.get("cpu_usage_cores", 0)),
                    "memory_bytes": float(row.get("memory_working_set_bytes", 0)),
                    "cpu_limit": float(row.get("cpu_limit", 0)),
                    "memory_limit": float(row.get("memory_limit", 0)),
                    "desired_replicas": int(row.get("desired_replicas", 1)),
                    "ready_replicas": int(row.get("ready_replicas", 1)),
                    "restart_count": int(row.get("restart_count", 0)),
                },
            }

            samples.append(sample)

        logger.info(f"Converted {len(samples)} samples to model format")
        return samples

    def compute_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Compute dataset statistics."""
        stats = {
            "total_samples": len(df),
            "namespace_count": df["namespace"].nunique()
            if "namespace" in df.columns
            else 0,
            "deployment_count": df["deployment"].nunique()
            if "deployment" in df.columns
            else 0,
        }

        if "severity" in df.columns:
            stats["severity_distribution"] = df["severity"].value_counts().to_dict()

        if "operational_label" in df.columns:
            stats["label_distribution"] = (
                df["operational_label"].value_counts().to_dict()
            )

        if "drift_type" in df.columns:
            stats["drift_types"] = df["drift_type"].unique().tolist()

        return stats

    def load_and_validate(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Load, validate, and convert dataset in one call."""
        df = self.load()
        df, warnings = self.validate(df)
        samples = self.to_model_format(df)
        stats = self.compute_statistics(df)

        for warning in warnings:
            logger.warning(warning)

        return samples, stats
