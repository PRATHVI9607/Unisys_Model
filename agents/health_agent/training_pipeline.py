"""Model training pipeline for Health Agent.

This module provides utilities for preparing the training dataset,
computing statistics, and generating training features for the Health Agent model.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Tuple, List, Optional, Any
import numpy as np
import pandas as pd

try:
    from .data_loader import HealthDataLoader
    from .spec_differ import SpecDiffer
    from .exceptions import DataLoaderError
except ImportError:
    from data_loader import HealthDataLoader
    from spec_differ import SpecDiffer
    from exceptions import DataLoaderError

logger = logging.getLogger(__name__)


class TrainingPipeline:
    """Orchestrate model training dataset preparation."""

    def __init__(self, dataset_path: str, output_dir: Optional[str] = None):
        """Initialize training pipeline.

        Args:
            dataset_path: Path to training dataset (CSV or JSON)
            output_dir: Directory to save processed datasets (optional)
        """
        self.loader = HealthDataLoader(dataset_path)
        self.output_dir = Path(output_dir) if output_dir else None
        self.raw_data: Optional[pd.DataFrame] = None
        self.processed_data: Optional[pd.DataFrame] = None
        self.stats: Dict[str, Any] = {}

    def run(self) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Run complete training pipeline.

        Returns:
            Tuple of (processed_dataframe, statistics_dict)
        """
        logger.info("Starting training pipeline...")

        # Load dataset
        self.raw_data = self.loader.load()
        logger.info(f"Loaded {len(self.raw_data)} samples")

        # Validate dataset
        validated_data, warnings = self.loader.validate(self.raw_data)
        if warnings:
            logger.warning(f"Dataset validation warnings: {warnings}")
        self.raw_data = validated_data

        # Process and enrich dataset
        self.processed_data = self._process_dataset(self.raw_data)
        logger.info(f"Processed data shape: {self.processed_data.shape}")

        # Compute statistics
        self.stats = self._compute_statistics(self.processed_data)
        logger.info(f"Computed statistics: {list(self.stats.keys())}")

        # Save artifacts if output_dir provided
        if self.output_dir:
            self._save_artifacts()
            logger.info(f"Saved training artifacts to {self.output_dir}")

        return self.processed_data, self.stats

    def _process_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process and enrich dataset for training.

        Args:
            df: Raw dataframe

        Returns:
            Processed dataframe with engineered features
        """
        df = df.copy()

        # Ensure severity is mapped to numeric scale
        severity_map = {
            "benign": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        if "severity" in df.columns:
            df["severity_score"] = df["severity"].map(severity_map)
            df["severity_score"] = df["severity_score"].fillna(0).astype(int)

        # Ensure label is numeric
        if "operational_label" in df.columns:
            label_map = {"normal": 0, "anomalous": 1, "drift": 2}
            df["label_encoded"] = df["operational_label"].map(label_map)
            df["label_encoded"] = df["label_encoded"].fillna(0).astype(int)

        # Process telemetry if present
        if "baseline_json" in df.columns:
            df["baseline_json"] = df["baseline_json"].apply(self._safe_json_load)

        if "live_json" in df.columns:
            df["live_json"] = df["live_json"].apply(self._safe_json_load)

        # Extract numeric features from telemetry
        df = self._extract_telemetry_features(df)

        # Handle missing values
        numeric_columns = df.select_dtypes(include=["float64", "int64"]).columns
        for col in numeric_columns:
            df[col] = df[col].fillna(df[col].median())

        logger.info(f"Processed {len(df)} samples with {len(df.columns)} features")
        return df

    def _extract_telemetry_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract numeric features from telemetry JSON fields.

        Args:
            df: Dataframe with telemetry

        Returns:
            Dataframe with extracted features
        """
        # Extract metrics if present
        metric_cols = [
            "cpu_usage",
            "memory_usage",
            "latency_p99",
            "error_rate",
            "request_rate",
        ]

        for col in metric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

        return df

    def _safe_json_load(self, val: Any) -> Dict:
        """Safely load JSON from string or return dict.

        Args:
            val: JSON string or dict

        Returns:
            Parsed dict or empty dict on error
        """
        if isinstance(val, dict):
            return val
        if isinstance(val, str):
            try:
                return json.loads(val)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    def _compute_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Compute dataset statistics for monitoring.

        Args:
            df: Processed dataframe

        Returns:
            Dictionary of statistics
        """
        stats = {
            "total_samples": len(df),
            "n_features": len(df.columns),
            "memory_mb": df.memory_usage(deep=True).sum() / 1024 / 1024,
        }

        # Severity distribution
        if "severity" in df.columns:
            stats["severity_distribution"] = df["severity"].value_counts().to_dict()

        # Label distribution
        if "operational_label" in df.columns:
            stats["label_distribution"] = (
                df["operational_label"].value_counts().to_dict()
            )

        # Feature statistics
        numeric_cols = df.select_dtypes(include=["float64", "int64"]).columns
        stats["feature_statistics"] = {}
        for col in numeric_cols:
            stats["feature_statistics"][col] = {
                "mean": float(df[col].mean()),
                "std": float(df[col].std()),
                "min": float(df[col].min()),
                "max": float(df[col].max()),
                "missing": int(df[col].isna().sum()),
            }

        # Deployment distribution
        if "deployment" in df.columns:
            stats["deployment_distribution"] = df["deployment"].value_counts().to_dict()

        return stats

    def _save_artifacts(self) -> None:
        """Save processed dataset and statistics.

        Saves:
        - processed_data.csv: The processed training data
        - statistics.json: Computed statistics
        - feature_names.json: List of feature columns
        """
        if not self.output_dir:
            return

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Save processed data
        data_path = self.output_dir / "processed_data.csv"
        self.processed_data.to_csv(data_path, index=False)
        logger.info(f"Saved processed data to {data_path}")

        # Save statistics
        stats_path = self.output_dir / "statistics.json"
        with open(stats_path, "w") as f:
            json.dump(self.stats, f, indent=2, default=str)
        logger.info(f"Saved statistics to {stats_path}")

        # Save feature names
        features_path = self.output_dir / "feature_names.json"
        with open(features_path, "w") as f:
            json.dump(list(self.processed_data.columns), f, indent=2)
        logger.info(f"Saved feature names to {features_path}")

    def get_train_test_split(
        self, test_size: float = 0.2, random_state: int = 42
    ) -> Tuple[Tuple[pd.DataFrame, pd.DataFrame], Tuple[np.ndarray, np.ndarray]]:
        """Get train/test split for model training.

        Args:
            test_size: Proportion of test set (0.0-1.0)
            random_state: Random seed for reproducibility

        Returns:
            Tuple of ((X_train, X_test), (y_train, y_test))
        """
        if self.processed_data is None:
            raise ValueError("Must call run() first to process data")

        # Separate features and labels
        if "label_encoded" in self.processed_data.columns:
            y = self.processed_data["label_encoded"].values
            X = self.processed_data.drop(
                columns=[
                    "label_encoded",
                    "operational_label",
                    "severity",
                    "severity_score",
                ]
            )
        elif "severity_score" in self.processed_data.columns:
            y = self.processed_data["severity_score"].values
            X = self.processed_data.drop(
                columns=["severity_score", "severity", "label_encoded"]
            )
        else:
            raise ValueError("No label column found in processed data")

        # Train/test split
        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )

        logger.info(
            f"Train/test split: {len(X_train)}/{len(X_test)} samples, "
            f"y distribution: {np.bincount(y_train.astype(int))}"
        )

        return (X_train, X_test), (y_train, y_test)
