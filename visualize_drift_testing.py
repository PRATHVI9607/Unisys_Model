#!/usr/bin/env python3
"""
DIT-Sec v3.0 Synthetic Drift Visualization
Displays model predictions on various synthetic test scenarios
"""

import sys
import json
import torch
import torch.nn as nn
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, List
import matplotlib.pyplot as plt
import matplotlib

matplotlib.use("Agg")  # Non-interactive backend

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "models" / "dit_sec_v3"))

# ============================================================================
# USE OFFICIAL INFERENCE MODULE (matches trained checkpoint exactly)
# ============================================================================

from models.dit_sec_v3.inference import DITSecModel_Enhanced, DITSecInference


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================


def extract_yaml_features(spec: dict, baseline_spec: dict = None) -> np.ndarray:
    """Extract 12D YAML features from pod spec - matches training exactly."""
    try:
        # Training uses path: spec.template.spec.containers
        # But for direct pod specs, use: spec.spec.containers
        template_spec = spec.get("spec", {}).get("template", {}).get("spec", {})
        if not template_spec:
            template_spec = spec.get("spec", {})  # Fallback for pod specs

        containers = template_spec.get("containers", [])
        volumes = template_spec.get("volumes", [])
        init_containers = template_spec.get("initContainers", [])

        def count_nodes(obj, depth=0, max_depth_list=None):
            if max_depth_list is None:
                max_depth_list = [0]
            count = 1
            max_depth_list[0] = max(max_depth_list[0], depth)
            if isinstance(obj, dict):
                count += sum(
                    count_nodes(v, depth + 1, max_depth_list) for v in obj.values()
                )
            elif isinstance(obj, list):
                count += sum(count_nodes(v, depth + 1, max_depth_list) for v in obj)
            return count

        node_count = float(count_nodes(spec))
        max_d = [0]
        count_nodes(spec, max_depth_list=max_d)
        depth = float(max_d[0])

        container_count = float(len(containers))
        volume_count = float(len(volumes))
        env_vars = float(sum(len(c.get("env", [])) for c in containers))

        init_container_count = float(1.0 if len(init_containers) > 0 else 0.0)
        persistent_vols = float(
            any(v.get("persistentVolumeClaim") is not None for v in volumes)
        )
        resource_limits = float(
            sum(1 for c in containers if c.get("resources", {}).get("limits"))
        )
        security_contexts = float(
            sum(1 for c in containers if c.get("securityContext"))
        )

        # Baseline features for comparison
        baseline_containers = 0
        baseline_volumes = 0
        if baseline_spec:
            baseline_template = (
                baseline_spec.get("spec", {}).get("template", {}).get("spec", {})
            )
            if not baseline_template:
                baseline_template = baseline_spec.get("spec", {})
            baseline_containers = float(len(baseline_template.get("containers", [])))
            baseline_volumes = float(len(baseline_template.get("volumes", [])))

        container_change = abs(container_count - baseline_containers)
        volume_change = abs(volume_count - baseline_volumes)
        has_structure = float(node_count > 0)

        # Return RAW values (no normalization - matches training)
        features = np.array(
            [
                node_count,
                depth,
                container_count,
                volume_count,
                env_vars,
                init_container_count,
                persistent_vols,
                resource_limits,
                security_contexts,
                container_change,
                volume_change,
                has_structure,
            ],
            dtype=np.float32,
        )
    except Exception as e:
        features = np.zeros(12, dtype=np.float32)

    return features


def extract_telemetry_features(telemetry: dict) -> np.ndarray:
    """Extract 14D telemetry features - matches training."""
    features = []
    try:
        request_rate = telemetry.get("request_rate", 0.0)
        latency_p99 = telemetry.get("latency_p99", 0.0)
        cpu_usage = telemetry.get("cpu_usage_cores", 0.0)
        memory_usage = telemetry.get("memory_working_set_bytes", 0.0)
        error_rate = telemetry.get("error_rate_5xx", 0.0)
        cpu_limit = telemetry.get("cpu_limit", 1.0)
        memory_limit = telemetry.get("memory_limit", 1e9)

        features = [
            request_rate,
            latency_p99,
            cpu_usage,
            memory_usage,
            error_rate,
            cpu_limit,
            memory_limit,
        ]

        cpu_ratio = cpu_usage / cpu_limit if cpu_limit > 0 else 0
        memory_ratio = memory_usage / memory_limit if memory_limit > 0 else 0
        error_ratio = error_rate / request_rate if request_rate > 0 else 0
        critical_flag = 1.0 if (error_rate > 5 or latency_p99 > 1000) else 0.0
        latency_mag = np.log1p(latency_p99)
        cpu_mag = np.log1p(cpu_usage)
        memory_mag = np.log1p(memory_usage)

        features.extend(
            [
                cpu_ratio,
                memory_ratio,
                error_ratio,
                critical_flag,
                latency_mag,
                cpu_mag,
                memory_mag,
            ]
        )
    except Exception as e:
        features = [0.0] * 14

    return np.array(features, dtype=np.float32)


def extract_drift_features(metadata: dict) -> np.ndarray:
    """Extract 6D drift semantics features - matches training exactly."""
    # Training uses: ["image", "replica", "config", "resource", "network", "other"]
    drift_types = ["image", "replica", "config", "resource", "network", "other"]
    drift_type_str = str(metadata.get("drift_type", "other")).lower()
    if drift_type_str in drift_types:
        drift_type_idx = drift_types.index(drift_type_str)
    else:
        drift_type_idx = drift_types.index("other")
    drift_type_encoded = float(drift_type_idx)

    # Magnitude: {"small": 1, "medium": 2, "large": 3, "critical": 4}
    magnitude_str = str(metadata.get("magnitude", "small")).lower()
    magnitude_mapping = {
        "small": 1,
        "medium": 2,
        "large": 3,
        "critical": 4,
        "tiny": 1,
        "extreme": 5,
    }
    magnitude_level = float(magnitude_mapping.get(magnitude_str, 1))

    num_drifts = float(metadata.get("num_drifts", 1))
    severity = float(metadata.get("severity", 1))

    # Phase: {"steady": 0, "degrading": 1, "recovering": 2}
    phase_str = str(metadata.get("phase", "steady")).lower()
    phase_mapping = {
        "steady": 0,
        "degrading": 1,
        "recovering": 2,
        "pre": 0,
        "transition": 1,
        "failed": 2,
    }
    phase_encoded = float(phase_mapping.get(phase_str, 0))

    # Is rolling update
    drift_type = str(metadata.get("drift_type", "")).lower()
    is_rolling = float("rolling" in drift_type or drift_type == "replica")

    # Return RAW values (no normalization - matches training)
    features = np.array(
        [
            drift_type_encoded,
            magnitude_level,
            num_drifts,
            severity,
            phase_encoded,
            is_rolling,
        ],
        dtype=np.float32,
    )

    return features


# ============================================================================
# LOAD ACTUAL TRAINING DATA SAMPLES
# ============================================================================


def load_csv_samples(csv_path: str, samples_per_class: int = 2):
    """Load actual samples from the training CSV."""
    import pandas as pd

    df = pd.read_csv(csv_path)

    # Get unique scenarios
    samples = []
    for label in df["operational_label"].unique():
        label_df = (
            df[df["operational_label"] == label]
            .drop_duplicates(subset=["scenario_name", "phase"])
            .head(samples_per_class)
        )
        for _, row in label_df.iterrows():
            samples.append(
                {
                    "scenario_name": row["scenario_name"],
                    "phase": row["phase"],
                    "label": row["operational_label"],
                    "drift_type": row["drift_type"],
                    "magnitude": row["magnitude"],
                    "num_drifts": row["num_drifts"],
                    "severity": row["severity"],
                    "cpu_limit": row["cpu_limit"],
                    "memory_limit": row["memory_limit"],
                    "request_rate": row["request_rate"],
                    "error_rate_5xx": row["error_rate_5xx"],
                    "latency_p99": row["latency_p99"],
                    "cpu_usage_cores": row["cpu_usage_cores"],
                    "memory_working_set_bytes": row["memory_working_set_bytes"],
                }
            )

    return samples


# Try to load actual samples from CSV
CSV_PATH = (
    Path(__file__).parent.parent
    / "Unisys_data"
    / "drift-collector-v4"
    / "dit-merged-complete.csv"
)
if CSV_PATH.exists():
    try:
        CSV_SAMPLES = load_csv_samples(str(CSV_PATH), samples_per_class=3)
        print(f"Loaded {len(CSV_SAMPLES)} actual training samples")
    except Exception as e:
        print(f"Could not load CSV: {e}")
        CSV_SAMPLES = []
else:
    CSV_SAMPLES = []
    print(f"CSV not found at {CSV_PATH}")


class SyntheticDataGenerator:
    """Generate synthetic test scenarios."""

    @staticmethod
    def generate_normal_pod_spec() -> dict:
        return {
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "1"}}}],
                "volumes": [],
            }
        }

    @staticmethod
    def generate_base_telemetry() -> dict:
        return {
            "request_rate": 100.0,
            "latency_p99": 50.0,
            "cpu_usage_cores": 0.2,
            "memory_working_set_bytes": 100e6,
            "error_rate_5xx": 0.1,
            "cpu_limit": 1.0,
            "memory_limit": 1e9,
        }

    @staticmethod
    def generate_scenario(
        scenario_type: str,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, str]:
        yaml_features = None
        telemetry_dict = SyntheticDataGenerator.generate_base_telemetry()
        metadata_dict = {
            "drift_type": "other",
            "magnitude_level": 1,
            "num_drifts": 0,
            "severity": 1,
            "phase": "steady",
            "is_rolling": False,
        }
        expected_class = "Unknown"

        if scenario_type == "normal_steady":
            yaml_features = extract_yaml_features(
                SyntheticDataGenerator.generate_normal_pod_spec()
            )
            expected_class = "Benign_Or_Subtle"

        elif scenario_type == "normal_high_load":
            pod_spec = SyntheticDataGenerator.generate_normal_pod_spec()
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["cpu_usage_cores"] = 0.8
            telemetry_dict["memory_working_set_bytes"] = 800e6
            telemetry_dict["request_rate"] = 500.0
            expected_class = "Benign_Or_Subtle"

        elif scenario_type == "perf_cpu_spike":
            pod_spec = SyntheticDataGenerator.generate_normal_pod_spec()
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["cpu_usage_cores"] = 1.5
            telemetry_dict["cpu_limit"] = 1.0
            metadata_dict["magnitude_level"] = 2
            metadata_dict["drift_type"] = "resource"
            expected_class = "Harmful_Performance_Degradation"

        elif scenario_type == "perf_memory_leak":
            pod_spec = SyntheticDataGenerator.generate_normal_pod_spec()
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["memory_working_set_bytes"] = 1.8e9
            telemetry_dict["memory_limit"] = 1e9
            metadata_dict["magnitude_level"] = 3
            metadata_dict["phase"] = "degrading"
            expected_class = "Harmful_Performance_Degradation"

        elif scenario_type == "perf_latency_spike":
            pod_spec = SyntheticDataGenerator.generate_normal_pod_spec()
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["latency_p99"] = 2500.0
            metadata_dict["magnitude_level"] = 2
            expected_class = "Harmful_Performance_Degradation"

        elif scenario_type == "sec_privilege_escalation":
            pod_spec = {
                "spec": {
                    "containers": [
                        {"name": "app", "securityContext": {"privileged": True}}
                    ],
                    "volumes": [],
                }
            }
            yaml_features = extract_yaml_features(pod_spec)
            metadata_dict["drift_type"] = "config"
            metadata_dict["magnitude_level"] = 4
            metadata_dict["severity"] = 3
            expected_class = "Harmful_Security_Breach"

        elif scenario_type == "sec_port_binding":
            pod_spec = SyntheticDataGenerator.generate_normal_pod_spec()
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["request_rate"] = 5000.0
            telemetry_dict["latency_p99"] = 10.0
            telemetry_dict["error_rate_5xx"] = 0.01
            metadata_dict["drift_type"] = "network"
            metadata_dict["magnitude_level"] = 2
            expected_class = "Harmful_Security_Breach"

        elif scenario_type == "multi_perf_and_config":
            pod_spec = {
                "spec": {
                    "containers": [
                        {"name": "app", "resources": {"limits": {"cpu": "0.5"}}}
                    ],
                    "volumes": [{}],
                }
            }
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["cpu_usage_cores"] = 1.0
            telemetry_dict["cpu_limit"] = 0.5
            telemetry_dict["error_rate_5xx"] = 5.0
            metadata_dict["num_drifts"] = 2
            metadata_dict["magnitude_level"] = 3
            metadata_dict["drift_type"] = "config"
            expected_class = "Harmful_Multi_Vector"

        elif scenario_type == "outage_cascading_failure":
            pod_spec = SyntheticDataGenerator.generate_normal_pod_spec()
            yaml_features = extract_yaml_features(pod_spec)
            telemetry_dict["error_rate_5xx"] = 80.0
            telemetry_dict["latency_p99"] = 10000.0
            telemetry_dict["cpu_usage_cores"] = 2.0
            telemetry_dict["memory_working_set_bytes"] = 2e9
            metadata_dict["magnitude_level"] = 4
            metadata_dict["severity"] = 3
            metadata_dict["phase"] = "degrading"
            expected_class = "Harmful_Critical_Outage"

        elif scenario_type == "sec_host_access":
            pod_spec = {
                "spec": {
                    "containers": [
                        {"name": "app", "securityContext": {"hostNetwork": True}}
                    ],
                    "volumes": [{"hostPath": {"path": "/"}}],
                }
            }
            yaml_features = extract_yaml_features(pod_spec)
            metadata_dict["drift_type"] = "security"
            metadata_dict["magnitude_level"] = 4
            metadata_dict["severity"] = 3
            expected_class = "Harmful_Security_Breach"

        else:
            yaml_features = extract_yaml_features(
                SyntheticDataGenerator.generate_normal_pod_spec()
            )
            expected_class = "Benign_Or_Subtle"

        telemetry_features = extract_telemetry_features(telemetry_dict)
        drift_features = extract_drift_features(metadata_dict)

        return yaml_features, telemetry_features, drift_features, expected_class


# ============================================================================
# CONFIGURABLE THRESHOLDS PER CLASS
# ============================================================================

# Per-class confidence thresholds (for display/reference only)
CLASS_THRESHOLDS = {
    "Benign_Or_Subtle": 0.50,
    "Harmful_Performance_Degradation": 0.20,
    "Harmful_Security_Breach": 0.30,
    "Harmful_Multi_Vector": 0.20,
    "Harmful_Critical_Outage": 0.20,
}

# Map class to base risk score (for HealthAgent output)
CLASS_TO_RISK = {
    "Benign_Or_Subtle": 0.1,
    "Harmful_Performance_Degradation": 0.6,
    "Harmful_Security_Breach": 0.9,
    "Harmful_Multi_Vector": 0.85,
    "Harmful_Critical_Outage": 0.95,
}

# Map severity level (from model) to HealthAgent severity
SEVERITY_TO_HEALTH = {
    "low": "low",
    "medium": "medium",
    "high": "high",
}

# Repair template suggestions based on predicted class
REPAIR_TEMPLATES = {
    "Benign_Or_Subtle": {
        "action": "monitor",
        "description": "No action needed - benign change detected",
        "remediation": "Continue monitoring",
    },
    "Harmful_Performance_Degradation": {
        "action": "scale",
        "description": "Performance degradation detected",
        "remediation": "Increase resource limits or scale replicas",
    },
    "Harmful_Security_Breach": {
        "action": "rollback",
        "description": "Security breach detected - potential compromise",
        "remediation": "Rollback to previous known-good version immediately",
    },
    "Harmful_Multi_Vector": {
        "action": "investigate",
        "description": "Multiple drift vectors detected - complex issue",
        "remediation": "Investigate all drift sources and apply comprehensive fix",
    },
    "Harmful_Critical_Outage": {
        "action": "emergency_rollback",
        "description": "Critical outage in progress",
        "remediation": "Emergency rollback to last stable state",
    },
}


def apply_class_threshold(
    probabilities: Dict, raw_confidence: float
) -> Tuple[str, float]:
    """
    Use raw top prediction from model.
    Threshold tuning can't fix fundamental model bias issues.

    Returns (predicted_class, confidence)
    """
    # Simply use the model's top prediction
    sorted_probs = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)
    top_class, top_prob = sorted_probs[0]

    return top_class, top_prob

    # Case 2: Top 2 classes are very close - use confidence gap logic
    # This helps when model is uncertain between two classes
    gap = top_prob - second_prob
    if gap < CONFIDENCE_GAP_THRESHOLD and second_prob > 0.15:
        # If gap is small, prefer the more harmful class (conservative)
        # But only if second class has meaningful probability
        second_threshold = CLASS_THRESHOLDS.get(second_class, 0.3)
        if second_prob >= second_threshold:
            return second_class, second_prob

    # Case 3: Fallback through priority order - find first class meeting threshold
    for cls in FALLBACK_ORDER:
        cls_prob = probabilities.get(cls, 0)
        cls_threshold = CLASS_THRESHOLDS.get(cls, 0.3)
        if cls_prob >= cls_threshold:
            return cls, cls_prob

    # Case 4: If top is benign but harmful classes have significant probability,
    # choose the highest harmful class (conservative approach)
    if top_class == "Benign_Or_Subtle":
        for cls in FALLBACK_ORDER[0:4]:  # Skip benign
            prob = probabilities.get(cls, 0)
            if prob > 0.15:  # Has meaningful probability
                # Use the harmful class but with lower confidence
                return cls, prob * 0.8

    # Default: use top class anyway (don't block prediction)
    return top_class, top_prob


# ============================================================================
# MAIN VISUALIZATION
# ============================================================================

# Class order MUST match DITSecInference.CLASS_NAMES exactly
CLASSES = [
    "Benign_Or_Subtle",  # index 0
    "Harmful_Performance_Degradation",  # index 1
    "Harmful_Security_Breach",  # index 2
    "Harmful_Multi_Vector",  # index 3
    "Harmful_Critical_Outage",  # index 4
]
CLASS_COLORS = ["#2ecc71", "#e74c3c", "#9b59b6", "#f39c12", "#c0392b"]

SCENARIOS = [
    # Use actual CSV samples
    ("csv_sample", "CSV Sample"),
]


def load_model(checkpoint_path: str) -> DITSecInference:
    """Load trained model using official inference interface."""
    return DITSecInference(checkpoint_path=checkpoint_path)


def run_inference(
    inferencer: DITSecInference, yaml: np.ndarray, telem: np.ndarray, drift: np.ndarray
) -> Dict:
    """
    Run inference using official inference interface.

    Returns full HealthAgent-compatible output including:
    - risk_score, severity, patch_proposal, explainability, confidence_interval
    - diagnostics: PRD-compliant structured diagnostics with:
      - predicted_impact (class name)
      - severity_level (integer 1-3)
      - confidence (float 0-1)
      - root_cause_attention (array of feature names)
      - recommended_repairs (array of repair actions)
    """
    result = inferencer.predict(
        yaml, telem, drift, return_probabilities=True, return_diagnostics=True
    )

    raw_pred_class = result["class_name"]
    raw_confidence = result["class_confidence"]
    class_probs = result["class_probabilities"]

    # Extract diagnostics if available
    diagnostics = result.get("diagnostics", {})

    # Apply threshold-based prediction
    pred_class, adjusted_confidence = apply_class_threshold(class_probs, raw_confidence)

    # Get severity from model
    model_severity = result["severity_name"].lower()

    # Calculate risk score (matches HealthAgent logic)
    base_risk = CLASS_TO_RISK.get(pred_class, 0.5)
    risk_score = base_risk * adjusted_confidence
    risk_score = min(max(risk_score, 0.0), 1.0)

    # Determine severity: use model severity when harmful, adjust for confidence
    # For benign predictions, default to low unless model explicitly says high
    if pred_class == "Benign_Or_Subtle":
        # For benign, severity should be low unless model strongly disagrees
        if model_severity == "high" and adjusted_confidence > 0.7:
            health_severity = "medium"  # Could be wrong but be slightly cautious
        else:
            health_severity = "low"
    else:
        # For harmful predictions, use model severity but boost based on risk
        model_severity_val = SEVERITY_TO_HEALTH.get(model_severity, "medium")
        # If risk score is high, ensure severity reflects that
        if risk_score >= 0.7:
            health_severity = "high"
        elif risk_score >= 0.4:
            health_severity = "medium"
        else:
            health_severity = model_severity_val

    # Get repair template
    repair_template = REPAIR_TEMPLATES.get(
        pred_class, REPAIR_TEMPLATES["Benign_Or_Subtle"]
    )

    # Calculate confidence interval
    confidence_margin = 0.1 * (
        1.0 - adjusted_confidence
    )  # More uncertain = wider interval
    confidence_interval = (
        max(0.0, risk_score - confidence_margin),
        min(1.0, risk_score + confidence_margin),
    )

    # Build explainability (matches HealthAgent format)
    explainability = {
        "model": "DIT-Sec v3.0",
        "class": pred_class,
        "confidence": float(adjusted_confidence),
        "raw_confidence": float(raw_confidence),
        "threshold_used": CLASS_THRESHOLDS.get(pred_class, 0.3),
        "severity_level": model_severity,
        "class_probabilities": {k: float(v) for k, v in class_probs.items()},
        "risk_score_base": base_risk,
        # Add diagnostics to explainability
        "root_cause_attention": diagnostics.get("root_cause_attention", []),
        "recommended_repairs": diagnostics.get("recommended_repairs", []),
    }

    return {
        # Core prediction
        "predicted_class": pred_class,
        "raw_predicted_class": raw_pred_class,
        "confidence": float(adjusted_confidence),
        "raw_confidence": float(raw_confidence),
        "class_probabilities": class_probs,
        # HealthAgent-compatible fields
        "risk_score": float(risk_score),
        "severity": health_severity,
        "severity_level": model_severity,
        "severity_confidence": result["severity_confidence"],
        # Repair/patch info
        "patch_proposal": repair_template,
        "repair_action": repair_template["action"],
        "repair_description": repair_template["description"],
        "remediation": repair_template["remediation"],
        # Explainability
        "explainability": explainability,
        "confidence_interval": confidence_interval,
        # Metadata
        "blast_radius": "unknown",
        # PRD-compliant diagnostics
        "diagnostics": diagnostics,
    }


def create_visualization(
    results: List[Dict], save_path: str = "dit_sec_visualization.png"
):
    """Create visualization of test results."""
    fig = plt.figure(figsize=(20, 12))
    fig.suptitle(
        "DIT-Sec v3.0 Synthetic Drift Testing Results", fontsize=16, fontweight="bold"
    )

    # 1. Scenario Results Table (left)
    ax1 = fig.add_subplot(2, 3, 1)
    ax1.axis("off")
    scenario_text = "SCENARIO RESULTS\n" + "=" * 40 + "\n\n"
    for i, r in enumerate(results):
        status = "✓" if r["expected"] == r["predicted"] else "✗"
        scenario_text += f"{i + 1}. {r['scenario_name'][:25]:25s} {status}\n"
        scenario_text += f"   Expected: {r['expected'][:20]:20s}\n"
        scenario_text += f"   Predicted: {r['predicted'][:20]:20s}\n"
        scenario_text += f"   Confidence: {r['confidence']:.2%}\n\n"
    ax1.text(
        0.05,
        0.95,
        scenario_text,
        transform=ax1.transAxes,
        fontsize=9,
        verticalalignment="top",
        fontfamily="monospace",
        bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
    )

    # 2. Accuracy Metrics (top center)
    ax2 = fig.add_subplot(2, 3, 2)
    correct = sum(1 for r in results if r["expected"] == r["predicted"])
    accuracy = correct / len(results)
    class_accuracy = {}
    for c in CLASSES:
        expected = [r for r in results if r["expected"] == c]
        if expected:
            class_accuracy[c] = sum(1 for r in expected if r["predicted"] == c) / len(
                expected
            )

    bars = ax2.bar(
        range(len(CLASSES)),
        [class_accuracy.get(c, 0) for c in CLASSES],
        color=CLASS_COLORS,
    )
    ax2.set_xticks(range(len(CLASSES)))
    ax2.set_xticklabels([c[:15] for c in CLASSES], rotation=45, ha="right", fontsize=8)
    ax2.set_ylabel("Accuracy")
    ax2.set_title(f"Per-Class Accuracy (Overall: {accuracy:.1%})")
    ax2.set_ylim(0, 1.1)
    for bar, c in zip(bars, CLASSES):
        if class_accuracy.get(c, 0) > 0:
            ax2.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.02,
                f"{class_accuracy[c]:.0%}",
                ha="center",
                fontsize=8,
            )

    # 3. Confidence Distribution (top right)
    ax3 = fig.add_subplot(2, 3, 3)
    confidences = [r["confidence"] for r in results]
    colors = ["green" if r["expected"] == r["predicted"] else "red" for r in results]
    ax3.bar(range(len(results)), confidences, color=colors, alpha=0.7)
    ax3.axhline(y=0.5, color="orange", linestyle="--", label="Random (20%)")
    ax3.set_xlabel("Test Scenario")
    ax3.set_ylabel("Confidence")
    ax3.set_title("Prediction Confidence by Scenario")
    ax3.set_ylim(0, 1.1)

    # 4. Confusion Matrix (bottom left)
    ax4 = fig.add_subplot(2, 3, 4)
    confusion = np.zeros((len(CLASSES), len(CLASSES)))
    for r in results:
        exp_idx = CLASSES.index(r["expected"]) if r["expected"] in CLASSES else 0
        pred_idx = CLASSES.index(r["predicted"]) if r["predicted"] in CLASSES else 0
        confusion[exp_idx][pred_idx] += 1

    im = ax4.imshow(confusion, cmap="Blues")
    ax4.set_xticks(range(len(CLASSES)))
    ax4.set_yticks(range(len(CLASSES)))
    ax4.set_xticklabels([c[:12] for c in CLASSES], rotation=45, ha="right", fontsize=8)
    ax4.set_yticklabels([c[:12] for c in CLASSES], fontsize=8)
    ax4.set_xlabel("Predicted")
    ax4.set_ylabel("Expected")
    ax4.set_title("Confusion Matrix")
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            if confusion[i][j] > 0:
                ax4.text(
                    j,
                    i,
                    int(confusion[i][j]),
                    ha="center",
                    va="center",
                    color="white" if confusion[i][j] > 2 else "black",
                )
    plt.colorbar(im, ax=ax4)

    # 5. Class Distribution (bottom center)
    ax5 = fig.add_subplot(2, 3, 5)
    pred_counts = [sum(1 for r in results if r["predicted"] == c) for c in CLASSES]
    exp_counts = [sum(1 for r in results if r["expected"] == c) for c in CLASSES]
    x = np.arange(len(CLASSES))
    width = 0.35
    ax5.bar(
        x - width / 2, exp_counts, width, label="Expected", color="steelblue", alpha=0.8
    )
    ax5.bar(
        x + width / 2, pred_counts, width, label="Predicted", color="coral", alpha=0.8
    )
    ax5.set_xticks(x)
    ax5.set_xticklabels([c[:12] for c in CLASSES], rotation=45, ha="right", fontsize=8)
    ax5.set_ylabel("Count")
    ax5.set_title("Expected vs Predicted Class Distribution")
    ax5.legend()

    # 6. Summary Stats (bottom right)
    ax6 = fig.add_subplot(2, 3, 6)
    ax6.axis("off")

    avg_conf = np.mean([r["confidence"] for r in results])
    min_conf = min([r["confidence"] for r in results])
    max_conf = max([r["confidence"] for r in results])

    avg_risk = np.mean([r["risk_score"] for r in results])
    max_risk = max([r["risk_score"] for r in results])

    action_counts = {}
    for r in results:
        action = r.get("repair_action", "unknown")
        action_counts[action] = action_counts.get(action, 0) + 1

    summary = f"""
    SUMMARY STATISTICS
    {"=" * 40}

    Total Scenarios: {len(results)}
    Correct Predictions: {correct}
    Overall Accuracy: {accuracy:.1%}

    Risk Score Metrics:
    • Average: {avg_risk:.2f}
    • Max: {max_risk:.2f}

    Confidence Metrics:
    • Average: {avg_conf:.1%}
    • Min: {min_conf:.1%}
    • Max: {max_conf:.1%}

    Repair Actions Distribution:
    """
    for action, count in sorted(action_counts.items()):
        summary += f"  • {action:20s} {count}\n"

    summary += "\nPer-Class Thresholds:\n"
    for c, t in CLASS_THRESHOLDS.items():
        summary += f"  • {c[:25]:25s} {t:.2f}\n"

    summary += "\nPer-Class Performance:\n"
    for c in CLASSES:
        if c in class_accuracy:
            summary += f"  • {c[:25]:25s} {class_accuracy[c]:.0%}\n"

    ax6.text(
        0.05,
        0.95,
        summary,
        transform=ax6.transAxes,
        fontsize=10,
        verticalalignment="top",
        fontfamily="monospace",
        bbox=dict(boxstyle="round", facecolor="lightgray", alpha=0.5),
    )

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    print(f"\n✓ Visualization saved to: {save_path}")
    return fig


def main():
    print("=" * 60)
    print("DIT-Sec v3.0 Synthetic Drift Visualization")
    print("=" * 60)

    # Find checkpoint
    checkpoint_paths = [
        Path(__file__).parent / "models" / "dit_sec_v3" / "dit_sec_v3_checkpoint.pth",
        Path(__file__).parent / "training_outputs" / "best_model.pth",
    ]
    checkpoint = None
    for p in checkpoint_paths:
        if p.exists():
            checkpoint = str(p)
            break

    if not checkpoint:
        print("ERROR: No checkpoint found!")
        return

    # Load model using official inference interface
    print(f"\nLoading model from: {checkpoint}")
    inferencer = load_model(checkpoint)
    print(f"✓ Model loaded successfully")

    # Run tests
    print("\n" + "=" * 60)
    print("Running synthetic drift tests...")
    print("=" * 60)

    results = []

    if CSV_SAMPLES:
        # Use actual CSV samples
        for sample in CSV_SAMPLES:
            # Extract features from CSV values
            yaml_spec = {
                "spec": {
                    "containers": [
                        {
                            "resources": {
                                "limits": {
                                    "cpu": str(sample.get("cpu_limit", 1)),
                                    "memory": str(sample.get("memory_limit", 1)) + "Gi",
                                }
                            }
                        }
                    ]
                }
            }

            yaml_features = extract_yaml_features(yaml_spec)

            # Build telemetry from CSV (use raw values - no normalization)
            telemetry_dict = {
                "request_rate": float(sample.get("request_rate", 100)),
                "latency_p99": float(sample.get("latency_p99", 50)),
                "cpu_usage_cores": float(sample.get("cpu_usage_cores", 0.2)),
                "memory_working_set_bytes": float(
                    sample.get("memory_working_set_bytes", 1e8)
                ),
                "error_rate_5xx": float(sample.get("error_rate_5xx", 0.1)),
                "cpu_limit": float(sample.get("cpu_limit", 1)),
                "memory_limit": float(
                    sample.get("memory_limit", 1e9)
                ),  # Already in bytes
            }
            telemetry_features = extract_telemetry_features(telemetry_dict)

            # Build drift metadata (use magnitude as string, not numeric)
            metadata_dict = {
                "drift_type": sample.get("drift_type", "other"),
                "magnitude": sample.get(
                    "magnitude", "small"
                ),  # String: tiny/small/medium/large/extreme
                "num_drifts": sample.get("num_drifts", 1),
                "severity": sample.get("severity", 1),
                "phase": sample.get("phase", "steady"),
                "is_rolling": False,
            }
            drift_features = extract_drift_features(metadata_dict)

            expected = sample["label"]
            scenario_name = f"{sample['scenario_name']} ({sample['phase']})"

            inference = run_inference(
                inferencer, yaml_features, telemetry_features, drift_features
            )

            match = "✓" if expected == inference["predicted_class"] else "✗"
            print(
                f"{match} {scenario_name:40s}\n"
                f"   Expected: {expected:30s} | Pred: {inference['predicted_class']:30s}\n"
                f"   Risk: {inference['risk_score']:.2f} | Severity: {inference['severity']:8s} | Conf: {inference['confidence']:.2f}\n"
                f"   Action: {inference['repair_action']:20s} | Threshold: {inference['explainability']['threshold_used']:.2f}\n"
                f"   All Class Probabilities & Severity:\n"
            )

            # Print all 5 classes with their probabilities and severity
            class_probs = inference["class_probabilities"]
            sorted_probs = sorted(class_probs.items(), key=lambda x: x[1], reverse=True)
            for cls, prob in sorted_probs:
                severity_for_class = SEVERITY_TO_HEALTH.get(
                    inference["severity_level"].lower()
                    if cls == inference["predicted_class"]
                    else "low",
                    "low",
                )
                print(
                    f"      • {cls:40s}: {prob:7.2%} | Severity: {severity_for_class:8s}"
                )

            results.append(
                {
                    "scenario_id": sample["scenario_name"],
                    "scenario_name": scenario_name,
                    "expected": expected,
                    "predicted": inference["predicted_class"],
                    "confidence": inference["confidence"],
                    "class_probabilities": inference["class_probabilities"],
                    "severity_level": inference["severity_level"],
                    # Full HealthAgent output
                    "risk_score": inference["risk_score"],
                    "severity": inference["severity"],
                    "repair_action": inference["repair_action"],
                    "repair_description": inference["repair_description"],
                    "remediation": inference["remediation"],
                    "confidence_interval": inference["confidence_interval"],
                    "explainability": inference["explainability"],
                }
            )
    else:
        # Fallback to synthetic scenarios
        for scenario_id, scenario_name in SCENARIOS:
            yaml, telem, drift, expected = SyntheticDataGenerator.generate_scenario(
                scenario_id
            )
            inference = run_inference(inferencer, yaml, telem, drift)

            match = "✓" if expected == inference["predicted_class"] else "✗"
            print(
                f"{match} {scenario_name:30s} | Expected: {expected:30s} | Predicted: {inference['predicted_class']:30s}\n"
                f"   Risk: {inference['risk_score']:.2f} | Severity: {inference['severity']:8s} | Action: {inference['repair_action']}\n"
                f"   All Class Probabilities & Severity:\n"
            )

            # Print all 5 classes with their probabilities and severity
            class_probs = inference["class_probabilities"]
            sorted_probs = sorted(class_probs.items(), key=lambda x: x[1], reverse=True)
            for cls, prob in sorted_probs:
                severity_for_class = SEVERITY_TO_HEALTH.get(
                    inference["severity_level"].lower()
                    if cls == inference["predicted_class"]
                    else "low",
                    "low",
                )
                print(
                    f"      • {cls:40s}: {prob:7.2%} | Severity: {severity_for_class:8s}"
                )

            results.append(
                {
                    "scenario_id": scenario_id,
                    "scenario_name": scenario_name,
                    "expected": expected,
                    "predicted": inference["predicted_class"],
                    "confidence": inference["confidence"],
                    "class_probabilities": inference["class_probabilities"],
                    "severity_level": inference["severity_level"],
                    "risk_score": inference["risk_score"],
                    "severity": inference["severity"],
                    "repair_action": inference["repair_action"],
                    "repair_description": inference["repair_description"],
                    "remediation": inference["remediation"],
                    "confidence_interval": inference["confidence_interval"],
                    "explainability": inference["explainability"],
                }
            )

    # Calculate accuracy
    correct = sum(1 for r in results if r["expected"] == r["predicted"])
    accuracy = correct / len(results)

    print("\n" + "=" * 60)
    print(f"RESULTS: {correct}/{len(results)} correct ({accuracy:.1%})")
    print("=" * 60)

    # Create visualization
    viz_path = Path(__file__).parent / "dit_sec_visualization.png"
    create_visualization(results, str(viz_path))

    # Also save JSON results
    json_path = Path(__file__).parent / "dit_sec_test_results.json"
    with open(json_path, "w") as f:
        json.dump(
            {
                "summary": {
                    "total": len(results),
                    "correct": correct,
                    "accuracy": accuracy,
                },
                "results": results,
            },
            f,
            indent=2,
        )
    print(f"✓ Results saved to: {json_path}")


if __name__ == "__main__":
    main()
