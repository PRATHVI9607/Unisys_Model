"""
Google Colab Training Notebook for DIT-Sec v3.0
GNN+Mamba Hybrid Model for Kubernetes Drift Detection

This notebook trains the DIT-Sec v3.0 model on the dit-merged-complete.csv dataset
and exports it for integration with the Health Agent.

Instructions:
1. Upload this notebook to Google Colab
2. Mount Google Drive: !from google.colab import drive; drive.mount('/content/drive')
3. Run cells sequentially
4. After training, download the model checkpoint and evaluation metrics
"""

# ============================================================================
# SECTION 1: SETUP & DEPENDENCIES
# ============================================================================

# Install required packages
import sys
import subprocess


def install_packages():
    """Install dependencies for Colab environment."""
    packages = [
        "torch==2.2.0",
        "torch-geometric==2.5.0",
        "onnx==1.16.0",
        "onnxruntime==1.17.0",
        "pandas>=2.0.0",
        "numpy>=1.26.0",
        "scikit-learn>=1.3.0",
        "matplotlib>=3.8.0",
        "seaborn>=0.13.0",
        "pydantic>=2.6.0",
        "PyYAML>=6.0.0",
    ]

    for package in packages:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", package])

    print("All dependencies installed!")


# Run installation
install_packages()

# ============================================================================
# SECTION 2: IMPORTS & SETUP
# ============================================================================

import os
import json
import logging
import warnings
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, Counter
from datetime import datetime

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import torch.nn.functional as F

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    auc,
    classification_report,
)

import matplotlib.pyplot as plt
import seaborn as sns
from torch_geometric.nn import GATConv
from torch_geometric.data import Data

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Set random seeds for reproducibility
def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


set_seed(42)

# Check GPU availability
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Training device: {device}")
if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(
        f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB"
    )

# ============================================================================
# SECTION 3: MOUNT GOOGLE DRIVE & LOAD DATASET
# ============================================================================

# Mount Google Drive (uncomment in Colab)
# from google.colab import drive
# drive.mount('/content/drive')

# For Colab, copy dataset from Drive or use local path
# Example paths:
# COLAB_DATASET_PATH = '/content/drive/MyDrive/dit-merged-complete.csv'
# LOCAL_DATASET_PATH = '/content/dit-merged-complete.csv'

# Define data paths
DATA_PATH = "./dit-merged-complete.csv"  # Update this path as needed
OUTPUT_DIR = Path("./training_outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

print(f"Dataset path: {DATA_PATH}")
print(f"Output directory: {OUTPUT_DIR}")

# ============================================================================
# SECTION 4: DATA LOADING & EXPLORATION
# ============================================================================


class DataLoader_KubeHeal:
    """Load and explore dit-merged-complete.csv dataset."""

    @staticmethod
    def load_csv(path: str) -> pd.DataFrame:
        """Load CSV dataset."""
        df = pd.read_csv(path)
        logger.info(f"Loaded {len(df)} samples from {path}")
        return df

    @staticmethod
    def explore_dataset(df: pd.DataFrame):
        """Print dataset exploration statistics."""
        print("\n" + "=" * 80)
        print("DATASET EXPLORATION")
        print("=" * 80)
        print(f"\nDataset shape: {df.shape}")
        print(f"\nColumn names and types:")
        print(df.dtypes)
        print(f"\nMissing values:\n{df.isnull().sum()}")
        print(f"\nBasic statistics:")
        print(df.describe())

        # Label distribution
        if "operational_label" in df.columns:
            print(f"\nOperational Label Distribution:")
            print(df["operational_label"].value_counts())
            print(df["operational_label"].value_counts(normalize=True))

        # Severity distribution
        if "severity" in df.columns:
            print(f"\nSeverity Distribution:")
            print(df["severity"].value_counts().sort_index())

        # Drift type distribution
        if "drift_type" in df.columns:
            print(f"\nDrift Type Distribution:")
            print(df["drift_type"].value_counts())

        print("\n" + "=" * 80)


# Load and explore dataset
print("Loading dataset...")
df = DataLoader_KubeHeal.load_csv(DATA_PATH)
DataLoader_KubeHeal.explore_dataset(df)

# ============================================================================
# SECTION 5: DATA TRANSFORMATION PIPELINE
# ============================================================================


class DITSecDataTransformer:
    """Transform CSV data into DIT-Sec model-ready format."""

    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.class_weights = None
        self.feature_names = None

    def parse_yaml_to_dict(self, yaml_str: str) -> Dict:
        """Parse YAML string to dictionary."""
        if not isinstance(yaml_str, str):
            return {}
        try:
            return json.loads(yaml_str.replace("'", '"'))
        except:
            return {}

    def extract_yaml_graph_features(self, spec_dict: Dict) -> np.ndarray:
        """Extract node count, depth, and structure from K8s spec."""
        if not spec_dict:
            return np.array([0, 0, 0, 0, 0], dtype=np.float32)

        def count_nodes(obj, depth=0, max_depth=[0]):
            count = 1
            max_depth[0] = max(max_depth[0], depth)
            if isinstance(obj, dict):
                count += sum(count_nodes(v, depth + 1, max_depth) for v in obj.values())
            elif isinstance(obj, list):
                count += sum(count_nodes(v, depth + 1, max_depth) for v in obj)
            return count

        node_count = count_nodes(spec_dict)
        max_d = [0]
        count_nodes(spec_dict, max_depth=max_d)
        depth = max_d[0]

        # Extract key structural features
        containers = len(
            spec_dict.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        volumes = len(
            spec_dict.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("volumes", [])
        )
        env_vars = sum(
            len(c.get("env", []))
            for c in spec_dict.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )

        return np.array(
            [node_count, depth, containers, volumes, env_vars], dtype=np.float32
        )

    def extract_telemetry_features(self, row: pd.Series) -> np.ndarray:
        """Extract telemetry features from row."""
        features = [
            row.get("request_rate", 0),
            row.get("latency_p99", 0),
            row.get("cpu_usage_cores", 0),
            row.get("memory_working_set_bytes", 0),
            row.get("error_rate_5xx", 0),
            row.get("cpu_limit", 0),
            row.get("memory_limit", 0),
        ]
        return np.array(features, dtype=np.float32)

    def transform(self) -> Tuple[List[Dict], Dict]:
        """Transform CSV to model-ready samples."""
        samples = []
        stats = {
            "total_samples": len(self.df),
            "label_distribution": {},
            "severity_distribution": {},
            "feature_names": [],
        }

        # Encode labels
        if "operational_label" in self.df.columns:
            labels = self.label_encoder.fit_transform(self.df["operational_label"])
            stats["label_distribution"] = dict(
                zip(self.label_encoder.classes_, np.bincount(labels))
            )
        else:
            labels = np.zeros(len(self.df), dtype=int)

        # Compute class weights for imbalanced data
        unique_labels = np.unique(labels)
        class_weights = np.zeros(len(unique_labels))
        for idx, label in enumerate(unique_labels):
            class_weights[idx] = 1.0 / (np.sum(labels == label) + 1e-8)
        self.class_weights = torch.tensor(class_weights, dtype=torch.float32)

        # Extract severity distribution
        if "severity" in self.df.columns:
            stats["severity_distribution"] = dict(
                self.df["severity"].value_counts().sort_index()
            )

        # Build samples
        for idx, row in self.df.iterrows():
            # Parse YAML specs
            old_spec = self.parse_yaml_to_dict(row.get("baseline_json", "{}"))
            new_spec = self.parse_yaml_to_dict(row.get("live_json", "{}"))

            # Extract features
            yaml_features = self.extract_yaml_graph_features(new_spec or old_spec)
            telemetry_features = self.extract_telemetry_features(row)

            sample = {
                "index": idx,
                "event_id": f"train-{idx}",
                "old_spec": old_spec,
                "new_spec": new_spec,
                "yaml_graph_features": yaml_features,
                "telemetry_features": telemetry_features,
                "severity": int(row.get("severity", 1)),
                "drift_type": str(row.get("drift_type", "unknown")),
                "drift_magnitude": str(row.get("magnitude", "unknown")),
                "operational_label": str(row.get("operational_label", "unknown")),
                "label_encoded": int(labels[idx]),
                "label": row.get("operational_label", "unknown"),
                "target": {
                    "namespace": str(row.get("namespace", "demo")),
                    "name": str(row.get("deployment", "app")),
                    "kind": "Deployment",
                },
            }
            samples.append(sample)

        stats["feature_names"] = [
            "request_rate",
            "latency_p99",
            "cpu_usage_cores",
            "memory_working_set_bytes",
            "error_rate_5xx",
            "cpu_limit",
            "memory_limit",
        ]

        return samples, stats


# Transform data
print("\nTransforming dataset...")
transformer = DITSecDataTransformer(df)
samples, transform_stats = transformer.transform()

print(f"\nTransformed {len(samples)} samples")
print(f"Label distribution: {transform_stats['label_distribution']}")
print(f"Severity distribution: {transform_stats['severity_distribution']}")
print(f"Class weights: {transformer.class_weights}")

# ============================================================================
# SECTION 6: PYTORCH DATASET & DATALOADER
# ============================================================================


class DITSecDataset(Dataset):
    """PyTorch Dataset for DIT-Sec training."""

    def __init__(self, samples: List[Dict], split: str = "train"):
        self.samples = samples
        self.split = split

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict:
        sample = self.samples[idx]

        # Convert to tensors
        item = {
            "index": sample["index"],
            "yaml_graph_features": torch.tensor(
                sample["yaml_graph_features"], dtype=torch.float32
            ),
            "telemetry_features": torch.tensor(
                sample["telemetry_features"], dtype=torch.float32
            ),
            "severity": torch.tensor(sample["severity"], dtype=torch.long),
            "label": torch.tensor(sample["label_encoded"], dtype=torch.long),
            "drift_type": sample["drift_type"],
            "operational_label": sample["operational_label"],
        }

        return item


# Create train/val/test splits
print("\nCreating train/val/test splits...")
train_samples, test_val_samples = train_test_split(
    samples,
    test_size=0.20,
    random_state=42,
    stratify=[s["label_encoded"] for s in samples],
)

val_samples, test_samples = train_test_split(
    test_val_samples,
    test_size=0.50,
    random_state=42,
    stratify=[s["label_encoded"] for s in test_val_samples],
)

print(f"Train samples: {len(train_samples)}")
print(f"Val samples: {len(val_samples)}")
print(f"Test samples: {len(test_samples)}")

# Create datasets and dataloaders
train_dataset = DITSecDataset(train_samples, split="train")
val_dataset = DITSecDataset(val_samples, split="val")
test_dataset = DITSecDataset(test_samples, split="test")

BATCH_SIZE = 32
train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

print(f"\nDataloader batches:")
print(f"  Train: {len(train_loader)} batches")
print(f"  Val: {len(val_loader)} batches")
print(f"  Test: {len(test_loader)} batches")

# ============================================================================
# SECTION 7: MODEL ARCHITECTURE
# ============================================================================


class DITSecModel_Simplified(nn.Module):
    """
    Simplified DIT-Sec v3.0 model optimized for Colab training.
    Multi-modal encoder fusion with YAML graph + telemetry encoding.
    """

    def __init__(
        self,
        yaml_feature_dim: int = 5,
        telemetry_feature_dim: int = 7,
        hidden_dim: int = 128,
        num_classes: int = 5,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes

        # YAML Graph Encoder
        self.yaml_encoder = nn.Sequential(
            nn.Linear(yaml_feature_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
        )

        # Telemetry Encoder (Mamba-like: sequential processing)
        self.telemetry_encoder = nn.Sequential(
            nn.Linear(telemetry_feature_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
        )

        # Multi-Head Cross-Attention fusion
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_dim, num_heads=4, dropout=dropout, batch_first=True
        )

        # Fusion MLP
        self.fusion_mlp = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
        )

        # Classification head
        self.classifier = nn.Linear(hidden_dim // 2, num_classes)

        # Risk score head (auxiliary)
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim // 2, 32), nn.ReLU(), nn.Linear(32, 1), nn.Sigmoid()
        )

    def forward(
        self, yaml_features: torch.Tensor, telemetry_features: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.

        Args:
            yaml_features: (batch_size, yaml_feature_dim)
            telemetry_features: (batch_size, telemetry_feature_dim)

        Returns:
            logits: (batch_size, num_classes)
            risk_scores: (batch_size, 1)
        """
        # Encode modalities
        yaml_encoded = self.yaml_encoder(yaml_features)  # (batch_size, hidden_dim)
        telemetry_encoded = self.telemetry_encoder(
            telemetry_features
        )  # (batch_size, hidden_dim)

        # Cross-attention fusion
        query = yaml_encoded.unsqueeze(1)  # (batch_size, 1, hidden_dim)
        key = telemetry_encoded.unsqueeze(1)  # (batch_size, 1, hidden_dim)
        value = telemetry_encoded.unsqueeze(1)  # (batch_size, 1, hidden_dim)

        attn_output, _ = self.attention(query, key, value)
        attn_output = attn_output.squeeze(1)  # (batch_size, hidden_dim)

        # Concatenate encodings
        fused = torch.cat(
            [yaml_encoded, attn_output], dim=1
        )  # (batch_size, hidden_dim*2)

        # Fusion MLP
        fused_rep = self.fusion_mlp(fused)  # (batch_size, hidden_dim//2)

        # Classification
        logits = self.classifier(fused_rep)  # (batch_size, num_classes)
        risk_scores = self.risk_head(fused_rep)  # (batch_size, 1)

        return logits, risk_scores


# Initialize model
num_classes = len(transformer.label_encoder.classes_)
model = DITSecModel_Simplified(
    yaml_feature_dim=5,
    telemetry_feature_dim=7,
    hidden_dim=128,
    num_classes=num_classes,
    dropout=0.1,
).to(device)

print(f"\nModel initialized on device: {device}")
print(f"Number of classes: {num_classes}")
print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

# ============================================================================
# SECTION 8: TRAINING SETUP
# ============================================================================

# Loss functions
criterion_classification = nn.CrossEntropyLoss(
    weight=transformer.class_weights.to(device)
)
criterion_risk = nn.MSELoss()

# Optimizer with warmup scheduler
optimizer = optim.AdamW(model.parameters(), lr=2e-4, weight_decay=1e-5)
scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
    optimizer, T_0=10, T_mult=2, eta_min=1e-6
)

# Training configuration
EPOCHS = 100
EARLY_STOPPING_PATIENCE = 15
early_stopping_counter = 0
best_val_loss = float("inf")
best_model_path = OUTPUT_DIR / "best_model.pth"

# Metrics tracking
train_history = {
    "epoch": [],
    "train_loss": [],
    "train_accuracy": [],
    "val_loss": [],
    "val_accuracy": [],
    "learning_rate": [],
}

print("\nTraining configuration:")
print(f"  Epochs: {EPOCHS}")
print(f"  Batch size: {BATCH_SIZE}")
print(f"  Learning rate: 2e-4")
print(f"  Optimizer: AdamW")
print(f"  Scheduler: Cosine Annealing with Warm Restarts (T_0=10)")
print(f"  Early stopping patience: {EARLY_STOPPING_PATIENCE}")
print(f"  Device: {device}")

# ============================================================================
# SECTION 9: TRAINING LOOP
# ============================================================================


def train_epoch(
    epoch: int, model, loader, optimizer, criterion_cls, criterion_risk, device
):
    """Train for one epoch."""
    model.train()
    total_loss = 0
    correct = 0
    total = 0

    for batch_idx, batch in enumerate(loader):
        yaml_features = batch["yaml_graph_features"].to(device)
        telemetry_features = batch["telemetry_features"].to(device)
        labels = batch["label"].to(device)
        severity = (
            batch["severity"].to(device).float().unsqueeze(1) / 4.0
        )  # Normalize severity to [0, 1]

        # Forward pass
        logits, risk_scores = model(yaml_features, telemetry_features)

        # Compute loss
        loss_cls = criterion_cls(logits, labels)
        loss_risk = criterion_risk(risk_scores, severity)
        loss = loss_cls + 0.5 * loss_risk  # Weighted combination

        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

        # Metrics
        total_loss += loss.item()
        _, predicted = logits.max(1)
        correct += predicted.eq(labels).sum().item()
        total += labels.size(0)

        if (batch_idx + 1) % 10 == 0:
            print(f"  Batch {batch_idx + 1}/{len(loader)}: loss={loss.item():.4f}")

    avg_loss = total_loss / len(loader)
    accuracy = 100.0 * correct / total

    return avg_loss, accuracy


def validate(model, loader, criterion_cls, criterion_risk, device):
    """Validate model."""
    model.eval()
    total_loss = 0
    correct = 0
    total = 0
    all_logits = []
    all_labels = []

    with torch.no_grad():
        for batch in loader:
            yaml_features = batch["yaml_graph_features"].to(device)
            telemetry_features = batch["telemetry_features"].to(device)
            labels = batch["label"].to(device)
            severity = batch["severity"].to(device).float().unsqueeze(1) / 4.0

            logits, risk_scores = model(yaml_features, telemetry_features)

            loss_cls = criterion_cls(logits, labels)
            loss_risk = criterion_risk(risk_scores, severity)
            loss = loss_cls + 0.5 * loss_risk

            total_loss += loss.item()
            _, predicted = logits.max(1)
            correct += predicted.eq(labels).sum().item()
            total += labels.size(0)

            all_logits.append(logits.cpu())
            all_labels.append(labels.cpu())

    avg_loss = total_loss / len(loader)
    accuracy = 100.0 * correct / total

    return avg_loss, accuracy


# Training loop
print("\n" + "=" * 80)
print("TRAINING STARTED")
print("=" * 80)

for epoch in range(EPOCHS):
    print(f"\nEpoch {epoch + 1}/{EPOCHS}")

    # Train
    train_loss, train_acc = train_epoch(
        epoch,
        model,
        train_loader,
        optimizer,
        criterion_classification,
        criterion_risk,
        device,
    )

    # Validate
    val_loss, val_acc = validate(
        model, val_loader, criterion_classification, criterion_risk, device
    )

    # Schedule step
    scheduler.step()

    # Log metrics
    train_history["epoch"].append(epoch + 1)
    train_history["train_loss"].append(train_loss)
    train_history["train_accuracy"].append(train_acc)
    train_history["val_loss"].append(val_loss)
    train_history["val_accuracy"].append(val_acc)
    train_history["learning_rate"].append(optimizer.param_groups[0]["lr"])

    print(f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}%")
    print(f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}%")
    print(f"Learning Rate: {optimizer.param_groups[0]['lr']:.2e}")

    # Early stopping
    if val_loss < best_val_loss:
        best_val_loss = val_loss
        early_stopping_counter = 0
        torch.save(model.state_dict(), best_model_path)
        print(f"✓ Best model saved (val_loss: {val_loss:.4f})")
    else:
        early_stopping_counter += 1
        if early_stopping_counter >= EARLY_STOPPING_PATIENCE:
            print(f"\nEarly stopping triggered after {epoch + 1} epochs")
            break

print("\n" + "=" * 80)
print("TRAINING COMPLETED")
print("=" * 80)

# ============================================================================
# SECTION 10: EVALUATION
# ============================================================================

# Load best model
model.load_state_dict(torch.load(best_model_path))
model = model.to(device)


def evaluate_model(model, loader, device, label_encoder):
    """Comprehensive model evaluation."""
    model.eval()
    all_logits = []
    all_labels = []
    all_probs = []

    with torch.no_grad():
        for batch in loader:
            yaml_features = batch["yaml_graph_features"].to(device)
            telemetry_features = batch["telemetry_features"].to(device)
            labels = batch["label"]

            logits, _ = model(yaml_features, telemetry_features)
            probs = F.softmax(logits, dim=1)

            all_logits.append(logits.cpu())
            all_labels.append(labels)
            all_probs.append(probs.cpu())

    logits_tensor = torch.cat(all_logits, dim=0).numpy()
    labels_array = torch.cat(all_labels, dim=0).numpy()
    probs_array = torch.cat(all_probs, dim=0).numpy()
    predictions = np.argmax(logits_tensor, axis=1)

    # Metrics
    accuracy = accuracy_score(labels_array, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels_array, predictions, average="weighted"
    )

    # Per-class metrics
    precision_per_class, recall_per_class, f1_per_class, support_per_class = (
        precision_recall_fscore_support(labels_array, predictions, average=None)
    )

    # Confusion matrix
    cm = confusion_matrix(labels_array, predictions)

    # ROC-AUC (one-vs-rest)
    try:
        roc_auc = roc_auc_score(
            labels_array, probs_array, multi_class="ovr", average="weighted"
        )
    except:
        roc_auc = 0.0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "precision_per_class": precision_per_class,
        "recall_per_class": recall_per_class,
        "f1_per_class": f1_per_class,
        "support_per_class": support_per_class,
        "confusion_matrix": cm,
        "predictions": predictions,
        "labels": labels_array,
        "probabilities": probs_array,
        "label_encoder": label_encoder,
    }


# Evaluate on test set
print("\nEvaluating on test set...")
test_metrics = evaluate_model(model, test_loader, device, transformer.label_encoder)

print("\n" + "=" * 80)
print("TEST SET EVALUATION")
print("=" * 80)
print(f"Accuracy: {test_metrics['accuracy']:.4f}")
print(f"Precision (weighted): {test_metrics['precision']:.4f}")
print(f"Recall (weighted): {test_metrics['recall']:.4f}")
print(f"F1 Score (weighted): {test_metrics['f1']:.4f}")
print(f"ROC-AUC (weighted): {test_metrics['roc_auc']:.4f}")

print("\nPer-class metrics:")
for i, class_name in enumerate(transformer.label_encoder.classes_):
    print(f"  {class_name}:")
    print(f"    Precision: {test_metrics['precision_per_class'][i]:.4f}")
    print(f"    Recall: {test_metrics['recall_per_class'][i]:.4f}")
    print(f"    F1: {test_metrics['f1_per_class'][i]:.4f}")
    print(f"    Support: {int(test_metrics['support_per_class'][i])}")

print("\nConfusion Matrix:")
print(test_metrics["confusion_matrix"])

print("\nClassification Report:")
print(
    classification_report(
        test_metrics["labels"],
        test_metrics["predictions"],
        target_names=transformer.label_encoder.classes_,
    )
)

# ============================================================================
# SECTION 11: VISUALIZATION
# ============================================================================


def plot_training_curves(history):
    """Plot training and validation curves."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Loss curve
    axes[0, 0].plot(
        history["epoch"], history["train_loss"], label="Train Loss", linewidth=2
    )
    axes[0, 0].plot(
        history["epoch"], history["val_loss"], label="Val Loss", linewidth=2
    )
    axes[0, 0].set_xlabel("Epoch")
    axes[0, 0].set_ylabel("Loss")
    axes[0, 0].set_title("Training and Validation Loss")
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3)

    # Accuracy curve
    axes[0, 1].plot(
        history["epoch"], history["train_accuracy"], label="Train Accuracy", linewidth=2
    )
    axes[0, 1].plot(
        history["epoch"], history["val_accuracy"], label="Val Accuracy", linewidth=2
    )
    axes[0, 1].set_xlabel("Epoch")
    axes[0, 1].set_ylabel("Accuracy (%)")
    axes[0, 1].set_title("Training and Validation Accuracy")
    axes[0, 1].legend()
    axes[0, 1].grid(True, alpha=0.3)

    # Learning rate
    axes[1, 0].plot(
        history["epoch"], history["learning_rate"], linewidth=2, color="green"
    )
    axes[1, 0].set_xlabel("Epoch")
    axes[1, 0].set_ylabel("Learning Rate")
    axes[1, 0].set_title("Learning Rate Schedule")
    axes[1, 0].set_yscale("log")
    axes[1, 0].grid(True, alpha=0.3)

    # Validation metrics
    axes[1, 1].text(
        0.5,
        0.7,
        f"Test Accuracy: {test_metrics['accuracy']:.4f}",
        ha="center",
        fontsize=12,
        weight="bold",
    )
    axes[1, 1].text(
        0.5,
        0.6,
        f"Test Precision: {test_metrics['precision']:.4f}",
        ha="center",
        fontsize=12,
    )
    axes[1, 1].text(
        0.5, 0.5, f"Test Recall: {test_metrics['recall']:.4f}", ha="center", fontsize=12
    )
    axes[1, 1].text(
        0.5, 0.4, f"Test F1: {test_metrics['f1']:.4f}", ha="center", fontsize=12
    )
    axes[1, 1].text(
        0.5,
        0.3,
        f"Test ROC-AUC: {test_metrics['roc_auc']:.4f}",
        ha="center",
        fontsize=12,
    )
    axes[1, 1].text(
        0.5, 0.15, f"Epochs: {len(history['epoch'])}", ha="center", fontsize=11
    )
    axes[1, 1].axis("off")

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "training_curves.png", dpi=300, bbox_inches="tight")
    print(f"\n✓ Saved training curves to {OUTPUT_DIR / 'training_curves.png'}")
    plt.show()


def plot_confusion_matrix(metrics):
    """Plot confusion matrix."""
    cm = metrics["confusion_matrix"]
    label_encoder = metrics["label_encoder"]

    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=True,
        xticklabels=label_encoder.classes_,
        yticklabels=label_encoder.classes_,
        ax=ax,
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title("Confusion Matrix - Test Set")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "confusion_matrix.png", dpi=300, bbox_inches="tight")
    print(f"✓ Saved confusion matrix to {OUTPUT_DIR / 'confusion_matrix.png'}")
    plt.show()


# Generate plots
print("\nGenerating visualizations...")
plot_training_curves(train_history)
plot_confusion_matrix(test_metrics)

# ============================================================================
# SECTION 12: MODEL EXPORT & SAVING
# ============================================================================


def export_model_checkpoint(model, transformer, history, metrics, output_dir):
    """Export trained model and metadata."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    # Save model checkpoint
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "model_config": {
            "yaml_feature_dim": 5,
            "telemetry_feature_dim": 7,
            "hidden_dim": 128,
            "num_classes": len(transformer.label_encoder.classes_),
            "dropout": 0.1,
        },
        "label_encoder_classes": list(transformer.label_encoder.classes_),
        "class_weights": transformer.class_weights.tolist(),
        "training_history": history,
        "test_metrics": {
            k: v.tolist() if isinstance(v, np.ndarray) else v
            for k, v in metrics.items()
            if k != "label_encoder"
        },
        "timestamp": datetime.now().isoformat(),
    }

    checkpoint_path = output_dir / "dit_sec_v3_checkpoint.pth"
    torch.save(checkpoint, checkpoint_path)
    print(f"✓ Saved model checkpoint to {checkpoint_path}")

    # Save label encoder mapping
    label_mapping = {
        i: class_name for i, class_name in enumerate(transformer.label_encoder.classes_)
    }
    with open(output_dir / "label_mapping.json", "w") as f:
        json.dump(label_mapping, f, indent=2)
    print(f"✓ Saved label mapping to {output_dir / 'label_mapping.json'}")

    # Save training history
    history_df = pd.DataFrame(history)
    history_df.to_csv(output_dir / "training_history.csv", index=False)
    print(f"✓ Saved training history to {output_dir / 'training_history.csv'}")

    # Save metrics summary
    metrics_summary = {
        "test_accuracy": float(metrics["accuracy"]),
        "test_precision": float(metrics["precision"]),
        "test_recall": float(metrics["recall"]),
        "test_f1": float(metrics["f1"]),
        "test_roc_auc": float(metrics["roc_auc"]),
        "per_class_metrics": {
            class_name: {
                "precision": float(metrics["precision_per_class"][i]),
                "recall": float(metrics["recall_per_class"][i]),
                "f1": float(metrics["f1_per_class"][i]),
                "support": int(metrics["support_per_class"][i]),
            }
            for i, class_name in enumerate(transformer.label_encoder.classes_)
        },
    }

    with open(output_dir / "metrics_summary.json", "w") as f:
        json.dump(metrics_summary, f, indent=2)
    print(f"✓ Saved metrics summary to {output_dir / 'metrics_summary.json'}")

    return checkpoint_path


# Export
print("\nExporting model...")
checkpoint_path = export_model_checkpoint(
    model, transformer, train_history, test_metrics, OUTPUT_DIR
)

# ============================================================================
# SECTION 13: SUMMARY & NEXT STEPS
# ============================================================================

print("\n" + "=" * 80)
print("TRAINING SUMMARY")
print("=" * 80)
print(f"\nDataset: dit-merged-complete.csv")
print(f"Total samples: {len(samples)}")
print(
    f"Train/Val/Test split: {len(train_samples)}/{len(val_samples)}/{len(test_samples)}"
)
print(f"\nModel: DITSecModel_Simplified")
print(f"Number of classes: {num_classes}")
print(f"Total parameters: {sum(p.numel() for p in model.parameters()):,}")
print(f"\nTraining configuration:")
print(f"  Epochs trained: {len(train_history['epoch'])}")
print(f"  Batch size: {BATCH_SIZE}")
print(f"  Optimizer: AdamW (lr=2e-4)")
print(f"  Scheduler: Cosine Annealing with Warm Restarts")
print(f"\nFinal Test Metrics:")
print(f"  Accuracy: {test_metrics['accuracy']:.4f}")
print(f"  Precision: {test_metrics['precision']:.4f}")
print(f"  Recall: {test_metrics['recall']:.4f}")
print(f"  F1 Score: {test_metrics['f1']:.4f}")
print(f"  ROC-AUC: {test_metrics['roc_auc']:.4f}")
print(f"\nOutput Files:")
print(f"  Model checkpoint: {checkpoint_path}")
print(f"  Training history: {OUTPUT_DIR / 'training_history.csv'}")
print(f"  Metrics summary: {OUTPUT_DIR / 'metrics_summary.json'}")
print(f"  Label mapping: {OUTPUT_DIR / 'label_mapping.json'}")
print(f"  Training curves: {OUTPUT_DIR / 'training_curves.png'}")
print(f"  Confusion matrix: {OUTPUT_DIR / 'confusion_matrix.png'}")

print("\n" + "=" * 80)
print("NEXT STEPS")
print("=" * 80)
print("""
1. Download all files from the 'training_outputs' directory:
   - dit_sec_v3_checkpoint.pth (model weights)
   - label_mapping.json (class labels)
   - metrics_summary.json (evaluation metrics)
   - training_history.csv (training curves data)
   - training_curves.png (visualization)
   - confusion_matrix.png (visualization)

2. Copy checkpoint to local machine:
   /home/ryan/Desktop/Unisys_Model/models/dit_sec_v3/dit_sec_v3_checkpoint.pth

3. Create inference wrapper in:
   /home/ryan/Desktop/Unisys_Model/models/dit_sec_v3/inference.py

4. Integrate with Health Agent in:
   /home/ryan/Desktop/Unisys_Model/agents/health_agent/agent.py

5. Test model with live pods in demo namespace

6. Run synthetic drift detection tests

For questions or issues, check the README.md in the project root.
""")

print("\n✓ Training notebook execution complete!")
print(f"  Timestamp: {datetime.now().isoformat()}")
