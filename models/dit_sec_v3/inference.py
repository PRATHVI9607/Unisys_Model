"""
DIT-Sec v3.0 Inference Wrapper
Production inference interface for trained DITSecModel_Enhanced

This module provides:
- Model loading from checkpoint
- Feature extraction from YAML/telemetry/drift data
- Inference with confidence scores
- Class and severity predictions
"""

import torch
import torch.nn as nn
from pathlib import Path
from typing import Dict, Tuple, Optional, List
import json
import numpy as np


# ============================================================================
# MODEL ARCHITECTURE (must match training_dit_sec_v3_improved.py)
# ============================================================================


class DITSecModel_Enhanced(nn.Module):
    """
    Production model for DIT Security classification.

    Architecture:
    - yaml_encoder: processes YAML configuration diffs (12D → 128D)
    - telemetry_encoder: processes system metrics (14D → 128D)
    - drift_encoder: processes drift semantics (6D → 64D)
    - attention: multi-head attention fusion (128D × 3 inputs)
    - fusion_mlp: multi-layer perceptron fusion (320D → 64D)
    - classifier: final classification head (64D → 5 classes)
    - severity_head: severity prediction head (64D → 3 levels)

    Total parameters: ~280K
    Focal Loss for class imbalance handling
    """

    def __init__(
        self,
        yaml_input_dim: int = 12,
        telemetry_input_dim: int = 14,
        drift_input_dim: int = 6,
        hidden_dim: int = 128,
        num_classes: int = 5,
        num_severity_levels: int = 3,
        dropout: float = 0.35,
        attention_heads: int = 4,
    ):
        super().__init__()

        self.hidden_dim = hidden_dim
        self.num_classes = num_classes
        self.num_severity_levels = num_severity_levels

        # YAML Configuration Encoder (12D → 128D)
        self.yaml_encoder = nn.Sequential(
            nn.Linear(yaml_input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
        )

        # Telemetry Encoder (14D → 128D)
        self.telemetry_encoder = nn.Sequential(
            nn.Linear(telemetry_input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
        )

        # Drift Semantics Encoder (6D → 64D)
        self.drift_encoder = nn.Sequential(
            nn.Linear(drift_input_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, hidden_dim // 2),
            nn.ReLU(),
        )

        # Multi-head Attention (combine three 128D streams)
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=attention_heads,
            dropout=dropout,
            batch_first=True,
        )

        # Fusion MLP (320D → 64D)
        # Input: concat(128, 128, 64) = 320D
        self.fusion_mlp = nn.Sequential(
            nn.Linear(hidden_dim * 2 + hidden_dim // 2, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
        )

        # Classification Head (64D → 5 classes)
        self.classifier = nn.Linear(hidden_dim // 2, num_classes)

        # Severity Head (64D → 3 levels)
        # Must be a single Linear layer, NOT Sequential
        self.severity_head = nn.Linear(hidden_dim // 2, num_severity_levels)

    def forward(
        self,
        yaml_features: torch.Tensor,
        telemetry_features: torch.Tensor,
        drift_features: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.

        Args:
            yaml_features: (batch_size, 12)
            telemetry_features: (batch_size, 14)
            drift_features: (batch_size, 6)

        Returns:
            (class_logits, severity_logits)
            - class_logits: (batch_size, 5)
            - severity_logits: (batch_size, 3)
        """
        batch_size = yaml_features.size(0)

        # Encode each stream
        yaml_encoded = self.yaml_encoder(yaml_features)  # (batch, 128)
        telemetry_encoded = self.telemetry_encoder(telemetry_features)  # (batch, 128)
        drift_encoded = self.drift_encoder(drift_features)  # (batch, 64)

        # Attention fusion: treat as sequence of 3 tokens
        # Stack into sequence: (batch, seq_len=3, hidden_dim)
        yaml_seq = yaml_encoded.unsqueeze(1)  # (batch, 1, 128)
        telemetry_seq = telemetry_encoded.unsqueeze(1)  # (batch, 1, 128)
        # Pad drift to match hidden_dim
        drift_padded = torch.cat(
            [
                drift_encoded,
                torch.zeros(batch_size, self.hidden_dim - drift_encoded.size(1)).to(
                    drift_encoded.device
                ),
            ],
            dim=1,
        ).unsqueeze(1)  # (batch, 1, 128)

        query_seq = torch.cat(
            [yaml_seq, telemetry_seq, drift_padded], dim=1
        )  # (batch, 3, 128)

        # Self-attention
        attn_out, _ = self.attention(query_seq, query_seq, query_seq)
        # Aggregate attention output
        attn_pooled = attn_out.mean(dim=1)  # (batch, 128)

        # Fusion: concatenate all three encodings
        fused = torch.cat(
            [yaml_encoded, telemetry_encoded, drift_encoded], dim=1
        )  # (batch, 320)

        # MLP fusion
        fused_output = self.fusion_mlp(fused)  # (batch, 64)

        # Final predictions
        class_logits = self.classifier(fused_output)  # (batch, 5)
        severity_logits = self.severity_head(fused_output)  # (batch, 3)

        return class_logits, severity_logits


# ============================================================================
# INFERENCE INTERFACE
# ============================================================================


class DITSecInference:
    """Production inference interface for DIT-Sec v3.0 model."""

    # Class mappings
    CLASS_NAMES = {
        0: "Benign_Or_Subtle",
        1: "Harmful_Performance_Degradation",
        2: "Harmful_Security_Breach",
        3: "Harmful_Multi_Vector",
        4: "Harmful_Critical_Outage",
    }

    SEVERITY_NAMES = {
        0: "Low",
        1: "Medium",
        2: "High",
    }

    def __init__(
        self,
        checkpoint_path: Optional[str] = None,
        device: Optional[str] = None,
    ):
        """
        Initialize inference interface.

        Args:
            checkpoint_path: path to dit_sec_v3_checkpoint.pth
                            defaults to models/dit_sec_v3/dit_sec_v3_checkpoint.pth
            device: torch device ('cpu', 'cuda', etc.)
                   defaults to 'cuda' if available else 'cpu'
        """
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        if checkpoint_path is None:
            # Default to packaged checkpoint
            checkpoint_path = Path(__file__).parent / "dit_sec_v3_checkpoint.pth"

        self.checkpoint_path = Path(checkpoint_path)

        # Load model
        self.model = self._load_model()
        self.model.eval()

    def _load_model(self) -> DITSecModel_Enhanced:
        """Load trained model from checkpoint."""
        if not self.checkpoint_path.exists():
            raise FileNotFoundError(
                f"Checkpoint not found: {self.checkpoint_path}\n"
                f"Expected: models/dit_sec_v3/dit_sec_v3_checkpoint.pth"
            )

        model = DITSecModel_Enhanced()
        checkpoint = torch.load(self.checkpoint_path, map_location=self.device)
        model.load_state_dict(checkpoint)
        model.to(self.device)
        return model

    def predict(
        self,
        yaml_features: np.ndarray,
        telemetry_features: np.ndarray,
        drift_features: np.ndarray,
        return_probabilities: bool = True,
    ) -> Dict:
        """
        Run inference on features.

        Args:
            yaml_features: (batch_size, 12) or (12,)
            telemetry_features: (batch_size, 14) or (14,)
            drift_features: (batch_size, 6) or (6,)
            return_probabilities: if True, return softmax probabilities

        Returns:
            {
                "class_id": int or (batch_size,) array,
                "class_name": str or (batch_size,) array,
                "class_confidence": float or (batch_size,) array,
                "class_probabilities": dict or list of dicts,
                "severity_id": int or (batch_size,) array,
                "severity_name": str or (batch_size,) array,
                "severity_confidence": float or (batch_size,) array,
            }
        """
        # Ensure batch dimension
        yaml_features = np.atleast_2d(yaml_features)
        telemetry_features = np.atleast_2d(telemetry_features)
        drift_features = np.atleast_2d(drift_features)

        # Convert to tensors
        yaml_t = torch.from_numpy(yaml_features).float().to(self.device)
        telemetry_t = torch.from_numpy(telemetry_features).float().to(self.device)
        drift_t = torch.from_numpy(drift_features).float().to(self.device)

        # Run inference
        with torch.no_grad():
            class_logits, severity_logits = self.model(yaml_t, telemetry_t, drift_t)

        class_probs = torch.softmax(class_logits, dim=1)
        severity_probs = torch.softmax(severity_logits, dim=1)

        class_preds = class_logits.argmax(dim=1).cpu().numpy()
        severity_preds = severity_logits.argmax(dim=1).cpu().numpy()

        class_confs = class_probs.max(dim=1)[0].cpu().numpy()
        severity_confs = severity_probs.max(dim=1)[0].cpu().numpy()

        # Format output
        batch_size = yaml_features.shape[0]

        if batch_size == 1:
            # Single sample
            result = {
                "class_id": int(class_preds[0]),
                "class_name": self.CLASS_NAMES[class_preds[0]],
                "class_confidence": float(class_confs[0]),
                "severity_id": int(severity_preds[0]),
                "severity_name": self.SEVERITY_NAMES[severity_preds[0]],
                "severity_confidence": float(severity_confs[0]),
            }

            if return_probabilities:
                result["class_probabilities"] = {
                    self.CLASS_NAMES[i]: float(class_probs[0, i])
                    for i in range(len(self.CLASS_NAMES))
                }
                result["severity_probabilities"] = {
                    self.SEVERITY_NAMES[i]: float(severity_probs[0, i])
                    for i in range(len(self.SEVERITY_NAMES))
                }
        else:
            # Batch
            result = {
                "class_id": class_preds,
                "class_name": np.array([self.CLASS_NAMES[cid] for cid in class_preds]),
                "class_confidence": class_confs,
                "severity_id": severity_preds,
                "severity_name": np.array(
                    [self.SEVERITY_NAMES[sid] for sid in severity_preds]
                ),
                "severity_confidence": severity_confs,
            }

            if return_probabilities:
                result["class_probabilities"] = [
                    {
                        self.CLASS_NAMES[i]: float(class_probs[j, i])
                        for i in range(len(self.CLASS_NAMES))
                    }
                    for j in range(batch_size)
                ]
                result["severity_probabilities"] = [
                    {
                        self.SEVERITY_NAMES[i]: float(severity_probs[j, i])
                        for i in range(len(self.SEVERITY_NAMES))
                    }
                    for j in range(batch_size)
                ]

        return result


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


def load_model(
    checkpoint_path: Optional[str] = None, device: Optional[str] = None
) -> DITSecInference:
    """Load inference interface."""
    return DITSecInference(checkpoint_path=checkpoint_path, device=device)


def predict(
    yaml_features: np.ndarray,
    telemetry_features: np.ndarray,
    drift_features: np.ndarray,
    checkpoint_path: Optional[str] = None,
    device: Optional[str] = None,
) -> Dict:
    """Quick inference without keeping model loaded."""
    inferencer = DITSecInference(checkpoint_path=checkpoint_path, device=device)
    return inferencer.predict(yaml_features, telemetry_features, drift_features)


# ============================================================================
# MAIN (TESTING)
# ============================================================================


if __name__ == "__main__":
    # Example usage
    print("DIT-Sec v3.0 Inference Interface")
    print("=" * 60)

    # Load model
    print("\nLoading model...")
    inferencer = load_model()
    print("✓ Model loaded")

    # Example: Normal operation
    print("\nExample 1: Normal operation")
    yaml_features = np.array(
        [[0.1, 0.2, 0.1, -0.1, 0.05, 0.1, -0.05, 0.08, 0.12, -0.07, 0.06, 0.11]]
    )
    telemetry_features = np.array(
        [
            [
                0.05,
                -0.1,
                0.08,
                0.15,
                -0.05,
                0.1,
                0.08,
                -0.06,
                0.04,
                0.12,
                -0.08,
                0.09,
                0.05,
                -0.03,
            ]
        ]
    )
    drift_features = np.array([[0.08, -0.05, 0.06, 0.1, -0.04, 0.07]])

    result = inferencer.predict(yaml_features, telemetry_features, drift_features)
    print(
        f"  Class: {result['class_name']} (confidence: {result['class_confidence']:.2%})"
    )
    print(
        f"  Severity: {result['severity_name']} (confidence: {result['severity_confidence']:.2%})"
    )

    # Example: Security breach
    print("\nExample 2: Security breach detection")
    yaml_features = np.array(
        [[1.5, 1.8, 1.2, -1.5, 1.1, 1.3, -1.2, 1.4, 1.6, -1.1, 1.3, 1.4]]
    )
    telemetry_features = np.array(
        [[1.8, -1.5, 1.2, 1.9, -1.3, 1.5, 1.4, -1.2, 1.0, 1.7, -1.4, 1.3, 1.1, -0.9]]
    )
    drift_features = np.array([[1.5, -1.2, 1.0, 1.3, -1.0, 1.2]])

    result = inferencer.predict(yaml_features, telemetry_features, drift_features)
    print(
        f"  Class: {result['class_name']} (confidence: {result['class_confidence']:.2%})"
    )
    print(
        f"  Severity: {result['severity_name']} (confidence: {result['severity_confidence']:.2%})"
    )
