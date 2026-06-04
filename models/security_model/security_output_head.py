"""
Security Output Head — KubeHeal v4 (Section 04.4)
=================================================
5-class classifier + risk grounded in class probabilities (same rationale as
the health head: keeps the conformal interval tight and risk consistent with
the label).
"""

import torch
import torch.nn as nn

SECURITY_LABELS = [
    "benign",
    "suspicious",
    "ransomware_staging",
    "ransomware_active",
    "data_exfiltration",
]

# Canonical per-class severity (also the regression target — see trainer).
CLASS_RISK = [0.05, 0.45, 0.65, 0.95, 0.80]


class SecurityOutputHead(nn.Module):
    def __init__(self, fused_dim: int = 64, num_labels: int = len(SECURITY_LABELS)):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, num_labels),
        )
        self.risk_adjust = nn.Sequential(
            nn.Linear(fused_dim, 16), nn.ReLU(), nn.Linear(16, 1), nn.Tanh(),
        )
        self.register_buffer(
            "class_risk", torch.tensor(CLASS_RISK[:num_labels], dtype=torch.float32)
        )

    def forward(self, fused_embedding: torch.Tensor):
        logits = self.classifier(fused_embedding)
        probs = torch.softmax(logits, dim=-1)
        base = (probs * self.class_risk).sum(-1, keepdim=True)
        adjust = self.risk_adjust(fused_embedding) * 0.10
        risk = torch.clamp(base + adjust, 0.0, 1.0)
        return logits, risk
