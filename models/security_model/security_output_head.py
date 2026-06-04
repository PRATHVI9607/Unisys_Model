"""
Security Output Head — KubeHeal v4 (Section 04.4)
=================================================
5-class label classifier + continuous risk regressor off the fused 64-dim
security embedding. The 5-label taxonomy captures attack progression so the
Fusion Agent can act early (staging) and distinguish exfiltration.
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


class SecurityOutputHead(nn.Module):
    def __init__(self, fused_dim: int = 64, num_labels: int = len(SECURITY_LABELS)):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, num_labels),
        )
        self.risk_regressor = nn.Sequential(
            nn.Linear(fused_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(self, fused_embedding: torch.Tensor):
        return self.classifier(fused_embedding), self.risk_regressor(fused_embedding)
