"""
Health Output Head — KubeHeal v4 (Section 03.5)
===============================================
Two heads off the fused health embedding:
  - 4-class label classifier
  - continuous risk regressor in [0,1]
"""

import torch
import torch.nn as nn


HEALTH_LABELS = [
    "benign",                          # no meaningful drift / safe drift
    "low_risk_drift",                  # drift, minimal impact
    "harmful_performance_degradation", # measurable performance harm
    "critical_config_error",          # severe / outage-level harm
]


class HealthOutputHead(nn.Module):
    def __init__(self, fused_dim: int = 128, num_labels: int = len(HEALTH_LABELS)):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, num_labels),
        )
        self.risk_regressor = nn.Sequential(
            nn.Linear(fused_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, fused_embedding: torch.Tensor):
        return self.classifier(fused_embedding), self.risk_regressor(fused_embedding)
