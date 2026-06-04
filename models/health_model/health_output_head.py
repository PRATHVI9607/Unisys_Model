"""
Health Output Head — KubeHeal v4 (Section 03.5)
===============================================
4-class classifier + a risk score GROUNDED in the class probabilities.

Why grounded risk (not a free sigmoid regressor): a free regressor's outputs
scatter far from the target, so the conformal nonconformity scores blow up and
ci_width → ~1.0 (every decision then escalates to human — autonomy dead).
Grounding risk = Σ p(class)·class_severity makes risk a smooth, bounded
function of the (well-trained) classifier, so the conformal interval is tight
and the risk can never contradict the label.
"""

import torch
import torch.nn as nn

HEALTH_LABELS = [
    "benign",
    "low_risk_drift",
    "harmful_performance_degradation",
    "critical_config_error",
]

# Canonical per-class severity (also the regression target — see trainer).
CLASS_RISK = [0.10, 0.40, 0.70, 0.95]


class HealthOutputHead(nn.Module):
    def __init__(self, fused_dim: int = 128, num_labels: int = len(HEALTH_LABELS)):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, num_labels),
        )
        # small learnable correction (±0.10) on top of the class-grounded risk
        self.risk_adjust = nn.Sequential(
            nn.Linear(fused_dim, 32), nn.ReLU(), nn.Linear(32, 1), nn.Tanh(),
        )
        self.register_buffer(
            "class_risk", torch.tensor(CLASS_RISK[:num_labels], dtype=torch.float32)
        )

    def forward(self, fused_embedding: torch.Tensor):
        logits = self.classifier(fused_embedding)
        probs = torch.softmax(logits, dim=-1)
        base = (probs * self.class_risk).sum(-1, keepdim=True)        # [B,1] in [0,1]
        adjust = self.risk_adjust(fused_embedding) * 0.10
        risk = torch.clamp(base + adjust, 0.0, 1.0)
        return logits, risk
