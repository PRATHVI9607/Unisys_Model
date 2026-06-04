"""
Dependency Correlation Module (DCM) — KubeHeal v4 (Section 05)
==============================================================
The novel contribution. Bidirectional cross-modal attention between the
Health Model's 128-dim embedding and the Security Model's 64-dim embedding.
Answers: "Are the health and security signals for this resource causally
related?" High correlation = compound incident (ransomware causing CPU thrash
that looks like drift) → escalate. Low = two independent events.

Bidirectional: health-queries-security AND security-queries-health. The
correlation head consumes both attended views + both projections.
"""

from typing import Tuple

import torch
import torch.nn as nn


class CrossModalAttention(nn.Module):
    def __init__(
        self,
        health_dim: int = 128,
        security_dim: int = 64,
        hidden_dim: int = 128,
        num_heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.health_proj = nn.Linear(health_dim, hidden_dim)
        self.security_proj = nn.Linear(security_dim, hidden_dim)

        self.health_queries_security = nn.MultiheadAttention(
            embed_dim=hidden_dim, num_heads=num_heads, dropout=dropout, batch_first=True
        )
        self.security_queries_health = nn.MultiheadAttention(
            embed_dim=hidden_dim, num_heads=num_heads, dropout=dropout, batch_first=True
        )
        self.layer_norm = nn.LayerNorm(hidden_dim)

        self.correlation_head = nn.Sequential(
            nn.Linear(hidden_dim * 4, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        health_embedding: torch.Tensor,    # [B,128]
        security_embedding: torch.Tensor,  # [B,64]
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        if health_embedding.dim() == 1:
            health_embedding = health_embedding.unsqueeze(0)
        if security_embedding.dim() == 1:
            security_embedding = security_embedding.unsqueeze(0)

        h = self.health_proj(health_embedding).unsqueeze(1)     # [B,1,H]
        s = self.security_proj(security_embedding).unsqueeze(1) # [B,1,H]

        h_att, h2s = self.health_queries_security(query=h, key=s, value=s)
        h_att = self.layer_norm(h_att + h)
        s_att, s2h = self.security_queries_health(query=s, key=h, value=h)
        s_att = self.layer_norm(s_att + s)

        combined = torch.cat([
            h.squeeze(1), h_att.squeeze(1),
            s.squeeze(1), s_att.squeeze(1),
        ], dim=-1)                                              # [B,4H]
        correlation_score = self.correlation_head(combined)    # [B,1]
        return correlation_score, h2s, s2h

    def correlate(self, health_embedding, security_embedding) -> float:
        self.eval()
        with torch.no_grad():
            score, _, _ = self.forward(
                torch.as_tensor(health_embedding, dtype=torch.float32),
                torch.as_tensor(security_embedding, dtype=torch.float32),
            )
        return float(score.reshape(-1)[0])

    def param_count(self) -> int:
        return sum(p.numel() for p in self.parameters())
