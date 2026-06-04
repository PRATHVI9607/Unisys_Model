"""
Health Fusion Attention — KubeHeal v4 (Section 03.4)
====================================================
Cross-attention fusion of the YAML graph embedding (query: "what changed?")
and the metric embedding (key/value: "what was the impact?").

Cross-attention (vs concat+MLP) lets the model learn conditional relevance:
a cpu_limits change attends to cpu_throttle + p99 latency; a memory_limits
change attends to memory_rss + pod_restarts.
"""

from typing import Tuple

import torch
import torch.nn as nn


class HealthFusionAttention(nn.Module):
    def __init__(self, yaml_dim: int = 128, metric_dim: int = 64,
                 fused_dim: int = 128, num_heads: int = 4):
        super().__init__()
        self.yaml_proj = nn.Linear(yaml_dim, fused_dim)
        self.metric_proj = nn.Linear(metric_dim, fused_dim)
        self.cross_attention = nn.MultiheadAttention(
            embed_dim=fused_dim, num_heads=num_heads, batch_first=True, dropout=0.1
        )
        self.layer_norm = nn.LayerNorm(fused_dim)
        self.output_mlp = nn.Sequential(
            nn.Linear(fused_dim * 2, fused_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(fused_dim, fused_dim),
        )

    def forward(self, yaml_embedding: torch.Tensor,
                metric_embedding: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        if yaml_embedding.dim() == 1:
            yaml_embedding = yaml_embedding.unsqueeze(0)
        if metric_embedding.dim() == 1:
            metric_embedding = metric_embedding.unsqueeze(0)

        yaml_q = self.yaml_proj(yaml_embedding).unsqueeze(1)    # [B,1,F]
        metric_kv = self.metric_proj(metric_embedding).unsqueeze(1)  # [B,1,F]

        attended, attn_weights = self.cross_attention(
            query=yaml_q, key=metric_kv, value=metric_kv
        )
        attended = attended.squeeze(1)                          # [B,F]
        yaml_flat = self.yaml_proj(yaml_embedding)              # [B,F]
        residual = self.layer_norm(attended + yaml_flat)
        combined = torch.cat([residual, attended], dim=-1)      # [B,2F]
        fused = self.output_mlp(combined)                       # [B,F]
        return fused, attn_weights
