"""
Security Fusion Attention — KubeHeal v4 (Section 04, mirrors health fusion).
============================================================================
Cross-attention between the syscall transformer embedding (query: "what did
the process do?") and the entropy embedding (key/value: "how random were the
writes?"). Output is the 64-dim security-domain embedding.
"""

from typing import Tuple

import torch
import torch.nn as nn


class SecurityFusionAttention(nn.Module):
    def __init__(self, syscall_dim: int = 64, entropy_dim: int = 64,
                 fused_dim: int = 64, num_heads: int = 4):
        super().__init__()
        self.syscall_proj = nn.Linear(syscall_dim, fused_dim)
        self.entropy_proj = nn.Linear(entropy_dim, fused_dim)
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

    def forward(self, syscall_embedding: torch.Tensor,
                entropy_embedding: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        if syscall_embedding.dim() == 1:
            syscall_embedding = syscall_embedding.unsqueeze(0)
        if entropy_embedding.dim() == 1:
            entropy_embedding = entropy_embedding.unsqueeze(0)
        q = self.syscall_proj(syscall_embedding).unsqueeze(1)
        kv = self.entropy_proj(entropy_embedding).unsqueeze(1)
        attended, attn = self.cross_attention(query=q, key=kv, value=kv)
        attended = attended.squeeze(1)
        sys_flat = self.syscall_proj(syscall_embedding)
        residual = self.layer_norm(attended + sys_flat)
        combined = torch.cat([residual, attended], dim=-1)
        fused = self.output_mlp(combined)
        return fused, attn
