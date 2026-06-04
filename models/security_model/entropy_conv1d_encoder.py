"""
Entropy Conv1D + Squeeze-Excitation Encoder — KubeHeal v4 (Section 04.3)
=======================================================================
Encodes a short univariate entropy time series (≤30 steps, bits/byte) into a
64-dim embedding. Multi-scale Conv1D (k=3,7,15) catches fast/medium/slow
encryption onset; SE block does channel-wise attention over filters.
"""

import torch
import torch.nn as nn


ENTROPY_WINDOW_LENGTH = 30   # 60s @ 2s resolution


class EntropyConv1DEncoder(nn.Module):
    def __init__(
        self,
        input_length: int = ENTROPY_WINDOW_LENGTH,
        output_dim: int = 64,
        num_filters: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.conv_3 = nn.Conv1d(1, num_filters, kernel_size=3, padding=1)
        self.conv_7 = nn.Conv1d(1, num_filters, kernel_size=7, padding=3)
        self.conv_15 = nn.Conv1d(1, num_filters, kernel_size=15, padding=7)

        se_in = num_filters * 3
        self.se_squeeze = nn.Linear(se_in, se_in // 4)
        self.se_excite = nn.Linear(se_in // 4, se_in)
        self.global_pool = nn.AdaptiveAvgPool1d(1)

        self.output_projection = nn.Linear(se_in, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)
        self.relu = nn.ReLU()

    def forward(self, entropy_series: torch.Tensor) -> torch.Tensor:
        """entropy_series: [B, L] → [B, 64]"""
        if entropy_series.dim() == 1:
            entropy_series = entropy_series.unsqueeze(0)
        x = entropy_series.unsqueeze(1)                  # [B,1,L]
        c3 = self.relu(self.conv_3(x))
        c7 = self.relu(self.conv_7(x))
        c15 = self.relu(self.conv_15(x))
        multi = torch.cat([c3, c7, c15], dim=1)          # [B,3F,L]
        pooled = self.global_pool(multi).squeeze(-1)     # [B,3F]

        se = self.relu(self.se_squeeze(pooled))
        se = torch.sigmoid(self.se_excite(se))
        recal = pooled * se

        emb = self.layer_norm(self.output_projection(recal))
        emb = self.dropout(emb)
        return emb
