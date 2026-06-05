"""
Metric BiLSTM Encoder — KubeHeal v4 Health Model (Section 03.3)
==============================================================
Replaces v3's Mamba SSM. Processes a 60×15 Prometheus metric window into a
64-dim embedding.

Why BiLSTM over Mamba: mamba-ssm needs compiled CUDA kernels (no GPU on
Minikube → CPU fallback 100-200ms/pass = demo-breaking). Our windows are
short (60 steps) so Mamba's O(n) advantage is irrelevant. BiLSTM is CPU-fast
(2-3ms), dependency-free (torch core), and bidirectional — capturing both
leading indicators (CPU rises before latency) and lagging ones (latency stays
high after CPU recovers).
"""

import numpy as np
import torch
import torch.nn as nn

# Torch-free schema lives in metric_schema.py so slim agents can import it
# without pulling torch; re-exported here for backward compatibility.
from models.health_model.metric_schema import (
    METRIC_COLUMNS, NUM_METRICS, INPUT_SEQUENCE_LENGTH,
)


class MetricBiLSTMEncoder(nn.Module):
    def __init__(
        self,
        input_dim: int = NUM_METRICS,
        hidden_dim: int = 64,
        output_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_norm = nn.LayerNorm(input_dim)
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.output_projection = nn.Linear(hidden_dim * 2, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, metrics: torch.Tensor) -> torch.Tensor:
        """metrics: [batch, 60, 15] → [batch, 64]"""
        if metrics.dim() == 2:
            metrics = metrics.unsqueeze(0)
        x = self.input_norm(metrics)
        _, (hn, _) = self.lstm(x)
        forward_final = hn[-2]   # last layer, forward
        backward_final = hn[-1]  # last layer, backward
        combined = torch.cat([forward_final, backward_final], dim=-1)
        emb = self.output_projection(combined)
        emb = self.layer_norm(emb)
        emb = self.dropout(emb)
        return emb


# Shared in-process cache: {(namespace, pod): (np.ndarray[60,15], fetch_time)}
_prometheus_cache: dict = {}
