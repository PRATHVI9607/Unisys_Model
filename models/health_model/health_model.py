"""
HealthModel — KubeHeal v4 end-to-end Health Model wrapper.
==========================================================
GATv2(YAML) + BiLSTM(metrics) → cross-attention fusion → output head.

forward(graph, metrics) → dict:
    risk_score [B,1], label_logits [B,4], health_embedding [B,128],
    node_importance [N], fusion_attn
"""

from typing import Dict, Optional

import torch
import torch.nn as nn
from torch_geometric.data import Data

from .yaml_gat_encoder import YAMLGATEncoder
from .metric_bilstm_encoder import MetricBiLSTMEncoder, NUM_METRICS, INPUT_SEQUENCE_LENGTH
from .health_fusion_attention import HealthFusionAttention
from .health_output_head import HealthOutputHead, HEALTH_LABELS


class HealthModel(nn.Module):
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        cfg = config or {}
        self.yaml_encoder = YAMLGATEncoder(
            hidden_dim=cfg.get("gat_hidden_dim", 128),
            output_dim=cfg.get("yaml_dim", 128),
            num_heads=cfg.get("gat_heads", 8),
            num_layers=cfg.get("gat_layers", 3),
        )
        self.metric_encoder = MetricBiLSTMEncoder(
            hidden_dim=cfg.get("lstm_hidden_dim", 64),
            output_dim=cfg.get("metric_dim", 64),
            num_layers=cfg.get("lstm_layers", 2),
        )
        self.fusion = HealthFusionAttention(
            yaml_dim=cfg.get("yaml_dim", 128),
            metric_dim=cfg.get("metric_dim", 64),
            fused_dim=cfg.get("fused_dim", 128),
        )
        self.output_head = HealthOutputHead(fused_dim=cfg.get("fused_dim", 128))
        self.labels = HEALTH_LABELS

    def forward(self, graph: Data, metrics: torch.Tensor) -> Dict:
        yaml_emb, node_importance = self.yaml_encoder(graph)   # [128], [N]
        metric_emb = self.metric_encoder(metrics)              # [B,64]
        if yaml_emb.dim() == 1:
            yaml_emb = yaml_emb.unsqueeze(0)                   # [1,128]
        fused, fusion_attn = self.fusion(yaml_emb, metric_emb) # [B,128]
        label_logits, risk = self.output_head(fused)
        return {
            "risk_score": risk,                # [B,1]
            "label_logits": label_logits,      # [B,4]
            "health_embedding": fused,         # [B,128]
            "node_importance": node_importance,# [N]
            "fusion_attn": fusion_attn,
        }

    def forward_export(self, node_ids, edge_index, pos_idx, pos_val, metrics):
        """ONNX-exportable forward: pure-tensor inputs → (logits, risk).
        Graph build stays in Python preprocessing (yaml_diff_to_graph)."""
        yaml_emb = self.yaml_encoder.encode_tensors(node_ids, edge_index, pos_idx, pos_val)
        metric_emb = self.metric_encoder(metrics)
        fused, _ = self.fusion(yaml_emb.unsqueeze(0), metric_emb)
        logits, risk = self.output_head(fused)
        return logits, risk

    def predict(self, graph: Data, metrics: torch.Tensor) -> Dict:
        self.eval()
        with torch.no_grad():
            out = self.forward(graph, metrics)
        probs = torch.softmax(out["label_logits"], dim=-1)[0]
        idx = int(torch.argmax(probs).item())
        return {
            "risk_score": float(out["risk_score"].reshape(-1)[0]),
            "label": self.labels[idx],
            "label_probabilities": {l: float(probs[i]) for i, l in enumerate(self.labels)},
            "health_embedding": out["health_embedding"][0].tolist(),
            "node_importance": out["node_importance"].tolist(),
        }

    def param_count(self) -> int:
        return sum(p.numel() for p in self.parameters())
