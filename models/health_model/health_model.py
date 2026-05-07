import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Tuple, Optional


class YAMLAttentionEncoder(nn.Module):
    """
    Pure-PyTorch attention-based encoder for Kubernetes YAML diffs.
    Replaces GATConv (torch_geometric) — no extra dependencies needed.
    Always outputs a fixed 128-dim vector regardless of spec size.
    """

    def __init__(
        self,
        node_dim: int = 64,
        hidden_dim: int = 128,
        num_heads: int = 4,
        dropout: float = 0.1
    ):
        super().__init__()
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim

        # Token embedding for hashed key+value strings
        self.node_embeddings = nn.Embedding(512, node_dim)

        # Multi-head self-attention over node tokens
        self.attn = nn.MultiheadAttention(
            embed_dim=node_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True
        )
        self.norm1 = nn.LayerNorm(node_dim)

        # Feed-forward
        self.ff = nn.Sequential(
            nn.Linear(node_dim, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, node_dim)
        )
        self.norm2 = nn.LayerNorm(node_dim)

        # Project pooled representation to exactly 128 dims
        self.output_proj = nn.Linear(node_dim, 128)

    # ------------------------------------------------------------------
    # YAML → flat node list
    # ------------------------------------------------------------------
    def _yaml_to_nodes(self, old_spec: Dict, new_spec: Dict) -> List[Dict]:
        nodes = []

        def traverse(obj, path="", prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    curr = f"{prefix}{path}.{k}" if path else f"{prefix}{k}"
                    nodes.append({"key": str(k), "value": str(v)[:50]})
                    traverse(v, curr, prefix)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    curr = f"{prefix}{path}[{i}]"
                    nodes.append({"key": f"[{i}]", "value": str(item)[:50]})
                    traverse(item, curr, prefix)

        traverse(old_spec, prefix="old_")
        traverse(new_spec, prefix="new_")

        # Guarantee at least one node
        if not nodes:
            nodes = [{"key": "empty", "value": "none"}]

        return nodes

    # ------------------------------------------------------------------
    # Forward — always returns shape (128,)
    # ------------------------------------------------------------------
    def forward(self, old_spec: Dict, new_spec: Dict) -> torch.Tensor:
        device = self.node_embeddings.weight.device
        nodes = self._yaml_to_nodes(old_spec, new_spec)

        # Node IDs → embeddings  shape: (1, num_nodes, node_dim)
        node_ids = torch.tensor(
            [hash(n["key"] + n["value"]) % 512 for n in nodes],
            dtype=torch.long, device=device
        )
        x = self.node_embeddings(node_ids).unsqueeze(0)   # (1, N, node_dim)

        # Self-attention + residual
        attn_out, _ = self.attn(x, x, x)
        x = self.norm1(x + attn_out)

        # Feed-forward + residual
        x = self.norm2(x + self.ff(x))

        # Mean-pool over nodes → (node_dim,)
        pooled = x.squeeze(0).mean(dim=0)

        # Project to 128
        return self.output_proj(pooled)   # (128,)


class PrometheusMambaEncoder(nn.Module):
    """
    LSTM-based encoder for Prometheus metrics (Mamba fallback).
    Always outputs shape (64,).
    """

    def __init__(
        self,
        input_dim: int = 15,
        hidden_dim: int = 64,
        num_steps: int = 60
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_steps = num_steps

        # Try Mamba, fall back to LSTM silently
        try:
            from mamba_ssm import Mamba2
            self.use_mamba = True
            self.ssm = Mamba2(d_model=hidden_dim, d_state=16, expand_factor=2, use_bias=False)
        except ImportError:
            self.use_mamba = False
            self.lstm = nn.LSTM(
                hidden_dim, hidden_dim,
                num_layers=2, batch_first=True, dropout=0.1
            )

        self.input_proj  = nn.Linear(input_dim, hidden_dim)
        self.output_proj = nn.Linear(hidden_dim, 64)

    def forward(self, metrics: torch.Tensor) -> torch.Tensor:
        """
        Args:
            metrics: shape (60, 15)  — single sample, no batch dim
        Returns:
            shape (64,)
        """
        # Add batch dim → (1, 60, 15)
        if metrics.dim() == 2:
            metrics = metrics.unsqueeze(0)

        x = self.input_proj(metrics)          # (1, 60, hidden_dim)

        if self.use_mamba:
            x = x.permute(1, 0, 2)
            outputs = [self.ssm(x[t:t+1]) for t in range(x.shape[0])]
            x = torch.cat(outputs, dim=0).permute(1, 0, 2)
        else:
            x, _ = self.lstm(x)               # (1, 60, hidden_dim)

        x = self.output_proj(x)               # (1, 60, 64)
        last = x[:, -1, :].squeeze(0)         # (64,)
        return last


class HealthModelOutputHead(nn.Module):
    """
    Classification + risk-scoring head.
    input_dim must match fusion output = 192.
    """

    def __init__(
        self,
        input_dim: int = 192,
        num_classes: int = 3,
        dropout: float = 0.1
    ):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(input_dim, input_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(input_dim // 2, num_classes)
        )
        self.risk_scorer = nn.Sequential(
            nn.Linear(input_dim, input_dim // 2),
            nn.GELU(),
            nn.Linear(input_dim // 2, 1),
            nn.Sigmoid()
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.risk_scorer(x).squeeze(-1), self.classifier(x)


class HealthModel(nn.Module):
    """
    Health/Drift Detection Model.
    YAML encoder (128) + Metrics encoder (64) → fused (192) → 3-class output.
    No torch_geometric dependency.
    """

    def __init__(self, config: Optional[Dict] = None):
        super().__init__()

        if config is None:
            config = {
                "gat":    {"node_dim": 64, "hidden_dim": 128, "num_heads": 4},
                "mamba":  {"input_dim": 15, "hidden_dim": 64, "num_steps": 60},
                "output": {"num_classes": 3}
            }

        self.yaml_encoder    = YAMLAttentionEncoder(**config["gat"])
        self.metrics_encoder = PrometheusMambaEncoder(**config["mamba"])

        # 128 (yaml) + 64 (metrics) = 192
        self.fusion_proj = nn.Linear(128 + 64, 192)
        self.output      = HealthModelOutputHead(
            input_dim=192,
            num_classes=config["output"]["num_classes"]
        )

        self.class_names = ["benign", "health-critical", "perf-risk"]

    def forward(
        self,
        old_spec: Optional[Dict]         = None,
        new_spec: Optional[Dict]         = None,
        metrics:  Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:

        device = next(self.parameters()).device

        # --- YAML branch: always (128,) ---
        if old_spec is not None and new_spec is not None:
            yaml_emb = self.yaml_encoder(old_spec, new_spec)   # (128,)
        else:
            yaml_emb = torch.zeros(128, device=device)

        # --- Metrics branch: always (64,) ---
        if metrics is not None:
            if metrics.dim() == 2:                             # (60, 15)
                metrics = metrics.to(device)
            metrics_emb = self.metrics_encoder(metrics)        # (64,)
        else:
            metrics_emb = torch.zeros(64, device=device)

        # --- Fusion: (192,) ---
        fused = torch.cat([yaml_emb, metrics_emb], dim=-1)    # (192,)
        fused = self.fusion_proj(fused)                        # (192,)

        risk_score, logits = self.output(fused)

        probs     = torch.softmax(logits, dim=-1)
        label_idx = torch.argmax(probs, dim=-1).item()
        label     = self.class_names[label_idx]

        return {
            "risk_score":    risk_score,
            "label":         label,
            "logits":        logits,
            "probabilities": probs
        }

    def predict(
        self,
        old_spec: Optional[Dict] = None,
        new_spec: Optional[Dict] = None,
        metrics:  Optional[List] = None
    ) -> Dict:
        self.eval()
        kwargs = {}
        if old_spec is not None and new_spec is not None:
            kwargs["old_spec"] = old_spec
            kwargs["new_spec"] = new_spec
        if metrics is not None:
            kwargs["metrics"] = torch.tensor(metrics, dtype=torch.float32)
        with torch.no_grad():
            result = self.forward(**kwargs)
        return {
            "risk_score":    result["risk_score"].item(),
            "label":         result["label"],
            "probabilities": result["probabilities"].tolist()
        }


# ---------------------------------------------------------------------------
# Quick smoke test
# ---------------------------------------------------------------------------
def create_health_sample(drift_type: str = "cpu_drift") -> Dict:
    old_spec = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": "nginx:latest",
                        "resources": {
                            "limits":   {"cpu": "500m", "memory": "512Mi"},
                            "requests": {"cpu": "250m", "memory": "256Mi"}
                        }
                    }]
                }
            }
        }
    }
    import copy
    new_spec = copy.deepcopy(old_spec)
    if drift_type == "cpu_drift":
        new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "50m"
    elif drift_type == "memory_drift":
        new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = "64Mi"

    metrics = np.random.randn(60, 15).astype(np.float32) * 0.2
    return {
        "old_spec": old_spec,
        "new_spec": new_spec,
        "metrics":  metrics,
        "label":    "health-critical" if drift_type == "cpu_drift" else "perf-risk"
    }


if __name__ == "__main__":
    print("Testing Health Model (no torch_geometric)...")
    model = HealthModel()
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")

    sample = create_health_sample("cpu_drift")
    result = model.predict(
        old_spec=sample["old_spec"],
        new_spec=sample["new_spec"],
        metrics=sample["metrics"]
    )
    print(f"Risk Score:    {result['risk_score']:.3f}")
    print(f"Label:         {result['label']}")
    print(f"Probabilities: {result['probabilities']}")
    print("✅ Smoke test passed.")