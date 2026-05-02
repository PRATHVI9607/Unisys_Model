import torch
import torch.nn as nn
from torch_geometric.nn import GATConv
from torch_geometric.data import Data
from torch_geometric.utils import add_self_loops
import numpy as np
from typing import Dict, List, Tuple, Optional


class YAMLGATEncoder(nn.Module):
    """
    Graph Attention Network encoder for Kubernetes YAML diffs.
    Focuses on config drift detection from Deployment spec changes.
    """
    
    def __init__(
        self,
        node_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 3,
        heads: int = 4,
        dropout: float = 0.1
    ):
        super().__init__()
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.heads = heads
        
        self.node_embeddings = nn.Embedding(512, node_dim)
        
        self.convs = nn.ModuleList([
            GATConv(node_dim, hidden_dim // heads, heads=heads, dropout=dropout, concat=True)
            for _ in range(num_layers)
        ])
        
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers)
        ])
        
        self.output_proj = nn.Linear(hidden_dim, 128)
    
    def parse_yaml_to_graph(self, old_spec: Dict, new_spec: Dict) -> Tuple:
        nodes = []
        edges = []
        node_idx = {}
        
        def traverse_tree(obj, path="", parent_idx=-1):
            nonlocal node_idx, nodes, edges
            if isinstance(obj, dict):
                for key, value in obj.items():
                    curr_path = f"{path}.{key}" if path else key
                    node_idx[curr_path] = len(nodes)
                    nodes.append({"key": key, "value": str(value)[:50], "path": curr_path})
                    if parent_idx >= 0:
                        edges.append((parent_idx, node_idx[curr_path]))
                    traverse_tree(value, curr_path, node_idx[curr_path])
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    curr_path = f"{path}[{i}]"
                    node_idx[curr_path] = len(nodes)
                    nodes.append({"key": f"[{i}]", "value": str(item)[:50], "path": curr_path})
                    if parent_idx >= 0:
                        edges.append((parent_idx, node_idx[curr_path]))
                    traverse_tree(item, curr_path, node_idx[curr_path])
        
        traverse_tree(old_spec, "old")
        traverse_tree(new_spec, "new")
        
        if not nodes:
            return [], torch.tensor([[0], [0]], dtype=torch.long)
        
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        if edge_index.shape[1] == 0:
            edge_index = torch.tensor([[0], [0]], dtype=torch.long)
        
        return nodes, edge_index
    
    def forward(self, old_spec: Dict, new_spec: Dict) -> torch.Tensor:
        nodes, edge_index = self.parse_yaml_to_graph(old_spec, new_spec)
        
        if not nodes:
            return torch.zeros(128, device=self.node_embeddings.weight.device)
        
        num_nodes = len(nodes)
        node_ids = [hash(n["key"] + n["value"]) % 512 for n in nodes]
        x = self.node_embeddings(torch.tensor(node_ids, device=self.node_embeddings.weight.device))
        
        edge_index, _ = add_self_loops(edge_index, num_nodes=num_nodes)
        
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = self.layer_norms[i](x)
            x = torch.relu(x)
        
        x = self.output_proj(x)
        pooled = torch.mean(x, dim=0)
        
        return pooled


class PrometheusMambaEncoder(nn.Module):
    """
    State Space Model encoder for Prometheus metrics.
    Designed for health/performance monitoring.
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
        
        try:
            from mamba_ssm import Mamba2
            self.use_mamba = True
            self.ssm = Mamba2(d_model=hidden_dim, d_state=16, expand_factor=2, use_bias=False)
        except ImportError:
            self.use_mamba = False
            self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers=2, batch_first=True, dropout=0.1)
        
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.output_proj = nn.Linear(hidden_dim, 64)
    
    def forward(self, metrics: torch.Tensor) -> torch.Tensor:
        batch_size = metrics.shape[0]
        x = self.input_proj(metrics)
        
        if self.use_mamba:
            x = x.permute(1, 0, 2)
            outputs = []
            for t in range(x.shape[0]):
                out = self.ssm(x[t:t+1])
                outputs.append(out)
            x = torch.cat(outputs, dim=0)
            x = x.permute(1, 0, 2)
        else:
            x, _ = self.lstm(x)
        
        x = self.output_proj(x)
        last_step = x[:, -1, :]
        
        return last_step


class HealthModelOutputHead(nn.Module):
    """
    Output head for health/config drift detection.
    """
    
    def __init__(
        self,
        input_dim: int = 192,
        num_classes: int = 3,
        dropout: float = 0.1
    ):
        super().__init__()
        self.num_classes = num_classes
        
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
    
    def forward(self, fused_embedding: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        risk_score = self.risk_scorer(fused_embedding).squeeze(-1)
        logits = self.classifier(fused_embedding)
        return risk_score, logits


class HealthModel(nn.Module):
    """
    Health/Drift Detection Model.
    Uses YAML diffs + Prometheus metrics to detect configuration drift.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        
        if config is None:
            config = {
                "gat": {"node_dim": 64, "hidden_dim": 128, "num_layers": 3, "heads": 4},
                "mamba": {"input_dim": 15, "hidden_dim": 64, "num_steps": 60},
                "output": {"num_classes": 3}
            }
        
        self.yaml_encoder = YAMLGATEncoder(**config["gat"])
        self.metrics_encoder = PrometheusMambaEncoder(**config["mamba"])
        
        self.fusion_proj = nn.Linear(128 + 64, 192)
        self.output = HealthModelOutputHead(input_dim=192, num_classes=config["output"]["num_classes"])
        
        self.class_names = ["benign", "health-critical", "perf-risk"]
    
    def forward(
        self,
        old_spec: Optional[Dict] = None,
        new_spec: Optional[Dict] = None,
        metrics: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        embeddings = {}
        
        if old_spec is not None and new_spec is not None:
            embeddings["yaml"] = self.yaml_encoder(old_spec, new_spec)
        
        if metrics is not None:
            embeddings["metrics"] = self.metrics_encoder(metrics)
        
        if not embeddings:
            raise ValueError("At least one input required")
        
        if "yaml" in embeddings and "metrics" in embeddings:
            fused = torch.cat([embeddings["yaml"], embeddings["metrics"]], dim=-1)
        elif "yaml" in embeddings:
            fused = torch.cat([embeddings["yaml"], torch.zeros(64, device=embeddings["yaml"].device)], dim=-1)
        elif "metrics" in embeddings:
            fused = torch.cat([torch.zeros(128, device=embeddings["metrics"].device), embeddings["metrics"]], dim=-1)
        
        fused = self.fusion_proj(fused)
        
        risk_score, logits = self.output(fused)
        
        probs = torch.softmax(logits, dim=-1)
        label_idx = torch.argmax(probs, dim=-1)
        label = self.class_names[label_idx]
        
        return {
            "risk_score": risk_score,
            "label": label,
            "logits": logits,
            "probabilities": probs
        }
    
    def predict(
        self,
        old_spec: Optional[Dict] = None,
        new_spec: Optional[Dict] = None,
        metrics: Optional[List] = None
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
            "risk_score": result["risk_score"].item(),
            "label": result["label"],
            "probabilities": result["probabilities"].tolist()
        }


def create_health_sample(drift_type: str = "cpu_drift") -> Dict:
    """Create sample data for health model."""
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
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                            "requests": {"cpu": "250m", "memory": "256Mi"}
                        }
                    }]
                }
            }
        }
    }
    
    new_spec = {"spec": {"template": {"spec": {"containers": [{}]}}}
    new_spec["spec"]["template"]["spec"]["containers"][0] = old_spec["spec"]["template"]["spec"]["containers"][0].copy()
    
    if drift_type == "cpu_drift":
        new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "50m"
    elif drift_type == "memory_drift":
        new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = "64Mi"
    
    metrics = np.random.randn(60, 15).astype(np.float32) * 0.2
    
    return {
        "old_spec": old_spec,
        "new_spec": new_spec,
        "metrics": metrics,
        "label": "health-critical" if drift_type == "cpu_drift" else "perf-risk"
    }


if __name__ == "__main__":
    print("Testing Health Model...")
    
    model = HealthModel()
    
    sample = create_health_sample("cpu_drift")
    result = model.predict(**sample)
    
    print(f"Risk Score: {result['risk_score']:.3f}")
    print(f"Label: {result['label']}")
    print(f"Probabilities: {result['probabilities']}")
    print(f"\nModel architecture: {sum(p.numel() for p in model.parameters()):,} parameters")