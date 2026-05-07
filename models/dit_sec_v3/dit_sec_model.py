import torch
import torch.nn as nn
from torch_geometric.nn import GATConv
from torch_geometric.data import Data
from torch_geometric.utils import add_self_loops
import numpy as np
from typing import Dict, List, Tuple, Optional
import json


class YAMLGATEncoder(nn.Module):
    """
    Graph Attention Network encoder for Kubernetes YAML diffs.
    Parses YAML to attributed graph and encodes parent→child relationships.
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
        self.edge_type_embeddings = nn.Embedding(8, node_dim)
        
        self.convs = nn.ModuleList([
        GATConv(
        node_dim if i == 0 else hidden_dim,
        hidden_dim // heads,
        heads=heads,
        dropout=dropout,
        concat=True
        )
        for i in range(num_layers)
        ])
        
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers)
        ])
        
        self.output_proj = nn.Linear(hidden_dim, 128)
    
    def parse_yaml_to_graph(self, old_spec: Dict, new_spec: Dict) -> Tuple:
        """
        Parse YAML specs to attributed graph.
        Returns: edge_index, node_features, edge_attrs
        """
        nodes = []
        edges = []
        node_idx = {}
        
        def traverse_tree(obj, path="", parent_idx=-1):
            nonlocal node_idx, nodes, edges
            if isinstance(obj, dict):
                for key, value in obj.items():
                    curr_path = f"{path}.{key}" if path else key
                    node_idx[curr_path] = len(nodes)
                    nodes.append({
                        "key": key,
                        "value": str(value)[:50],
                        "path": curr_path
                    })
                    if parent_idx >= 0:
                        edges.append((parent_idx, node_idx[curr_path]))
                    traverse_tree(value, curr_path, node_idx[curr_path])
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    curr_path = f"{path}[{i}]"
                    node_idx[curr_path] = len(nodes)
                    nodes.append({
                        "key": f"[{i}]",
                        "value": str(item)[:50],
                        "path": curr_path
                    })
                    if parent_idx >= 0:
                        edges.append((parent_idx, node_idx[curr_path]))
                    traverse_tree(item, curr_path, node_idx[curr_path])
        
        traverse_tree(old_spec, "old")
        old_base_idx = len(nodes)
        traverse_tree(new_spec, "new")
        
        if not nodes:
            return torch.zeros((1, self.node_dim)), torch.tensor([[0, 0]], dtype=torch.long)
        
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        
        if edge_index.shape[1] == 0:
            edge_index = torch.tensor([[0], [0]], dtype=torch.long)
        
        return nodes, edge_index
    
    def add_positional_tokens(
        self,
        nodes: List[Dict],
        containers_idx: Dict[int, str]
    ) -> List[Dict]:
        """
        Add [CONTAINER_N] positional tokens to each container sub-tree.
        """
        updated_nodes = []
        for node in nodes:
            updated_nodes.append(node)
            
            path = node.get("path", "")
            if "containers" in path:
                match = path.replace("old.", "").replace("new.", "")
                if "[" in match:
                    try:
                        idx = int(match.split("[")[1].split("]")[0])
                        node["positional_token"] = f"[CONTAINER_{idx}]"
                    except:
                        pass
        
        return updated_nodes
    
    def forward(self, old_spec: Dict, new_spec: Dict) -> torch.Tensor:
        """
        Encode YAML diff to 128-dim graph embedding.
        
        Args:
            old_spec: Original K8s spec
            new_spec: Modified K8s spec
            
        Returns:
            graph_embedding: [128] tensor
        """
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
    O(n) complexity for long metric windows.
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
            self.ssm = Mamba2(
                d_model=hidden_dim,
                d_state=16,
                expand_factor=2,
                use_bias=False
            )
        except ImportError:
            self.use_mamba = False
            self.lstm = nn.LSTM(
                hidden_dim,
                hidden_dim,
                num_layers=2,
                batch_first=True,
                dropout=0.1
            )
        
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.output_proj = nn.Linear(hidden_dim, 64)
    
    def forward(self, metrics: torch.Tensor) -> torch.Tensor:
        """
        Encode Prometheus metrics to 64-dim temporal embedding.
        
        Args:
            metrics: [batch, num_steps, input_dim] tensor
                    Example: 5-min window, 15 metrics, 5s resolution
                    
        Returns:
            temporal_embedding: [batch, 64] tensor
        """
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


class FalcoTransformerEncoder(nn.Module):
    """
    Transformer encoder for Falco eBPF syscall event sequences.
    """
    
    def __init__(
        self,
        vocab_size: int = 256,
        embed_dim: int = 64,
        num_heads: int = 4,
        num_layers: int = 2,
        max_seq_len: int = 256,
        dropout: float = 0.1
    ):
        super().__init__()
        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        self.max_seq_len = max_seq_len
        
        self.syscall_vocab = {
            "read": 1, "write": 2, "open": 3, "close": 4,
            "rename": 5, "truncate": 6, "mmap": 7, "mprotect": 8,
            "socket": 9, "connect": 10, "accept": 11, "sendto": 12,
            "recvfrom": 13, "execve": 14, "fork": 15, "clone": 16,
            "kill": 17, "exit": 18, "unlink": 19, "create": 20,
            "stat": 21, "access": 22, "chmod": 23, "chown": 24,
            "getuid": 25, "setuid": 26, "getgid": 27, "setgid": 28,
            "geteuid": 29, "getegid": 30, "setpgid": 31, "getppid": 32,
            "unknown": 0
        }
        
        self.token_embedding = nn.Embedding(vocab_size, embed_dim)
        self.position_embedding = nn.Embedding(max_seq_len, embed_dim)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout,
            batch_first=True,
            activation="gelu"
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        self.output_proj = nn.Linear(embed_dim, 64)
    
    def encode_syscalls(self, syscalls: List[Dict]) -> torch.Tensor:
        """
        Encode syscall sequence to tensor.
        
        Args:
            syscalls: List of {"syscall": str, "timestamp": float, ...}
            
        Returns:
            input_ids: [max_seq_len] tensor
        """
        tokens = []
        for i, call in enumerate(syscalls[:self.max_seq_len]):
            syscall_name = call.get("syscall", "unknown").lower()
            token_id = self.syscall_vocab.get(syscall_name, self.syscall_vocab["unknown"])
            tokens.append(token_id)
        
        while len(tokens) < self.max_seq_len:
            tokens.append(0)
        
        return torch.tensor(tokens, dtype=torch.long)
    
    def forward(self, syscalls: List[Dict]) -> torch.Tensor:
        """
        Encode Falco events to 64-dim event embedding.
        
        Args:
            syscalls: List of syscall events
            
        Returns:
            event_embedding: [64] tensor
        """
        input_ids = self.encode_syscalls(syscalls)
        
        x = self.token_embedding(input_ids)
        
        positions = torch.arange(self.max_seq_len)
        x = x + self.position_embedding(positions)
        
        x = x.unsqueeze(0)
        
        x = self.transformer(x)
        
        x = x.squeeze(0)
        
        x = self.output_proj(x)
        
        pooled = torch.mean(x, dim=0)
        
        return pooled


class EntropyConv1DEncoder(nn.Module):
    """
    Conv1D + Squeeze-Excitation encoder for file entropy series.
    Lightweight CNN for <30 timestep entropy windows.
    """
    
    def __init__(
        self,
        input_channels: int = 1,
        hidden_channels: int = 32,
        output_dim: int = 64,
        dropout: float = 0.1
    ):
        super().__init__()
        
        self.conv1 = nn.Conv1d(input_channels, hidden_channels, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(hidden_channels, hidden_channels * 2, kernel_size=3, padding=1)
        self.conv3 = nn.Conv1d(hidden_channels * 2, hidden_channels * 2, kernel_size=3, padding=1)
        
        self.se_pool = nn.AdaptiveAvgPool1d(1)
        self.se_fc1  = nn.Linear(hidden_channels * 2, hidden_channels // 2)
        self.se_fc2  = nn.Linear(hidden_channels // 2, hidden_channels * 2)
        
        self.pool = nn.AdaptiveMaxPool1d(1)
        
        self.output_proj = nn.Linear(hidden_channels * 2, output_dim)
        
        self.dropout = nn.Dropout(dropout)
        self.norm = nn.LayerNorm(output_dim)
    
    def forward(self, entropy_series: torch.Tensor) -> torch.Tensor:
        """
        Encode entropy timeseries to 64-dim embedding.
        
        Args:
            entropy_series: [batch, num_timesteps] or [num_timesteps] tensor
                         Example: 20s window of entropy values
                         
        Returns:
            entropy_embedding: [output_dim] tensor
        """
        if entropy_series.dim() == 1:
            entropy_series = entropy_series.unsqueeze(0)
        
        if entropy_series.dim() == 2:
            entropy_series = entropy_series.unsqueeze(1)
        
        x = torch.relu(self.conv1(entropy_series))
        x = self.dropout(x)
        
        x = torch.relu(self.conv2(x))
        
        se = self.se_pool(x).squeeze(-1)
        se = torch.relu(self.se_fc1(se))
        se = torch.sigmoid(self.se_fc2(se))
        x  = x * se.unsqueeze(-1)
        
        x = self.pool(x).squeeze(-1)
        
        x = self.output_proj(x)
        x = self.norm(x)
        
        return x


class MultiHeadCrossAttentionFusion(nn.Module):
    """
    Multi-Head Cross-Attention for fusing 4 modality embeddings.
    """
    
    def __init__(
        self,
        embedding_dims: Dict[str, int],
        fusion_dim: int = 192,
        num_heads: int = 3,
        dropout: float = 0.1
    ):
        super().__init__()
        self.embedding_dims = embedding_dims
        self.fusion_dim = fusion_dim
        self.num_heads = num_heads
        
        self.slot_dim = fusion_dim // 4
        self.projections = nn.ModuleDict({
            name: nn.Linear(dim, self.slot_dim)
            for name, dim in embedding_dims.items()
        })
        
        self.cross_attention = nn.MultiheadAttention(
            embed_dim=fusion_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True
        )
        
        self.fusion_norm = nn.LayerNorm(fusion_dim)
        self.ffn = nn.Sequential(
            nn.Linear(fusion_dim, fusion_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(fusion_dim * 2, fusion_dim),
            nn.Dropout(dropout)
        )
    
    def forward(
        self,
        embeddings: Dict[str, torch.Tensor]
    ) -> torch.Tensor:
        """
        Fuse 4 modality embeddings via cross-attention.
        
        Args:
            embeddings: Dict of {"yaml": [...], "metrics": [...], "events": [...], "entropy": [...]}
            
        Returns:
            fused: [fusion_dim] tensor
        """
        device = next(iter(embeddings.values())).device

        projected = []
        for name in ["yaml", "metrics", "events", "entropy"]:
            if name in embeddings and name in self.projections:
                emb = embeddings[name]
                if emb.dim() > 1:
                    emb = emb.squeeze()
                if emb.dim() == 0:
                    emb = emb.unsqueeze(0)
                p = self.projections[name](emb)   # [slot_dim]
            else:
                p = torch.zeros(self.slot_dim, device=device)
            projected.append(p)

        # [4, slot_dim] -> [1, 1, fusion_dim=192]
        stacked  = torch.stack(projected, dim=0)         # [4, 48]
        fused_in = stacked.view(1, 1, self.fusion_dim)   # [1, 1, 192]

        fused, _ = self.cross_attention(fused_in, fused_in, fused_in)  # [1, 1, 192]
        fused    = fused.squeeze(0).squeeze(0)           # [192]
        residual = fused_in.squeeze(0).squeeze(0)        # [192]

        fused = self.fusion_norm(fused + residual)
        fused = self.ffn(fused)

        return fused


class DITSecOutputHead(nn.Module):
    """
    Output head for risk score and classification.
    """
    
    def __init__(
        self,
        input_dim: int = 192,
        num_classes: int = 5,
        dropout: float = 0.1
    ):
        super().__init__()
        self.num_classes = num_classes
        
        self.classifier = nn.Sequential(
            nn.Linear(input_dim, input_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(input_dim // 2, input_dim // 4),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(input_dim // 4, num_classes)
        )
        
        self.risk_scorer = nn.Sequential(
            nn.Linear(input_dim, input_dim // 2),
            nn.GELU(),
            nn.Linear(input_dim // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(
        self,
        fused_embedding: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Generate risk score and classification.
        
        Args:
            fused_embedding: [input_dim] tensor from MHCA fusion
            
        Returns:
            risk_score: [1] tensor in [0, 1]
            logits: [num_classes] tensor for classification
        """
        risk_score = self.risk_scorer(fused_embedding)
        
        logits = self.classifier(fused_embedding)
        
        return risk_score.squeeze(-1), logits


class DITSecModel(nn.Module):
    """
    Full DIT-Sec v3.0 model: GNN + Mamba + Transformer + Conv1D + MHCA
    """
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        
        if config is None:
            config = {
                "gat": {"node_dim": 64, "hidden_dim": 128, "num_layers": 3, "heads": 4},
                "mamba": {"input_dim": 15, "hidden_dim": 64, "num_steps": 60},
                "transformer": {"vocab_size": 256, "embed_dim": 64, "num_heads": 4, "num_layers": 2},
                "conv1d": {"input_channels": 1, "hidden_channels": 32, "output_dim": 64},
                "fusion": {"num_heads": 3},
                "output": {"num_classes": 5}
            }
        
        self.yaml_encoder = YAMLGATEncoder(**config["gat"])
        self.metrics_encoder = PrometheusMambaEncoder(**config["mamba"])
        self.events_encoder = FalcoTransformerEncoder(**config["transformer"])
        self.entropy_encoder = EntropyConv1DEncoder(**config["conv1d"])
        
        embedding_dims = {
            "yaml": 128,
            "metrics": 64,
            "events": 64,
            "entropy": 64
        }
        self.fusion = MultiHeadCrossAttentionFusion(
            embedding_dims=embedding_dims,
            num_heads=config["fusion"]["num_heads"]
        )
        self.output = DITSecOutputHead(
            input_dim=192,
            num_classes=config["output"]["num_classes"]
        )
        
        self.class_names = [
            "benign",
            "health-critical",
            "ransomware-critical",
            "sec-medium",
            "perf-risk"
        ]
    
    def forward(
        self,
        old_spec: Optional[Dict] = None,
        new_spec: Optional[Dict] = None,
        metrics: Optional[torch.Tensor] = None,
        syscalls: Optional[List[Dict]] = None,
        entropy_series: Optional[torch.Tensor] = None,
        return_embeddings: bool = False
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through DIT-Sec model.
        
        Args:
            old_spec: Original K8s spec (YAML)
            new_spec: Modified K8s spec (YAML)
            metrics: Prometheus metrics tensor
            syscalls: Falco syscall events
            entropy_series: File entropy series
            return_embeddings: If True, return intermediate embeddings
            
        Returns:
            Dict with keys: "risk_score", "label", "logits", optional "embeddings"
        """
        embeddings = {}
        
        if old_spec is not None and new_spec is not None:
            embeddings["yaml"] = self.yaml_encoder(old_spec, new_spec)
        
        if metrics is not None:
            embeddings["metrics"] = self.metrics_encoder(metrics)
        
        if syscalls is not None:
            embeddings["events"] = self.events_encoder(syscalls)
        
        if entropy_series is not None:
            embeddings["entropy"] = self.entropy_encoder(entropy_series)
        
        if not embeddings:
            raise ValueError("At least one input modality required")
        
        fused = self.fusion(embeddings)
        
        risk_score, logits = self.output(fused)
        
        probs = torch.softmax(logits, dim=-1)
        label_idx = torch.argmax(probs, dim=-1)
        label = self.class_names[label_idx]
        
        result = {
            "risk_score": risk_score,
            "label": label,
            "logits": logits,
            "probabilities": probs
        }
        
        if return_embeddings:
            result["embeddings"] = embeddings
        
        return result
    
    def predict(
        self,
        old_spec: Optional[Dict] = None,
        new_spec: Optional[Dict] = None,
        metrics: Optional[List] = None,
        syscalls: Optional[List[Dict]] = None,
        entropy_series: Optional[List[float]] = None
    ) -> Dict:
        """
        Convenience method for inference with Python types.
        """
        self.eval()
        
        with torch.no_grad():
            kwargs = {}
            
            if old_spec is not None and new_spec is not None:
                kwargs["old_spec"] = old_spec
                kwargs["new_spec"] = new_spec
            
            if metrics is not None:
                metrics_tensor = torch.tensor(metrics, dtype=torch.float32)
                kwargs["metrics"] = metrics_tensor
            
            if syscalls is not None:
                kwargs["syscalls"] = syscalls
            
            if entropy_series is not None:
                entropy_tensor = torch.tensor(entropy_series, dtype=torch.float32)
                kwargs["entropy_series"] = entropy_tensor
            
            result = self.forward(**kwargs)
            
            return {
                "risk_score": result["risk_score"].item(),
                "label": result["label"],
                "probabilities": result["probabilities"].tolist()
            }


def create_sample_data(include_all_modalities: bool = False) -> Dict:
    """Create sample data for testing."""
    old_spec = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:latest",
                            "resources": {
                                "limits": {"cpu": "500m", "memory": "512Mi"},
                                "requests": {"cpu": "250m", "memory": "256Mi"}
                            }
                        }
                    ]
                }
            }
        }
    }
    
    new_spec = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:latest",
                            "resources": {
                                "limits": {"cpu": "50m", "memory": "512Mi"},
                                "requests": {"cpu": "250m", "memory": "256Mi"}
                            }
                        }
                    ]
                }
            }
        }
    }
    
    metrics = np.random.randn(60, 15).astype(np.float32)
    
    syscalls = [
        {"syscall": "write", "timestamp": 0.0, "path": "/data/file1.txt"},
        {"syscall": "write", "timestamp": 0.1, "path": "/data/file2.txt"},
        {"syscall": "rename", "timestamp": 0.2, "path": "/data/file1.txt"},
    ]
    
    entropy_series = np.random.rand(20).astype(np.float32) * 8
    
    if include_all_modalities:
        return {
            "old_spec": old_spec,
            "new_spec": new_spec,
            "metrics": metrics,
            "syscalls": syscalls,
            "entropy_series": entropy_series
        }
    
    return {
        "old_spec": old_spec,
        "new_spec": new_spec
    }


if __name__ == "__main__":
    print("Testing DIT-Sec v3.0 Model...")
    
    model = DITSecModel()
    
    sample = create_sample_data(include_all_modalities=True)
    
    result = model.predict(**sample)
    
    print(f"Risk Score: {result['risk_score']:.3f}")
    print(f"Label: {result['label']}")
    print(f"Probabilities: {result['probabilities']}")
    
    print("\nModel architecture:")
    print(f"  YAML Encoder: {model.yaml_encoder.__class__.__name__}")
    print(f"  Metrics Encoder: {model.metrics_encoder.__class__.__name__}")
    print(f"  Events Encoder: {model.events_encoder.__class__.__name__}")
    print(f"  Entropy Encoder: {model.entropy_encoder.__class__.__name__}")
    print(f"  Fusion: {model.fusion.__class__.__name__}")
    print(f"  Output: {model.output.__class__.__name__}")
