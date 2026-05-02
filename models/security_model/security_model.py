import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Tuple, Optional


class FalcoTransformerEncoder(nn.Module):
    """
    Transformer encoder for Falco eBPF syscall event sequences.
    Focuses on ransomware detection patterns.
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
        tokens = []
        for i, call in enumerate(syscalls[:self.max_seq_len]):
            syscall_name = call.get("syscall", "unknown").lower()
            token_id = self.syscall_vocab.get(syscall_name, self.syscall_vocab["unknown"])
            tokens.append(token_id)
        
        while len(tokens) < self.max_seq_len:
            tokens.append(0)
        
        return torch.tensor(tokens, dtype=torch.long)
    
    def forward(self, syscalls: List[Dict]) -> torch.Tensor:
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
    Designed for detecting encrypted files.
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
        
        self.se = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Linear(hidden_channels * 2, hidden_channels // 2),
            nn.ReLU(),
            nn.Linear(hidden_channels // 2, hidden_channels * 2),
            nn.Sigmoid()
        )
        
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.output_proj = nn.Linear(hidden_channels * 2, output_dim)
        self.dropout = nn.Dropout(dropout)
        self.norm = nn.LayerNorm(output_dim)
    
    def forward(self, entropy_series: torch.Tensor) -> torch.Tensor:
        if entropy_series.dim() == 1:
            entropy_series = entropy_series.unsqueeze(0)
        if entropy_series.dim() == 2:
            entropy_series = entropy_series.unsqueeze(1)
        
        x = torch.relu(self.conv1(entropy_series))
        x = self.dropout(x)
        x = torch.relu(self.conv2(x))
        
        se_weight = self.se(x)
        x = x * se_weight
        
        x = self.pool(x).squeeze(-1)
        x = self.output_proj(x)
        x = self.norm(x)
        
        return x


class FilePatternEncoder(nn.Module):
    """
    Encoder for file write patterns.
    Detects rapid file modification patterns.
    """
    
    def __init__(self, embed_dim: int = 64):
        super().__init__()
        
        self.pattern_fc = nn.Sequential(
            nn.Linear(10, embed_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(embed_dim, embed_dim)
        )
    
    def forward(self, pattern_features: torch.Tensor) -> torch.Tensor:
        if pattern_features.dim() == 1:
            pattern_features = pattern_features.unsqueeze(0)
        
        x = self.pattern_fc(pattern_features)
        
        return x


class SecurityModelOutputHead(nn.Module):
    """
    Output head for ransomware/security detection.
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


class SecurityModel(nn.Module):
    """
    Security/Ransomware Detection Model.
    Uses syscalls + entropy + file patterns to detect ransomware.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        
        if config is None:
            config = {
                "transformer": {"vocab_size": 256, "embed_dim": 64, "num_heads": 4, "num_layers": 2},
                "conv1d": {"input_channels": 1, "hidden_channels": 32, "output_dim": 64},
                "pattern": {"embed_dim": 64},
                "output": {"num_classes": 3}
            }
        
        self.events_encoder = FalcoTransformerEncoder(**config["transformer"])
        self.entropy_encoder = EntropyConv1DEncoder(**config["conv1d"])
        self.pattern_encoder = FilePatternEncoder(**config["pattern"])
        
        self.fusion_proj = nn.Linear(64 + 64 + 64, 192)
        self.output = SecurityModelOutputHead(input_dim=192, num_classes=config["output"]["num_classes"])
        
        self.class_names = ["benign", "ransomware-critical", "sec-medium"]
    
    def forward(
        self,
        syscalls: Optional[List[Dict]] = None,
        entropy_series: Optional[torch.Tensor] = None,
        file_patterns: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        embeddings = {}
        
        if syscalls is not None:
            embeddings["events"] = self.events_encoder(syscalls)
        
        if entropy_series is not None:
            embeddings["entropy"] = self.entropy_encoder(entropy_series)
        
        if file_patterns is not None:
            embeddings["patterns"] = self.pattern_encoder(file_patterns)
        
        if not embeddings:
            raise ValueError("At least one input required")
        
        emb_list = []
        for name in ["events", "entropy", "patterns"]:
            if name in embeddings:
                emb_list.append(embeddings[name])
            else:
                emb_list.append(torch.zeros(64, device=next(self.parameters()).device if list(self.parameters()) else "cpu"))
        
        fused = torch.cat(emb_list, dim=-1)
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
        syscalls: Optional[List[Dict]] = None,
        entropy_series: Optional[List[float]] = None,
        file_patterns: Optional[List[float]] = None
    ) -> Dict:
        self.eval()
        
        kwargs = {}
        if syscalls is not None:
            kwargs["syscalls"] = syscalls
        if entropy_series is not None:
            kwargs["entropy_series"] = torch.tensor(entropy_series, dtype=torch.float32)
        if file_patterns is not None:
            kwargs["file_patterns"] = torch.tensor(file_patterns, dtype=torch.float32)
        
        with torch.no_grad():
            result = self.forward(**kwargs)
        
        return {
            "risk_score": result["risk_score"].item(),
            "label": result["label"],
            "probabilities": result["probabilities"].tolist()
        }


def create_ransomware_sample(attack_type: str = "ransomware") -> Dict:
    """Create sample data for security model."""
    
    if attack_type == "ransomware":
        syscalls = [
            {"syscall": "write", "path": "/data/file1.txt"},
            {"syscall": "write", "path": "/data/file2.txt"},
            {"syscall": "rename", "path": "/data/file1.txt"},
            {"syscall": "rename", "path": "/data/file2.txt"},
            {"syscall": "ftruncate", "path": "/data/file1.txt"},
        ] + [{"syscall": "write", "path": f"/data/file{i}.txt"} for i in range(5, 100)]
        
        entropy_series = np.random.rand(20).astype(np.float32) * 2 + 6.0
    else:
        syscalls = [
            {"syscall": "read", "path": "/etc/passwd"},
            {"syscall": "stat", "path": "/proc/cpuinfo"},
            {"syscall": "read", "path": "/etc/hosts"},
        ]
        
        entropy_series = np.random.rand(20).astype(np.float32) * 4
    
    file_patterns = [100, 50, 200, 150, 80, 120, 90, 60, 70, 110]
    
    return {
        "syscalls": syscalls,
        "entropy_series": entropy_series.tolist(),
        "file_patterns": file_patterns,
        "label": "ransomware-critical" if attack_type == "ransomware" else "benign"
    }


if __name__ == "__main__":
    print("Testing Security Model...")
    
    model = SecurityModel()
    
    sample = create_ransomware_sample("ransomware")
    result = model.predict(**sample)
    
    print(f"Risk Score: {result['risk_score']:.3f}")
    print(f"Label: {result['label']}")
    print(f"Probabilities: {result['probabilities']}")
    print(f"\nModel architecture: {sum(p.numel() for p in model.parameters()):,} parameters")