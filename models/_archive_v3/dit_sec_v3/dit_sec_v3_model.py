"""
DIT-Sec v3 — GNN + Mamba Hybrid Architecture
============================================
Exact architecture from KubeHeal PRD v3:

  YAML Diff      → GAT (3 layers, PyG GATConv)         → 128-dim
  Prom Metrics   → Mamba SSM (pure-PyTorch, O(n))      → 64-dim
  Falco Events   → Transformer Encoder (4h × 2L)       → 64-dim
  Entropy Series → Conv1D + Squeeze-Excitation          → 64-dim
                 → MHCA Fusion (3 heads × 64-dim slice)
                 → MLP Output Head
                 → risk_score [0,1] + label + CI
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv
from torch_geometric.data import Data
from torch_geometric.utils import add_self_loops
import numpy as np
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────
# 1. YAML Diff → Graph Attention Network (3 layers, 128-dim)
# ─────────────────────────────────────────────────────────────

class YAMLGATEncoder(nn.Module):
    """
    K8s YAML spec parsed to attributed AST graph.
    Nodes = spec fields, Edges = parent→child + sibling.
    GAT (3 layers, 4 heads each) → 128-dim graph embedding.
    Positional tokens [CONTAINER_0], [CONTAINER_1], … prevent
    container-index collapse (Loophole 7 fix).
    """

    VOCAB      = 512   # hash bucket for key+value strings
    CONTAINER_TOKENS = 16  # supports up to 16 containers

    def __init__(
        self,
        node_dim:   int = 64,
        hidden_dim: int = 128,
        num_layers: int = 3,
        heads:      int = 4,
        dropout:    float = 0.1,
    ):
        super().__init__()
        self.node_dim   = node_dim
        self.hidden_dim = hidden_dim
        self.heads      = heads

        # Node feature embedding
        self.node_embed = nn.Embedding(self.VOCAB, node_dim)
        # Positional token for container index (Loophole 7)
        self.pos_embed  = nn.Embedding(self.CONTAINER_TOKENS + 1, node_dim)

        # 3-layer GAT stack
        head_dim = hidden_dim // heads
        self.gat_layers = nn.ModuleList()
        self.norms       = nn.ModuleList()
        for i in range(num_layers):
            in_d = node_dim if i == 0 else hidden_dim
            self.gat_layers.append(
                GATConv(in_d, head_dim, heads=heads,
                        dropout=dropout, concat=True)
            )
            self.norms.append(nn.LayerNorm(hidden_dim))

        self.output_proj = nn.Linear(hidden_dim, 128)
        self.dropout     = nn.Dropout(dropout)

    # ── helpers ──────────────────────────────────────────────

    def _yaml_to_graph(
        self, old_spec: Dict, new_spec: Dict
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Return (node_ids [N], edge_index [2, E])."""
        nodes:  List[int]            = []
        edges:  List[Tuple[int,int]] = []
        pos_ids: List[int]           = []   # container positional token
        path2idx: Dict[str, int]     = {}

        def traverse(obj, path: str, parent: int, prefix: str,
                     container_idx: int = -1):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    cp = f"{prefix}{path}.{k}" if path else f"{prefix}{k}"
                    idx = len(nodes)
                    path2idx[cp] = idx
                    # node id from hash
                    nodes.append(hash(k + str(v)[:50]) % self.VOCAB)
                    # container positional token
                    cidx = container_idx
                    if "containers" in path and isinstance(obj, dict):
                        cidx = container_idx  # inherit from parent
                    pos_ids.append(max(0, min(cidx + 1, self.CONTAINER_TOKENS)))
                    if parent >= 0:
                        edges.append((parent, idx))
                        edges.append((idx, parent))   # bidirectional
                    traverse(v, cp, idx, prefix, cidx)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    cp = f"{prefix}{path}[{i}]"
                    idx = len(nodes)
                    path2idx[cp] = idx
                    nodes.append(hash(f"[{i}]" + str(item)[:50]) % self.VOCAB)
                    # detect containers list → assign positional token
                    if path.endswith("containers"):
                        cidx = i   # [CONTAINER_i]
                    else:
                        cidx = container_idx
                    pos_ids.append(max(0, min(cidx + 1, self.CONTAINER_TOKENS)))
                    if parent >= 0:
                        edges.append((parent, idx))
                        edges.append((idx, parent))
                    traverse(item, cp, idx, prefix, cidx)

        traverse(old_spec, "", -1, "old.")
        traverse(new_spec, "", -1, "new.")

        if not nodes:
            nodes    = [0]
            pos_ids  = [0]
            edges    = [(0, 0)]

        node_ids   = torch.tensor(nodes,   dtype=torch.long)
        pos_tensor = torch.tensor(pos_ids, dtype=torch.long)
        if edges:
            edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        else:
            n = len(nodes)
            edge_index = torch.zeros((2, n), dtype=torch.long)

        return node_ids, pos_tensor, edge_index

    # ── forward ──────────────────────────────────────────────

    def forward(self, old_spec: Dict, new_spec: Dict) -> torch.Tensor:
        """Returns 128-dim graph embedding."""
        device = self.node_embed.weight.device

        node_ids, pos_ids, edge_index = self._yaml_to_graph(old_spec, new_spec)
        node_ids   = node_ids.to(device)
        pos_ids    = pos_ids.to(device)
        edge_index = edge_index.to(device)

        # Node features: field embedding + positional token
        x = self.node_embed(node_ids) + self.pos_embed(pos_ids)  # (N, node_dim)

        # Add self-loops
        edge_index, _ = add_self_loops(edge_index, num_nodes=x.size(0))

        # 3-layer GAT with residual
        for gat, norm in zip(self.gat_layers, self.norms):
            h = gat(x, edge_index)         # (N, hidden_dim)
            h = F.elu(h)
            h = self.dropout(h)
            if x.size(-1) == h.size(-1):   # residual only if dims match
                h = h + x
            x = norm(h)

        # Mean-pool over nodes → (hidden_dim,)
        pooled = x.mean(dim=0)
        return self.output_proj(pooled)    # (128,)


# ─────────────────────────────────────────────────────────────
# 2. Prom Metrics → Mamba SSM (pure-PyTorch, O(n))  → 64-dim
# ─────────────────────────────────────────────────────────────

class MambaSSMBlock(nn.Module):
    """
    Simplified Mamba / S4-style State Space Model block.
    Processes sequences in O(n) with learned A, B, C, D matrices.
    Input/output: (batch, seq, d_model).
    No CUDA kernels needed — pure PyTorch.
    """

    def __init__(self, d_model: int, d_state: int = 16, expand: int = 2):
        super().__init__()
        self.d_model = d_model
        self.d_state = d_state
        d_inner = d_model * expand

        # Input projection
        self.in_proj  = nn.Linear(d_model, d_inner * 2, bias=False)
        # SSM parameters
        self.A_log    = nn.Parameter(torch.randn(d_inner, d_state))
        self.B_proj   = nn.Linear(d_inner, d_state, bias=False)
        self.C_proj   = nn.Linear(d_inner, d_state, bias=False)
        self.D        = nn.Parameter(torch.ones(d_inner))
        # Output
        self.out_proj = nn.Linear(d_inner, d_model, bias=False)
        self.norm     = nn.LayerNorm(d_model)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (batch, seq, d_model) → (batch, seq, d_model)"""
        residual = x
        B, L, _ = x.shape

        # Split gate and input
        xz    = self.in_proj(x)              # (B, L, 2*d_inner)
        xi, z = xz.chunk(2, dim=-1)          # each (B, L, d_inner)
        xi    = F.silu(xi)

        # SSM via sequential scan (O(n))
        A = -torch.exp(self.A_log.float())   # (d_inner, d_state) — stable negative
        B_t = self.B_proj(xi)                # (B, L, d_state)
        C_t = self.C_proj(xi)                # (B, L, d_state)

        # Discretise: Δ = softplus(constant) — simplified ZOH
        dt = F.softplus(torch.ones(1, device=x.device) * 0.1)  # scalar
        dA = torch.exp(dt * A)               # (d_inner, d_state)

        # Sequential scan over time steps
        h   = torch.zeros(B, xi.size(-1), self.d_state, device=x.device)
        ys  = []
        for t in range(L):
            dB = dt * B_t[:, t, :].unsqueeze(1)  # (B, 1, d_state)
            h  = h * dA.unsqueeze(0) + xi[:, t, :].unsqueeze(-1) * dB
            y  = (h * C_t[:, t, :].unsqueeze(1)).sum(-1)  # (B, d_inner)
            ys.append(y)

        y = torch.stack(ys, dim=1)           # (B, L, d_inner)
        y = y + xi * self.D.unsqueeze(0).unsqueeze(0)
        y = y * F.silu(z)                    # gating

        out = self.out_proj(y)               # (B, L, d_model)
        return self.norm(out + residual)


class PrometheusMambaEncoder(nn.Module):
    """
    Mamba SSM encoder for Prometheus metrics.
    Input:  (60, 15) — 5-min window, 15 metrics, 5s resolution.
    Output: 64-dim temporal embedding.
    """

    def __init__(
        self,
        input_dim:  int = 15,
        hidden_dim: int = 64,
        d_state:    int = 16,
        num_layers: int = 2,
    ):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.ssm_blocks = nn.ModuleList([
            MambaSSMBlock(hidden_dim, d_state=d_state)
            for _ in range(num_layers)
        ])
        self.output_proj = nn.Linear(hidden_dim, 64)

    def forward(self, metrics: torch.Tensor) -> torch.Tensor:
        """
        metrics: (T, 15) or (B, T, 15).
        Returns: 64-dim vector.
        """
        if metrics.dim() == 2:
            metrics = metrics.unsqueeze(0)          # (1, T, 15)
        x = self.input_proj(metrics)                # (1, T, hidden)
        for blk in self.ssm_blocks:
            x = blk(x)
        last = x[:, -1, :]                          # (1, hidden)
        return self.output_proj(last).squeeze(0)    # (64,)


# ─────────────────────────────────────────────────────────────
# 3. Falco Events → Transformer Encoder (4 heads, 2 layers) → 64-dim
# ─────────────────────────────────────────────────────────────

SYSCALL_VOCAB = {
    "read": 1, "write": 2, "open": 3, "close": 4,
    "rename": 5, "truncate": 6, "ftruncate": 6,
    "mmap": 7, "mprotect": 8,
    "socket": 9, "connect": 10, "accept": 11,
    "sendto": 12, "recvfrom": 13,
    "execve": 14, "fork": 15, "clone": 16,
    "kill": 17, "exit": 18, "unlink": 19,
    "creat": 20, "create": 20,
    "stat": 21, "access": 22, "chmod": 23, "chown": 24,
    "getuid": 25, "setuid": 26, "getgid": 27, "setgid": 28,
    "geteuid": 29, "getegid": 30, "setpgid": 31, "getppid": 32,
    "lseek": 33, "dup": 34, "dup2": 35, "pipe": 36,
    "msync": 37, "munmap": 38, "brk": 39,
    "<unknown>": 0, "unknown": 0,
}


class FalcoTransformerEncoder(nn.Module):
    """
    Transformer encoder for Falco eBPF syscall sequences.
    Syscall sequence max 256 events.
    Output: 64-dim event embedding.
    """

    def __init__(
        self,
        vocab_size:  int = 256,
        embed_dim:   int = 64,
        num_heads:   int = 4,
        num_layers:  int = 2,
        max_seq_len: int = 256,
        dropout:     float = 0.1,
    ):
        super().__init__()
        self.max_seq_len = max_seq_len

        self.token_embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_embed   = nn.Embedding(max_seq_len, embed_dim)

        enc_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout, batch_first=True, activation="gelu",
        )
        self.transformer = nn.TransformerEncoder(enc_layer, num_layers=num_layers)
        self.output_proj = nn.Linear(embed_dim, 64)

    def _encode_syscalls(self, syscalls: List[Dict]) -> torch.Tensor:
        ids = []
        for call in syscalls[:self.max_seq_len]:
            name = call.get("syscall", "unknown").lower().strip()
            ids.append(SYSCALL_VOCAB.get(name, 0))
        # pad
        ids += [0] * (self.max_seq_len - len(ids))
        return torch.tensor(ids, dtype=torch.long)

    def forward(self, syscalls: List[Dict]) -> torch.Tensor:
        device = self.token_embed.weight.device
        ids    = self._encode_syscalls(syscalls).to(device)
        pos    = torch.arange(self.max_seq_len, device=device)

        x = self.token_embed(ids) + self.pos_embed(pos)   # (seq, d)
        x = x.unsqueeze(0)                                 # (1, seq, d)
        x = self.transformer(x)                            # (1, seq, d)
        x = self.output_proj(x.squeeze(0))                 # (seq, 64)
        return x.mean(dim=0)                               # (64,)


# ─────────────────────────────────────────────────────────────
# 4. Entropy Series → Conv1D + Squeeze-Excitation → 64-dim
# ─────────────────────────────────────────────────────────────

class EntropyConv1DEncoder(nn.Module):
    """
    Lightweight Conv1D + Squeeze-Excitation for entropy time-series.
    Input: (T,) or (1, T) where T ≤ 30 timesteps.
    Output: 64-dim entropy embedding.
    50× less compute than transformer for short windows.
    """

    def __init__(
        self,
        hidden_ch:  int = 32,
        output_dim: int = 64,
        dropout:    float = 0.1,
    ):
        super().__init__()
        self.conv1 = nn.Conv1d(1, hidden_ch,      kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(hidden_ch, hidden_ch * 2, kernel_size=3, padding=1)
        self.conv3 = nn.Conv1d(hidden_ch * 2, hidden_ch * 2, kernel_size=3, padding=1)

        ch2 = hidden_ch * 2
        # Squeeze-Excitation
        self.se_pool = nn.AdaptiveAvgPool1d(1)
        self.se_fc1  = nn.Linear(ch2, ch2 // 4)
        self.se_fc2  = nn.Linear(ch2 // 4, ch2)

        self.global_pool = nn.AdaptiveMaxPool1d(1)
        self.out_proj    = nn.Linear(ch2, output_dim)
        self.norm        = nn.LayerNorm(output_dim)
        self.dropout     = nn.Dropout(dropout)

    def forward(self, entropy: torch.Tensor) -> torch.Tensor:
        """entropy: (T,) or (1,T) or (B,T)."""
        if entropy.dim() == 1:
            entropy = entropy.unsqueeze(0).unsqueeze(0)  # (1,1,T)
        elif entropy.dim() == 2:
            entropy = entropy.unsqueeze(1)               # (B,1,T)

        x = F.relu(self.conv1(entropy))
        x = self.dropout(x)
        x = F.relu(self.conv2(x))
        x = F.relu(self.conv3(x))

        # SE attention
        se  = self.se_pool(x).squeeze(-1)
        se  = F.relu(self.se_fc1(se))
        se  = torch.sigmoid(self.se_fc2(se))
        x   = x * se.unsqueeze(-1)

        x   = self.global_pool(x).squeeze(-1)   # (B, ch2)
        x   = self.out_proj(x)
        x   = self.norm(x)
        return x.squeeze(0)                      # (64,)


# ─────────────────────────────────────────────────────────────
# 5. MHCA Fusion (3 heads × 64-dim slots) → 192-dim
# ─────────────────────────────────────────────────────────────

class MHCAFusion(nn.Module):
    """
    Multi-Head Cross-Attention fusion over 4 modality embeddings.
    Each modality projected to 48-dim slot; 4 slots → 192-dim sequence.
    3-head self-attention over slots → mean-pooled → 192-dim fused.
    """

    MODALITIES = ["yaml", "metrics", "events", "entropy"]

    def __init__(
        self,
        yaml_dim:    int = 128,
        metrics_dim: int = 64,
        events_dim:  int = 64,
        entropy_dim: int = 64,
        num_heads:   int = 3,
        dropout:     float = 0.1,
    ):
        super().__init__()
        self.slot_dim  = 48
        self.fusion_dim = self.slot_dim * 4  # = 192

        in_dims = {
            "yaml":    yaml_dim,
            "metrics": metrics_dim,
            "events":  events_dim,
            "entropy": entropy_dim,
        }
        self.projs = nn.ModuleDict({
            k: nn.Linear(v, self.slot_dim) for k, v in in_dims.items()
        })

        # Cross-attention over 4 slots
        self.mhca = nn.MultiheadAttention(
            embed_dim=self.slot_dim, num_heads=num_heads,
            dropout=dropout, batch_first=True,
        )
        self.norm1 = nn.LayerNorm(self.slot_dim)

        # FFN after attention
        self.ffn = nn.Sequential(
            nn.Linear(self.slot_dim, self.slot_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(self.slot_dim * 2, self.slot_dim),
        )
        self.norm2 = nn.LayerNorm(self.slot_dim)

        # Final projection 192 → 192
        self.out_proj = nn.Linear(self.fusion_dim, self.fusion_dim)

    def forward(self, embeddings: Dict[str, torch.Tensor]) -> torch.Tensor:
        """
        embeddings: subset of {yaml(128), metrics(64), events(64), entropy(64)}.
        Returns: 192-dim fused vector.
        """
        device = next(iter(embeddings.values())).device
        slots  = []
        for name in self.MODALITIES:
            if name in embeddings:
                e = embeddings[name]
                if e.dim() > 1:
                    e = e.squeeze()
                slots.append(self.projs[name](e))   # (48,)
            else:
                slots.append(torch.zeros(self.slot_dim, device=device))

        seq = torch.stack(slots, dim=0).unsqueeze(0)  # (1, 4, 48)

        # Cross-attention
        attn_out, attn_weights = self.mhca(seq, seq, seq)
        seq = self.norm1(seq + attn_out)
        seq = self.norm2(seq + self.ffn(seq))

        # Flatten slots → 192-dim
        fused = seq.squeeze(0).reshape(self.fusion_dim)  # (192,)
        return self.out_proj(fused), attn_weights          # (192,), (1,4,4)


# ─────────────────────────────────────────────────────────────
# 6. Output Head → risk_score [0,1] + 5-class logits
# ─────────────────────────────────────────────────────────────

CLASS_NAMES = [
    "benign",
    "health-critical",
    "ransomware-critical",
    "sec-medium",
    "perf-risk",
]


class DITSecOutputHead(nn.Module):
    def __init__(self, input_dim: int = 192, num_classes: int = 5, dropout: float = 0.1):
        super().__init__()
        h = input_dim // 2
        self.risk_head = nn.Sequential(
            nn.Linear(input_dim, h), nn.GELU(),
            nn.Linear(h, 1), nn.Sigmoid(),
        )
        self.cls_head = nn.Sequential(
            nn.Linear(input_dim, h), nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(h, h // 2), nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(h // 2, num_classes),
        )

    def forward(self, x: torch.Tensor):
        return self.risk_head(x).squeeze(-1), self.cls_head(x)


# ─────────────────────────────────────────────────────────────
# 7. Full DIT-Sec v3 Model
# ─────────────────────────────────────────────────────────────

class DITSecV3(nn.Module):
    """
    KubeHeal DIT-Sec v3 — GNN + Mamba Hybrid.

    Modality routing:
      Health path  → yaml + metrics
      Security path→ events + entropy
      Full path    → all four modalities
    """

    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        cfg = config or {}

        self.yaml_enc    = YAMLGATEncoder(
            node_dim=cfg.get("gat_node_dim", 64),
            hidden_dim=cfg.get("gat_hidden_dim", 128),
            num_layers=cfg.get("gat_layers", 3),
            heads=cfg.get("gat_heads", 4),
        )
        self.metrics_enc = PrometheusMambaEncoder(
            input_dim=cfg.get("metrics_input_dim", 15),
            hidden_dim=cfg.get("mamba_hidden_dim", 64),
            d_state=cfg.get("mamba_d_state", 16),
        )
        self.events_enc  = FalcoTransformerEncoder(
            embed_dim=cfg.get("transformer_embed_dim", 64),
            num_heads=cfg.get("transformer_heads", 4),
            num_layers=cfg.get("transformer_layers", 2),
        )
        self.entropy_enc = EntropyConv1DEncoder(
            hidden_ch=cfg.get("conv1d_hidden_ch", 32),
            output_dim=64,
        )
        self.fusion = MHCAFusion(num_heads=cfg.get("mhca_heads", 3))
        self.output = DITSecOutputHead(
            input_dim=192,
            num_classes=cfg.get("num_classes", len(CLASS_NAMES)),
        )

        self.class_names = CLASS_NAMES

    # ── forward ──────────────────────────────────────────────

    def forward(
        self,
        old_spec:       Optional[Dict]         = None,
        new_spec:       Optional[Dict]         = None,
        metrics:        Optional[torch.Tensor] = None,
        syscalls:       Optional[List[Dict]]   = None,
        entropy_series: Optional[torch.Tensor] = None,
        return_attn:    bool = False,
    ) -> Dict:
        if all(x is None for x in [old_spec, new_spec, metrics, syscalls, entropy_series]):
            raise ValueError("At least one input modality required.")

        device = next(self.parameters()).device
        embs: Dict[str, torch.Tensor] = {}

        if old_spec is not None and new_spec is not None:
            embs["yaml"] = self.yaml_enc(old_spec, new_spec)

        if metrics is not None:
            m = metrics.to(device)
            if m.dim() == 2:
                m = m.unsqueeze(0)        # add batch dim
            embs["metrics"] = self.metrics_enc(m.squeeze(0))

        if syscalls is not None:
            embs["events"] = self.events_enc(syscalls)

        if entropy_series is not None:
            embs["entropy"] = self.entropy_enc(entropy_series.to(device))

        fused, attn_weights = self.fusion(embs)
        risk_score, logits  = self.output(fused)

        probs     = torch.softmax(logits, dim=-1)
        label_idx = int(torch.argmax(probs).item())
        label     = self.class_names[label_idx]

        out = {
            "risk_score":    risk_score,
            "label":         label,
            "logits":        logits,
            "probabilities": probs,
        }
        if return_attn:
            out["attn_weights"] = attn_weights
        return out

    # ── convenience predict ──────────────────────────────────

    def predict(
        self,
        old_spec:       Optional[Dict]       = None,
        new_spec:       Optional[Dict]       = None,
        metrics:        Optional[List]       = None,
        syscalls:       Optional[List[Dict]] = None,
        entropy_series: Optional[List[float]]= None,
    ) -> Dict:
        self.eval()
        with torch.no_grad():
            kwargs: Dict = {}
            if old_spec  and new_spec:
                kwargs["old_spec"] = old_spec
                kwargs["new_spec"] = new_spec
            if metrics is not None:
                kwargs["metrics"] = torch.tensor(metrics, dtype=torch.float32)
            if syscalls is not None:
                kwargs["syscalls"] = syscalls
            if entropy_series is not None:
                kwargs["entropy_series"] = torch.tensor(
                    entropy_series, dtype=torch.float32
                )
            out = self.forward(**kwargs)
        return {
            "risk_score":    float(out["risk_score"]),
            "label":         out["label"],
            "probabilities": out["probabilities"].tolist(),
        }

    def param_count(self) -> int:
        return sum(p.numel() for p in self.parameters())


# ─────────────────────────────────────────────────────────────
# Quick smoke test
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import copy

    print("=" * 60)
    print("DIT-Sec v3  GNN+Mamba  smoke test")
    print("=" * 60)

    model = DITSecV3()
    print(f"Parameters: {model.param_count():,}")
    print(f"Encoders:")
    print(f"  YAML  → GAT ({model.yaml_enc.num_layers if hasattr(model.yaml_enc, 'num_layers') else 3}L) → 128-dim")
    print(f"  Metrics → MambaSSM → 64-dim")
    print(f"  Events  → Transformer → 64-dim")
    print(f"  Entropy → Conv1D+SE → 64-dim")
    print(f"  Fusion  → MHCA (3 heads) → 192-dim")

    # --- HEALTH sample ---
    old_spec = {
        "spec": {"template": {"spec": {"containers": [
            {"name": "app", "resources": {
                "limits": {"cpu": "500m", "memory": "512Mi"}}}
        ]}}}
    }
    new_spec = copy.deepcopy(old_spec)
    new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "50m"
    metrics  = np.random.randn(60, 15).astype(np.float32)

    r = model.predict(old_spec=old_spec, new_spec=new_spec, metrics=metrics.tolist())
    print(f"\n[Health]  risk={r['risk_score']:.3f}  label={r['label']}")

    # --- SECURITY sample ---
    syscalls = [{"syscall": "write"}, {"syscall": "rename"}] * 60
    entropy  = (np.random.rand(20) * 2 + 6.2).tolist()

    r2 = model.predict(syscalls=syscalls, entropy_series=entropy)
    print(f"[Security] risk={r2['risk_score']:.3f}  label={r2['label']}")

    # --- ALL modalities ---
    r3 = model.predict(
        old_spec=old_spec, new_spec=new_spec,
        metrics=metrics.tolist(),
        syscalls=syscalls, entropy_series=entropy
    )
    print(f"[Full]     risk={r3['risk_score']:.3f}  label={r3['label']}")
    print("✅ Smoke test passed.")
