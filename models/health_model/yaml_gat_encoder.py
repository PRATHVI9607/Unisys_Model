"""
YAML GAT Encoder — KubeHeal v4 Health Model (Section 03.2)
==========================================================
Converts a Kubernetes YAML diff (old spec vs new spec) into a 128-dim graph
embedding using a Graph Attention Network (GATv2).

Why GATv2 over GAT: GATv2 (Brody et al., 2022) uses *dynamic* attention —
concatenate then transform — fixing GAT's static-attention limitation where
the neighbor ranking is query-independent. For K8s YAML the importance of a
parent node depends on which child changed; GATv2 learns this, GAT cannot.

Why GAT at all: K8s YAML is a hierarchical DAG. Serializing to text loses
parent-child structure. GAT encodes each field as a node and parent→child as
edges, propagating information through the hierarchy with learned attention.

Container disambiguation: each containers[i] subtree gets a learned positional
token so containers[0] and containers[2] do not collapse to the same embedding.
"""

import hashlib
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv
from torch_geometric.data import Data


NODE_FEATURE_DIM = 64
VOCAB_SIZE = 10000          # K8s field names + tokenized values
MAX_CONTAINER_TOKENS = 6    # containers[0..4] + overflow


def stable_token_id(text: str, mod: int = VOCAB_SIZE) -> int:
    """Process-stable hash → vocab id. Python's built-in hash() is randomized
    per process (PYTHONHASHSEED), which would map the same field to different
    embedding rows at train vs serve time. md5 is deterministic everywhere."""
    h = hashlib.md5(text.encode("utf-8")).hexdigest()
    return int(h, 16) % mod


class YAMLGATEncoder(nn.Module):
    def __init__(
        self,
        node_feature_dim: int = NODE_FEATURE_DIM,
        hidden_dim: int = 128,
        output_dim: int = 128,
        num_heads: int = 8,
        num_layers: int = 3,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.node_embedding = nn.Embedding(VOCAB_SIZE, node_feature_dim)
        self.positional_embedding = nn.Embedding(MAX_CONTAINER_TOKENS, node_feature_dim)

        self.gat_layers = nn.ModuleList()
        in_channels = node_feature_dim
        for i in range(num_layers):
            out_channels = hidden_dim // num_heads
            concat = i < num_layers - 1
            self.gat_layers.append(
                GATv2Conv(
                    in_channels=in_channels,
                    out_channels=out_channels,
                    heads=num_heads,
                    dropout=dropout,
                    add_self_loops=True,
                    concat=concat,
                )
            )
            # concat=True → out = out_channels*heads = hidden_dim
            # concat=False (last) → out = out_channels = hidden_dim//num_heads
            in_channels = hidden_dim if concat else out_channels

        last_dim = hidden_dim // num_heads
        self.output_projection = nn.Linear(last_dim, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, data: Data) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            graph_embedding: [output_dim] embedding for the whole diff
            node_importance: [num_nodes] per-node attention importance
        """
        device = self.node_embedding.weight.device
        # data.x may be token ids [N] (long) — embed them
        if data.x.dtype == torch.long:
            x = self.node_embedding(data.x.to(device))
        else:
            x = data.x.to(device)

        edge_index = data.edge_index.to(device)

        # Inject container positional tokens onto container-root nodes
        ci = getattr(data, "container_indices", None)
        cp = getattr(data, "container_positions", None)
        if ci is not None and cp is not None and len(ci) > 0:
            ci_t = torch.as_tensor(ci, dtype=torch.long, device=device)
            cp_t = torch.clamp(torch.as_tensor(cp, dtype=torch.long, device=device),
                               0, MAX_CONTAINER_TOKENS - 1)
            x = x.clone()
            x[ci_t] = x[ci_t] + self.positional_embedding(cp_t)

        all_attn = []
        for i, gat in enumerate(self.gat_layers):
            x, (ei, attn) = gat(x, edge_index, return_attention_weights=True)
            all_attn.append((ei, attn))
            if i < len(self.gat_layers) - 1:
                x = F.relu(x)
                x = self.dropout(x)

        graph_embedding = x.mean(dim=0)
        graph_embedding = self.output_projection(graph_embedding)
        graph_embedding = self.layer_norm(graph_embedding)

        # Per-node importance from last layer's attention (sum over edges→node)
        num_nodes = x.shape[0]
        node_importance = torch.zeros(num_nodes, device=device)
        ei_last, attn_last = all_attn[-1]
        attn_mean = attn_last.mean(dim=-1)  # [num_edges]
        tgt = ei_last[1]                    # destination node per edge
        node_importance.index_add_(0, tgt, attn_mean)
        node_importance = node_importance / (node_importance.sum() + 1e-8)

        return graph_embedding, node_importance


# ──────────────────────────────────────────────────────────────
# YAML diff → PyG graph
# ──────────────────────────────────────────────────────────────

def _flatten(obj, prefix: str, out: Dict[str, str]) -> None:
    """Flatten a nested dict/list to {dotted_path: value_str}."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _flatten(item, f"{prefix}[{i}]", out)
    else:
        out[prefix] = str(obj)


def yaml_diff_to_graph(old_yaml: dict, new_yaml: dict) -> Data:
    """
    Build a PyG Data object from a YAML diff.

    Nodes  = union of all field paths in old+new (plus structural parents).
    Edges  = parent→child (bidirectional) over the path hierarchy.
    Node feature = stable_token_id(path_leaf + value) so changed values get
    distinct ids ("50m" != "500m").

    Adds:
      data.x                  [N] long token ids
      data.edge_index         [2, E]
      data.change_mask        [N] bool — True where old != new
      data.field_paths        list[str] — dotted path per node (for interpretation)
      data.container_indices  list[int] — node idx of each containers[i] root
      data.container_positions list[int] — positional token per container root
    """
    old_flat: Dict[str, str] = {}
    new_flat: Dict[str, str] = {}
    _flatten(old_yaml or {}, "", old_flat)
    _flatten(new_yaml or {}, "", new_flat)

    all_leaf_paths = sorted(set(old_flat) | set(new_flat))

    # Build the set of all path prefixes (structural nodes) so the graph is a tree
    node_paths: List[str] = []
    seen = set()

    def _ensure_path(path: str):
        # register every ancestor prefix of `path`, in order
        parts = _split_path(path)
        cur = ""
        for p in parts:
            cur = f"{cur}.{p}" if cur and not p.startswith("[") else (cur + p if p.startswith("[") else p)
            if cur not in seen:
                seen.add(cur)
                node_paths.append(cur)

    for lp in all_leaf_paths:
        _ensure_path(lp)

    if not node_paths:
        node_paths = ["root"]

    path_to_idx = {p: i for i, p in enumerate(node_paths)}

    # Node token ids + change mask
    tokens: List[int] = []
    change_mask: List[bool] = []
    for p in node_paths:
        leaf = p.split(".")[-1]
        ov = old_flat.get(p)
        nv = new_flat.get(p)
        val = nv if nv is not None else (ov if ov is not None else "")
        tokens.append(stable_token_id(f"{leaf}={val}"[:64]))
        change_mask.append(ov != nv)

    # Edges parent→child (bidirectional)
    edges: List[Tuple[int, int]] = []
    for p in node_paths:
        parent = _parent_path(p)
        if parent is not None and parent in path_to_idx:
            a, b = path_to_idx[parent], path_to_idx[p]
            edges.append((a, b))
            edges.append((b, a))
    if not edges:
        edges = [(0, 0)]

    # Container positional tokens: any path ending in containers[i]
    container_indices: List[int] = []
    container_positions: List[int] = []
    for p, idx in path_to_idx.items():
        ci = _container_index(p)
        if ci is not None:
            container_indices.append(idx)
            container_positions.append(min(ci, MAX_CONTAINER_TOKENS - 1))

    data = Data(
        x=torch.tensor(tokens, dtype=torch.long),
        edge_index=torch.tensor(edges, dtype=torch.long).t().contiguous(),
    )
    data.change_mask = torch.tensor(change_mask, dtype=torch.bool)
    data.field_paths = node_paths
    data.container_indices = container_indices
    data.container_positions = container_positions
    return data


def _split_path(path: str) -> List[str]:
    """Split 'a.b[0].c' → ['a','b','[0]','c']."""
    parts: List[str] = []
    for seg in path.split("."):
        while "[" in seg:
            head, rest = seg.split("[", 1)
            if head:
                parts.append(head)
            idx, seg = rest.split("]", 1)
            parts.append(f"[{idx}]")
        if seg:
            parts.append(seg)
    return parts


def _parent_path(path: str) -> Optional[str]:
    if path.endswith("]"):
        # drop the trailing [i]
        return path[: path.rfind("[")] or None
    if "." in path:
        return path.rsplit(".", 1)[0]
    return None


def _container_index(path: str) -> Optional[int]:
    """If path is exactly '...containers[i]', return i."""
    if "containers[" in path and path.endswith("]"):
        tail = path[path.rfind("containers["):]
        if tail.startswith("containers[") and tail.endswith("]"):
            inner = tail[len("containers["):-1]
            if inner.isdigit():
                return int(inner)
    return None
