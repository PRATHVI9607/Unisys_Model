"""
SecurityModel — KubeHeal v4 end-to-end Security Model wrapper.
=============================================================
Transformer(syscalls) + Conv1D-SE(entropy) → cross-attention fusion → head.

forward(syscall_ids, path_ids, padding_mask, entropy_series) → dict:
    risk_score [B,1], label_logits [B,5], security_embedding [B,64],
    syscall_salience [B,L], fusion_attn
"""

import hashlib
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn

from .falco_transformer_encoder import (
    FalcoTransformerEncoder, MAX_SEQUENCE_LENGTH, SYSCALL_VOCAB_SIZE, PATH_VOCAB_SIZE,
)
from .entropy_conv1d_encoder import EntropyConv1DEncoder, ENTROPY_WINDOW_LENGTH
from .security_fusion_attention import SecurityFusionAttention
from .security_output_head import SecurityOutputHead, SECURITY_LABELS


# Stable syscall name → id (0 reserved for PAD). Core set; unknowns hash in.
SYSCALL_BASE = {
    "<pad>": 0, "read": 1, "write": 2, "open": 3, "openat": 4, "close": 5,
    "rename": 6, "renameat": 7, "renameat2": 8, "unlink": 9, "unlinkat": 10,
    "ftruncate": 11, "truncate": 12, "mmap": 13, "munmap": 14, "msync": 15,
    "mprotect": 16, "fsync": 17, "fdatasync": 18, "stat": 19, "fstat": 20,
    "lstat": 21, "chmod": 22, "fchmod": 23, "execve": 24, "fork": 25,
    "clone": 26, "socket": 27, "connect": 28, "sendto": 29, "recvfrom": 30,
    "getdents": 31, "lseek": 32, "creat": 33, "dup": 34, "pwrite64": 35,
}


def syscall_to_id(name: str) -> int:
    name = (name or "").lower().strip()
    if name in SYSCALL_BASE:
        return SYSCALL_BASE[name]
    h = int(hashlib.md5(name.encode()).hexdigest(), 16)
    return 64 + (h % (SYSCALL_VOCAB_SIZE - 64))   # keep low ids for known set


def path_to_id(path: str) -> int:
    if not path:
        return 0
    h = int(hashlib.md5(path.encode()).hexdigest(), 16)
    return 1 + (h % (PATH_VOCAB_SIZE - 1))


def encode_syscall_window(events: List[Dict], max_len: int = MAX_SEQUENCE_LENGTH):
    """events: [{'syscall':str,'fd_path':str}, ...] →
    (syscall_ids[1,L], path_ids[1,L], padding_mask[1,L])"""
    sys_ids, path_ids = [], []
    for e in events[:max_len]:
        sys_ids.append(syscall_to_id(e.get("syscall", "")))
        path_ids.append(path_to_id(e.get("fd_path", "")))
    n = len(sys_ids)
    pad = max_len - n
    sys_ids += [0] * pad
    path_ids += [0] * pad
    mask = [False] * n + [True] * pad
    return (
        torch.tensor([sys_ids], dtype=torch.long),
        torch.tensor([path_ids], dtype=torch.long),
        torch.tensor([mask], dtype=torch.bool),
    )


def pad_entropy(series: List[float], length: int = ENTROPY_WINDOW_LENGTH) -> torch.Tensor:
    s = list(series)[:length]
    s += [0.0] * (length - len(s))
    return torch.tensor([s], dtype=torch.float32)


class SecurityModel(nn.Module):
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        cfg = config or {}
        self.syscall_encoder = FalcoTransformerEncoder(
            num_heads=cfg.get("tf_heads", 4),
            num_layers=cfg.get("tf_layers", 2),
            output_dim=cfg.get("syscall_dim", 64),
        )
        self.entropy_encoder = EntropyConv1DEncoder(output_dim=cfg.get("entropy_dim", 64))
        self.fusion = SecurityFusionAttention(
            syscall_dim=cfg.get("syscall_dim", 64),
            entropy_dim=cfg.get("entropy_dim", 64),
            fused_dim=cfg.get("fused_dim", 64),
        )
        self.output_head = SecurityOutputHead(fused_dim=cfg.get("fused_dim", 64))
        self.labels = SECURITY_LABELS

    def forward(self, syscall_ids, path_ids, padding_mask, entropy_series) -> Dict:
        sys_emb, salience = self.syscall_encoder(syscall_ids, path_ids, padding_mask)
        ent_emb = self.entropy_encoder(entropy_series)
        fused, fusion_attn = self.fusion(sys_emb, ent_emb)
        label_logits, risk = self.output_head(fused)
        return {
            "risk_score": risk,
            "label_logits": label_logits,
            "security_embedding": fused,
            "syscall_salience": salience,
            "fusion_attn": fusion_attn,
        }

    def predict(self, events: List[Dict], entropy_series: List[float]) -> Dict:
        self.eval()
        sid, pid, mask = encode_syscall_window(events)
        ent = pad_entropy(entropy_series)
        with torch.no_grad():
            out = self.forward(sid, pid, mask, ent)
        probs = torch.softmax(out["label_logits"], dim=-1)[0]
        idx = int(torch.argmax(probs).item())
        return {
            "risk_score": float(out["risk_score"].reshape(-1)[0]),
            "label": self.labels[idx],
            "label_probabilities": {l: float(probs[i]) for i, l in enumerate(self.labels)},
            "security_embedding": out["security_embedding"][0].tolist(),
        }

    def param_count(self) -> int:
        return sum(p.numel() for p in self.parameters())
