"""
Falco Transformer Encoder — KubeHeal v4 Security Model (Section 04.2)
====================================================================
Encodes a sequence of Falco syscall events (≤256) into a 64-dim embedding.

Transformer (kept from v3) is right here: ransomware syscall patterns have
long-range dependencies (open → many reads → close → reopen → encrypt →
write → rename) spanning hundreds of events. Self-attention models any-to-any
position regardless of distance. Pre-LN + CLS token + sinusoidal PE.
"""

import math
from typing import Tuple

import torch
import torch.nn as nn


MAX_SEQUENCE_LENGTH = 256
SYSCALL_VOCAB_SIZE = 512
PATH_VOCAB_SIZE = 10000
EVENT_EMBEDDING_DIM = 64


class FalcoTransformerEncoder(nn.Module):
    def __init__(
        self,
        vocab_size: int = SYSCALL_VOCAB_SIZE,
        embed_dim: int = EVENT_EMBEDDING_DIM,
        num_heads: int = 4,
        num_layers: int = 2,
        max_seq_len: int = MAX_SEQUENCE_LENGTH,
        output_dim: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.max_seq_len = max_seq_len
        self.syscall_embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.path_embedding = nn.Embedding(PATH_VOCAB_SIZE, embed_dim // 2, padding_idx=0)
        self.register_buffer(
            "position_encoding", self._build_sinusoidal_pe(max_seq_len + 1, embed_dim)
        )
        enc_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout,
            batch_first=True,
            norm_first=True,
            activation="gelu",
        )
        self.transformer = nn.TransformerEncoder(enc_layer, num_layers=num_layers)
        self.cls_token = nn.Parameter(torch.randn(1, 1, embed_dim))
        self.output_projection = nn.Linear(embed_dim, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)

    @staticmethod
    def _build_sinusoidal_pe(max_len: int, d_model: int) -> torch.Tensor:
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        return pe.unsqueeze(0)

    def forward(
        self,
        syscall_ids: torch.Tensor,    # [B, L]
        path_ids: torch.Tensor,       # [B, L]
        padding_mask: torch.Tensor,   # [B, L] True = pad
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        B, L = syscall_ids.shape
        sys_emb = self.syscall_embedding(syscall_ids)            # [B,L,E]
        path_emb = self.path_embedding(path_ids)                 # [B,L,E/2]
        path_padded = torch.zeros_like(sys_emb)
        path_padded[:, :, : path_emb.shape[-1]] = path_emb
        x = sys_emb + path_padded
        x = x + self.position_encoding[:, 1 : L + 1, :].to(x.device)

        cls = self.cls_token.expand(B, -1, -1)                   # [B,1,E]
        cls = cls + self.position_encoding[:, 0:1, :].to(x.device)
        x = torch.cat([cls, x], dim=1)                           # [B,L+1,E]

        cls_mask = torch.zeros(B, 1, dtype=torch.bool, device=padding_mask.device)
        mask_ext = torch.cat([cls_mask, padding_mask], dim=1)

        encoded = self.transformer(x, src_key_padding_mask=mask_ext)
        cls_out = encoded[:, 0, :]                               # [B,E]
        emb = self.layer_norm(self.output_projection(cls_out))   # [B,output_dim]

        # Per-token salience proxy: cosine sim of each token to the CLS output
        with torch.no_grad():
            tok = encoded[:, 1:, :]                              # [B,L,E]
            sal = torch.einsum("ble,be->bl", tok, cls_out)
            sal = sal.masked_fill(padding_mask, float("-inf"))
            attn_weights = torch.softmax(sal, dim=-1)            # [B,L]
        return emb, attn_weights
