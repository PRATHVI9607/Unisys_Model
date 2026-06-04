"""
Shared training utilities — KubeHeal v4.
========================================
Centralises the hyperparameter-hygiene decisions so all three training
scripts behave identically:

  • setup_torch()        — pin CPU threads (fixes per-sample thread thrash that
                           stalled training) + deterministic seeds.
  • clipped_step()       — gradient-explosion guard: clip global grad-norm, and
                           if the norm is non-finite (NaN/Inf) SKIP the step
                           instead of corrupting weights. GATv2 attention +
                           BiLSTM recurrence can spike gradients; clipping to
                           1.0 + a finite-check keeps training stable.
  • make_plateau()       — ReduceLROnPlateau (mode=max on val F1/AUROC):
                           halves LR after `patience` stale epochs so the model
                           anneals only when it actually plateaus, instead of a
                           blind cosine decay that may cut LR too early/late.
  • warmup_factor()      — short linear LR warm-up for the first epoch so the
                           transformer / attention layers don't diverge from a
                           cold start at full LR.
"""

import os
import random

import numpy as np
import torch


def setup_torch(seed: int = 42, threads: int = 1) -> torch.device:
    """Pin threads (critical on CPU: tiny per-sample graph ops thread-thrash
    with the default 6 threads → 10-100× slowdown) and seed everything."""
    os.environ.setdefault("OMP_NUM_THREADS", str(threads))
    os.environ.setdefault("MKL_NUM_THREADS", str(threads))
    torch.set_num_threads(threads)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def clipped_step(model, optimizer, max_norm: float = 1.0) -> float:
    """Clip grad-norm and step ONLY if finite. Returns the (pre-clip) grad norm.
    Non-finite grads (explosion) → step skipped, grads zeroed, returns inf."""
    grad_norm = torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm)
    if not torch.isfinite(grad_norm):
        optimizer.zero_grad(set_to_none=True)
        return float("inf")
    optimizer.step()
    return float(grad_norm)


def make_plateau(optimizer, mode: str = "max", factor: float = 0.5,
                 patience: int = 2, min_lr: float = 1e-6):
    """ReduceLROnPlateau on the validation metric (F1 or AUROC)."""
    return torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode=mode, factor=factor, patience=patience, min_lr=min_lr,
    )


def warmup_factor(epoch: int, warmup_epochs: int = 1) -> float:
    """Linear warm-up multiplier in [0.1, 1.0] over the first warmup_epochs."""
    if epoch >= warmup_epochs:
        return 1.0
    return 0.1 + 0.9 * (epoch / max(1, warmup_epochs))
