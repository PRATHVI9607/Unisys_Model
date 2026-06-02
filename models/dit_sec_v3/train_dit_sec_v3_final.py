"""
DIT-Sec v3 — Unified Training Script
=====================================
Two-domain training:
  HEALTH   domain → YAML diff + Prometheus metrics   (from real CSV)
  SECURITY domain → Falco syscalls + entropy series  (synthetic)

Output
------
  models/dit_sec_v3/models/dit_sec_v3_trained.pt    — best checkpoint
  models/dit_sec_v3/results/training_curves.png      — loss/acc curves
  models/dit_sec_v3/results/confusion_matrix.png     — val confusion matrix
  models/dit_sec_v3/results/class_distribution.png   — class balance chart
  models/dit_sec_v3/results/training_report.json     — full metrics
"""

import sys
import os
import json
import csv
import random
import argparse
import math
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, classification_report, f1_score
)

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))
from dit_sec_v3_model import DITSecV3, CLASS_NAMES

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

LABEL_MAP = {name: i for i, name in enumerate(CLASS_NAMES)}
# benign=0, health-critical=1, ransomware-critical=2, sec-medium=3, perf-risk=4

CSV_LABEL_MAP = {
    "Benign_Or_Subtle":               "benign",
    "Harmful_Security_Breach":        "health-critical",
    "Harmful_Performance_Degradation": "perf-risk",
    "Harmful_Critical_Outage":        "health-critical",
    "Harmful_Multi_Vector":           "health-critical",
}

METRIC_COLS = [
    "request_rate", "error_rate_5xx", "latency_p99",
    "cpu_usage_cores", "memory_working_set_bytes",
    "cpu_limit", "memory_limit",
    "desired_replicas", "current_replicas", "ready_replicas",
    "restart_count", "app_instance_count",
]
METRIC_NORMS = {
    "request_rate": 10.0, "error_rate_5xx": 0.1, "latency_p99": 0.05,
    "cpu_usage_cores": 2.0, "memory_working_set_bytes": 1e9,
    "cpu_limit": 2.0, "memory_limit": 2048.0,
    "desired_replicas": 10.0, "current_replicas": 10.0,
    "ready_replicas": 10.0, "restart_count": 10.0, "app_instance_count": 10.0,
}
T_STEPS = 60
NUM_METRICS = 15


# ─────────────────────────────────────────────
# Health domain data — load from CSV
# ─────────────────────────────────────────────

def _parse_json(s) -> Dict:
    if not s or not str(s).strip():
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}


def _extract_metrics(row: Dict) -> np.ndarray:
    m = np.zeros((T_STEPS, NUM_METRICS), dtype=np.float32)
    for i, col in enumerate(METRIC_COLS):
        try:
            v = float(row.get(col) or 0.0)
            norm = METRIC_NORMS.get(col, 1.0)
            m[:, i] = np.clip(v / norm, -5.0, 5.0)
        except Exception:
            pass
    m += np.random.randn(*m.shape).astype(np.float32) * 0.02
    return m


def load_health_csv(csv_path: str) -> List[Dict]:
    samples = []
    label_counts: Dict[str, int] = defaultdict(int)

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            op_label = row.get("operational_label", "Benign_Or_Subtle").strip()
            label = CSV_LABEL_MAP.get(op_label, "benign")
            label_counts[label] += 1

            try:
                severity = float(row.get("severity") or 1.0)
            except Exception:
                severity = 1.0
            risk_score = min(1.0, severity / 3.0)

            samples.append({
                "domain":     "health",
                "label":      label,
                "risk_score": risk_score,
                "old_spec":   _parse_json(row.get("baseline_json")),
                "new_spec":   _parse_json(row.get("live_json")),
                "metrics":    _extract_metrics(row),
            })

    print(f"[CSV] Loaded {len(samples)} health samples: {dict(label_counts)}", flush=True)
    return samples


# ─────────────────────────────────────────────
# Security domain data — synthetic generator
# ─────────────────────────────────────────────

BENIGN_SYSCALLS = ["read", "stat", "open", "close", "getuid", "access"]
ATTACK_SYSCALLS = ["write", "rename", "ftruncate", "mmap", "msync", "unlink"]
MED_SYSCALLS    = ["write", "open", "read", "chmod", "stat", "close"]


def _make_syscalls(label: str, n: int = 120) -> List[Dict]:
    if label == "ransomware-critical":
        pool = ATTACK_SYSCALLS * 4 + BENIGN_SYSCALLS
    elif label == "sec-medium":
        pool = MED_SYSCALLS * 3 + BENIGN_SYSCALLS
    else:
        pool = BENIGN_SYSCALLS * 6 + ["write"]
    return [{"syscall": random.choice(pool)} for _ in range(n)]


def _make_entropy(label: str, n: int = 20) -> np.ndarray:
    if label == "ransomware-critical":
        base  = random.uniform(7.0, 7.9)
        noise = np.random.randn(n) * 0.15
    elif label == "sec-medium":
        base  = random.uniform(5.5, 6.8)
        noise = np.random.randn(n) * 0.3
    else:
        base  = random.uniform(1.0, 4.5)
        noise = np.random.randn(n) * 0.5
    return np.clip(base + noise, 0.0, 8.0).astype(np.float32)


def _risk_from_security_label(label: str) -> float:
    return {"ransomware-critical": 0.93, "sec-medium": 0.55, "benign": 0.05}[label]


def generate_security_samples(n: int = 4000) -> List[Dict]:
    weights = {"ransomware-critical": 0.30, "sec-medium": 0.25, "benign": 0.45}
    labels  = list(weights.keys())
    probs   = list(weights.values())
    samples = []
    for _ in range(n):
        label = random.choices(labels, weights=probs)[0]
        samples.append({
            "domain":         "security",
            "label":          label,
            "risk_score":     _risk_from_security_label(label),
            "syscalls":       _make_syscalls(label),
            "entropy_series": _make_entropy(label),
        })
    counts: Dict[str, int] = defaultdict(int)
    for s in samples:
        counts[s["label"]] += 1
    print(f"[Synthetic] Generated {n} security samples: {dict(counts)}", flush=True)
    return samples


# ─────────────────────────────────────────────
# Dataset
# ─────────────────────────────────────────────

class DITSecDataset(Dataset):
    def __init__(self, samples: List[Dict]):
        self.samples = samples

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict:
        return self.samples[idx]


def _collate(batch):
    return batch  # list of dicts — model handles individually


# ─────────────────────────────────────────────
# Class weights for imbalanced training
# ─────────────────────────────────────────────

def compute_class_weights(samples: List[Dict], device) -> torch.Tensor:
    counts: Dict[str, int] = defaultdict(int)
    for s in samples:
        counts[s["label"]] += 1
    total = len(samples)
    weights = []
    for name in CLASS_NAMES:
        c = counts.get(name, 1)
        weights.append(total / (len(CLASS_NAMES) * c))
    return torch.tensor(weights, dtype=torch.float32).to(device)


# ─────────────────────────────────────────────
# Training helpers
# ─────────────────────────────────────────────

def _forward_sample(model: DITSecV3, s: Dict, device) -> Dict:
    kwargs: Dict = {}
    if s.get("old_spec") and s.get("new_spec"):
        kwargs["old_spec"] = s["old_spec"]
        kwargs["new_spec"] = s["new_spec"]
    if s.get("metrics") is not None:
        kwargs["metrics"] = torch.tensor(s["metrics"], dtype=torch.float32).to(device)
    if s.get("syscalls"):
        kwargs["syscalls"] = s["syscalls"]
    if s.get("entropy_series") is not None:
        es = s["entropy_series"]
        kwargs["entropy_series"] = torch.tensor(es, dtype=torch.float32).to(device)
    return model(**kwargs)


def run_epoch(
    model: DITSecV3,
    loader: DataLoader,
    criterion,
    optimizer,
    device,
    train: bool = True,
) -> Tuple[float, float, List[int], List[int]]:
    model.train(train)
    total_loss = 0.0
    all_preds, all_labels = [], []

    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for batch in loader:
            if train:
                optimizer.zero_grad()

            logits_list, label_ids = [], []
            for s in batch:
                try:
                    out = _forward_sample(model, s, device)
                    logits_list.append(out["logits"])
                    label_ids.append(LABEL_MAP[s["label"]])
                except Exception:
                    continue

            if not logits_list:
                continue

            logits = torch.stack(logits_list)          # (N, 5)
            labels = torch.tensor(label_ids, dtype=torch.long, device=device)
            loss   = criterion(logits, labels)

            if train:
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()

            total_loss += loss.item()
            preds = torch.argmax(logits, dim=-1).cpu().tolist()
            all_preds.extend(preds)
            all_labels.extend(label_ids)

    n = len(loader)
    avg_loss = total_loss / max(n, 1)
    acc = sum(p == l for p, l in zip(all_preds, all_labels)) / max(len(all_preds), 1)
    return avg_loss, acc, all_preds, all_labels


# ─────────────────────────────────────────────
# Plot helpers
# ─────────────────────────────────────────────

def plot_training_curves(history: Dict, out_dir: Path):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("DIT-Sec v3  GNN+Mamba  Training", fontsize=14, fontweight="bold")

    epochs = range(1, len(history["train_loss"]) + 1)

    ax = axes[0]
    ax.plot(epochs, history["train_loss"], "b-o", label="Train Loss", markersize=3)
    ax.plot(epochs, history["val_loss"],   "r-o", label="Val Loss",   markersize=3)
    ax.set_xlabel("Epoch"); ax.set_ylabel("Cross-Entropy Loss")
    ax.set_title("Loss")
    ax.legend(); ax.grid(True, alpha=0.3)

    ax = axes[1]
    ax.plot(epochs, history["train_acc"], "b-o", label="Train Acc", markersize=3)
    ax.plot(epochs, history["val_acc"],   "r-o", label="Val Acc",   markersize=3)
    ax.set_xlabel("Epoch"); ax.set_ylabel("Accuracy")
    ax.set_title("Accuracy")
    ax.set_ylim(0, 1.05); ax.legend(); ax.grid(True, alpha=0.3)

    plt.tight_layout()
    path = out_dir / "training_curves.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[Plot] Saved {path}", flush=True)


def plot_confusion_matrix(preds: List[int], labels: List[int], out_dir: Path):
    cm      = confusion_matrix(labels, preds, labels=list(range(len(CLASS_NAMES))))
    cm_norm = cm.astype(float) / (cm.sum(axis=1, keepdims=True) + 1e-9)

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("DIT-Sec v3  Validation Confusion Matrix", fontsize=13, fontweight="bold")

    for ax, data, fmt, title in zip(
        axes,
        [cm, cm_norm],
        ["d", ".2f"],
        ["Counts", "Normalised"],
    ):
        sns.heatmap(
            data, ax=ax, annot=True, fmt=fmt, cmap="Blues",
            xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES,
            linewidths=0.5,
        )
        ax.set_xlabel("Predicted"); ax.set_ylabel("True")
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=30)

    plt.tight_layout()
    path = out_dir / "confusion_matrix.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[Plot] Saved {path}", flush=True)


def plot_class_distribution(samples: List[Dict], out_dir: Path):
    counts: Dict[str, int] = defaultdict(int)
    for s in samples:
        counts[s["label"]] += 1

    names  = CLASS_NAMES
    values = [counts.get(n, 0) for n in names]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(names, values, color=["#4CAF50", "#F44336", "#9C27B0", "#FF9800", "#2196F3"])
    ax.set_title("Training Class Distribution", fontsize=13, fontweight="bold")
    ax.set_ylabel("Count")
    ax.set_xlabel("Class")
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                str(val), ha="center", va="bottom", fontsize=10)
    plt.xticks(rotation=25, ha="right", fontsize=9)
    plt.tight_layout()
    path = out_dir / "class_distribution.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[Plot] Saved {path}", flush=True)


# ─────────────────────────────────────────────
# Main training loop
# ─────────────────────────────────────────────

def train(
    csv_path:    str,
    epochs:      int   = 30,
    lr:          float = 2e-4,
    batch_size:  int   = 32,
    val_split:   float = 0.15,
    sec_samples: int   = 4000,
    output_dir:  str   = None,
    seed:        int   = 42,
    patience:    int   = 7,
):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    out_dir = Path(output_dir or (Path(__file__).parent / "models"))
    res_dir = Path(__file__).parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    res_dir.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}", flush=True)

    health_samples   = load_health_csv(csv_path)
    security_samples = generate_security_samples(sec_samples)
    all_samples      = health_samples + security_samples
    random.shuffle(all_samples)

    n_val         = int(len(all_samples) * val_split)
    val_samples   = all_samples[:n_val]
    train_samples = all_samples[n_val:]
    print(f"Train: {len(train_samples)}  Val: {len(val_samples)}", flush=True)

    plot_class_distribution(train_samples, res_dir)

    train_loader = DataLoader(
        DITSecDataset(train_samples),
        batch_size=batch_size, shuffle=True, collate_fn=_collate,
    )
    val_loader = DataLoader(
        DITSecDataset(val_samples),
        batch_size=batch_size, shuffle=False, collate_fn=_collate,
    )

    model = DITSecV3().to(device)
    print(f"Parameters: {model.param_count():,}", flush=True)

    class_weights = compute_class_weights(train_samples, device)
    criterion     = nn.CrossEntropyLoss(weight=class_weights)
    optimizer     = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler     = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    history = {
        "train_loss": [], "train_acc": [],
        "val_loss":   [], "val_acc":   [],
    }
    best_val_f1             = 0.0
    best_ckpt               = out_dir / "dit_sec_v3_trained.pt"
    last_val_preds: List[int] = []
    last_val_labels: List[int] = []
    no_improve              = 0

    for epoch in range(1, epochs + 1):
        t_loss, t_acc, _, _ = run_epoch(
            model, train_loader, criterion, optimizer, device, train=True
        )
        v_loss, v_acc, v_preds, v_labels = run_epoch(
            model, val_loader, criterion, optimizer, device, train=False
        )
        scheduler.step()

        val_f1 = f1_score(v_labels, v_preds, average="macro", zero_division=0) if v_labels else 0.0

        history["train_loss"].append(t_loss)
        history["train_acc"].append(t_acc)
        history["val_loss"].append(v_loss)
        history["val_acc"].append(v_acc)

        improved = val_f1 > best_val_f1
        if improved:
            best_val_f1    = val_f1
            no_improve     = 0
            torch.save(model.state_dict(), best_ckpt)
            last_val_preds  = v_preds
            last_val_labels = v_labels
        else:
            no_improve += 1

        flag   = " ★" if improved else ""
        lr_now = optimizer.param_groups[0]["lr"]
        print(
            f"Epoch {epoch:3d}/{epochs}  "
            f"loss {t_loss:.4f}/{v_loss:.4f}  "
            f"acc {t_acc:.3f}/{v_acc:.3f}  "
            f"F1 {val_f1:.3f}  lr {lr_now:.2e}{flag}",
            flush=True,
        )

        if no_improve >= patience:
            print(
                f"Early stopping: no val F1 improvement for {patience} epochs",
                flush=True,
            )
            break

    # ── Plots ──────────────────────────────────────────────
    plot_training_curves(history, res_dir)
    if last_val_preds:
        plot_confusion_matrix(last_val_preds, last_val_labels, res_dir)

    # ── Classification report ──────────────────────────────
    if last_val_labels:
        present_labels = sorted(set(last_val_labels))
        report = classification_report(
            last_val_labels, last_val_preds,
            labels=present_labels,
            target_names=[CLASS_NAMES[i] for i in present_labels],
            zero_division=0,
        )
        print("\n" + report, flush=True)

    # ── JSON report ────────────────────────────────────────
    report_data = {
        "architecture": "DIT-Sec v3 — GNN+Mamba Hybrid",
        "encoders": {
            "yaml":    "YAMLGATEncoder (GATConv 3L×4H)",
            "metrics": "PrometheusMambaEncoder (SSM 2L)",
            "events":  "FalcoTransformerEncoder (4H×2L)",
            "entropy": "EntropyConv1DEncoder (Conv1D+SE)",
        },
        "fusion":          "MHCAFusion (3-head cross-attention)",
        "total_params":    model.param_count(),
        "epochs_trained":  len(history["train_loss"]),
        "best_val_f1":     round(best_val_f1, 4),
        "final_train_acc": round(history["train_acc"][-1], 4) if history["train_acc"] else 0,
        "final_val_acc":   round(history["val_acc"][-1], 4)   if history["val_acc"]   else 0,
        "final_train_loss": round(history["train_loss"][-1], 4) if history["train_loss"] else 0,
        "final_val_loss":   round(history["val_loss"][-1], 4)   if history["val_loss"]   else 0,
        "classes":         CLASS_NAMES,
        "checkpoint":      str(best_ckpt),
    }
    report_path = res_dir / "training_report.json"
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[Report] {report_path}", flush=True)
    print(f"[Best checkpoint] {best_ckpt}  (val F1={best_val_f1:.4f})", flush=True)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(description="Train DIT-Sec v3 GNN+Mamba model")
    p.add_argument(
        "--csv",
        default=str(Path(__file__).parent.parent / "health_model" / "dit-merged-complete.csv"),
    )
    p.add_argument("--epochs",      type=int,   default=30)
    p.add_argument("--lr",          type=float, default=2e-4)
    p.add_argument("--batch-size",  type=int,   default=32)
    p.add_argument("--val-split",   type=float, default=0.15)
    p.add_argument("--sec-samples", type=int,   default=4000)
    p.add_argument("--output-dir",  type=str,   default=None)
    p.add_argument("--seed",        type=int,   default=42)
    p.add_argument("--patience",    type=int,   default=7)
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    train(
        csv_path=args.csv,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        val_split=args.val_split,
        sec_samples=args.sec_samples,
        output_dir=args.output_dir,
        seed=args.seed,
        patience=args.patience,
    )
