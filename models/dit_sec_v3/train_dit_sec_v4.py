import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import json
import argparse
import traceback
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict
import random

from dit_sec_model import (
    DITSecModel,
    create_sample_data,
    YAMLGATEncoder,
    PrometheusMambaEncoder,
    FalcoTransformerEncoder,
    EntropyConv1DEncoder
)

LABEL_LIST = ["benign", "health-critical", "ransomware-critical", "sec-medium", "perf-risk"]


def custom_collate_fn(batch):
    """Custom collate that handles None values and variable-length data."""
    result = {}
    for key in batch[0].keys():
        values = [sample[key] for sample in batch]
        if all(v is None for v in values):
            result[key] = values
        elif any(v is None for v in values):
            result[key] = values
        elif isinstance(values[0], np.ndarray):
            result[key] = values
        elif isinstance(values[0], str):
            result[key] = values
        elif isinstance(values[0], dict):
            result[key] = values
        elif isinstance(values[0], list):
            result[key] = values
        elif isinstance(values[0], (int, float)):
            result[key] = torch.tensor(values, dtype=torch.float32)
        else:
            result[key] = values
    return result


def _get_field(batch_field, idx):
    """Safely extract per-sample field from collated batch."""
    if batch_field is None:
        return None
    if isinstance(batch_field, (list, tuple)):
        val = batch_field[idx]
        return None if val is None else val
    return None


class KubeHealDataset(Dataset):
    """Dataset for DIT-Sec training with synthetic Chaos Mesh simulation."""

    def __init__(self, data_path: str, mode: str = "train",
                 val_split: float = 0.1, augment: bool = True):
        self.mode = mode
        self.augment = augment
        self.samples = self._load_data(data_path)

        if val_split > 0:
            random.shuffle(self.samples)
            split_idx = int(len(self.samples) * (1 - val_split))
            self.samples = self.samples[:split_idx] if mode == "train" else self.samples[split_idx:]

        self.class_weights = self._compute_class_weights()

    def _load_data(self, data_path: str) -> List[Dict]:
        samples = []
        if Path(data_path).exists():
            with open(data_path, 'r') as f:
                for line in f:
                    try:
                        samples.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        if not samples:
            samples = self._generate_synthetic(15000)
        return samples

    def _generate_synthetic(self, num_samples: int) -> List[Dict]:
        samples = []
        label_counts = defaultdict(int)

        for _ in range(num_samples):
            label = random.choices(
                LABEL_LIST, weights=[0.60, 0.15, 0.10, 0.08, 0.07]
            )[0]
            label_counts[label] += 1

            sample = {
                "old_spec": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "spec": {
                        "replicas": random.choice([1, 2, 3, 5]),
                        "template": {
                            "spec": {
                                "containers": [{
                                    "name": "app",
                                    "image": f"nginx:{random.choice(['latest', '1.21', '1.20'])}",
                                    "resources": {
                                        "limits": {
                                            "cpu": f"{random.randint(100, 1000)}m",
                                            "memory": f"{random.randint(128, 2048)}Mi"
                                        },
                                        "requests": {
                                            "cpu": f"{random.randint(50, 500)}m",
                                            "memory": f"{random.randint(64, 1024)}Mi"
                                        }
                                    }
                                }]
                            }
                        }
                    }
                },
                "new_spec": None,
                "metrics": None,
                "syscalls": None,
                "entropy_series": None,
                "label": label,
                "risk_score": self._label_to_risk_score(label)
            }

            if label != "benign":
                sample["new_spec"] = self._apply_drift(sample["old_spec"], label)
                sample["metrics"] = self._generate_metrics(label, sample["new_spec"])

            if label in ["ransomware-critical", "sec-medium"]:
                sample["syscalls"] = self._generate_syscalls(label)
                sample["entropy_series"] = self._generate_entropy(label)

            samples.append(sample)

        print(f"Generated {num_samples} synthetic samples")
        print(f"  Label distribution: {dict(label_counts)}")
        return samples

    def _apply_drift(self, old_spec: Dict, label: str) -> Dict:
        import copy
        new_spec = copy.deepcopy(old_spec)
        c = new_spec["spec"]["template"]["spec"]["containers"][0]
        if label == "health-critical":
            c["resources"]["limits"]["cpu"] = f"{random.randint(10, 100)}m"
        elif label == "perf-risk":
            c["resources"]["limits"]["memory"] = f"{random.randint(32, 128)}Mi"
        elif label in ["ransomware-critical", "sec-medium"]:
            c["image"] = "compromised:v1.0"
        return new_spec

    def _generate_metrics(self, label: str, new_spec: Dict) -> np.ndarray:
        num_steps, num_metrics = 60, 15
        base = np.random.randn(num_steps, num_metrics) * 0.1
        c = new_spec["spec"]["template"]["spec"]["containers"][0]
        if label == "health-critical":
            cpu_limit = int(c["resources"]["limits"]["cpu"].rstrip("m"))
            base[:, 0] += max(0, (1000 - cpu_limit) / 1000) + np.random.randn(num_steps) * 0.2
        elif label == "perf-risk":
            mem_limit = int(c["resources"]["limits"]["memory"].rstrip("Mi"))
            base[:, 1] += min(1.0, (2048 - mem_limit) / 2048) + np.random.randn(num_steps) * 0.2
        return base.astype(np.float32)

    def _generate_syscalls(self, label: str) -> List[Dict]:
        patterns = {
            "ransomware-critical": [
                {"syscall": "write",     "path": "/data/file1.txt"},
                {"syscall": "write",     "path": "/data/file2.txt"},
                {"syscall": "rename",    "path": "/data/file1.txt"},
                {"syscall": "rename",    "path": "/data/file2.txt"},
                {"syscall": "ftruncate", "path": "/data/file1.txt"},
            ],
            "sec-medium": [
                {"syscall": "write", "path": "/tmp/file.txt"},
                {"syscall": "write", "path": "/tmp/file2.txt"},
            ]
        }
        syscalls = [
            {"syscall": c["syscall"], "timestamp": i * 0.1, "path": c["path"]}
            for i, c in enumerate(patterns.get(label, []))
        ]
        for _ in range(random.randint(5, 20)):
            syscalls.append({
                "syscall": random.choice(["read", "stat", "access"]),
                "timestamp": random.random() * 2,
                "path": random.choice(["/etc/passwd", "/proc/cpuinfo", "/data/config.yaml"])
            })
        return syscalls

    def _generate_entropy(self, label: str) -> np.ndarray:
        n = 20
        if label == "ransomware-critical":
            return (np.random.rand(n) * 2 + 6.0).astype(np.float32)
        elif label == "sec-medium":
            return (np.random.rand(n) * 3 + 4.0).astype(np.float32)
        return (np.random.rand(n) * 4).astype(np.float32)

    def _label_to_risk_score(self, label: str) -> float:
        return {"benign": 0.1, "health-critical": 0.85,
                "ransomware-critical": 0.93, "sec-medium": 0.55,
                "perf-risk": 0.65}.get(label, 0.1)

    def _compute_class_weights(self) -> torch.Tensor:
        counts = defaultdict(int)
        for s in self.samples:
            counts[s["label"]] += 1
        total = len(self.samples)
        weights = [
            total / (len(counts) * counts[l]) if counts[l] > 0 else 1.0
            for l in LABEL_LIST
        ]
        return torch.tensor(weights, dtype=torch.float32)

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        s = self.samples[idx]
        return {
            "old_spec":       s.get("old_spec"),
            "new_spec":       s.get("new_spec"),
            "metrics":        s.get("metrics"),
            "syscalls":       s.get("syscalls"),
            "entropy_series": s.get("entropy_series"),
            "label":          s.get("label"),
            "risk_score":     float(s.get("risk_score", 0.0))
        }


def run_model_on_sample(model, sample, device):
    """
    Safely run model forward pass on a single sample dict.
    Handles tensor conversion, device placement, and shape fixes.
    Returns model output dict or None on failure.
    """
    old_spec = sample.get("old_spec")
    new_spec = sample.get("new_spec")
    metrics  = sample.get("metrics")
    syscalls = sample.get("syscalls")
    entropy  = sample.get("entropy_series")

    # Convert numpy metrics → tensor [1, T, C]
    if metrics is not None:
        if isinstance(metrics, np.ndarray):
            metrics = torch.tensor(metrics, dtype=torch.float32)
        if metrics.dim() == 2:
            metrics = metrics.unsqueeze(0)  # [1, 60, 15]
        metrics = metrics.to(device)

    # Convert numpy entropy → tensor [T]
    if entropy is not None:
        if isinstance(entropy, np.ndarray):
            entropy = torch.tensor(entropy, dtype=torch.float32)
        if entropy.dim() == 0:
            entropy = entropy.unsqueeze(0)
        entropy = entropy.to(device)

    # Need at least one valid modality
    if old_spec is None and new_spec is None and metrics is None:
        return None

    # Skip YAML encoder if either spec missing
    if old_spec is None or new_spec is None:
        old_spec = new_spec = None

    return model(
        old_spec=old_spec,
        new_spec=new_spec,
        metrics=metrics,
        syscalls=syscalls,
        entropy_series=entropy,
        return_embeddings=False
    )


def train_epoch(model, dataloader, optimizer, criterion, device, epoch, debug=False):
    model.train()
    total_loss, correct, total, num_batches = 0.0, 0, 0, 0
    first_error_shown = False

    for batch_idx, batch in enumerate(dataloader):
        labels = batch.get("label", [])
        if not labels:
            continue

        optimizer.zero_grad()
        outputs, valid_labels, valid_true_risks = [], [], []

        for i in range(len(labels)):
            sample = {
                "old_spec":       _get_field(batch.get("old_spec"), i),
                "new_spec":       _get_field(batch.get("new_spec"), i),
                "metrics":        _get_field(batch.get("metrics"), i),
                "syscalls":       _get_field(batch.get("syscalls"), i),
                "entropy_series": _get_field(batch.get("entropy_series"), i),
            }
            try:
                result = run_model_on_sample(model, sample, device)
                if result is not None:
                    outputs.append(result)
                    valid_labels.append(labels[i])
                    rs = batch["risk_score"]
                    valid_true_risks.append(
                        rs[i].item() if isinstance(rs, torch.Tensor) else float(rs[i])
                    )
            except Exception as e:
                if debug and not first_error_shown:
                    print(f"\n[DEBUG] batch={batch_idx} sample={i} label={labels[i]}")
                    traceback.print_exc()
                    first_error_shown = True

        if not outputs:
            continue

        logits = torch.stack([o["logits"] for o in outputs])  # [B, 5]
        label_idx = torch.tensor(
            [LABEL_LIST.index(l) for l in valid_labels], dtype=torch.long
        ).to(device)

        pred_risk = torch.stack([
            o["risk_score"].squeeze() if isinstance(o["risk_score"], torch.Tensor)
            else torch.tensor(float(o["risk_score"]))
            for o in outputs
        ]).to(device)

        true_risk = torch.tensor(valid_true_risks, dtype=torch.float32).to(device)

        class_loss = criterion(logits, label_idx)
        risk_loss  = nn.functional.mse_loss(pred_risk, true_risk)
        loss = class_loss + 0.5 * risk_loss

        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        total_loss  += loss.item()
        num_batches += 1
        preds = torch.argmax(logits, dim=-1)
        correct += (preds == label_idx).sum().item()
        total   += len(label_idx)

    return {
        "loss":     total_loss / num_batches if num_batches > 0 else 0.0,
        "accuracy": correct / total          if total > 0       else 0.0
    }


def validate(model, dataloader, criterion, device):
    model.eval()
    total_loss, correct, total, num_batches = 0.0, 0, 0, 0
    all_risk_scores, all_true_scores = [], []

    with torch.no_grad():
        for batch in dataloader:
            labels = batch.get("label", [])
            if not labels:
                continue

            outputs, valid_labels, valid_true_risks = [], [], []

            for i in range(len(labels)):
                sample = {
                    "old_spec":       _get_field(batch.get("old_spec"), i),
                    "new_spec":       _get_field(batch.get("new_spec"), i),
                    "metrics":        _get_field(batch.get("metrics"), i),
                    "syscalls":       _get_field(batch.get("syscalls"), i),
                    "entropy_series": _get_field(batch.get("entropy_series"), i),
                }
                try:
                    result = run_model_on_sample(model, sample, device)
                    if result is not None:
                        outputs.append(result)
                        valid_labels.append(labels[i])
                        rs = batch["risk_score"]
                        valid_true_risks.append(
                            rs[i].item() if isinstance(rs, torch.Tensor) else float(rs[i])
                        )
                except Exception:
                    continue

            if not outputs:
                continue

            logits = torch.stack([o["logits"] for o in outputs])
            label_idx = torch.tensor(
                [LABEL_LIST.index(l) for l in valid_labels], dtype=torch.long
            ).to(device)

            loss = criterion(logits, label_idx)
            total_loss  += loss.item()
            num_batches += 1

            preds = torch.argmax(logits, dim=-1)
            correct += (preds == label_idx).sum().item()
            total   += len(label_idx)

            for o in outputs:
                rs = o["risk_score"]
                all_risk_scores.append(rs.item() if isinstance(rs, torch.Tensor) else float(rs))
            all_true_scores.extend(valid_true_risks)

    risk_mse = float(np.mean([(p - t) ** 2 for p, t in zip(all_risk_scores, all_true_scores)])) \
               if all_risk_scores else float('inf')

    return {
        "loss":     total_loss / num_batches if num_batches > 0 else 0.0,
        "accuracy": correct / total          if total > 0       else 0.0,
        "risk_mse": risk_mse
    }


def train_dit_sec(
    data_path: str,
    model_arch: str = "gnn_mamba",
    epochs: int = 40,
    lr: float = 2e-4,
    batch_size: int = 32,
    output_path: str = "models/dit_sec_v3.pt",
    checkpoint_dir: str = "models/checkpoints",
    debug: bool = False
) -> DITSecModel:

    Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    model = DITSecModel().to(device)
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    train_dataset = KubeHealDataset(data_path, mode="train", val_split=0.1)
    val_dataset   = KubeHealDataset(data_path, mode="val",   val_split=0.1)

    train_loader = DataLoader(train_dataset, batch_size=batch_size,
                              shuffle=True,  num_workers=0, collate_fn=custom_collate_fn)
    val_loader   = DataLoader(val_dataset,   batch_size=batch_size,
                              shuffle=False, num_workers=0, collate_fn=custom_collate_fn)

    criterion = nn.CrossEntropyLoss(weight=train_dataset.class_weights.to(device))
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=10, T_mult=2)

    best_val_loss = float('inf')
    best_val_acc  = 0.0

    for epoch in range(epochs):
        train_m = train_epoch(model, train_loader, optimizer, criterion, device, epoch, debug)
        val_m   = validate(model, val_loader, criterion, device)
        scheduler.step()

        print(
            f"Epoch {epoch+1:03d}/{epochs} | "
            f"Train Loss: {train_m['loss']:.4f} | Train Acc: {train_m['accuracy']:.4f} | "
            f"Val Loss: {val_m['loss']:.4f} | Val Acc: {val_m['accuracy']:.4f} | "
            f"Risk MSE: {val_m['risk_mse']:.4f}"
        )

        if val_m['loss'] < best_val_loss:
            best_val_loss = val_m['loss']
            best_val_acc  = val_m['accuracy']
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_loss': val_m['loss'],
                'val_acc':  val_m['accuracy']
            }, output_path)
            print(f"  -> Saved best model (val_loss={best_val_loss:.4f}) to {output_path}")

    print(f"\nTraining complete! Best val accuracy: {best_val_acc:.4f}")
    print(f"Model saved to: {output_path}")
    return model


def main():
    parser = argparse.ArgumentParser(description="Train DIT-Sec v3 Model")
    parser.add_argument("--data",       type=str,   required=True,                  help="Path to training data JSONL")
    parser.add_argument("--model-arch", type=str,   default="gnn_mamba",            help="Model architecture")
    parser.add_argument("--epochs",     type=int,   default=40,                     help="Number of epochs")
    parser.add_argument("--lr",         type=float, default=2e-4,                   help="Learning rate")
    parser.add_argument("--batch-size", type=int,   default=32,                     help="Batch size")
    parser.add_argument("--output",     type=str,   default="models/dit_sec_v3.pt", help="Output model path")
    parser.add_argument("--debug",      action="store_true",                         help="Print first forward-pass error traceback")
    args = parser.parse_args()

    train_dit_sec(
        data_path=args.data,
        model_arch=args.model_arch,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        output_path=args.output,
        debug=args.debug
    )


if __name__ == "__main__":
    main()
