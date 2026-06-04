import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
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


class KubeHealDataset(Dataset):
    """
    Dataset for DIT-Sec training.
    Supports synthetic generation via Chaos Mesh simulation.
    """
    
    def __init__(
        self,
        data_path: str,
        mode: str = "train",
        val_split: float = 0.1,
        augment: bool = True
    ):
        self.mode = mode
        self.augment = augment
        
        self.samples = self._load_data(data_path)
        
        if val_split > 0 and mode == "train":
            random.shuffle(self.samples)
            split_idx = int(len(self.samples) * (1 - val_split))
            self.samples = self.samples[:split_idx]
        elif val_split > 0 and mode == "val":
            random.shuffle(self.samples)
            split_idx = int(len(self.samples) * (1 - val_split))
            self.samples = self.samples[split_idx:]
        
        self.class_weights = self._compute_class_weights()
    
    def _load_data(self, data_path: str) -> List[Dict]:
        """Load training data from JSONL file."""
        samples = []
        
        if Path(data_path).exists():
            with open(data_path, 'r') as f:
                for line in f:
                    try:
                        sample = json.loads(line.strip())
                        samples.append(sample)
                    except json.JSONDecodeError:
                        continue
        
        if not samples and not Path(data_path).exists():
            samples = self._generate_synthetic(15000)
        
        return samples
    
    def _generate_synthetic(self, num_samples: int) -> List[Dict]:
        """
        Generate synthetic training data.
        Uses Chaos Mesh-style simulation patterns.
        """
        samples = []
        
        label_counts = defaultdict(int)
        
        for i in range(num_samples):
            label = random.choices(
                ["benign", "health-critical", "ransomware-critical", "sec-medium", "perf-risk"],
                weights=[0.60, 0.15, 0.10, 0.08, 0.07]
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
                sample["new_spec"] = self._apply_drift(
                    sample["old_spec"],
                    label
                )
                sample["metrics"] = self._generate_metrics(
                    label,
                    sample["new_spec"]
                )
            
            if label in ["ransomware-critical", "sec-medium"]:
                sample["syscalls"] = self._generate_syscalls(label)
                sample["entropy_series"] = self._generate_entropy(label)
            
            samples.append(sample)
        
        print(f"Generated {num_samples} synthetic samples")
        print(f"  Label distribution: {dict(label_counts)}")
        
        return samples
    
    def _apply_drift(self, old_spec: Dict, label: str) -> Dict:
        """Apply configuration drift based on label."""
        import copy
        new_spec = copy.deepcopy(old_spec)
        
        if label == "health-critical":
            cpu_val = random.randint(10, 100)
            new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = f"{cpu_val}m"
        
        elif label == "perf-risk":
            mem_val = random.randint(32, 128)
            new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = f"{mem_val}Mi"
        
        elif label in ["ransomware-critical", "sec-medium"]:
            new_spec["spec"]["template"]["spec"]["containers"][0]["image"] = "compromised:v1.0"
        
        return new_spec
    
    def _generate_metrics(self, label: str, new_spec: Dict) -> np.ndarray:
        """Generate synthetic Prometheus metrics."""
        num_steps = 60
        num_metrics = 15
        
        base_metrics = np.random.randn(num_steps, num_metrics) * 0.1
        
        if label == "health-critical":
            cpu_limit = int(new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"].rstrip("m"))
            cpu_throttle = max(0, (1000 - cpu_limit) / 1000) + np.random.randn(num_steps, 1) * 0.2
            base_metrics[:, 0] += cpu_throttle.squeeze()
        
        elif label == "perf-risk":
            mem_limit = int(new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"].rstrip("Mi"))
            mem_usage = min(1.0, (2048 - mem_limit) / 2048) + np.random.randn(num_steps, 1) * 0.2
            base_metrics[:, 1] += mem_usage.squeeze()
        
        return base_metrics.astype(np.float32)
    
    def _generate_syscalls(self, label: str) -> List[Dict]:
        """Generate synthetic Falco syscall events."""
        syscalls = []
        
        base_patterns = {
            "ransomware-critical": [
                {"syscall": "write", "path": "/data/file1.txt"},
                {"syscall": "write", "path": "/data/file2.txt"},
                {"syscall": "rename", "path": "/data/file1.txt"},
                {"syscall": "rename", "path": "/data/file2.txt"},
                {"syscall": "ftruncate", "path": "/data/file1.txt"},
            ],
            "sec-medium": [
                {"syscall": "write", "path": "/tmp/file.txt"},
                {"syscall": "write", "path": "/tmp/file2.txt"},
            ]
        }
        
        patterns = base_patterns.get(label, [])
        
        for i, call in enumerate(patterns):
            syscalls.append({
                "syscall": call["syscall"],
                "timestamp": i * 0.1,
                "path": call["path"]
            })
        
        for _ in range(random.randint(5, 20)):
            syscalls.append({
                "syscall": random.choice(["read", "stat", "access"]),
                "timestamp": random.random() * 2,
                "path": random.choice(["/etc/passwd", "/proc/cpuinfo", "/data/config.yaml"])
            })
        
        return syscalls
    
    def _generate_entropy(self, label: str) -> np.ndarray:
        """Generate synthetic entropy series."""
        num_timesteps = 20
        
        if label == "ransomware-critical":
            entropy = np.random.rand(num_timesteps) * 2 + 6.0
        elif label == "sec-medium":
            entropy = np.random.rand(num_timesteps) * 3 + 4.0
        else:
            entropy = np.random.rand(num_timesteps) * 4
        
        return entropy.astype(np.float32)
    
    def _label_to_risk_score(self, label: str) -> float:
        """Convert label to risk score."""
        mapping = {
            "benign": 0.1,
            "health-critical": 0.85,
            "ransomware-critical": 0.93,
            "sec-medium": 0.55,
            "perf-risk": 0.65
        }
        return mapping.get(label, 0.1)
    
    def _compute_class_weights(self) -> torch.Tensor:
        """Compute class weights for imbalanced data."""
        counts = defaultdict(int)
        for sample in self.samples:
            counts[sample["label"]] += 1
        
        total = len(self.samples)
        weights = []
        for label in ["benign", "health-critical", "ransomware-critical", "sec-medium", "perf-risk"]:
            count = counts[label]
            weight = total / (len(counts) * count) if count > 0 else 1.0
            weights.append(weight)
        
        return torch.tensor(weights, dtype=torch.float32)
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Dict:
        sample = self.samples[idx]
        
        return {
            "old_spec": sample.get("old_spec"),
            "new_spec": sample.get("new_spec"),
            "metrics": sample.get("metrics"),
            "syscalls": sample.get("syscalls"),
            "entropy_series": sample.get("entropy_series"),
            "label": sample.get("label"),
            "risk_score": sample.get("risk_score")
        }


def train_epoch(
    model: DITSecModel,
    dataloader: DataLoader,
    optimizer: optim.Optimizer,
    criterion: nn.Module,
    device: torch.device,
    epoch: int
) -> Dict[str, float]:
    """Train one epoch."""
    model.train()
    
    total_loss = 0.0
    correct = 0
    total = 0
    
    for batch_idx, batch in enumerate(dataloader):
        if batch["label"] is None:
            continue
        
        optimizer.zero_grad()
        
        batch_samples = []
        for i in range(len(batch["label"])):
            sample = {
                "old_spec": batch["old_spec"][i] if batch["old_spec"] else None,
                "new_spec": batch["new_spec"][i] if batch["new_spec"] else None,
                "metrics": batch["metrics"][i] if batch["metrics"] is not None else None,
                "syscalls": batch["syscalls"][i] if batch["syscalls"] else None,
                "entropy_series": batch["entropy_series"][i] if batch["entropy_series"] is not None else None
            }
            batch_samples.append(sample)
        
        outputs = []
        for sample in batch_samples:
            try:
                result = model(
                    old_spec=sample.get("old_spec"),
                    new_spec=sample.get("new_spec"),
                    metrics=sample.get("metrics"),
                    syscalls=sample.get("syscalls"),
                    entropy_series=sample.get("entropy_series"),
                    return_embeddings=False
                )
                outputs.append(result)
            except Exception as e:
                continue
        
        if not outputs:
            continue
        
        logits = torch.stack([o["logits"] for o in outputs])
        risk_scores = torch.tensor(
            [float(o["risk_score"]) for o in outputs],
            device=device
        ).unsqueeze(1)
        
        labels = batch["label"]
        label_idx = torch.tensor(
            [["benign", "health-critical", "ransomware-critical", "sec-medium", "perf-risk"].index(l)]
            for l in labels
        ).to(device)
        
        class_loss = criterion(logits, label_idx)
        
        risk_loss = nn.functional.mse_loss(
            torch.stack([o["risk_score"] for o in outputs]).squeeze(),
            risk_scores.squeeze()
        )
        
        loss = class_loss + 0.5 * risk_loss
        
        loss.backward()
        
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        
        optimizer.step()
        
        total_loss += loss.item()
        
        preds = torch.argmax(logits, dim=-1)
        correct += (preds == label_idx).sum().item()
        total += len(label_idx)
    
    return {
        "loss": total_loss / len(dataloader),
        "accuracy": correct / total if total > 0 else 0.0
    }


def validate(
    model: DITSecModel,
    dataloader: DataLoader,
    criterion: nn.Module,
    device: torch.device
) -> Dict[str, float]:
    """Validate model."""
    model.eval()
    
    total_loss = 0.0
    correct = 0
    total = 0
    
    all_preds = []
    all_labels = []
    all_risk_scores = []
    all_true_scores = []
    
    with torch.no_grad():
        for batch in dataloader:
            outputs = []
            for i in range(len(batch.get("label", []))):
                try:
                    result = model(
                        old_spec=batch["old_spec"][i] if batch["old_spec"] else None,
                        new_spec=batch["new_spec"][i] if batch["new_spec"] else None,
                        metrics=batch["metrics"][i] if batch["metrics"] is not None else None,
                        syscalls=batch["syscalls"][i] if batch["syscalls"] else None,
                        entropy_series=batch["entropy_series"][i] if batch["entropy_series"] is not None else None
                    )
                    outputs.append(result)
                except:
                    continue
            
            if not outputs:
                continue
            
            logits = torch.stack([o["logits"] for o in outputs])
            risk_scores = torch.stack([o["risk_score"] for o in outputs])
            
            labels = batch["label"]
            label_idx = torch.tensor(
                [0] * len(outputs)
            ).to(device)
            
            for l in labels:
                try:
                    label_idx = torch.cat([
                        label_idx,
                        torch.tensor(
                            [["benign", "health-critical", "ransomware-critical", "sec-medium", "perf-risk"].index(l)]
                        ).to(device)
                    ])
                except:
                    pass
            
            loss = criterion(logits, label_idx)
            total_loss += loss.item()
            
            preds = torch.argmax(logits, dim=-1)
            correct += (preds == label_idx[:len(preds)]).sum().item()
            total += len(preds)
            
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels)
            all_risk_scores.extend(risk_scores.cpu().tolist())
            all_true_scores.extend(batch["risk_score"])
    
    accuracy = correct / total if total > 0 else 0.0
    
    if all_risk_scores and all_true_scores:
        risk_mse = np.mean([
            (p - t) ** 2
            for p, t in zip(all_risk_scores, all_true_scores)
        ])
    else:
        risk_mse = float('inf')
    
    return {
        "loss": total_loss / len(dataloader) if len(dataloader) > 0 else 0.0,
        "accuracy": accuracy,
        "risk_mse": risk_mse
    }


def train_dit_sec(
    data_path: str,
    model_arch: str = "gnn_mamba",
    epochs: int = 40,
    lr: float = 2e-4,
    batch_size: int = 32,
    output_path: str = "models/dit_sec_v3.pt",
    checkpoint_dir: str = "models/checkpoints"
) -> None:
    """
    Train DIT-Sec v3 model.
    
    Args:
        data_path: Path to training data JSONL
        model_arch: Model architecture (gnn_mamba, pure_transformer, etc)
        epochs: Number of training epochs
        lr: Learning rate
        batch_size: Batch size
        output_path: Output model path
        checkpoint_dir: Checkpoint directory
    """
    Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    model = DITSecModel().to(device)
    
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    train_dataset = KubeHealDataset(data_path, mode="train", val_split=0.1)
    val_dataset = KubeHealDataset(data_path, mode="val", val_split=0.1)
    
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0
    )
    
    criterion = nn.CrossEntropyLoss(weight=train_dataset.class_weights.to(device))
    
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
        optimizer,
        T_0=10,
        T_mult=2
    )
    
    best_val_acc = 0.0
    best_val_loss = float('inf')
    
    for epoch in range(epochs):
        train_metrics = train_epoch(
            model, train_loader, optimizer, criterion, device, epoch
        )
        
        val_metrics = validate(model, val_loader, criterion, device)
        
        scheduler.step()
        
        print(
            f"Epoch {epoch+1}/{epochs} "
            f"Train Loss: {train_metrics['loss']:.4f} "
            f"Train Acc: {train_metrics['accuracy']:.4f} "
            f"Val Loss: {val_metrics['loss']:.4f} "
            f"Val Acc: {val_metrics['accuracy']:.4f}"
        )
        
        if val_metrics['loss'] < best_val_loss:
            best_val_loss = val_metrics['loss']
            best_val_acc = val_metrics['accuracy']
            
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_loss': val_metrics['loss'],
                'val_acc': val_metrics['accuracy']
            }, output_path)
            
            print(f"  -> Saved best model to {output_path}")
    
    print(f"\nTraining complete!")
    print(f"Best validation accuracy: {best_val_acc:.4f}")
    print(f"Model saved to: {output_path}")
    
    return model


def main():
    parser = argparse.ArgumentParser(description="Train DIT-Sec v3 Model")
    parser.add_argument("--data", type=str, required=True, help="Path to training data")
    parser.add_argument("--model-arch", type=str, default="gnn_mamba", help="Model architecture")
    parser.add_argument("--epochs", type=int, default=40, help="Number of epochs")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--output", type=str, default="models/dit_sec_v3.pt", help="Output model path")
    
    args = parser.parse_args()
    
    train_dit_sec(
        data_path=args.data,
        model_arch=args.model_arch,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        output_path=args.output
    )


if __name__ == "__main__":
    main()