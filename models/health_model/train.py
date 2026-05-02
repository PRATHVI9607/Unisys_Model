import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import json
import argparse
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
import random


class HealthDataset(Dataset):
    """
    Dataset for Health/Drift Model training.
    Focuses on config drift scenarios.
    """
    
    def __init__(self, data_path: str = None, mode: str = "train", val_split: float = 0.1):
        self.mode = mode
        self.samples = self._load_data(data_path)
        
        if val_split > 0:
            random.shuffle(self.samples)
            if mode == "train":
                self.samples = self.samples[:int(len(self.samples) * (1 - val_split))]
            else:
                self.samples = self.samples[int(len(self.samples) * (1 - val_split)):]
        
        self.class_weights = self._compute_weights()
    
    def _load_data(self, data_path: str) -> List[Dict]:
        samples = []
        if data_path and Path(data_path).exists():
            with open(data_path, 'r') as f:
                for line in f:
                    samples.append(json.loads(line.strip()))
        if not samples:
            samples = self._generate_synthetic(10000)
        return samples
    
    def _generate_synthetic(self, num_samples: int) -> List[Dict]:
        samples = []
        labels = ["benign", "health-critical", "perf-risk"]
        weights = [0.65, 0.20, 0.15]
        
        for _ in range(num_samples):
            label = random.choices(labels, weights=weights)[0]
            
            old_spec = self._create_base_spec()
            new_spec = self._apply_drift(old_spec, label)
            metrics = self._generate_metrics(label, new_spec)
            
            sample = {
                "old_spec": old_spec,
                "new_spec": new_spec,
                "metrics": metrics,
                "label": label,
                "risk_score": 0.1 if label == "benign" else (0.85 if label == "health-critical" else 0.65)
            }
            samples.append(sample)
        
        return samples
    
    def _create_base_spec(self) -> Dict:
        return {
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
        }
    
    def _apply_drift(self, old_spec: Dict, label: str) -> Dict:
        import copy
        new_spec = copy.deepcopy(old_spec)
        
        if label == "health-critical":
            cpu = random.randint(10, 100)
            new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = f"{cpu}m"
        elif label == "perf-risk":
            mem = random.randint(32, 128)
            new_spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = f"{mem}Mi"
        
        return new_spec
    
    def _generate_metrics(self, label: str, spec: Dict) -> np.ndarray:
        metrics = np.random.randn(60, 15).astype(np.float32) * 0.1
        
        if label == "health-critical":
            cpu = int(spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"].rstrip("m"))
            throttle = max(0, (1000 - cpu) / 1000)
            metrics[:, 0] += throttle + np.random.randn(60) * 0.2
        elif label == "perf-risk":
            mem = int(spec["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"].rstrip("Mi"))
            usage = min(1.0, (2048 - mem) / 2048)
            metrics[:, 1] += usage + np.random.randn(60) * 0.2
        
        return metrics
    
    def _compute_weights(self) -> torch.Tensor:
        counts = defaultdict(int)
        for s in self.samples:
            counts[s["label"]] += 1
        total = len(self.samples)
        weights = []
        for label in ["benign", "health-critical", "perf-risk"]:
            w = total / (len(counts) * counts[label]) if counts[label] > 0 else 1.0
            weights.append(w)
        return torch.tensor(weights, dtype=torch.float32)
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Dict:
        return self.samples[idx]


def train_health_model(
    data_path: str = None,
    epochs: int = 40,
    lr: float = 2e-4,
    batch_size: int = 32,
    output_path: str = "models/health_model/health_model.pt"
) -> None:
    """Train Health/Drift Model."""
    from health_model import HealthModel
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    
    model = HealthModel().to(device)
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    dataset = HealthDataset(data_path)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss(weight=dataset.class_weights.to(device))
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=10)
    
    best_acc = 0.0
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch in loader:
            optimizer.zero_grad()
            
            outputs = []
            for i in range(len(batch["label"])):
                try:
                    result = model(
                        old_spec=batch["old_spec"][i],
                        new_spec=batch["new_spec"][i],
                        metrics=torch.tensor(batch["metrics"][i], dtype=torch.float32)
                    )
                    outputs.append(result)
                except:
                    continue
            
            if not outputs:
                continue
            
            logits = torch.stack([o["logits"] for o in outputs])
            labels = torch.tensor(
                [["benign", "health-critical", "perf-risk"].index(l) for l in batch["label"]]
            ).to(device)
            
            loss = criterion(logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            preds = torch.argmax(logits, dim=-1)
            correct += (preds == labels).sum().item()
            total += len(labels)
        
        scheduler.step()
        acc = correct / total if total > 0 else 0.0
        
        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), output_path)
        
        print(f"Epoch {epoch+1}/{epochs} Loss: {total_loss/len(loader):.4f} Acc: {acc:.4f}")
    
    print(f"Training complete! Best accuracy: {best_acc:.4f}")
    print(f"Model saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, help="Training data path")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--output", type=str, default="models/health_model/health_model.pt")
    args = parser.parse_args()
    
    train_health_model(
        data_path=args.data,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        output_path=args.output
    )


if __name__ == "__main__":
    main()