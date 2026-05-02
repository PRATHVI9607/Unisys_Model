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


class SecurityDataset(Dataset):
    """
    Dataset for Security/Ransomware Model training.
    Focuses on ransomware patterns.
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
        labels = ["benign", "ransomware-critical", "sec-medium"]
        weights = [0.70, 0.15, 0.15]
        
        for _ in range(num_samples):
            label = random.choices(labels, weights=weights)[0]
            
            syscalls = self._generate_syscalls(label)
            entropy = self._generate_entropy(label)
            patterns = self._generate_patterns(label)
            
            sample = {
                "syscalls": syscalls,
                "entropy_series": entropy.tolist(),
                "file_patterns": patterns.tolist(),
                "label": label,
                "risk_score": 0.1 if label == "benign" else (0.93 if label == "ransomware-critical" else 0.55)
            }
            samples.append(sample)
        
        return samples
    
    def _generate_syscalls(self, label: str) -> List[Dict]:
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
        
        syscalls = []
        patterns = base_patterns.get(label, [])
        for i, call in enumerate(patterns):
            syscalls.append({"syscall": call["syscall"], "timestamp": i * 0.1, "path": call["path"]})
        
        for _ in range(random.randint(5, 30)):
            syscalls.append({
                "syscall": random.choice(["read", "stat", "access"]),
                "timestamp": random.random() * 2,
                "path": random.choice(["/etc/passwd", "/proc/cpuinfo"])
            })
        
        return syscalls
    
    def _generate_entropy(self, label: str) -> np.ndarray:
        if label == "ransomware-critical":
            entropy = np.random.rand(20) * 2 + 6.0
        elif label == "sec-medium":
            entropy = np.random.rand(20) * 3 + 4.0
        else:
            entropy = np.random.rand(20) * 4
        return entropy.astype(np.float32)
    
    def _generate_patterns(self, label: str) -> np.ndarray:
        if label == "ransomware-critical":
            patterns = np.random.randint(50, 200, 10).astype(np.float32)
        elif label == "sec-medium":
            patterns = np.random.randint(20, 80, 10).astype(np.float32)
        else:
            patterns = np.random.randint(5, 30, 10).astype(np.float32)
        return patterns
    
    def _compute_weights(self) -> torch.Tensor:
        counts = defaultdict(int)
        for s in self.samples:
            counts[s["label"]] += 1
        total = len(self.samples)
        weights = []
        for label in ["benign", "ransomware-critical", "sec-medium"]:
            w = total / (len(counts) * counts[label]) if counts[label] > 0 else 1.0
            weights.append(w)
        return torch.tensor(weights, dtype=torch.float32)
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Dict:
        return self.samples[idx]


def train_security_model(
    data_path: str = None,
    epochs: int = 40,
    lr: float = 2e-4,
    batch_size: int = 32,
    output_path: str = "models/security_model/security_model.pt"
) -> None:
    """Train Security/Ransomware Model."""
    from security_model import SecurityModel
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    
    model = SecurityModel().to(device)
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    dataset = SecurityDataset(data_path)
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
                        syscalls=batch["syscalls"][i],
                        entropy_series=torch.tensor(batch["entropy_series"][i], dtype=torch.float32),
                        file_patterns=torch.tensor(batch["file_patterns"][i], dtype=torch.float32)
                    )
                    outputs.append(result)
                except:
                    continue
            
            if not outputs:
                continue
            
            logits = torch.stack([o["logits"] for o in outputs])
            labels = torch.tensor(
                [["benign", "ransomware-critical", "sec-medium"].index(l) for l in batch["label"]]
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
    parser.add_argument("--output", type=str, default="models/security_model/security_model.pt")
    args = parser.parse_args()
    
    train_security_model(
        data_path=args.data,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        output_path=args.output
    )


if __name__ == "__main__":
    main()