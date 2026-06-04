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
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:           # skip empty lines
                        continue
                    try:
                        samples.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"Warning: skipping line {line_num} — {e}")
                        continue
        if not samples:
            print("No valid data found — generating synthetic dataset...")
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
                "metrics": metrics.tolist(),
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


# ─────────────────────────────────────────────
# Lightweight HealthModel (no torch_geometric)
# ─────────────────────────────────────────────

def _spec_to_vector(spec) -> torch.Tensor:
    """Extract a fixed-size numeric vector from a K8s spec dict."""
    try:
        container = spec["spec"]["template"]["spec"]["containers"][0]
        resources = container.get("resources", {})

        def parse_cpu(val: str) -> float:
            if val is None:
                return 0.0
            val = str(val)
            if val.endswith("m"):
                return float(val[:-1]) / 1000.0
            return float(val)

        def parse_mem(val: str) -> float:
            if val is None:
                return 0.0
            val = str(val)
            if val.endswith("Mi"):
                return float(val[:-2])
            if val.endswith("Gi"):
                return float(val[:-2]) * 1024.0
            return float(val)

        lim_cpu  = parse_cpu(resources.get("limits",   {}).get("cpu"))
        lim_mem  = parse_mem(resources.get("limits",   {}).get("memory"))
        req_cpu  = parse_cpu(resources.get("requests", {}).get("cpu"))
        req_mem  = parse_mem(resources.get("requests", {}).get("memory"))
        replicas = float(spec["spec"].get("replicas", 1))

        return torch.tensor([lim_cpu, lim_mem, req_cpu, req_mem, replicas],
                            dtype=torch.float32)
    except Exception:
        return torch.zeros(5, dtype=torch.float32)


class HealthModel(nn.Module):
    """
    Health / config-drift classifier.
    Inputs : old_spec dict, new_spec dict, metrics tensor (60×15)
    Output : dict with keys 'logits' (3,) and 'risk_score' (scalar)
    """

    METRICS_DIM  = 60 * 15   # flattened
    SPEC_DIM     = 5          # per spec vector
    HIDDEN       = 128
    NUM_CLASSES  = 3

    def __init__(self):
        super().__init__()

        # metrics encoder
        self.metrics_enc = nn.Sequential(
            nn.Linear(self.METRICS_DIM, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, self.HIDDEN),
            nn.ReLU(),
        )

        # spec-diff encoder
        self.spec_enc = nn.Sequential(
            nn.Linear(self.SPEC_DIM * 2, 64),
            nn.ReLU(),
            nn.Linear(64, self.HIDDEN // 2),
            nn.ReLU(),
        )

        # classifier head
        self.classifier = nn.Sequential(
            nn.Linear(self.HIDDEN + self.HIDDEN // 2, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, self.NUM_CLASSES),
        )

        self.risk_head = nn.Sequential(
            nn.Linear(self.HIDDEN + self.HIDDEN // 2, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, old_spec, new_spec, metrics: torch.Tensor) -> Dict:
        # metrics: (60, 15)  →  flatten
        m = metrics.view(-1).unsqueeze(0)          # (1, 900)
        m_feat = self.metrics_enc(m)               # (1, 128)

        # spec vectors
        old_vec = _spec_to_vector(old_spec).unsqueeze(0)   # (1, 5)
        new_vec = _spec_to_vector(new_spec).unsqueeze(0)   # (1, 5)
        s_feat  = self.spec_enc(torch.cat([old_vec, new_vec], dim=-1))  # (1, 64)

        combined = torch.cat([m_feat, s_feat], dim=-1)     # (1, 192)

        logits     = self.classifier(combined).squeeze(0)  # (3,)
        risk_score = self.risk_head(combined).squeeze()     # scalar

        return {"logits": logits, "risk_score": risk_score}


# ─────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────

def train_health_model(
    data_path: str = None,
    epochs: int = 40,
    lr: float = 2e-4,
    batch_size: int = 32,
    output_path: str = "models/health_model/health_model.pt"
) -> None:
    """Train Health/Drift Model."""

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    model = HealthModel().to(device)
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")

    dataset = HealthDataset(data_path)
    loader  = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss(weight=dataset.class_weights.to(device))
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=10)

    label_map = ["benign", "health-critical", "perf-risk"]
    best_acc  = 0.0

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        correct    = 0
        total      = 0
        skipped    = 0

        for batch in loader:
            optimizer.zero_grad()

            outputs     = []
            valid_labels = []

            for i in range(len(batch["label"])):
                try:
                    metrics_raw = batch["metrics"][i]
                    if isinstance(metrics_raw, torch.Tensor):
                        metrics_t = metrics_raw.float()
                    else:
                        metrics_t = torch.tensor(metrics_raw, dtype=torch.float32)

                    # ensure shape (60, 15)
                    if metrics_t.numel() == 60 * 15:
                        metrics_t = metrics_t.view(60, 15)
                    else:
                        skipped += 1
                        continue

                    result = model(
                        old_spec=batch["old_spec"][i],
                        new_spec=batch["new_spec"][i],
                        metrics=metrics_t.to(device),
                    )
                    outputs.append(result)
                    valid_labels.append(batch["label"][i])

                except Exception as e:
                    skipped += 1
                    continue

            if not outputs:
                continue

            logits = torch.stack([o["logits"] for o in outputs])          # (N, 3)
            labels = torch.tensor(
                [label_map.index(l) for l in valid_labels],
                dtype=torch.long,
                device=device,
            )

            loss = criterion(logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            total_loss += loss.item()
            preds   = torch.argmax(logits, dim=-1)
            correct += (preds == labels).sum().item()
            total   += len(labels)

        scheduler.step()
        acc = correct / total if total > 0 else 0.0

        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), output_path)

        print(f"Epoch {epoch+1}/{epochs}  Loss: {total_loss/max(len(loader),1):.4f}  Acc: {acc:.4f}"
              + (f"  (skipped {skipped})" if skipped else ""))

    print(f"\nTraining complete!  Best accuracy: {best_acc:.4f}")
    print(f"Model saved to: {output_path}")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",       type=str,   help="Training data path (JSONL)")
    parser.add_argument("--epochs",     type=int,   default=40)
    parser.add_argument("--lr",         type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int,   default=32)
    parser.add_argument("--output",     type=str,   default="models/health_model/health_model.pt")
    args = parser.parse_args()

    train_health_model(
        data_path=args.data,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()