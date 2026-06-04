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
import csv


def custom_collate_fn(batch):
    """Custom collate function to handle nested dicts and variable-sized specs."""
    collated = {
        "old_spec": [],
        "new_spec": [],
        "metrics": [],
        "label": [],
        "risk_score": [],
        "severity": [],
        "phase": [],
        "app_name": []
    }
    
    for item in batch:
        collated["old_spec"].append(item["old_spec"])
        collated["new_spec"].append(item["new_spec"])
        collated["metrics"].append(torch.tensor(item["metrics"], dtype=torch.float32))
        collated["label"].append(item["label"])
        collated["risk_score"].append(item.get("risk_score", 0.5))
        collated["severity"].append(item.get("severity", 1.0))
        collated["phase"].append(item.get("phase", "steady"))
        collated["app_name"].append(item.get("app_name", "unknown"))
    
    # Stack tensors
    collated["metrics"] = torch.stack(collated["metrics"])
    collated["risk_score"] = torch.tensor(collated["risk_score"], dtype=torch.float32)
    collated["severity"] = torch.tensor(collated["severity"], dtype=torch.float32)
    
    return collated


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
        
        # Try loading from CSV if path is provided
        if data_path and Path(data_path).exists():
            try:
                if data_path.endswith('.csv'):
                    samples = self._process_csv_data(data_path)
                elif data_path.endswith('.jsonl'):
                    with open(data_path, 'r') as f:
                        for line in f:
                            samples.append(json.loads(line.strip()))
            except Exception as e:
                print(f"Error loading data from {data_path}: {e}")
        
        if not samples:
            samples = self._generate_synthetic(10000)
        
        return samples
    
    def _process_csv_data(self, csv_path: str) -> List[Dict]:
        """Process CSV data into samples for training."""
        samples = []
        
        # Map operational labels to model classes
        label_mapping = {
            "Benign_Or_Subtle": "benign",
            "Harmful_Security_Breach": "health-critical",
            "Harmful_Performance_Degradation": "perf-risk",
            "Harmful_Critical_Outage": "health-critical",
            "Harmful_Multi_Vector": "health-critical"
        }
        
        label_counts = defaultdict(int)
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    try:
                        # Extract label from operational_label column
                        op_label = str(row.get('operational_label', 'Benign_Or_Subtle')).strip()
                        label_counts[op_label] += 1
                        label = label_mapping.get(op_label, "benign")
                        
                        # Extract severity for risk score
                        try:
                            severity = float(row.get('severity', 1)) if row.get('severity') else 1.0
                        except (ValueError, TypeError):
                            severity = 1.0
                        
                        # Parse JSON specs if available
                        old_spec = self._parse_json_field(row.get('baseline_json'))
                        new_spec = self._parse_json_field(row.get('live_json'))
                        
                        # Extract metrics as numpy array
                        metrics = self._extract_metrics(row)
                        
                        # Calculate risk score based on severity and metrics
                        risk_score = min(1.0, severity / 3.0)
                        
                        sample = {
                            "old_spec": old_spec,
                            "new_spec": new_spec,
                            "metrics": metrics,
                            "label": label,
                            "risk_score": risk_score,
                            "severity": severity,
                            "phase": str(row.get('phase', 'steady')),
                            "app_name": str(row.get('app_name', 'unknown'))
                        }
                        samples.append(sample)
                    except Exception as e:
                        if idx < 3:
                            print(f"Error processing row {idx}: {e}")
                        continue
        except Exception as e:
            print(f"Error reading CSV file {csv_path}: {e}")
        
        # Print actual label distribution from CSV
        print(f"Labels found in CSV: {dict(label_counts)}")
        
        return samples
    
    def _parse_json_field(self, json_str) -> Dict:
        """Safely parse JSON field from CSV."""
        if not json_str or json_str.strip() == '':
            return self._create_base_spec()
        
        try:
            return json.loads(json_str)
        except:
            return self._create_base_spec()
    
    def _extract_metrics(self, row: Dict) -> np.ndarray:
        """Extract metrics from CSV row into 2D array."""
        # Create a metrics array (60, 15) matching the model expectations
        metrics = np.zeros((60, 15), dtype=np.float32)
        
        # Extract numeric metrics
        metric_columns = {
            0: 'request_rate',
            1: 'error_rate_5xx',
            2: 'latency_p99',
            3: 'cpu_usage_cores',
            4: 'memory_working_set_bytes',
            5: 'cpu_limit',
            6: 'memory_limit',
            7: 'desired_replicas',
            8: 'current_replicas',
            9: 'ready_replicas',
            10: 'restart_count',
            11: 'app_instance_count'
        }
        
        # Normalize and fill metrics
        normalization_factors = {
            'request_rate': 10.0,
            'error_rate_5xx': 0.1,
            'latency_p99': 0.05,
            'cpu_usage_cores': 2.0,
            'memory_working_set_bytes': 1e9,
            'cpu_limit': 2.0,
            'memory_limit': 2048.0,
            'desired_replicas': 10.0,
            'current_replicas': 10.0,
            'ready_replicas': 10.0,
            'restart_count': 10.0,
            'app_instance_count': 10.0
        }
        
        for metric_idx, col_name in metric_columns.items():
            if col_name in row:
                try:
                    value = float(row[col_name]) if row[col_name] else 0.0
                    normalized = value / normalization_factors.get(col_name, 1.0)
                    # Fill all time steps with this value (assuming it's a recent metric)
                    metrics[:, metric_idx] = np.clip(normalized, -5.0, 5.0)
                except (ValueError, TypeError):
                    metrics[:, metric_idx] = 0.0
        
        # Add some temporal variation across the 60 time steps
        for i in range(60):
            noise = np.random.randn(15) * 0.05
            metrics[i] = np.clip(metrics[i] + noise, -5.0, 5.0)
        
        # Ensure shape is exactly (60, 15)
        assert metrics.shape == (60, 15), f"Metrics shape {metrics.shape} is not (60, 15)"
        return metrics
    
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
    
    def _get_label_distribution(self) -> Dict:
        """Get distribution of labels in dataset."""
        counts = defaultdict(int)
        for s in self.samples:
            counts[s["label"]] += 1
        return dict(counts)
    
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
    print(f"Loaded {len(dataset)} samples")
    print(f"Label distribution: {dataset._get_label_distribution()}")
    
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, collate_fn=custom_collate_fn)
    print(f"Batches per epoch: {len(loader)}")
    
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss(weight=dataset.class_weights.to(device))
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=10)
    
    best_acc = 0.0
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        batch_count = 0
        
        for batch_idx, batch in enumerate(loader):
            batch_count += 1
            optimizer.zero_grad()
            
            try:
                # batch["metrics"] is already stacked tensor of shape (batch_size, 60, 15)
                metrics_batch = batch["metrics"].to(device)
                
                logits_list = []
                valid_labels = []
                
                for i in range(len(batch["label"])):
                    try:
                        m = metrics_batch[i]
                        if m.shape != torch.Size([60, 15]):
                            print(f"  Warning: Metrics shape is {m.shape}, expected (60, 15)")
                            continue
                        
                        result = model(
                            old_spec=batch["old_spec"][i],
                            new_spec=batch["new_spec"][i],
                            metrics=m
                        )
                        logits_list.append(result["logits"])
                        valid_labels.append(batch["label"][i])
                    except Exception as e:
                        if batch_idx == 0 and i == 0:
                            print(f"  Warning: Error processing sample: {str(e)[:150]}")
                        continue
                
                if not logits_list:
                    continue
                
                logits = torch.stack(logits_list)
                labels = torch.tensor(
                    [["benign", "health-critical", "perf-risk"].index(l) for l in valid_labels]
                ).to(device)
                
                loss = criterion(logits, labels)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                
                total_loss += loss.item()
                preds = torch.argmax(logits, dim=-1)
                correct += (preds == labels).sum().item()
                total += len(labels)
            except Exception as e:
                if batch_idx < 3:
                    print(f"  Error in batch {batch_idx}: {str(e)[:150]}")
                continue
        
        scheduler.step()
        acc = correct / total if total > 0 else 0.0
        avg_loss = total_loss / batch_count if batch_count > 0 else 0.0
        
        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), output_path)
        
        print(f"Epoch {epoch+1}/{epochs} Loss: {avg_loss:.4f} Acc: {acc:.4f} (batches: {batch_count}, samples: {total})")
    
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