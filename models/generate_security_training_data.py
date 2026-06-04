"""
Synthetic Security training-data generator — KubeHeal v4.
=========================================================
Real ransomware syscall traces require a live cluster + Falco (PRD Section
10.1). For offline training we synthesise behaviorally-faithful samples:
entropy distributions and syscall mixes per label drawn from documented
ransomware behavior. Writes JSONL of {events, entropy_series, label}.

Usage: python models/generate_security_training_data.py --output data/security_training.jsonl
"""

import argparse
import json
import random
from pathlib import Path

from models.security_model.security_output_head import SECURITY_LABELS

BENIGN = ["read", "stat", "open", "openat", "close", "getdents", "lseek", "fstat"]
ATTACK = ["open", "read", "write", "rename", "ftruncate", "unlink", "pwrite64", "fsync"]
MMAP = ["mmap", "write", "msync", "munmap", "mprotect", "rename"]
EXFIL = ["open", "read", "socket", "connect", "sendto", "sendto", "read"]


def _events(label, n=120):
    if label == "ransomware_active":
        pool = ATTACK * 5 + ["rename"] * 8
        pathset = [f"/data/file_{i}.locked" for i in range(40)]
    elif label == "ransomware_staging":
        pool = ATTACK * 2 + BENIGN
        pathset = [f"/data/file_{i}" for i in range(40)]
    elif label == "data_exfiltration":
        pool = EXFIL * 4 + BENIGN
        pathset = [f"/data/db_{i}.dump" for i in range(20)]
    elif label == "suspicious":
        pool = ATTACK + BENIGN * 3
        pathset = [f"/data/file_{i}" for i in range(40)]
    else:  # benign
        pool = BENIGN * 6 + ["write"]
        pathset = [f"/var/log/app_{i}.log" for i in range(10)]
    return [{"syscall": random.choice(pool), "fd_path": random.choice(pathset)}
            for _ in range(n)]


def _entropy(label, n=30):
    if label == "ransomware_active":
        base, noise = random.uniform(7.4, 7.95), 0.1
    elif label == "ransomware_staging":
        base, noise = random.uniform(5.5, 7.0), 0.3
    elif label == "data_exfiltration":
        base, noise = random.uniform(4.0, 6.0), 0.4   # plaintext copy, mid entropy
    elif label == "suspicious":
        base, noise = random.uniform(4.5, 6.5), 0.4
    else:
        base, noise = random.uniform(1.0, 4.0), 0.5
    vals = []
    for i in range(n):
        # staging ramps up over time
        b = base + (i / n) * (1.5 if label == "ransomware_staging" else 0.0)
        vals.append(max(0.0, min(8.0, b + random.gauss(0, noise))))
    return vals


def _risk(label):
    return {"benign": 0.04, "suspicious": 0.45, "ransomware_staging": 0.62,
            "ransomware_active": 0.95, "data_exfiltration": 0.80}[label]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="data/security_training.jsonl")
    ap.add_argument("--ransomware-samples", type=int, default=4000)
    ap.add_argument("--benign-samples", type=int, default=4000)
    ap.add_argument("--staging-samples", type=int, default=2000)
    ap.add_argument("--exfil-samples", type=int, default=2000)
    ap.add_argument("--suspicious-samples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    plan = [
        ("ransomware_active", args.ransomware_samples),
        ("benign", args.benign_samples),
        ("ransomware_staging", args.staging_samples),
        ("data_exfiltration", args.exfil_samples),
        ("suspicious", args.suspicious_samples),
    ]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.output, "w") as f:
        rows = []
        for label, count in plan:
            for _ in range(count):
                rows.append({"events": _events(label), "entropy_series": _entropy(label),
                             "label": label, "risk": _risk(label)})
        random.shuffle(rows)
        for r in rows:
            f.write(json.dumps(r) + "\n"); n += 1
    print(f"[gen] wrote {n} security samples → {args.output}")


if __name__ == "__main__":
    main()
