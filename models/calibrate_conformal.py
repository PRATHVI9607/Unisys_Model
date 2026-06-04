"""
Conformal calibration — KubeHeal v4 (PRD Section 10.2 step 4).
==============================================================
Standalone (re)calibration of the conformal confidence thresholds for the
Health and Security models on a held-out calibration set that must NOT overlap
training/validation. The trainers already calibrate inline at the end of a
run; this script lets you re-calibrate independently (e.g. on fresh data)
without retraining.

Nonconformity score = 1 - p(true_class); q = (1-alpha) quantile. A test
prediction whose own (1 - max_prob) exceeds q is "uncertain" → escalate.

Usage:
    python models/calibrate_conformal.py --coverage 0.90
"""

import argparse
import csv
import json
import random
import sys
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel
from models.health_model.health_output_head import HEALTH_LABELS
from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
from models.health_model.health_conformal import ConformalClassifier
from models.security_model.security_model import (
    SecurityModel, encode_syscall_window, pad_entropy,
)
from models.security_model.security_output_head import SECURITY_LABELS
from models.train_health_model import load_csv, LABEL_IDX as H_IDX
from models.train_security_model import load as load_sec, LABEL_IDX as S_IDX


def _calibrate_health(ckpt, samples, alpha):
    m = HealthModel()
    m.load_state_dict(torch.load(ckpt, map_location="cpu")); m.eval()
    scores = []
    with torch.no_grad():
        for s in samples:
            g = yaml_diff_to_graph(s["old"], s["new"])
            mt = torch.tensor(s["metrics"], dtype=torch.float32)
            probs = torch.softmax(m(g, mt)["label_logits"][0], -1)
            scores.append(1.0 - float(probs[H_IDX[s["label"]]]))
    c = ConformalClassifier(alpha=alpha); q = c.calibrate_scores(scores)
    return c, q


def _calibrate_security(ckpt, rows, alpha):
    m = SecurityModel()
    m.load_state_dict(torch.load(ckpt, map_location="cpu")); m.eval()
    scores = []
    with torch.no_grad():
        for r in rows:
            sid, pid, mask = encode_syscall_window(r["events"])
            ent = pad_entropy(r["entropy_series"])
            probs = torch.softmax(m(sid, pid, mask, ent)["label_logits"][0], -1)
            scores.append(1.0 - float(probs[S_IDX[r["label"]]]))
    c = ConformalClassifier(alpha=alpha); q = c.calibrate_scores(scores)
    return c, q


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--coverage", type=float, default=0.90)
    ap.add_argument("--health-csv", default=str(ROOT / "models/health_model/dit-merged-complete.csv"))
    ap.add_argument("--security-data", default=str(ROOT / "data/security_training.jsonl"))
    ap.add_argument("--n", type=int, default=400, help="calibration sample count")
    ap.add_argument("--seed", type=int, default=7)  # distinct from training seed
    args = ap.parse_args()
    random.seed(args.seed)
    alpha = 1.0 - args.coverage

    hck = ROOT / "models/health_model/checkpoints/best_health_model.pt"
    if hck.exists():
        s = load_csv(args.health_csv); random.shuffle(s)
        c, q = _calibrate_health(str(hck), s[: args.n], alpha)
        c.save(str(hck.parent / "health_conformal.json"))
        print(f"[health] coverage={args.coverage}  q={q:.4f}", flush=True)
    else:
        print("[health] no checkpoint — skipped", flush=True)

    sck = ROOT / "models/security_model/checkpoints/best_security_model.pt"
    if sck.exists() and Path(args.security_data).exists():
        rows = load_sec(args.security_data); random.shuffle(rows)
        c, q = _calibrate_security(str(sck), rows[: args.n], alpha)
        c.save(str(sck.parent / "security_conformal.json"))
        print(f"[security] coverage={args.coverage}  q={q:.4f}", flush=True)
    else:
        print("[security] no checkpoint/data — skipped", flush=True)


if __name__ == "__main__":
    main()
