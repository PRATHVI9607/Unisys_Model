"""
Train the KubeHeal v4 Health Model (GATv2 + BiLSTM + fusion + head).
====================================================================
Loads the REAL drift dataset (models/health_model/dit-merged-complete.csv),
builds a YAML graph from baseline_json/live_json and a 60×15 metric window
from the scalar Prometheus columns, then trains classification + risk
regression jointly with class-weighted loss.

Usage:
    python -u models/train_health_model.py --epochs 30 --batch-size 16 --patience 6
Outputs:
    models/health_model/checkpoints/best_health_model.pt
    models/health_model/checkpoints/health_conformal.json
    models/health_model/checkpoints/health_report.json
"""

import argparse
import csv
import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import f1_score, classification_report

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel
from models.health_model.health_output_head import HEALTH_LABELS, CLASS_RISK
from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
from models.health_model.metric_bilstm_encoder import (
    METRIC_COLUMNS, NUM_METRICS, INPUT_SEQUENCE_LENGTH,
)
from models.health_model.health_conformal import ConformalRegressor
from models.train_utils import (
    setup_torch, clipped_step, make_plateau, focal_loss, augment_minority,
)

LABEL_IDX = {l: i for i, l in enumerate(HEALTH_LABELS)}

CSV_LABEL_MAP = {
    "Benign_Or_Subtle": "benign",
    "Harmful_Performance_Degradation": "harmful_performance_degradation",
    "Harmful_Critical_Outage": "critical_config_error",
    "Harmful_Multi_Vector": "critical_config_error",
    "Harmful_Security_Breach": "critical_config_error",
}

# CSV scalar columns → which of the 15 metric channels they populate
CSV_METRIC_MAP = {
    "request_rate": "http_request_rate",
    "error_rate_5xx": "http_error_rate",
    "latency_p99": "http_p99_latency_ms",
    "cpu_usage_cores": "cpu_usage_millicores",
    "memory_working_set_bytes": "memory_working_set_bytes",
    "cpu_limit": "cpu_limit_millicores",
    "memory_limit": "memory_limit_bytes",
    "restart_count": "pod_restarts_total",
    "app_instance_count": "http_request_rate",  # weak proxy; harmless
}
NORM = {
    "http_request_rate": 100.0, "http_error_rate": 10.0, "http_p99_latency_ms": 2000.0,
    "cpu_usage_millicores": 2000.0, "memory_working_set_bytes": 1e9,
    "cpu_limit_millicores": 2000.0, "memory_limit_bytes": 2e9,
    "pod_restarts_total": 10.0,
}


def _f(row, key, default=0.0):
    try:
        return float(row.get(key) or default)
    except Exception:
        return default


def build_metric_window(row: Dict) -> np.ndarray:
    """Scalar CSV metrics → [60,15], broadcast across time + light noise."""
    base = np.zeros(NUM_METRICS, dtype=np.float32)
    for csv_col, metric in CSV_METRIC_MAP.items():
        if metric in METRIC_COLUMNS:
            idx = METRIC_COLUMNS.index(metric)
            base[idx] = _f(row, csv_col) / NORM.get(metric, 1.0)
    # derive cpu_throttle proxy from usage/limit ratio
    try:
        ti = METRIC_COLUMNS.index("cpu_throttle_percent")
        usage = _f(row, "cpu_usage_cores"); limit = _f(row, "cpu_limit") or 1.0
        base[ti] = min(1.0, usage / max(limit, 1e-6))
    except ValueError:
        pass
    win = np.tile(base, (INPUT_SEQUENCE_LENGTH, 1))
    win += np.random.randn(*win.shape).astype(np.float32) * 0.02
    return win.astype(np.float32)


def load_csv(path: str) -> List[Dict]:
    samples, counts = [], defaultdict(int)
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            op = (row.get("operational_label") or "Benign_Or_Subtle").strip()
            label = CSV_LABEL_MAP.get(op, "benign")
            # subtle-but-nonzero drift → low_risk_drift
            sev = _f(row, "severity", 1.0)
            if label == "benign" and sev >= 1.5:
                label = "low_risk_drift"
            counts[label] += 1
            try:
                old = json.loads(row.get("baseline_json") or "{}")
                new = json.loads(row.get("live_json") or "{}")
            except Exception:
                old, new = {}, {}
            samples.append({
                "old": old, "new": new,
                "metrics": build_metric_window(row),
                "label": label,
                "risk": min(1.0, sev / 3.0),
            })
    print(f"[CSV] {len(samples)} samples: {dict(counts)}", flush=True)
    return samples


def class_weights(samples, device):
    counts = defaultdict(int)
    for s in samples:
        counts[s["label"]] += 1
    total = len(samples)
    w = [total / (len(HEALTH_LABELS) * max(counts.get(l, 1), 1)) for l in HEALTH_LABELS]
    return torch.tensor(w, dtype=torch.float32, device=device)


def run_epoch(model, samples, optimizer, cw, device, train: bool, bs: int,
              focal_gamma: float = 1.0):
    model.train(train)
    # Focal loss (alpha=inverse-freq) handles imbalance; a plain shuffle avoids
    # the double-correction (oversample + inverse-freq focal) that collapses the
    # majority class. SMOTE is inapplicable here (cannot interpolate YAML graphs).
    order = list(range(len(samples)))
    if train:
        random.shuffle(order)
    total, nb, preds, labels = 0.0, 0, [], []
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for i in range(0, len(order), bs):
            batch = [samples[j] for j in order[i:i + bs]]
            logit_list, risk_list, lab_list, rt_list = [], [], [], []
            for s in batch:
                try:
                    g = yaml_diff_to_graph(s["old"], s["new"])
                    m = torch.tensor(s["metrics"], dtype=torch.float32, device=device)
                    out = model(g, m)
                    lid = LABEL_IDX[s["label"]]
                    logit_list.append(out["label_logits"][0])
                    risk_list.append(out["risk_score"].reshape(-1)[0])
                    lab_list.append(lid)
                    rt_list.append(CLASS_RISK[lid])   # grounded target → tight conformal
                except Exception:
                    continue
            if not logit_list:
                continue
            logits = torch.stack(logit_list)
            y = torch.tensor(lab_list, dtype=torch.long, device=device)
            # focal WITHOUT class-weight alpha: oversample-augmentation already
            # rebalances the data, so stacking inverse-freq alpha here would
            # double-correct and collapse precision (as the γ=2+α run showed).
            fl = focal_loss(logits, y, alpha=None, gamma=focal_gamma)
            risk = torch.stack(risk_list)
            rt = torch.tensor(rt_list, dtype=torch.float32, device=device)
            loss = fl + 0.5 * F.mse_loss(risk, rt)
            if train:
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                clipped_step(model, optimizer, max_norm=1.0)
            total += float(loss); nb += 1
            preds.extend(torch.argmax(logits, -1).cpu().tolist())
            labels.extend(lab_list)
    f1 = f1_score(labels, preds, average="weighted", zero_division=0) if labels else 0.0
    acc = (sum(p == l for p, l in zip(preds, labels)) / max(len(preds), 1))
    return total / max(1, nb), acc, f1, preds, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(ROOT / "models/health_model/dit-merged-complete.csv"))
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--val-split", type=float, default=0.15)
    ap.add_argument("--patience", type=int, default=6)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--focal-gamma", type=float, default=1.0)
    ap.add_argument("--oversample-ratio", type=float, default=0.5,
                    help="oversample minority up to this × the largest class (0 disables)")
    args = ap.parse_args()

    device = setup_torch(args.seed)   # pins threads (CPU speed) + seeds
    out_dir = ROOT / "models/health_model/checkpoints"; out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Device: {device}  threads={torch.get_num_threads()}", flush=True)

    samples = load_csv(args.csv)
    random.shuffle(samples)
    n_val = int(len(samples) * args.val_split)
    val, train = samples[:n_val], samples[n_val:]
    # hold out calibration from val tail
    n_cal = max(50, len(val) // 2)
    cal, val = val[:n_cal], val[n_cal:]
    print(f"Train {len(train)}  Val {len(val)}  Calib {len(cal)}", flush=True)

    # Data-level imbalance fix: mild minority oversampling with metric-noise
    # augmentation (TRAIN only — never touch val/calib).
    if args.oversample_ratio > 0:
        train = augment_minority(
            train, label_of=lambda s: LABEL_IDX[s["label"]],
            num_classes=len(HEALTH_LABELS), target_ratio=args.oversample_ratio,
        )
        aug_counts = defaultdict(int)
        for s in train:
            aug_counts[s["label"]] += 1
        print(f"Train after augment: {len(train)}  {dict(aug_counts)}", flush=True)

    model = HealthModel().to(device)
    print(f"Params: {model.param_count():,}", flush=True)
    cw = class_weights(train, device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-2)
    # ReduceLROnPlateau on val F1 — anneal only when the model actually stalls.
    sched = make_plateau(opt, mode="max", factor=0.5, patience=2, min_lr=1e-6)
    base_lr = args.lr

    best_f1, no_imp = 0.0, 0
    ckpt = out_dir / "best_health_model.pt"
    last = ([], [])
    for ep in range(1, args.epochs + 1):
        # Epoch 1 = warm-up at 0.1×lr (GAT/attention cold-start stability);
        # epoch 2 restores full lr; from epoch 2 on, ReduceLROnPlateau owns lr.
        if ep == 1:
            for g in opt.param_groups: g["lr"] = base_lr * 0.1
        elif ep == 2:
            for g in opt.param_groups: g["lr"] = base_lr
        tl, ta, tf, _, _ = run_epoch(model, train, opt, cw, device, True, args.batch_size, args.focal_gamma)
        vl, va, vf, vp, vy = run_epoch(model, val, opt, cw, device, False, args.batch_size, args.focal_gamma)
        if ep >= 2:
            sched.step(vf)   # plateau watches val F1
        improved = vf > best_f1
        if improved or not ckpt.exists():   # always keep at least one checkpoint
            best_f1 = max(best_f1, vf); no_imp = 0 if improved else no_imp + 1
            torch.save(model.state_dict(), ckpt)
            if vp:
                last = (vp, vy)
        else:
            no_imp += 1
        print(f"Epoch {ep:3d}/{args.epochs}  loss {tl:.3f}/{vl:.3f}  "
              f"acc {ta:.3f}/{va:.3f}  F1 {vf:.3f}  lr {opt.param_groups[0]['lr']:.2e}"
              f"{' *' if improved else ''}", flush=True)
        if no_imp >= args.patience:
            print(f"Early stop at epoch {ep}", flush=True)
            break

    # conformal calibration on held-out set (reload best if one was saved)
    if ckpt.exists():
        model.load_state_dict(torch.load(ckpt, map_location=device))
    model.eval()
    scores = []  # nonconformity = 1 - p(true class)
    with torch.no_grad():
        for s in cal:
            try:
                g = yaml_diff_to_graph(s["old"], s["new"])
                m = torch.tensor(s["metrics"], dtype=torch.float32, device=device)
                probs = torch.softmax(model(g, m)["label_logits"][0], dim=-1)
                scores.append(1.0 - float(probs[LABEL_IDX[s["label"]]]))
            except Exception:
                continue
    conf = ConformalRegressor(alpha=0.10)
    q = conf.calibrate_scores(scores)
    conf.save(str(out_dir / "health_conformal.json"))
    print(f"[Conformal] confidence threshold q={q:.4f}  (escalate if 1-max_prob > q)", flush=True)

    if last[0]:
        present = sorted(set(last[1]))
        print("\n" + classification_report(
            last[1], last[0], labels=present,
            target_names=[HEALTH_LABELS[i] for i in present], zero_division=0), flush=True)

    json.dump({"best_val_f1": best_f1, "params": model.param_count(),
               "labels": HEALTH_LABELS, "conformal_q": q},
              open(out_dir / "health_report.json", "w"), indent=2)
    print(f"[done] best F1={best_f1:.4f}  ckpt={ckpt}", flush=True)


if __name__ == "__main__":
    main()
