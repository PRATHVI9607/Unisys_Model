"""
Train the KubeHeal v4 Security Model (Transformer + Conv1D-SE + fusion + head).
==============================================================================
Trains on data/security_training.jsonl (generate it first). Class-weighted CE
+ risk MSE, conformal calibration on a held-out tail.

Usage:
    python models/generate_security_training_data.py
    python -u models/train_security_model.py --epochs 25 --batch-size 32
"""

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import f1_score, classification_report

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.security_model.security_model import (
    SecurityModel, encode_syscall_window, pad_entropy,
)
from models.security_model.security_output_head import SECURITY_LABELS
from models.security_model.security_conformal import ConformalRegressor

LABEL_IDX = {l: i for i, l in enumerate(SECURITY_LABELS)}


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            rows.append(json.loads(line))
    counts = defaultdict(int)
    for r in rows:
        counts[r["label"]] += 1
    print(f"[data] {len(rows)} samples: {dict(counts)}", flush=True)
    return rows


def class_weights(rows, device):
    counts = defaultdict(int)
    for r in rows:
        counts[r["label"]] += 1
    total = len(rows)
    w = [total / (len(SECURITY_LABELS) * max(counts.get(l, 1), 1)) for l in SECURITY_LABELS]
    return torch.tensor(w, dtype=torch.float32, device=device)


def run_epoch(model, rows, opt, cw, device, train, bs):
    model.train(train)
    if train:
        random.shuffle(rows)
    total, preds, labels = 0.0, [], []
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for i in range(0, len(rows), bs):
            batch = rows[i:i + bs]
            if train:
                opt.zero_grad()
            sids, pids, masks, ents, ys, rts = [], [], [], [], [], []
            for r in batch:
                sid, pid, mask = encode_syscall_window(r["events"])
                sids.append(sid); pids.append(pid); masks.append(mask)
                ents.append(pad_entropy(r["entropy_series"]))
                ys.append(LABEL_IDX[r["label"]]); rts.append(r["risk"])
            sid = torch.cat(sids).to(device); pid = torch.cat(pids).to(device)
            mask = torch.cat(masks).to(device); ent = torch.cat(ents).to(device)
            out = model(sid, pid, mask, ent)
            y = torch.tensor(ys, dtype=torch.long, device=device)
            ce = F.cross_entropy(out["label_logits"], y, weight=cw)
            risk = out["risk_score"].reshape(-1)
            rt = torch.tensor(rts, dtype=torch.float32, device=device)
            loss = ce + 0.5 * F.mse_loss(risk, rt)
            if train:
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
            total += float(loss)
            preds.extend(torch.argmax(out["label_logits"], -1).cpu().tolist())
            labels.extend(ys)
    f1 = f1_score(labels, preds, average="weighted", zero_division=0) if labels else 0.0
    acc = sum(p == l for p, l in zip(preds, labels)) / max(len(preds), 1)
    return total / max(1, len(rows) // bs), acc, f1, preds, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/security_training.jsonl")
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--val-split", type=float, default=0.15)
    ap.add_argument("--patience", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed); np.random.seed(args.seed); torch.manual_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    out_dir = ROOT / "models/security_model/checkpoints"; out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Device: {device}", flush=True)

    rows = load(args.data)
    random.shuffle(rows)
    n_val = int(len(rows) * args.val_split)
    val, train = rows[:n_val], rows[n_val:]
    n_cal = max(50, len(val) // 2)
    cal, val = val[:n_cal], val[n_cal:]
    print(f"Train {len(train)}  Val {len(val)}  Calib {len(cal)}", flush=True)

    model = SecurityModel().to(device)
    print(f"Params: {model.param_count():,}", flush=True)
    cw = class_weights(train, device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-2)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)

    best_f1, no_imp = 0.0, 0
    ckpt = out_dir / "best_security_model.pt"
    last = ([], [])
    for ep in range(1, args.epochs + 1):
        tl, ta, tf, _, _ = run_epoch(model, train, opt, cw, device, True, args.batch_size)
        vl, va, vf, vp, vy = run_epoch(model, val, opt, cw, device, False, args.batch_size)
        sched.step()
        improved = vf > best_f1
        if improved:
            best_f1, no_imp = vf, 0
            torch.save(model.state_dict(), ckpt); last = (vp, vy)
        else:
            no_imp += 1
        print(f"Epoch {ep:3d}/{args.epochs}  loss {tl:.3f}/{vl:.3f}  "
              f"acc {ta:.3f}/{va:.3f}  F1 {vf:.3f}{' *' if improved else ''}", flush=True)
        if no_imp >= args.patience:
            print(f"Early stop at epoch {ep}", flush=True); break

    model.load_state_dict(torch.load(ckpt, map_location=device)); model.eval()
    cp, ct = [], []
    with torch.no_grad():
        for r in cal:
            sid, pid, mask = encode_syscall_window(r["events"])
            ent = pad_entropy(r["entropy_series"])
            out = model(sid.to(device), pid.to(device), mask.to(device), ent.to(device))
            cp.append(float(out["risk_score"].reshape(-1)[0])); ct.append(r["risk"])
    conf = ConformalRegressor(alpha=0.05); q = conf.calibrate(cp, ct)
    conf.save(str(out_dir / "security_conformal.json"))
    print(f"[Conformal] q={q:.4f}  ci_width={2*q:.4f}", flush=True)

    if last[0]:
        present = sorted(set(last[1]))
        print("\n" + classification_report(
            last[1], last[0], labels=present,
            target_names=[SECURITY_LABELS[i] for i in present], zero_division=0), flush=True)

    json.dump({"best_val_f1": best_f1, "params": model.param_count(),
               "labels": SECURITY_LABELS, "conformal_q": q},
              open(out_dir / "security_report.json", "w"), indent=2)
    print(f"[done] best F1={best_f1:.4f}  ckpt={ckpt}", flush=True)


if __name__ == "__main__":
    main()
