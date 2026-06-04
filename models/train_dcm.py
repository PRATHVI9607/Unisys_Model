"""
Train the DCM (Dependency Correlation Module) — KubeHeal v4 (Section 05.3).
==========================================================================
Staged training: load FROZEN health + security models as feature extractors,
build (health_embedding, security_embedding, is_compound) pairs, train the
cross-modal attention with BCE. Freezing keeps the base models specialists.

Compound (1): a harmful-health sample paired with an active/staging-ransomware
  sample — the ransomware's CPU thrash shows up as drift (shared root cause).
Independent (0): randomly paired health + security samples (no relationship).

Usage:
    python -u models/train_dcm.py --epochs 25
"""

import argparse
import csv
import json
import random
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import roc_auc_score

from models.train_utils import setup_torch, clipped_step, make_plateau

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel
from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
from models.security_model.security_model import SecurityModel, encode_syscall_window, pad_entropy
from models.dcm.cross_modal_attention import CrossModalAttention
from models.train_health_model import load_csv as load_health_csv
from models.train_security_model import load as load_sec


@torch.no_grad()
def health_embed(model, s, device):
    g = yaml_diff_to_graph(s["old"], s["new"])
    m = torch.tensor(s["metrics"], dtype=torch.float32, device=device)
    return model(g, m)["health_embedding"][0].cpu()


@torch.no_grad()
def sec_embed(model, r, device):
    sid, pid, mask = encode_syscall_window(r["events"])
    ent = pad_entropy(r["entropy_series"])
    out = model(sid.to(device), pid.to(device), mask.to(device), ent.to(device))
    return out["security_embedding"][0].cpu()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--health-model", default=str(ROOT / "models/health_model/checkpoints/best_health_model.pt"))
    ap.add_argument("--security-model", default=str(ROOT / "models/security_model/checkpoints/best_security_model.pt"))
    ap.add_argument("--health-csv", default=str(ROOT / "models/health_model/dit-merged-complete.csv"))
    ap.add_argument("--security-data", default=str(ROOT / "data/security_training.jsonl"))
    ap.add_argument("--pairs", type=int, default=4000)
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--lr", type=float, default=5e-4)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--patience", type=int, default=6)
    args = ap.parse_args()

    device = setup_torch(args.seed)
    out_dir = ROOT / "models/dcm/checkpoints"; out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Device: {device}", flush=True)

    health = HealthModel().to(device)
    health.load_state_dict(torch.load(args.health_model, map_location=device))
    health.eval()
    [p.requires_grad_(False) for p in health.parameters()]
    sec = SecurityModel().to(device)
    sec.load_state_dict(torch.load(args.security_model, map_location=device))
    sec.eval()
    [p.requires_grad_(False) for p in sec.parameters()]
    print("Loaded + froze base models", flush=True)

    hsamples = load_health_csv(args.health_csv)
    ssamples = load_sec(args.security_data)
    harmful = [s for s in hsamples if s["risk"] >= 0.6] or hsamples
    benign_h = [s for s in hsamples if s["risk"] < 0.4] or hsamples
    ransom = [r for r in ssamples if r["label"] in ("ransomware_active", "ransomware_staging")] or ssamples

    # Pre-compute a pool of embeddings (cap for speed)
    print("Embedding pools...", flush=True)
    H_harm = [health_embed(health, s, device) for s in random.sample(harmful, min(400, len(harmful)))]
    H_ben = [health_embed(health, s, device) for s in random.sample(benign_h, min(400, len(benign_h)))]
    S_ran = [sec_embed(sec, r, device) for r in random.sample(ransom, min(400, len(ransom)))]
    S_any = [sec_embed(sec, r, device) for r in random.sample(ssamples, min(400, len(ssamples)))]

    pairs = []  # (h_emb, s_emb, label)
    half = args.pairs // 2
    for _ in range(half):  # compound
        pairs.append((random.choice(H_harm), random.choice(S_ran), 1.0))
    for _ in range(half):  # independent
        pairs.append((random.choice(H_ben), random.choice(S_any), 0.0))
    random.shuffle(pairs)
    n_val = int(len(pairs) * 0.15)
    val, train = pairs[:n_val], pairs[n_val:]
    print(f"Pairs: train {len(train)} val {len(val)}", flush=True)

    dcm = CrossModalAttention().to(device)
    opt = torch.optim.AdamW(dcm.parameters(), lr=args.lr, weight_decay=1e-4)
    sched = make_plateau(opt, mode="max", factor=0.5, patience=3, min_lr=1e-6)
    crit = nn.BCELoss()
    print(f"DCM params {dcm.param_count():,}", flush=True)

    def batch_iter(data, bs, shuffle):
        if shuffle:
            random.shuffle(data)
        for i in range(0, len(data), bs):
            b = data[i:i + bs]
            h = torch.stack([x[0] for x in b]).to(device)
            s = torch.stack([x[1] for x in b]).to(device)
            y = torch.tensor([[x[2]] for x in b], dtype=torch.float32, device=device)
            yield h, s, y

    best_auroc, no_imp = 0.0, 0
    ckpt = out_dir / "best_dcm.pt"
    for ep in range(1, args.epochs + 1):
        dcm.train()
        tot = 0.0
        for h, s, y in batch_iter(train, args.batch_size, True):
            opt.zero_grad(set_to_none=True)
            score, _, _ = dcm(h, s)
            loss = crit(score, y)
            loss.backward()
            clipped_step(dcm, opt, max_norm=1.0)   # clip + NaN/Inf guard
            tot += float(loss)
        dcm.eval()
        ys, ps = [], []
        with torch.no_grad():
            for h, s, y in batch_iter(val, args.batch_size, False):
                score, _, _ = dcm(h, s)
                ps.extend(score.reshape(-1).cpu().tolist())
                ys.extend(y.reshape(-1).cpu().tolist())
        auroc = roc_auc_score(ys, ps) if len(set(ys)) > 1 else 0.0
        sched.step(auroc)
        improved = auroc > best_auroc
        if improved:
            best_auroc, no_imp = auroc, 0
            torch.save(dcm.state_dict(), ckpt)
        else:
            no_imp += 1
        print(f"Epoch {ep:3d}/{args.epochs}  loss {tot/max(1,len(train)//args.batch_size):.4f}  "
              f"val AUROC {auroc:.4f}  lr {opt.param_groups[0]['lr']:.2e}"
              f"{' *' if improved else ''}", flush=True)
        if no_imp >= args.patience:
            print(f"Early stop at epoch {ep}", flush=True); break

    json.dump({"best_val_auroc": best_auroc, "params": dcm.param_count()},
              open(out_dir / "dcm_report.json", "w"), indent=2)
    print(f"[done] best AUROC={best_auroc:.4f}  ckpt={ckpt}", flush=True)


if __name__ == "__main__":
    main()
