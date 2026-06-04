"""
Compound-incident dataset generator — KubeHeal v4 (PRD Section 05.3 / 10.1).
===========================================================================
Builds the DCM training set: (health_embedding, security_embedding, is_compound)
triples, written to data/compound_incidents.jsonl.

Positive (compound=1): a harmful-health sample paired with an active/staging
ransomware sample — the ransomware's CPU thrash shows up as drift (shared root
cause). Negative (0): randomly paired independent health + security samples.

On a real cluster you'd inject ransomware+drift simultaneously via Chaos Mesh;
offline we pair the existing labelled health (real CSV) and security (synthetic)
samples through the frozen base models to produce the embedding pairs.

Usage:
    python models/generate_compound_dataset.py --output data/compound_incidents.jsonl
"""

import argparse
import json
import random
import sys
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel
from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
from models.security_model.security_model import (
    SecurityModel, encode_syscall_window, pad_entropy,
)
from models.train_health_model import load_csv
from models.train_security_model import load as load_sec


@torch.no_grad()
def _h_emb(m, s):
    g = yaml_diff_to_graph(s["old"], s["new"])
    mt = torch.tensor(s["metrics"], dtype=torch.float32)
    return m(g, mt)["health_embedding"][0].tolist()


@torch.no_grad()
def _s_emb(m, r):
    sid, pid, mask = encode_syscall_window(r["events"])
    ent = pad_entropy(r["entropy_series"])
    return m(sid, pid, mask, ent)["security_embedding"][0].tolist()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="data/compound_incidents.jsonl")
    ap.add_argument("--positive-samples", type=int, default=5000)
    ap.add_argument("--negative-samples", type=int, default=5000)
    ap.add_argument("--health-csv", default=str(ROOT / "models/health_model/dit-merged-complete.csv"))
    ap.add_argument("--security-data", default=str(ROOT / "data/security_training.jsonl"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed); torch.manual_seed(args.seed)

    hck = ROOT / "models/health_model/checkpoints/best_health_model.pt"
    sck = ROOT / "models/security_model/checkpoints/best_security_model.pt"
    hm = HealthModel()
    if hck.exists():
        hm.load_state_dict(torch.load(hck, map_location="cpu"))
    hm.eval()
    sm = SecurityModel()
    if sck.exists():
        sm.load_state_dict(torch.load(sck, map_location="cpu"))
    sm.eval()

    health = load_csv(args.health_csv)
    sec = load_sec(args.security_data)
    harmful = [s for s in health if s["risk"] >= 0.6] or health
    benign_h = [s for s in health if s["risk"] < 0.4] or health
    ransom = [r for r in sec if r["label"] in ("ransomware_active", "ransomware_staging")] or sec

    # cache embedding pools (cap for speed)
    H_harm = [_h_emb(hm, s) for s in random.sample(harmful, min(400, len(harmful)))]
    H_ben = [_h_emb(hm, s) for s in random.sample(benign_h, min(400, len(benign_h)))]
    S_ran = [_s_emb(sm, r) for r in random.sample(ransom, min(400, len(ransom)))]
    S_any = [_s_emb(sm, r) for r in random.sample(sec, min(400, len(sec)))]

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.output, "w") as f:
        for _ in range(args.positive_samples):
            f.write(json.dumps({"health_embedding": random.choice(H_harm),
                                "security_embedding": random.choice(S_ran),
                                "is_compound": 1}) + "\n"); n += 1
        for _ in range(args.negative_samples):
            f.write(json.dumps({"health_embedding": random.choice(H_ben),
                                "security_embedding": random.choice(S_any),
                                "is_compound": 0}) + "\n"); n += 1
    print(f"[gen] wrote {n} compound-incident pairs → {args.output}", flush=True)


if __name__ == "__main__":
    main()
