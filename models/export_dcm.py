"""
Export the DCM to ONNX (FP16) — KubeHeal v4 (PRD Section 08.4).
==============================================================
DCM has fixed-shape float embedding inputs (health[128] + security[64]) so the
graph is fully ONNX-friendly.

Usage:
    python models/export_dcm.py --input models/dcm/checkpoints/best_dcm.pt \
        --output models/dcm_v4.onnx --quantize fp16
"""

import argparse
import sys
from pathlib import Path

import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.dcm.cross_modal_attention import CrossModalAttention
from models.export_security_model import _validate, _try_fp16


class _Wrap(nn.Module):
    def __init__(self, m):
        super().__init__(); self.m = m

    def forward(self, health_embedding, security_embedding):
        score, _, _ = self.m(health_embedding, security_embedding)
        return score


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "models/dcm/checkpoints/best_dcm.pt"))
    ap.add_argument("--output", default=str(ROOT / "models/dcm_v4.onnx"))
    ap.add_argument("--quantize", default="fp16", choices=["fp16", "none"])
    ap.add_argument("--opset", type=int, default=17)
    args = ap.parse_args()

    m = CrossModalAttention()
    if Path(args.input).exists():
        m.load_state_dict(torch.load(args.input, map_location="cpu")); print(f"loaded {args.input}")
    else:
        print(f"WARN: no checkpoint at {args.input} — random weights")
    m.eval()
    wrap = _Wrap(m).eval()
    dummy = (torch.zeros(1, 128), torch.zeros(1, 64))
    torch.onnx.export(
        wrap, dummy, args.output, opset_version=args.opset, do_constant_folding=True,
        input_names=["health_embedding", "security_embedding"], output_names=["correlation_score"],
        dynamic_axes={"health_embedding": {0: "batch"}, "security_embedding": {0: "batch"},
                      "correlation_score": {0: "batch"}},
    )
    print(f"exported ONNX(FP32) → {args.output}")
    _validate(args.output, dummy)
    if args.quantize == "fp16":
        _try_fp16(args.output, dummy)


if __name__ == "__main__":
    main()
