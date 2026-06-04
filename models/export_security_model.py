"""
Export the Security Model to ONNX (FP16) — KubeHeal v4 (PRD Section 08.4).
=========================================================================
FP16 (not INT8): attention softmax produces near-zero weights that INT8's
coarse levels collapse → accuracy loss. FP16 keeps precision near zero and
halves model size.

Usage:
    python models/export_security_model.py \
        --input models/security_model/checkpoints/best_security_model.pt \
        --output models/security_model_v4.onnx --quantize fp16
"""

import argparse
import sys
from pathlib import Path

import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.security_model.security_model import SecurityModel
from models.security_model.falco_transformer_encoder import MAX_SEQUENCE_LENGTH
from models.security_model.entropy_conv1d_encoder import ENTROPY_WINDOW_LENGTH


class _ExportWrapper(nn.Module):
    """ONNX-friendly: fixed inputs → (logits, risk). Drops the salience/aux
    outputs (computed server-side from attention) so the graph is static."""
    def __init__(self, model: SecurityModel):
        super().__init__()
        self.model = model

    def forward(self, syscall_ids, path_ids, padding_mask, entropy_series):
        out = self.model(syscall_ids, path_ids, padding_mask, entropy_series)
        return out["label_logits"], out["risk_score"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "models/security_model/checkpoints/best_security_model.pt"))
    ap.add_argument("--output", default=str(ROOT / "models/security_model_v4.onnx"))
    ap.add_argument("--quantize", default="fp16", choices=["fp16", "none"])
    ap.add_argument("--opset", type=int, default=17)
    args = ap.parse_args()

    model = SecurityModel()
    if Path(args.input).exists():
        model.load_state_dict(torch.load(args.input, map_location="cpu"))
        print(f"loaded {args.input}")
    else:
        print(f"WARN: no checkpoint at {args.input} — exporting random weights")
    model.eval()
    wrapper = _ExportWrapper(model).eval()

    L = MAX_SEQUENCE_LENGTH
    dummy = (
        torch.zeros(1, L, dtype=torch.long),
        torch.zeros(1, L, dtype=torch.long),
        torch.zeros(1, L, dtype=torch.bool),
        torch.rand(1, ENTROPY_WINDOW_LENGTH, dtype=torch.float32),
    )
    torch.onnx.export(
        wrapper, dummy, args.output, opset_version=args.opset, do_constant_folding=True,
        input_names=["syscall_ids", "path_ids", "padding_mask", "entropy_series"],
        output_names=["logits", "risk"],
        dynamic_axes={"syscall_ids": {0: "batch"}, "path_ids": {0: "batch"},
                      "padding_mask": {0: "batch"}, "entropy_series": {0: "batch"},
                      "logits": {0: "batch"}, "risk": {0: "batch"}},
    )
    print(f"exported ONNX(FP32) → {args.output}")
    _validate(args.output, dummy)   # FP32 must load+run

    if args.quantize == "fp16":
        _try_fp16(args.output, dummy)


def _validate(path, dummy):
    import onnxruntime as ort
    sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    sess.run(None, {i.name: d.numpy() for i, d in zip(sess.get_inputs(), dummy)})
    print(f"validated: {Path(path).name} loads + runs ✓")


def _try_fp16(path, dummy):
    """Best-effort FP16. If the converted graph won't load (transformer Cast
    nodes can break onnxruntime), keep the validated FP32 — a working artifact
    beats a broken smaller one (model is only ~2MB)."""
    try:
        import onnx
        from onnxconverter_common import float16
        fp16_path = path.replace(".onnx", "_fp16.onnx")
        onnx.save(float16.convert_float_to_float16(onnx.load(path), keep_io_types=True), fp16_path)
        _validate(fp16_path, dummy)
        Path(path).unlink(missing_ok=True)
        Path(fp16_path).rename(path)
        print(f"FP16 ONNX → {path}")
    except Exception as e:
        print(f"WARN: FP16 conversion unusable ({str(e)[:80]}); kept validated FP32")
        Path(path.replace('.onnx', '_fp16.onnx')).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
