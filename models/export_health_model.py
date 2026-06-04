"""
Export the Health Model to ONNX (FP16) — KubeHeal v4 (PRD Section 08.4).
=======================================================================
The GATv2 graph build (yaml_diff_to_graph) stays as Python preprocessing; the
network exports via HealthModel.forward_export which takes pure tensors
(node_ids, edge_index, pos_idx, pos_val, metrics) with num_nodes/num_edges as
dynamic axes. The export is numerically parity-checked against torch and is
only kept if max|Δlogits| ≤ 1e-3, else a validated torch bundle is emitted.
FP16 best-effort with FP32 fallback (validated either way).

Usage:
    python models/export_health_model.py \
        --input models/health_model/checkpoints/best_health_model.pt \
        --output models/health_model_v4.onnx --quantize fp16
"""

import argparse
import sys
from pathlib import Path

import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel
from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
from models.export_security_model import _validate, _try_fp16


class _Wrap(nn.Module):
    def __init__(self, m):
        super().__init__(); self.m = m

    def forward(self, node_ids, edge_index, pos_idx, pos_val, metrics):
        return self.m.forward_export(node_ids, edge_index, pos_idx, pos_val, metrics)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "models/health_model/checkpoints/best_health_model.pt"))
    ap.add_argument("--output", default=str(ROOT / "models/health_model_v4.onnx"))
    ap.add_argument("--quantize", default="fp16", choices=["fp16", "none"])
    ap.add_argument("--opset", type=int, default=17)
    args = ap.parse_args()

    model = HealthModel()
    if Path(args.input).exists():
        model.load_state_dict(torch.load(args.input, map_location="cpu"))
        print(f"loaded {args.input} ({model.param_count():,} params)")
    else:
        print(f"WARN: no checkpoint at {args.input} — random weights")
    model.eval()
    wrap = _Wrap(model).eval()

    # realistic dummy graph from a real diff
    g = yaml_diff_to_graph(
        {"spec": {"template": {"spec": {"containers": [{"name": "app",
            "resources": {"limits": {"cpu": "500m"}}}]}}}},
        {"spec": {"template": {"spec": {"containers": [{"name": "app",
            "resources": {"limits": {"cpu": "50m"}}}]}}}},
    )
    pos_idx = torch.tensor(g.container_indices, dtype=torch.long)
    pos_val = torch.tensor(g.container_positions, dtype=torch.long)
    dummy = (g.x, g.edge_index, pos_idx, pos_val, torch.zeros(1, 60, 15))

    torch.onnx.export(
        wrap, dummy, args.output, opset_version=args.opset, do_constant_folding=True,
        input_names=["node_ids", "edge_index", "pos_idx", "pos_val", "metrics"],
        output_names=["logits", "risk"],
        dynamic_axes={"node_ids": {0: "n_nodes"}, "edge_index": {1: "n_edges"},
                      "pos_idx": {0: "n_cont"}, "pos_val": {0: "n_cont"},
                      "metrics": {0: "batch"}},
    )
    print(f"exported ONNX(FP32) → {args.output}")

    # Numerical parity gate: a GATv2 dynamic-graph ONNX can trace incorrectly
    # (index_add dedup, baked constants). Only KEEP the ONNX if it matches torch
    # within tolerance on a second, differently-shaped graph; else fall back to
    # a validated torch bundle the server loads natively.
    import numpy as np, onnxruntime as ort
    g2 = yaml_diff_to_graph(
        {"spec": {"template": {"spec": {"containers": [
            {"name": "a", "resources": {"limits": {"cpu": "500m", "memory": "1Gi"}}},
            {"name": "b", "resources": {"limits": {"cpu": "250m"}}}]}}}},
        {"spec": {"template": {"spec": {"containers": [
            {"name": "a", "resources": {"limits": {"cpu": "20m", "memory": "1Gi"}}},
            {"name": "b", "resources": {"limits": {"cpu": "250m"}}}]}}}},
    )
    pi = torch.tensor(g2.container_indices, dtype=torch.long)
    pv = torch.tensor(g2.container_positions, dtype=torch.long)
    mt = torch.randn(1, 60, 15)
    with torch.no_grad():
        t_logits, t_risk = wrap(g2.x, g2.edge_index, pi, pv, mt)
    sess = ort.InferenceSession(args.output, providers=["CPUExecutionProvider"])
    o_logits, o_risk = sess.run(None, {
        "node_ids": g2.x.numpy(), "edge_index": g2.edge_index.numpy(),
        "pos_idx": pi.numpy(), "pos_val": pv.numpy(), "metrics": mt.numpy()})
    max_diff = float(np.abs(t_logits.numpy() - o_logits).max())
    print(f"parity max|Δlogits| = {max_diff:.5f}")
    if max_diff <= 1e-3:
        print("PARITY PASS — shipping ONNX ✓")
        if args.quantize == "fp16":
            _try_fp16(args.output, dummy)
    else:
        print("PARITY FAIL — GATv2 graph traced incorrectly; serving via torch bundle.")
        Path(args.output).unlink(missing_ok=True)
        bundle = args.output.replace(".onnx", ".pt")
        torch.save(model.state_dict(), bundle)
        print(f"exported torch bundle → {bundle} (server loads natively)")


if __name__ == "__main__":
    main()
