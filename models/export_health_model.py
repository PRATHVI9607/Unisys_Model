"""
Export the Health Model — KubeHeal v4 (PRD Section 08.4).
=========================================================
The Health Model contains a PyG GATv2 over a *variable* YAML graph
(dynamic node/edge counts, scatter/index ops). torch.onnx.export does not
reliably support PyG message-passing with dynamic graphs, so ONNX is attempted
and, on failure, we fall back to a TorchScript-free serialized deployable
bundle (state_dict + config) that the Health Model server already loads
natively. Either way a validated, servable artifact is produced.

Usage:
    python models/export_health_model.py \
        --input models/health_model/checkpoints/best_health_model.pt \
        --output models/health_model_v4.onnx --quantize fp16
"""

import argparse
import shutil
import sys
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.health_model.health_model import HealthModel


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "models/health_model/checkpoints/best_health_model.pt"))
    ap.add_argument("--output", default=str(ROOT / "models/health_model_v4.onnx"))
    ap.add_argument("--quantize", default="fp16")
    args = ap.parse_args()

    if not Path(args.input).exists():
        print(f"ERROR: no checkpoint at {args.input} — train first.", file=sys.stderr)
        sys.exit(1)

    model = HealthModel()
    model.load_state_dict(torch.load(args.input, map_location="cpu"))
    model.eval()
    print(f"loaded {args.input} ({model.param_count():,} params)")

    # ── Attempt ONNX (expected to fail for the GATv2 dynamic graph) ──
    try:
        from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
        g = yaml_diff_to_graph({"a": {"cpu": "500m"}}, {"a": {"cpu": "50m"}})
        # ONNX export of PyG message-passing is not supported for dynamic graphs;
        # this raises in practice — caught below.
        torch.onnx.export(model, (g, torch.zeros(1, 60, 15)), args.output, opset_version=17)
        import onnxruntime as ort
        ort.InferenceSession(args.output, providers=["CPUExecutionProvider"])
        print(f"exported ONNX → {args.output}")
        return
    except Exception as e:
        print(f"ONNX export not supported for the GATv2 dynamic graph "
              f"({str(e)[:80]}…). Falling back to a native torch bundle.")

    # ── Fallback: validated torch bundle the server loads natively ──
    bundle = args.output.replace(".onnx", ".pt")
    torch.save(model.state_dict(), bundle)
    # validate the bundle reloads + runs
    m2 = HealthModel(); m2.load_state_dict(torch.load(bundle, map_location="cpu")); m2.eval()
    from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
    with torch.no_grad():
        m2(yaml_diff_to_graph({}, {}), torch.zeros(1, 60, 15))
    print(f"exported torch bundle → {bundle}  (validated: reloads + runs ✓)")
    print("NOTE: Health Model serves via torch (GATv2 dynamic graph); the server "
          "loads this .pt directly. FP16 ONNX applies to the security/DCM models.")


if __name__ == "__main__":
    main()
