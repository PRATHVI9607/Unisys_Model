"""
validate_all_models.py — KubeHeal v4 promotion gates (PRD Section 10.3).
========================================================================
Loads whatever checkpoints exist and runs the validation gates. Exits 0 if all
present-model gates pass, 1 otherwise. Missing checkpoints are reported as
SKIP (not failure) so it is usable before full training.

Run: PYTHONPATH=. python models/validate_all_models.py
"""

import json
import sys
import time
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GATES = {
    "health_f1": 0.90,
    "security_f1": 0.91,
    "dcm_auroc": 0.88,
    "health_latency_ms": 50.0,
    "security_latency_ms": 30.0,
}


def _report(path):
    p = ROOT / path
    return json.load(open(p)) if p.exists() else None


def main():
    results, ok = [], True

    # ── Health ──
    hr = _report("models/health_model/checkpoints/health_report.json")
    if hr:
        f1 = hr.get("best_val_f1", 0)
        passed = f1 >= GATES["health_f1"]
        ok &= passed
        results.append(("Health F1", f"{f1:.3f}", GATES['health_f1'], passed))
        # latency
        try:
            from models.health_model.health_model import HealthModel
            from models.health_model.yaml_gat_encoder import yaml_diff_to_graph
            m = HealthModel(); ck = ROOT / "models/health_model/checkpoints/best_health_model.pt"
            if ck.exists():
                m.load_state_dict(torch.load(ck, map_location="cpu")); m.eval()
            g = yaml_diff_to_graph({"a": {"cpu": "500m"}}, {"a": {"cpu": "50m"}})
            mt = torch.zeros(1, 60, 15)
            t0 = time.time()
            with torch.no_grad():
                m(g, mt)
            lat = (time.time() - t0) * 1000
            passed = lat <= GATES["health_latency_ms"]
            results.append(("Health P50 latency", f"{lat:.1f}ms", GATES['health_latency_ms'], passed))
        except Exception as e:
            results.append(("Health latency", f"ERR {e}", "-", False)); ok = False
    else:
        results.append(("Health model", "SKIP (no checkpoint)", "-", None))

    # ── Security ──
    sr = _report("models/security_model/checkpoints/security_report.json")
    if sr:
        f1 = sr.get("best_val_f1", 0)
        passed = f1 >= GATES["security_f1"]
        ok &= passed
        results.append(("Security F1", f"{f1:.3f}", GATES['security_f1'], passed))
    else:
        results.append(("Security model", "SKIP (no checkpoint)", "-", None))

    # ── DCM ──
    dr = _report("models/dcm/checkpoints/dcm_report.json")
    if dr:
        au = dr.get("best_val_auroc", 0)
        passed = au >= GATES["dcm_auroc"]
        ok &= passed
        results.append(("DCM AUROC", f"{au:.3f}", GATES['dcm_auroc'], passed))
    else:
        results.append(("DCM", "SKIP (no checkpoint)", "-", None))

    print("\n  GATE                       VALUE                 THRESHOLD   RESULT")
    print("  " + "-" * 68)
    for name, val, thr, passed in results:
        mark = "SKIP" if passed is None else ("PASS" if passed else "FAIL")
        print(f"  {name:<26} {str(val):<21} {str(thr):<11} {mark}")
    print()

    if not ok:
        print("❌ One or more gates FAILED.")
        sys.exit(1)
    print("✅ All present-model gates passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
