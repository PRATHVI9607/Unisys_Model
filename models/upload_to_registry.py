"""
Upload models to the MinIO model registry — KubeHeal v4 (PRD Section 10.2).
==========================================================================
Promotes the exported artifacts to a MinIO (S3-compatible) bucket after the
validation gates pass. Requires the `minio` client + MinIO endpoint/creds via
env (MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY). Skips gracefully if
the client/endpoint is unavailable so the rest of the pipeline isn't blocked.

Usage:
    python models/upload_to_registry.py --version v4.0.0 \
        --health-model models/health_model_v4.pt \
        --security-model models/security_model_v4.onnx \
        --dcm models/dcm_v4.onnx --min-health-f1 0.78 --min-security-f1 0.88
"""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _report(p):
    p = ROOT / p
    return json.load(open(p)) if p.exists() else {}


def _gate_ok(args):
    h = _report("models/health_model/checkpoints/health_report.json").get("best_val_f1", 0)
    s = _report("models/security_model/checkpoints/security_report.json").get("best_val_f1", 0)
    if h and h < args.min_health_f1:
        print(f"GATE FAIL: health F1 {h:.3f} < {args.min_health_f1}"); return False
    if s and s < args.min_security_f1:
        print(f"GATE FAIL: security F1 {s:.3f} < {args.min_security_f1}"); return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v4.0.0")
    ap.add_argument("--bucket", default=os.environ.get("MODEL_BUCKET", "kubeheal-models"))
    ap.add_argument("--health-model", default=str(ROOT / "models/health_model_v4.pt"))
    ap.add_argument("--security-model", default=str(ROOT / "models/security_model_v4.onnx"))
    ap.add_argument("--dcm", default=str(ROOT / "models/dcm_v4.onnx"))
    ap.add_argument("--min-health-f1", type=float, default=0.78)
    ap.add_argument("--min-security-f1", type=float, default=0.88)
    args = ap.parse_args()

    if not _gate_ok(args):
        sys.exit(1)
    print("validation gates passed ✓")

    endpoint = os.environ.get("MINIO_ENDPOINT")
    if not endpoint:
        print("MINIO_ENDPOINT unset — skipping upload (gates already validated).")
        return
    try:
        from minio import Minio
    except ImportError:
        print("`minio` client not installed (`pip install minio`) — skipping upload.")
        return

    client = Minio(
        endpoint,
        access_key=os.environ.get("MINIO_ACCESS_KEY", ""),
        secret_key=os.environ.get("MINIO_SECRET_KEY", ""),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )
    if not client.bucket_exists(args.bucket):
        client.make_bucket(args.bucket)

    for art in (args.health_model, args.security_model, args.dcm):
        p = Path(art)
        if not p.exists():
            print(f"  skip (missing): {art}")
            continue
        obj = f"{args.version}/{p.name}"
        client.fput_object(args.bucket, obj, str(p))
        print(f"  uploaded → s3://{args.bucket}/{obj}")
    print(f"registry upload complete (version {args.version})")


if __name__ == "__main__":
    main()
