"""
Health training-data generator — KubeHeal v4 (PRD Section 10.1).
================================================================
Generates labelled (YAML diff, Prometheus window, health_label) samples by
injecting config changes into a LIVE cluster and recording the resulting
metric window. Requires a running Minikube + victim Deployment + Prometheus
(it shells out to kubectl and queries Prometheus over HTTP).

The repo already ships a large real dataset at
models/health_model/dit-merged-complete.csv — this script is for regenerating
or expanding it on a cluster (the only way to add new critical/perf *graph*
diversity and lift minority recall beyond the data ceiling).

Usage (on a cluster):
    python models/generate_health_training_data.py \
        --namespace demo --victim-deployment victim-app \
        --output data/health_training.jsonl --samples 15000
"""

import argparse
import json
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Injection recipes → ground-truth health label
RECIPES = [
    # (label, cpu_limit, memory_limit) — benign tweaks vs harmful vs critical
    ("benign", "500m", "512Mi"),
    ("low_risk_drift", "400m", "448Mi"),
    ("harmful_performance_degradation", "80m", "256Mi"),
    ("critical_config_error", "10m", "64Mi"),
    ("critical_config_error", "0", "0"),
]


def _kubectl(*args, timeout=15):
    return subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)


def _get_spec(ns, dep):
    r = _kubectl("get", "deployment", dep, "-n", ns, "-o", "json")
    return json.loads(r.stdout)["spec"] if r.returncode == 0 and r.stdout else {}


def _patch(ns, dep, cpu, mem):
    patch = {"spec": {"template": {"spec": {"containers": [
        {"name": "app", "resources": {"limits": {"cpu": cpu, "memory": mem}}}]}}}}
    _kubectl("patch", "deployment", dep, "-n", ns, "--type=merge", "-p", json.dumps(patch))


def _fetch_window(namespace, dep, prometheus_url):
    """Pull a 60×15 metric window via the shared v4 Prometheus client."""
    import asyncio
    from agents.health_agent.prometheus_client import wait_for_fresh_metrics
    arr = asyncio.run(wait_for_fresh_metrics(namespace, dep, prometheus_url, timeout_s=20))
    return arr.tolist()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="demo")
    ap.add_argument("--victim-deployment", default="victim-app")
    ap.add_argument("--output", default="data/health_training.jsonl")
    ap.add_argument("--samples", type=int, default=15000)
    ap.add_argument("--prometheus-url",
                    default="http://prometheus-operated.monitoring.svc.cluster.local:9090")
    ap.add_argument("--settle", type=int, default=20, help="secs to let metrics react")
    args = ap.parse_args()

    if _kubectl("version", "--client").returncode != 0:
        print("ERROR: kubectl not available — this generator needs a live cluster.",
              file=sys.stderr)
        sys.exit(1)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    baseline = _get_spec(args.namespace, args.victim_deployment)
    n = 0
    with open(args.output, "w") as f:
        for i in range(args.samples):
            label, cpu, mem = random.choice(RECIPES)
            _patch(args.namespace, args.victim_deployment, cpu, mem)
            time.sleep(args.settle)
            new_spec = _get_spec(args.namespace, args.victim_deployment)
            metrics = _fetch_window(args.namespace, args.victim_deployment, args.prometheus_url)
            f.write(json.dumps({"old_spec": baseline, "new_spec": new_spec,
                                "metrics": metrics, "label": label}) + "\n")
            n += 1
            if i % 50 == 0:
                print(f"  {i}/{args.samples} ({label})", flush=True)
            # reset to baseline between samples
            _patch(args.namespace, args.victim_deployment, "500m", "512Mi")
    print(f"[gen] wrote {n} health samples → {args.output}", flush=True)


if __name__ == "__main__":
    main()
