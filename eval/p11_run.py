"""Bounded P11 k3d scenarios with test-mode gates and exact-resource cleanup.

The load runner creates only one uniquely named ConfigMap and Job in `kubeheal`.
The chaos runner may delete/restart one explicitly named Deployment pod, with its
PVC left intact. All kubectl calls are pinned by p11_harness to k3d-kubeheal.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from eval import p11_harness as harness

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "docs" / "kubeheal" / "results" / "p11"
CONTEXT = harness.ALLOWED_CONTEXT
NAMESPACE = "kubeheal"
DEFAULT_URL = "http://kubeheal-inference:8000/v1/health/predict"
SAFE_CHAOS_DEPLOYMENTS = frozenset({"kubeheal-inference"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _name(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6]}"


def _hpa_state() -> dict:
    raw = harness.kubectl(CONTEXT, ["get", "hpa", "kubeheal-inference", "-n", NAMESPACE, "-o", "json"])
    item = json.loads(raw)
    status = item.get("status") or {}
    return {
        "time_utc": _now(),
        "current_replicas": status.get("currentReplicas"),
        "desired_replicas": status.get("desiredReplicas"),
        "current_metrics": status.get("currentMetrics", []),
    }


def _load_script(url: str, vus: int, duration: str) -> str:
    meta_path = ROOT / "models" / "bundles" / "health" / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    features = {name: 0.0 for name in meta["features"]}
    body = json.dumps({"features": features}, separators=(",", ":"))
    return "\n".join((
        'import http from "k6/http";',
        'import { check } from "k6";',
        f"const endpoint = {json.dumps(url)};",
        f"const body = {json.dumps(body)};",
        f"export const options = {{ vus: {vus}, duration: {json.dumps(duration)}, summaryTrendStats: ['med', 'p(95)'] }};",
        "export default function () {",
        "  const r = http.post(endpoint, body, { headers: { 'Content-Type': 'application/json' } });",
        "  check(r, { 'health prediction returned 200': x => x.status === 200 });",
        "}",
        "",
    ))


def _parse_k6_latency(logs: str) -> tuple[float | str, float | str]:
    """Return median and p95 milliseconds from k6 http_req_duration summary, if present."""
    pattern = re.compile(r"\b(med|p\(95\))=([0-9]+(?:\.[0-9]+)?)(µs|us|ms|s)\b")
    factors = {"µs": 0.001, "us": 0.001, "ms": 1.0, "s": 1000.0}
    found: dict[str, float] = {}
    for line in logs.splitlines():
        if "http_req_duration" not in line:
            continue
        for label, value, unit in pattern.findall(line):
            found[label] = float(value) * factors[unit]
    return found.get("med", "not measured"), found.get("p(95)", "not measured")


def _cleanup_load(name: str) -> list[str]:
    results = []
    for kind, resource in (("job", name), ("configmap", name + "-script")):
        result = harness.kubectl(CONTEXT, ["delete", kind, resource, "-n", NAMESPACE, "--ignore-not-found=true"])
        results.append(result.strip())
    return results


def _deployment_counts(namespace: str, deployment: str) -> tuple[int, int]:
    raw = harness.kubectl(CONTEXT, ["get", "deployment/" + deployment, "-n", namespace, "-o", "json"])
    item = json.loads(raw)
    return int((item.get("spec") or {}).get("replicas", 1) or 0), int((item.get("status") or {}).get("readyReplicas", 0) or 0)


def run_load(vus: int, duration: str, target_url: str) -> dict:
    if not 10 <= vus <= 200:
        raise ValueError("vus must be between 10 and 200")
    harness.assert_test_mode(CONTEXT)
    name = _name(f"p11-load-{vus}")
    manifest = harness.k6_job_manifest(name, NAMESPACE, target_url, vus)
    script = _load_script(target_url, vus, duration)
    manifest["objects"][0]["data"]["load.js"] = script
    manifest["script"] = script
    samples: list[dict] = []
    logs = ""
    outcome = "failed"
    start = time.monotonic()
    before = _hpa_state()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(harness.apply_k6_job, CONTEXT, manifest)
            while not future.done():
                harness.assert_test_mode(CONTEXT)
                samples.append(_hpa_state())
                time.sleep(5)
            logs = future.result()
        samples.append(_hpa_state())
        outcome = "completed"
    except Exception:
        try:
            logs = harness.kubectl(CONTEXT, ["logs", "job/" + name, "-n", NAMESPACE, "--all-containers=true", "--tail=200"])
        except Exception as log_error:
            logs += f"\nLOG_CAPTURE_FAILED {type(log_error).__name__}: {log_error}\n"
        raise
    finally:
        cleanup = _cleanup_load(name)
        elapsed_s = round(time.monotonic() - start, 3)
        med, p95 = _parse_k6_latency(logs)
        RESULTS.mkdir(parents=True, exist_ok=True)
        run_id = name
        (RESULTS / f"{run_id}.log").write_text(logs, encoding="utf-8")
        (RESULTS / f"{run_id}-hpa.json").write_text(json.dumps({"before": before, "samples": samples}, indent=2) + "\n", encoding="utf-8")
        row = {
            "scenario": "E1 k6 health inference",
            "vus": vus,
            "duration": duration,
            "status": outcome,
            "p50_ms": med,
            "p95_ms": p95,
            "latency_status": "measured" if isinstance(med, float) and isinstance(p95, float) else "not measured",
            "hpa_samples": len(samples),
            "replicas_before": before.get("current_replicas", "not measured"),
            "replicas_after": samples[-1].get("current_replicas", "not measured") if samples else "not measured",
            "elapsed_s": elapsed_s,
            "cleanup": " | ".join(cleanup),
        }
        harness.write_results(RESULTS, run_id, [row], cluster=CONTEXT, status="measured" if outcome == "completed" else "not measured")
        print(json.dumps(row, sort_keys=True))
    return row


def run_pod_chaos(namespace: str, deployment: str, action: str) -> dict:
    if action not in {"restart", "delete-one-pod"}:
        raise ValueError("action must be restart or delete-one-pod")
    if deployment not in SAFE_CHAOS_DEPLOYMENTS:
        raise ValueError(f"P11 chaos is restricted to {sorted(SAFE_CHAOS_DEPLOYMENTS)}")
    harness.assert_test_mode(CONTEXT)
    desired, ready = _deployment_counts(namespace, deployment)
    if desired < 1 or ready < desired:
        raise RuntimeError(f"refusing chaos: {namespace}/{deployment} is not at baseline ready replicas ({ready}/{desired})")
    start_utc = _now()
    start = time.monotonic()
    result = harness.chaos_command(CONTEXT, namespace, deployment, action=action)
    deadline = time.monotonic() + 180
    recovered = False
    samples = []
    while time.monotonic() < deadline:
        harness.assert_test_mode(CONTEXT)
        desired, ready = _deployment_counts(namespace, deployment)
        samples.append({"time_utc": _now(), "desired": desired, "ready": ready})
        if desired > 0 and ready >= desired:
            recovered = True
            break
        time.sleep(2)
    if not recovered:
        raise TimeoutError(f"{namespace}/{deployment} did not return to ready replicas within 180s")
    row = {
        "scenario": "E2 deployment restart" if action == "restart" else "E2 pod delete/recreate",
        "namespace": namespace,
        "deployment": deployment,
        "action_output": result.strip(),
        "ready_samples": len(samples),
        "replicas_after": samples[-1]["ready"],
        "start_utc": start_utc,
        "elapsed_s": round(time.monotonic() - start, 3),
        "status": "measured",
    }
    run_id = _name("p11-chaos")
    harness.write_results(RESULTS, run_id, [row], cluster=CONTEXT, status="measured")
    print(json.dumps(row, sort_keys=True))
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="scenario", required=True)
    load = sub.add_parser("load", help="run a bounded scoring load and sample the inference HPA")
    load.add_argument("--vus", type=int, action="append", required=True, help="repeat for 10 to 200 VUs")
    load.add_argument("--duration", default="2m", help="k6 duration, default is a chosen value")
    load.add_argument("--target-url", default=DEFAULT_URL)
    chaos = sub.add_parser("chaos", help="restart an allowlisted Deployment or delete one pod")
    chaos.add_argument("--namespace", choices=sorted(harness.ALLOWED_NAMESPACES), required=True)
    chaos.add_argument("--deployment", choices=sorted(SAFE_CHAOS_DEPLOYMENTS), required=True)
    chaos.add_argument("--action", choices=("restart", "delete-one-pod"), required=True)
    args = parser.parse_args()
    if args.scenario == "load":
        if len(set(args.vus)) != len(args.vus):
            parser.error("--vus values must be unique")
        for vus in args.vus:
            run_load(vus, args.duration, args.target_url)
    else:
        run_pod_chaos(args.namespace, args.deployment, args.action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
