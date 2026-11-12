"""Bounded P11 k3d scenarios with test-mode gates and exact-resource cleanup.

The load runner creates only one uniquely named ConfigMap and Job in `kubeheal`.
The chaos runner may delete one explicitly selected Deployment pod, with its PVC
left intact. All kubectl calls are pinned by p11_harness to k3d-kubeheal.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import re
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from eval import p11_harness as harness

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "docs" / "kubeheal" / "results" / "p11"
CONTEXT = harness.ALLOWED_CONTEXT
NAMESPACE = "kubeheal"
DEFAULT_URL = "http://kubeheal-inference:8000/v1/health/predict"
SAFE_CHAOS_DEPLOYMENTS = frozenset({"kubeheal-inference"})
UNMEASURED_REASONS = {
    "P11-E3": "not measured: no disposable database-volume scenario is configured; the run must not overwrite or delete existing PVC data",
    "P11-E4": "not measured: the current event path does not expose timestamps for each action stage",
    "P11-E5": "not measured: controlled comparison drivers for the five baselines are not implemented or verified",
    "  Falco rules only": "not measured: no live Falco rules-only baseline is installed; replay fixtures are hand-written",
    "  fixed entropy threshold": "not measured: no controlled fixed-threshold detector run is available",
    "  diff-only drift": "not measured: no controlled comparison run is available",
    "  single replica": "not measured: no controlled single-replica comparison run is available",
    "  pod-delete-only": "not measured: no controlled pod-delete-only ransomware comparison run is available",
    "P11-E6": "not measured: the deployed LightGBM bundle has no paired FP32/FP16 deployment variants for a controlled comparison",
    "V5-E1": "not measured: the scripted V5 acceptance lab scenarios have not been run; full containment is not yet live-verified",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _name(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex}"


def _validate_duration(duration: str) -> None:
    match = re.fullmatch(r"([1-9][0-9]?)(s|m)", duration)
    if not match:
        raise ValueError("duration must be an integer from 1 to 99 followed by s or m")
    value = int(match.group(1)) * (60 if match.group(2) == "m" else 1)
    if value > 600:
        raise ValueError("duration is capped at 10 minutes per k6 Job")


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
        try:
            raw = harness.kubectl(CONTEXT, ["get", kind, resource, "-n", NAMESPACE,
                                            "-o", "json", "--ignore-not-found=true"])
            if not raw.strip():
                results.append(f"{kind}/{resource}: absent")
                continue
            item = json.loads(raw)
            labels = ((item.get("metadata") or {}).get("labels") or {})
            if labels.get("kubeheal.ai/p11-run-id") != name:
                results.append(f"{kind}/{resource}: retained, ownership label mismatch")
                continue
            deleted = harness.kubectl(CONTEXT, ["delete", kind, resource, "-n", NAMESPACE,
                                                "--ignore-not-found=true"])
            results.append(f"{kind}/{resource}: {deleted.strip()}")
        except Exception as exc:
            results.append(f"{kind}/{resource}: cleanup failed: {type(exc).__name__}: {exc}")
    return results


def _coverage_markdown(rows: list[dict]) -> str:
    measured_e1 = [row for row in rows if row.get("scenario") == "E1 k6 health inference" and row.get("status") == "completed"]
    measured_e2 = [row for row in rows if str(row.get("scenario", "")).startswith("E2 ") and row.get("status") == "measured"]
    lines = [
        "# P11 and V5-E1 evaluation coverage",
        "",
        "Values below come from files in this directory. `not measured` means no run produced that value; it is not a zero.",
        "",
        "| Item | Status | Evidence or reason |",
        "|---|---|---|",
    ]
    if measured_e1:
        levels = ", ".join(str(row.get("vus")) for row in measured_e1)
        lines.append(f"| P11-E1 k6 scoring load | measured | VUs {levels}; see per-run CSV, raw k6 logs, and HPA samples below |")
    else:
        lines.append("| P11-E1 k6 scoring load | not measured | no completed live load run recorded yet |")
    if measured_e2:
        lines.append(f"| P11-E2 inference pod recovery | measured | {len(measured_e2)} completed recovery run(s); see per-run CSV |")
    else:
        lines.append("| P11-E2 inference pod recovery | not measured | no completed live recovery run recorded yet |")
    lines.append("| P11-E3 RPO/RTO | not measured | " + UNMEASURED_REASONS["P11-E3"].removeprefix("not measured: ") + " |")
    lines.append("| P11-E4 stage timing | not measured | " + UNMEASURED_REASONS["P11-E4"].removeprefix("not measured: ") + " |")
    lines.append("| P11-E5 baseline comparisons | not measured | " + UNMEASURED_REASONS["P11-E5"].removeprefix("not measured: ") + " |")
    for baseline in ("Falco rules only", "fixed entropy threshold", "diff-only drift", "single replica", "pod-delete-only"):
        key = "  " + baseline
        reason = UNMEASURED_REASONS.get(key, "not measured: no controlled comparison run is available").removeprefix("not measured: ")
        lines.append(f"| P11-E5 {baseline} | not measured | {reason} |")
    lines.append("| P11-E6 FP32/FP16 latency and memory | not measured | " + UNMEASURED_REASONS["P11-E6"].removeprefix("not measured: ") + " |")
    if rows:
        lines.append("| P11-E7 run metadata | recorded per run | machine, cluster, timestamp, and status are stored in each JSON sidecar |")
    else:
        lines.append("| P11-E7 run metadata | not measured | no live result sidecar exists yet |")
    lines.append("| V5-E1 scripted lab scenarios | not measured | " + UNMEASURED_REASONS["V5-E1"].removeprefix("not measured: ") + " |")
    lines.extend(["", "## Run files", ""])
    if rows:
        lines.extend(f"- `{row.get('scenario', 'scenario')}`: `{row.get('status', 'not measured')}`; elapsed `{row.get('elapsed_s', 'not measured')}` seconds." for row in rows)
    else:
        lines.append("No live scenario output is recorded yet.")
    return "\n".join(lines) + "\n"


def update_coverage_summary() -> Path:
    rows = []
    if RESULTS.exists():
        for path in sorted(RESULTS.glob("*.csv")):
            with path.open(newline="", encoding="utf-8") as fh:
                rows.extend(csv.DictReader(fh))
    RESULTS.mkdir(parents=True, exist_ok=True)
    summary = RESULTS / "P11_COVERAGE.md"
    summary.write_text(_coverage_markdown(rows), encoding="utf-8")
    return summary


def _deployment_counts(namespace: str, deployment: str) -> tuple[int, int]:
    raw = harness.kubectl(CONTEXT, ["get", "deployment/" + deployment, "-n", namespace, "-o", "json"])
    item = json.loads(raw)
    return int((item.get("spec") or {}).get("replicas", 1) or 0), int((item.get("status") or {}).get("readyReplicas", 0) or 0)


def _selector_matches(labels: dict, selector: dict) -> bool:
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key = expr.get("key")
        operator = expr.get("operator")
        values = set(expr.get("values") or [])
        present = key in labels
        if operator == "In" and (not present or labels[key] not in values):
            return False
        if operator == "NotIn" and present and labels[key] in values:
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
        if operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return False
    return True


def _ready_pods(namespace: str, deployment: str) -> list[dict]:
    deployment_obj = json.loads(harness.kubectl(
        CONTEXT, ["get", "deployment/" + deployment, "-n", namespace, "-o", "json"]))
    deployment_meta = deployment_obj.get("metadata") or {}
    deployment_uid = deployment_meta.get("uid")
    selector = (deployment_obj.get("spec") or {}).get("selector") or {}
    if not deployment_uid or not selector:
        raise RuntimeError(f"{namespace}/{deployment} has no UID or pod selector")
    raw = harness.kubectl(CONTEXT, ["get", "pods", "-n", namespace, "-o", "json"])
    items = json.loads(raw).get("items", [])
    ready = []
    replica_owner_cache: dict[str, bool] = {}
    for item in items:
        meta = item.get("metadata") or {}
        labels = meta.get("labels") or {}
        if not _selector_matches(labels, selector):
            continue
        owner_refs = meta.get("ownerReferences") or []
        replica_refs = [ref for ref in owner_refs if ref.get("kind") == "ReplicaSet" and ref.get("controller") is True]
        if len(replica_refs) != 1:
            continue
        replica_name = replica_refs[0].get("name")
        if not replica_name:
            continue
        if replica_name not in replica_owner_cache:
            raw_rs = harness.kubectl(CONTEXT, ["get", "replicaset/" + replica_name, "-n", namespace, "-o", "json"])
            rs = json.loads(raw_rs)
            rs_meta = rs.get("metadata") or {}
            parents = [ref for ref in rs_meta.get("ownerReferences", [])
                       if ref.get("kind") == "Deployment" and ref.get("controller") is True]
            replica_owner_cache[replica_name] = len(parents) == 1 and parents[0].get("name") == deployment \
                and parents[0].get("uid") == deployment_uid
        if not replica_owner_cache[replica_name]:
            continue
        status = item.get("status") or {}
        container_statuses = status.get("containerStatuses") or []
        if status.get("phase") == "Running" and container_statuses \
                and all(container.get("ready") is True for container in container_statuses):
            ready.append(item)
    return ready


def _free_local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _delete_pod_with_uid(namespace: str, pod_name: str, pod_uid: str) -> str:
    """Delete exactly the captured Pod UID through a context-pinned, bounded kubectl proxy."""
    port = _free_local_port()
    base = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        ["kubectl", "--context", CONTEXT, "proxy", "--address=127.0.0.1", f"--port={port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("kubectl proxy exited before becoming ready")
            try:
                with urlopen(base + "/version", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.2)
        else:
            raise TimeoutError("kubectl proxy did not become ready within 10 seconds")
        path = f"{base}/api/v1/namespaces/{namespace}/pods/{pod_name}"
        body = json.dumps({"apiVersion": "v1", "kind": "DeleteOptions",
                           "preconditions": {"uid": pod_uid}}).encode("utf-8")
        request = Request(path, data=body, headers={"Content-Type": "application/json"}, method="DELETE")
        with urlopen(request, timeout=10) as response:
            if response.status not in {200, 202}:
                raise RuntimeError(f"Pod delete API returned HTTP {response.status}")
            return response.read().decode("utf-8")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_load(vus: int, duration: str, target_url: str) -> dict:
    if not 10 <= vus <= 200:
        raise ValueError("vus must be between 10 and 200")
    _validate_duration(duration)
    if target_url != DEFAULT_URL:
        raise ValueError(f"target_url is restricted to {DEFAULT_URL}")
    harness.assert_test_mode(CONTEXT)
    name = _name(f"p11-load-{vus}")
    manifest = harness.k6_job_manifest(name, NAMESPACE, target_url, vus)
    for obj in manifest["objects"]:
        labels = obj["metadata"].setdefault("labels", {})
        labels["kubeheal.ai/p11-run-id"] = name
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
        update_coverage_summary()
        print(json.dumps(row, sort_keys=True))
    return row


def run_pod_chaos(namespace: str, deployment: str, action: str) -> dict:
    if namespace not in harness.ALLOWED_NAMESPACES:
        raise ValueError(f"namespace is not in the P11 allowlist: {namespace!r}")
    if action != "delete-one-pod":
        raise ValueError("P11 runner supports only delete-one-pod")
    if deployment not in SAFE_CHAOS_DEPLOYMENTS:
        raise ValueError(f"P11 chaos is restricted to {sorted(SAFE_CHAOS_DEPLOYMENTS)}")
    harness.assert_test_mode(CONTEXT)
    desired, ready = _deployment_counts(namespace, deployment)
    original_desired = desired
    if desired < 1 or ready < original_desired:
        raise RuntimeError(f"refusing chaos: {namespace}/{deployment} is not at baseline ready replicas ({ready}/{original_desired})")
    before_pods = _ready_pods(namespace, deployment)
    if not before_pods:
        raise RuntimeError(f"refusing chaos: {namespace}/{deployment} has no Ready pod")
    target = before_pods[0]
    target_name = (target.get("metadata") or {}).get("name")
    target_uid = (target.get("metadata") or {}).get("uid")
    if not target_name or not target_uid:
        raise RuntimeError("refusing chaos: selected pod is missing its name or UID")
    start_utc = _now()
    start = time.monotonic()
    harness.assert_test_mode(CONTEXT)
    result = _delete_pod_with_uid(namespace, target_name, target_uid)
    deadline = time.monotonic() + 180
    recovered = False
    samples = []
    while time.monotonic() < deadline:
        harness.assert_test_mode(CONTEXT)
        desired, ready = _deployment_counts(namespace, deployment)
        pods = _ready_pods(namespace, deployment)
        old_uid_present = any((pod.get("metadata") or {}).get("uid") == target_uid for pod in pods)
        samples.append({"time_utc": _now(), "desired": desired, "ready": ready, "old_uid_ready": old_uid_present})
        if desired == original_desired and ready >= original_desired and not old_uid_present:
            recovered = True
            break
        time.sleep(2)
    if not recovered:
        raise TimeoutError(f"{namespace}/{deployment} did not return to ready replicas within 180s")
    row = {
        "scenario": "E2 pod delete/recreate",
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
    update_coverage_summary()
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
    chaos.add_argument("--action", choices=("delete-one-pod",), required=True)
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
