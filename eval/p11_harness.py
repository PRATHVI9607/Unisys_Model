"""Offline-safe builders and result helpers for P11 evaluation runs.

Cluster-facing functions only accept the context ``k3d-kubeheal`` and accept an injectable runner.
Nothing in this module executes a cluster command during import or unit tests.

Values labelled "chosen default, not measured" below (k6 image pin, run duration, Job deadline,
wait timeout, poll interval, resource limits) are plain choices made for this harness. None of them
came from a measurement, and the k6 image tag has not been checked for existence here.
"""
from __future__ import annotations

import csv
import json
import platform
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

Runner = Callable[..., subprocess.CompletedProcess]

# The only context this harness may talk to. The pre-existing user cluster "hybrid-demo" must never
# be touched, so it is not merely absent from the list: it is rejected explicitly.
ALLOWED_CONTEXT = "k3d-kubeheal"
FORBIDDEN_CONTEXTS = frozenset({"hybrid-demo"})
# Namespaces that chaos, delete, restart and load helpers may act in.
ALLOWED_NAMESPACES = frozenset({"prod", "staging", "dev", "kubeheal"})

# Chosen defaults, not measured: Job deadline, client wait, poll interval.
K6_ACTIVE_DEADLINE_SECONDS = 900
K6_WAIT_SECONDS = 960
K6_POLL_INTERVAL_SECONDS = 10


def _check_namespace(namespace: str) -> None:
    if namespace not in ALLOWED_NAMESPACES:
        raise ValueError(f"namespace {namespace!r} is not allowed; allowed: {sorted(ALLOWED_NAMESPACES)}")


def kubectl(context: str, args: Sequence[str], *, runner: Runner = subprocess.run,
            input_text: str | None = None) -> str:
    """Run kubectl against the allow-listed context only; runner injection keeps tests offline."""
    if context in FORBIDDEN_CONTEXTS:
        raise ValueError(f"context {context!r} must never be used")
    if context != ALLOWED_CONTEXT:
        raise ValueError(f"context must be exactly {ALLOWED_CONTEXT!r}")
    result = runner(["kubectl", "--context", context, *args], check=True, capture_output=True,
                    text=True, input=input_text)
    return result.stdout


def assert_test_mode(context: str, *, runner: Runner = subprocess.run) -> None:
    """Refuse to continue unless the global kill switch is exactly `test` (the same rule as demo/scripts/hpa_load.ps1).

    Chaos and delete helpers act on the cluster themselves, outside the Executor. Running them while KubeHeal
    can act (`enforce`, or an unreadable mode) would mix the test load with real remediation.
    """
    mode = kubectl(context, ["get", "configmap", "kubeheal-mode", "-n", "kubeheal", "-o", "jsonpath={.data.mode}"],
                   runner=runner).strip()
    if mode != "test":
        raise RuntimeError(f"refusing to act: kubeheal-mode is {mode!r}, expected 'test'")


def k6_script(target_url: str, pod_count: int, duration: str = "2m") -> str:
    """Build the k6 script. The harness maps k6 virtual users to simulated monitored pods as a
    stand-in (a VU is not a pod). The default duration 2m is a chosen default, not measured."""
    if not target_url.startswith(("http://", "https://")):
        raise ValueError("target_url must be an http(s) URL")
    if not 10 <= pod_count <= 200:
        raise ValueError("pod_count must be between 10 and 200")
    if not duration:
        raise ValueError("duration is required")
    return f'''import http from "k6/http";
import {{ check }} from "k6";
export const options = {{ vus: {pod_count}, duration: "{duration}", summaryTrendStats: ["med", "p(95)"] }};
export default function () {{ const r = http.get("{target_url}"); check(r, {{ "status 200": x => x.status === 200 }}); }}
'''


def k6_job_manifest(name: str, namespace: str, target_url: str, pod_count: int,
                    anti_affinity_labels: Sequence[str] = ("kubeheal-health-model", "kubeheal-security-model", "kubeheal-dcm", "kubeheal-inference")) -> dict:
    """Return ``{"objects": [ConfigMap, Job], "script": <k6 JS>}``.

    Only the two entries in ``objects`` are rendered and applied. The k6 script lives in the
    ConfigMap (key ``load.js``), which the Job mounts read-only at /scripts. ``script`` is a
    convenience copy and is never part of any Kubernetes object.

    Scheduling uses *preferred* (soft) pod anti-affinity against the model-server pods with
    weight 100, so the load generator avoids their nodes when it can but never stays Pending on a
    small (for example 3-node) cluster. The image pin 0.54.0 (existence not verified here),
    activeDeadlineSeconds 900 and cpu 1 / 512Mi limits are chosen defaults, not measured.
    """
    if not name or not namespace or not anti_affinity_labels:
        raise ValueError("name, namespace and model-server anti-affinity labels are required")
    _check_namespace(namespace)
    script = k6_script(target_url, pod_count)
    config = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": name + "-script", "namespace": namespace},
              "data": {"load.js": script}}
    pod_spec = {
        "restartPolicy": "Never",
        "affinity": {"podAntiAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": [{
            "weight": 100,
            "podAffinityTerm": {
                "labelSelector": {"matchExpressions": [{"key": "app", "operator": "In",
                                                        "values": list(anti_affinity_labels)}]},
                "topologyKey": "kubernetes.io/hostname"}}]}},
        "containers": [{"name": "k6", "image": "grafana/k6:0.54.0",  # chosen version pin, not verified
                        "args": ["run", "/scripts/load.js"],
                        "volumeMounts": [{"name": "script", "mountPath": "/scripts", "readOnly": True}],
                        # chosen defaults, not measured
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                      "limits": {"cpu": "1", "memory": "512Mi"}}}],
        "volumes": [{"name": "script", "configMap": {"name": name + "-script"}}],
    }
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app": "kubeheal-p11-k6"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": K6_ACTIVE_DEADLINE_SECONDS,
                 "template": {"metadata": {"labels": {"app": "kubeheal-p11-k6"}}, "spec": pod_spec}},
    }
    return {"objects": [config, job], "script": script}


def _job_state(context: str, name: str, namespace: str, runner: Runner) -> str:
    """Return "complete", "failed" or "running" from the Job's true conditions."""
    out = kubectl(context, ["get", "job/" + name, "-n", namespace, "-o",
                            'jsonpath={.status.conditions[?(@.status=="True")].type}'], runner=runner)
    types = out.split()
    if "Failed" in types:
        return "failed"
    if "Complete" in types:
        return "complete"
    return "running"


def apply_k6_job(context: str, manifest: Mapping, *, runner: Runner = subprocess.run,
                 wait_seconds: float = K6_WAIT_SECONDS, poll_seconds: float = K6_POLL_INTERVAL_SECONDS,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> str:
    """Apply the ConfigMap and Job, wait until the Job is complete or failed, return its logs.

    The rendered document contains only ``manifest["objects"]``. The wait polls the Job conditions
    so a failed Job ends the wait immediately instead of blocking for the full timeout. Raises
    RuntimeError on a failed Job and TimeoutError after ``wait_seconds`` (chosen default 960, not
    measured).
    """
    objects = manifest.get("objects")
    if not objects or len(objects) != 2:
        raise ValueError("manifest was not produced by k6_job_manifest")
    import yaml
    job = objects[1]
    name = job["metadata"]["name"]
    ns = job["metadata"]["namespace"]
    _check_namespace(ns)
    rendered = "---\n".join(yaml.safe_dump(item, sort_keys=False) for item in objects)
    kubectl(context, ["apply", "-f", "-"], runner=runner, input_text=rendered)
    deadline = clock() + wait_seconds
    while True:
        state = _job_state(context, name, ns, runner)
        if state == "complete":
            break
        if state == "failed":
            raise RuntimeError(f"k6 job {name} failed")
        if clock() >= deadline:
            raise TimeoutError(f"k6 job {name} neither completed nor failed within {wait_seconds}s")
        sleep(poll_seconds)
    return kubectl(context, ["logs", "job/" + name, "-n", ns], runner=runner)


def chaos_command(context: str, namespace: str, deployment: str, *, action: str,
                  runner: Runner = subprocess.run) -> str:
    """Run a bounded deployment restart or model-server pod deletion for chaos evaluation."""
    if action not in {"restart", "delete-one-pod"}:
        raise ValueError("action must be restart or delete-one-pod")
    _check_namespace(namespace)
    assert_test_mode(context, runner=runner)
    if action == "restart":
        return kubectl(context, ["rollout", "restart", "deployment/" + deployment, "-n", namespace], runner=runner)
    pods = json.loads(kubectl(context, ["get", "pods", "-n", namespace, "-l", "app=" + deployment, "-o", "json"], runner=runner))
    items = pods.get("items", [])
    if not items:
        raise RuntimeError(f"no pods found for app={deployment}")
    pod_name = items[0]["metadata"]["name"]
    return kubectl(context, ["delete", "pod", pod_name, "-n", namespace, "--wait=false"], runner=runner)


def database_pod_delete_command(context: str, namespace: str, pod: str, *, runner: Runner = subprocess.run) -> str:
    """Baseline operation for P11: delete a database pod while leaving its PVC intact."""
    if not pod:
        raise ValueError("pod is required")
    _check_namespace(namespace)
    assert_test_mode(context, runner=runner)
    return kubectl(context, ["delete", "pod", pod, "-n", namespace, "--wait=false"], runner=runner)


@dataclass(frozen=True)
class ResultMetadata:
    machine: str
    cluster: str
    date_utc: str
    scenario: str
    status: str = "not measured"


def result_metadata(cluster: str, scenario: str, *, machine: str | None = None,
                    now: datetime | None = None, status: str = "not measured") -> ResultMetadata:
    if not cluster or not scenario:
        raise ValueError("cluster and scenario are required")
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return ResultMetadata(machine or platform.node(), cluster, stamp.astimezone(timezone.utc).isoformat(timespec="seconds"), scenario, status)


def write_results(out_dir: Path, scenario: str, rows: Iterable[Mapping], *, cluster: str,
                  machine: str | None = None, status: str = "measured",
                  now: datetime | None = None, overwrite: bool = False) -> tuple[Path, Path]:
    """Write CSV and JSON metadata. Empty rows are explicitly recorded as not measured.

    Refuses to replace an existing result (FileExistsError) unless ``overwrite=True``.
    """
    records = [dict(row) for row in rows]
    actual_status = status if records else "not measured"
    csv_path = out_dir / f"{scenario}.csv"
    meta_path = out_dir / f"{scenario}.json"
    if not overwrite:
        existing = [str(p) for p in (csv_path, meta_path) if p.exists()]
        if existing:
            raise FileExistsError(f"refusing to overwrite existing results: {', '.join(existing)}")
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(key for row in records for key in row))
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        if fields:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(records)
        else:
            fh.write("status\nnot measured\n")
    meta_path.write_text(json.dumps({**asdict(result_metadata(cluster, scenario, machine=machine, now=now,
                                                                      status=actual_status)),
                                    "rows": len(records)}, indent=2) + "\n", encoding="utf-8")
    return csv_path, meta_path


def baseline_scenarios() -> tuple[str, ...]:
    return ("falco-rules-only", "fixed-entropy-threshold", "diff-only-drift", "single-replica", "pod-delete-only")


def model_precision_rows(fp32_latency_ms: float | None = None, fp16_latency_ms: float | None = None,
                         fp32_memory_bytes: int | None = None, fp16_memory_bytes: int | None = None) -> list[dict]:
    """Normalize measured precision results; absent measurements remain explicit."""
    if all(x is None for x in (fp32_latency_ms, fp16_latency_ms, fp32_memory_bytes, fp16_memory_bytes)):
        return []
    return [{"precision": p, "latency_ms": latency if latency is not None else "not measured",
             "memory_bytes": memory if memory is not None else "not measured"}
            for p, latency, memory in (("fp32", fp32_latency_ms, fp32_memory_bytes),
                                       ("fp16", fp16_latency_ms, fp16_memory_bytes))]
