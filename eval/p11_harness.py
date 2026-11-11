"""Offline-safe builders and result helpers for P11 evaluation runs.

Cluster-facing functions require an explicit context and accept an injectable runner.  Nothing in
this module executes a cluster command during import or unit tests.
"""
from __future__ import annotations

import csv
import json
import platform
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

Runner = Callable[..., subprocess.CompletedProcess]


def kubectl(context: str, args: Sequence[str], *, runner: Runner = subprocess.run,
            input_text: str | None = None) -> str:
    """Run kubectl with a required explicit context; useful runner injection keeps tests offline."""
    if not context or context.strip() != context:
        raise ValueError("an explicit Kubernetes context is required")
    result = runner(["kubectl", "--context", context, *args], check=True, capture_output=True,
                    text=True, input=input_text)
    return result.stdout


def k6_script(target_url: str, pod_count: int, duration: str = "2m") -> str:
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
                    anti_affinity_labels: Sequence[str] = ("kubeheal-health-model", "kubeheal-security-model", "kubeheal-dcm")) -> dict:
    """Return a bounded k6 Job manifest; the selected node must be labelled away from model pods."""
    if not name or not namespace or not anti_affinity_labels:
        raise ValueError("name, namespace and model-server anti-affinity labels are required")
    script = k6_script(target_url, pod_count)
    config = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": name + "-script", "namespace": namespace},
              "data": {"load.js": script}}
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app": "kubeheal-p11-k6"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 900,
                 "template": {"metadata": {"labels": {"app": "kubeheal-p11-k6"}},
                              "spec": {"restartPolicy": "Never",
                                       "affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
                                           "labelSelector": {"matchExpressions": [{"key": "app", "operator": "In",
                                                                                   "values": list(anti_affinity_labels)}]},
                                           "topologyKey": "kubernetes.io/hostname"}]}},
                                       "containers": [{"name": "k6", "image": "grafana/k6:0.54.0",
                                                       "args": ["run", "/scripts/load.js"],
                                                       "volumeMounts": [{"name": "script", "mountPath": "/scripts", "readOnly": True}],
                                                       "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                                                     "limits": {"cpu": "1", "memory": "512Mi"}}}]}}},
        "_script": script,
    }
    job["spec"]["template"]["spec"]["volumes"] = [{"name": "script", "configMap": {"name": name + "-script"}}]
    return {"objects": [config, job], "_script": script}


def apply_k6_job(context: str, manifest: Mapping, *, runner: Runner = subprocess.run) -> str:
    """Apply a generated Job. The k6 JS is embedded in the container invocation via stdin."""
    script = manifest.get("_script")
    objects = manifest.get("objects")
    if not script or not objects:
        raise ValueError("manifest was not produced by k6_job_manifest")
    import yaml
    rendered = "---\n".join(yaml.safe_dump(item, sort_keys=False) for item in objects)
    kubectl(context, ["apply", "-f", "-"], runner=runner, input_text=rendered)
    job = objects[1]
    name = job["metadata"]["name"]
    ns = job["metadata"]["namespace"]
    kubectl(context, ["wait", "--for=condition=complete", "job/" + name, "-n", ns, "--timeout=960s"], runner=runner)
    return kubectl(context, ["logs", "job/" + name, "-n", ns], runner=runner)


def chaos_command(context: str, namespace: str, deployment: str, *, action: str,
                  runner: Runner = subprocess.run) -> str:
    """Run a bounded deployment restart or model-server pod deletion for chaos evaluation."""
    if action not in {"restart", "delete-one-pod"}:
        raise ValueError("action must be restart or delete-one-pod")
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
                  now: datetime | None = None) -> tuple[Path, Path]:
    """Write CSV and JSON metadata. Empty rows are explicitly recorded as not measured."""
    records = [dict(row) for row in rows]
    actual_status = status if records else "not measured"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"{scenario}.csv"
    meta_path = out_dir / f"{scenario}.json"
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
