"""
Resource profile: measure per-pod CPU and memory over a time window (P9-H4, spec S-CL-3).
=========================================================================================
Requests and limits for the KubeHeal pods are not guessed: this script measures usage and writes

  * resource_profile.csv          one row per (component, pod, container, metric) with summary statistics
  * resource_profile_values.yaml  a values snippet for deploy/helm/kubeheal (resources: per component)
  * resource_profile_meta.json    source, window, step, time of the run and the statistics chosen

Which statistic becomes the request and which the limit is a decision, so there is no default: pass
--request-stat and --limit-stat (min, mean, p50, p90, p95, p99, max; or any pNN). When several pods
of one component are measured, the highest value across pods is used.

Sources (run it on a machine that can reach the cluster; the orchestrator runs it, not CI):

  Prometheus (cAdvisor series, needs a reachable URL, e.g. kubectl port-forward):
    python eval/resource_profile.py --source prometheus --prometheus-url http://127.0.0.1:9090 \\
        --namespace kubeheal --window-s <n> --step-s <n> --rate-window-s <n> \\
        --request-stat <stat> --limit-stat <stat> --out-dir <dir>

  metrics-server (polls the metrics API through kubectl, so it needs an explicit context):
    python eval/resource_profile.py --source metrics-server --context <ctx> \\
        --namespace kubeheal --window-s <n> --step-s <n> --request-stat <stat> --limit-stat <stat> \\
        --out-dir <dir>

Run the load you want to size for while it samples (the numbers describe only that window).
Only the parsing and statistics are unit-tested (tests/test_platform_resource_profile.py); the script
has not been run against a cluster.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# Pod name prefix -> (component id, values path in deploy/helm/kubeheal). Longest prefix wins.
COMPONENTS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "kubeheal-health-model": ("health-model", ("modelServers", "health")),
    "kubeheal-security-model": ("security-model", ("modelServers", "security")),
    "kubeheal-dcm": ("dcm", ("modelServers", "dcm")),
    "health-agent": ("health-agent", ("healthAgent",)),
    "security-agent": ("security-agent", ("securityAgent",)),
    "fusion-agent": ("fusion-agent", ("fusionAgent",)),
    "executor": ("executor", ("executor",)),
    "kubeheal-dashboard": ("dashboard", ("dashboard",)),
    "redis": ("redis", ("redis",)),
    "minio": ("minio", ("minio",)),
}

CPU = "cpu_cores"
MEM = "memory_bytes"
_STAT_RE = re.compile(r"^(min|mean|max|p(\d{1,2}(?:\.\d+)?))$")
Series = Dict[Tuple[str, str], List[float]]   # (pod, container) -> samples


# ---- parsing ----------------------------------------------------------------------------------

def component_for_pod(pod: str) -> Optional[str]:
    best = None
    for prefix in COMPONENTS:
        if pod == prefix or pod.startswith(prefix + "-"):
            if best is None or len(prefix) > len(best):
                best = prefix
    return COMPONENTS[best][0] if best else None


def parse_cpu_quantity(q: str) -> float:
    """Kubernetes CPU quantity to cores: '250m', '12345678n', '1500u', '2'."""
    q = str(q).strip()
    for suffix, scale in (("n", 1e-9), ("u", 1e-6), ("m", 1e-3)):
        if q.endswith(suffix):
            return float(q[:-1]) * scale
    return float(q)


def parse_memory_quantity(q: str) -> float:
    """Kubernetes memory quantity to bytes: '512Mi', '12345Ki', '1G', '123456'."""
    q = str(q).strip()
    binary = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60}
    decimal = {"k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "m": 1e-3}
    for suffix, scale in binary.items():
        if q.endswith(suffix):
            return float(q[:-2]) * scale
    for suffix, scale in decimal.items():
        if q.endswith(suffix):
            return float(q[:-1]) * scale
    return float(q)


def parse_query_range(payload: dict) -> Series:
    """Prometheus /api/v1/query_range matrix result to {(pod, container): [values]}."""
    if payload.get("status") != "success":
        raise ValueError(f"prometheus query failed: {payload.get('error') or payload.get('status')}")
    data = payload.get("data") or {}
    if data.get("resultType") != "matrix":
        raise ValueError(f"expected a matrix result, got {data.get('resultType')!r}")
    out: Series = {}
    for item in data.get("result", []):
        metric = item.get("metric", {})
        pod = metric.get("pod")
        if not pod:
            continue
        key = (pod, metric.get("container", ""))
        for _ts, raw in item.get("values", []):
            value = float(raw)
            if math.isnan(value) or math.isinf(value):   # Prometheus can emit NaN, never count it as a sample
                continue
            out.setdefault(key, []).append(value)
    return out


def parse_metrics_api(payload: dict) -> Dict[Tuple[str, str], Tuple[float, float]]:
    """metrics.k8s.io PodMetricsList to {(pod, container): (cpu_cores, memory_bytes)}."""
    out: Dict[Tuple[str, str], Tuple[float, float]] = {}
    for item in payload.get("items", []):
        pod = item.get("metadata", {}).get("name")
        for c in item.get("containers", []):
            usage = c.get("usage", {})
            if pod and "cpu" in usage and "memory" in usage:
                out[(pod, c.get("name", ""))] = (parse_cpu_quantity(usage["cpu"]),
                                                  parse_memory_quantity(usage["memory"]))
    return out


# ---- statistics -------------------------------------------------------------------------------

def validate_stat(name: str) -> str:
    if not _STAT_RE.match(name):
        raise argparse.ArgumentTypeError(f"unknown statistic {name!r}: use min, mean, max or pNN (e.g. p95)")
    return name


def statistic(samples: Sequence[float], name: str) -> float:
    """min, mean, max or a nearest-rank percentile pNN."""
    if not samples:
        raise ValueError("no samples")
    ordered = sorted(samples)
    if name == "min":
        return ordered[0]
    if name == "max":
        return ordered[-1]
    if name == "mean":
        return sum(ordered) / len(ordered)
    m = _STAT_RE.match(name)
    if not m or not m.group(2):
        raise ValueError(f"unknown statistic {name!r}")
    pct = float(m.group(2))
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


SUMMARY_STATS = ("min", "mean", "p50", "p90", "p95", "p99", "max")


def build_rows(cpu: Series, mem: Series) -> List[dict]:
    rows = []
    for metric, series in ((CPU, cpu), (MEM, mem)):
        for (pod, container), samples in sorted(series.items()):
            if not samples:
                continue
            row = {"component": component_for_pod(pod) or "", "pod": pod, "container": container,
                   "metric": metric, "samples": len(samples)}
            for s in SUMMARY_STATS:
                row[s] = statistic(samples, s)
            rows.append(row)
    return rows


CSV_FIELDS = ["component", "pod", "container", "metric", "samples", *SUMMARY_STATS]


def write_csv(rows: Iterable[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


# ---- values snippet ---------------------------------------------------------------------------

def _fmt_cpu(cores: float) -> str:
    return f"{max(1, math.ceil(cores * 1000))}m"


def _fmt_mem(bytes_: float) -> str:
    return f"{max(1, math.ceil(bytes_ / 2**20))}Mi"


def build_values(cpu: Series, mem: Series, request_stat: str, limit_stat: str) -> dict:
    """{component values path: {'requests': {...}, 'limits': {...}}}. Highest value across a
    component's pods and containers of the chosen statistic. Components with no samples are omitted."""
    per_component: Dict[str, Dict[str, Dict[str, float]]] = {}
    for metric, series in ((CPU, cpu), (MEM, mem)):
        for (pod, _container), samples in series.items():
            comp = component_for_pod(pod)
            if comp is None or not samples:
                continue
            slot = per_component.setdefault(comp, {"requests": {}, "limits": {}})
            for kind, stat in (("requests", request_stat), ("limits", limit_stat)):
                value = statistic(samples, stat)
                res = "cpu" if metric == CPU else "memory"
                slot[kind][res] = max(slot[kind].get(res, 0.0), value)
    by_comp_path = {v[0]: v[1] for v in COMPONENTS.values()}
    out = {}
    for comp, slot in per_component.items():
        out[by_comp_path[comp]] = {
            kind: {"cpu": _fmt_cpu(vals["cpu"]), "memory": _fmt_mem(vals["memory"])}
            for kind, vals in slot.items() if "cpu" in vals and "memory" in vals
        }
    return out


def render_values_yaml(values: dict, header: str) -> str:
    """Tiny YAML writer for the snippet (nested maps of strings only, no PyYAML dependency)."""
    tree: dict = {}
    for path, resources in values.items():
        node = tree
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = {"resources": resources}
    lines = [f"# {line}" for line in header.splitlines()]

    def emit(node: dict, depth: int) -> None:
        for key in sorted(node):
            val = node[key]
            if isinstance(val, dict):
                lines.append(f"{'  ' * depth}{key}:")
                emit(val, depth + 1)
            else:
                lines.append(f'{"  " * depth}{key}: "{val}"')

    emit(tree, 0)
    return "\n".join(lines) + "\n"


# ---- sources ----------------------------------------------------------------------------------

def prometheus_queries(namespace: str, rate_window_s: int) -> Dict[str, str]:
    sel = f'namespace="{namespace}",container!="",container!="POD"'
    return {
        CPU: f"sum by (pod, container) (rate(container_cpu_usage_seconds_total{{{sel}}}[{int(rate_window_s)}s]))",
        MEM: f"max by (pod, container) (container_memory_working_set_bytes{{{sel}}})",
    }


def fetch_query_range(base_url: str, query: str, start: float, end: float, step_s: int,
                      opener: Callable = urllib.request.urlopen) -> dict:
    params = urllib.parse.urlencode({"query": query, "start": f"{start:.3f}", "end": f"{end:.3f}",
                                     "step": f"{int(step_s)}s"})
    with opener(f"{base_url.rstrip('/')}/api/v1/query_range?{params}", timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def measure_prometheus(base_url: str, namespace: str, window_s: int, step_s: int, rate_window_s: int,
                       end: Optional[float] = None, opener: Callable = urllib.request.urlopen) -> Tuple[Series, Series]:
    end = time.time() if end is None else end
    start = end - window_s
    queries = prometheus_queries(namespace, rate_window_s)
    cpu = parse_query_range(fetch_query_range(base_url, queries[CPU], start, end, step_s, opener))
    mem = parse_query_range(fetch_query_range(base_url, queries[MEM], start, end, step_s, opener))
    return cpu, mem


def kubectl_metrics(context: str, namespace: str) -> dict:
    cmd = ["kubectl", "--context", context, "get", "--raw",
           f"/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods"]
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def measure_metrics_server(fetch: Callable[[], dict], window_s: int, step_s: int,
                           sleep: Callable[[float], None] = time.sleep,
                           clock: Callable[[], float] = time.monotonic) -> Tuple[Series, Series]:
    """Poll the metrics API every step_s seconds for window_s seconds (the first sample is immediate)."""
    cpu: Series = {}
    mem: Series = {}
    deadline = clock() + window_s
    while True:
        for key, (c, m) in parse_metrics_api(fetch()).items():
            cpu.setdefault(key, []).append(c)
            mem.setdefault(key, []).append(m)
        if clock() + step_s > deadline:
            break
        sleep(step_s)
    return cpu, mem


# ---- CLI --------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--source", required=True, choices=["prometheus", "metrics-server"])
    p.add_argument("--namespace", required=True)
    p.add_argument("--window-s", type=int, required=True, help="length of the measurement window in seconds")
    p.add_argument("--step-s", type=int, required=True, help="sample step in seconds")
    p.add_argument("--rate-window-s", type=int, help="prometheus only: rate() window in seconds")
    p.add_argument("--prometheus-url", help="prometheus only: base URL")
    p.add_argument("--context", help="metrics-server only: kubectl context (explicit on purpose)")
    p.add_argument("--request-stat", type=validate_stat, required=True)
    p.add_argument("--limit-stat", type=validate_stat, required=True)
    p.add_argument("--out-dir", required=True)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.window_s <= 0 or args.step_s <= 0:
        print("--window-s and --step-s must be positive", file=sys.stderr)
        return 2
    if args.source == "prometheus":
        if not args.prometheus_url or not args.rate_window_s or args.rate_window_s <= 0:
            print("--source prometheus needs --prometheus-url and a positive --rate-window-s", file=sys.stderr)
            return 2
        cpu, mem = measure_prometheus(args.prometheus_url, args.namespace, args.window_s, args.step_s,
                                      args.rate_window_s)
    else:
        if not args.context:
            print("--source metrics-server needs --context", file=sys.stderr)
            return 2
        cpu, mem = measure_metrics_server(lambda: kubectl_metrics(args.context, args.namespace),
                                          args.window_s, args.step_s)
    rows = build_rows(cpu, mem)
    if not rows:
        print("no samples returned: nothing written (is the namespace right and the load running?)",
              file=sys.stderr)
        return 1
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_csv(rows, out / "resource_profile.csv")
    header = (f"Measured by eval/resource_profile.py at {now} from {args.source}, namespace {args.namespace}.\n"
              f"Window {args.window_s}s, step {args.step_s}s. requests = {args.request_stat}, "
              f"limits = {args.limit_stat} (highest across a component's pods).\n"
              "Describes only the load that ran during the window. Merge into your values file.")
    (out / "resource_profile_values.yaml").write_text(
        render_values_yaml(build_values(cpu, mem, args.request_stat, args.limit_stat), header), encoding="utf-8")
    (out / "resource_profile_meta.json").write_text(json.dumps({
        "measured_at": now, "source": args.source, "namespace": args.namespace, "window_s": args.window_s,
        "step_s": args.step_s, "rate_window_s": args.rate_window_s, "request_stat": args.request_stat,
        "limit_stat": args.limit_stat, "rows": len(rows)}, indent=2), encoding="utf-8")
    print(f"wrote {len(rows)} rows to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
