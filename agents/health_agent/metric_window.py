"""
Prometheus window of the 11 raw metrics for the LightGBM health model (V5-D4a).
================================================================================
Port of v5's `agents/health_agent/prometheus.py`. It feeds `kubeheal.features.health.health_features`
and is separate from `metric_queries.py` / `prometheus_client.py`, which feed the legacy neural model's
15 channels and are not touched.

Window: [change seen, assess time] at a 15 s step (`METRIC_STEP_S`, the scrape interval), raw SI units
(cores, bytes, requests per second, seconds, counts). A series that returns nothing, or whose query
fails, is MISSING (None in the result), never 0. `kubeheal.features.health` treats None as no data.

Pods of a Deployment are selected by `pod_regex` (`<name>-<pod-template-hash>-<suffix>`), not by a plain
prefix, so sibling workloads (`web-migrate-x7k2p`, `web-db-0`, `web-agent-k8s2z`) stay out.

Per query, which exporter has to provide it, so a missing column can be traced:

  query name                  exporter / series needed
  --------------------------  ----------------------------------------------------------------------
  cpu_usage_cores             cAdvisor (kubelet): container_cpu_usage_seconds_total
  cpu_limit_cores             kube-state-metrics v2: kube_pod_container_resource_limits{resource="cpu"};
                              empty when no container has a CPU limit
  cpu_throttled_ratio         cAdvisor: container_cpu_cfs_throttled_periods_total and
                              container_cpu_cfs_periods_total; CFS periods exist only with a CPU limit
  memory_working_set_bytes    cAdvisor: container_memory_working_set_bytes
  memory_limit_bytes          kube-state-metrics v2: kube_pod_container_resource_limits{resource="memory"};
                              empty when no container has a memory limit
  request_rate_rps            demo victim app: http_requests_total{method,path,status}; the ServiceMonitor
                              makes Prometheus attach the `namespace` and `pod` target labels
  error_rate_rps              demo victim app: http_requests_total{status=~"5.."}; a real 0 when requests
                              are instrumented but no 5xx happened, missing when the app is not scraped
  latency_p99_s               demo victim app: http_request_duration_seconds_bucket histogram (same
                              ServiceMonitor labels)
  restarts_total              kube-state-metrics v2: kube_pod_container_status_restarts_total
  replicas_desired            kube-state-metrics v2: kube_deployment_spec_replicas
  replicas_ready              kube-state-metrics v2: kube_deployment_status_replicas_ready
  replicas_updated *          kube-state-metrics v2: kube_deployment_status_replicas_updated
  replicas_unavailable *      kube-state-metrics v2: kube_deployment_status_replicas_unavailable

  * not model features (not in RAW_METRICS): they show a stuck rollout, because replicas_ready also
    counts pods of the old ReplicaSet. They are fetched so the agent can use them, never fed to the model.

The k3d kubelet exposes no container_fs_* series; none is needed here.

Differences from v5: `step_s` is a parameter (default METRIC_STEP_S); the result has one key per query,
with None for a missing metric (v5 left the key out; `health_features` treats both the same); the
`missing_metrics` helper names the model metrics that came back empty.
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import Any

import aiohttp

from kubeheal.features.health import METRIC_STEP_S, RAW_METRICS

log = logging.getLogger("kubeheal.health.metric_window")

# Not model features: rollout-progress series fetched next to RAW_METRICS.
EXTRA_METRICS: tuple[str, ...] = ("replicas_updated", "replicas_unavailable")

QUERY_TIMEOUT_S = 10

# Kubernetes' random-name alphabet (no vowels, no 0/1/3): the pod-template-hash (1-10 chars) and the pod suffix (5).
_K8S_ALNUM = "[bcdfghjklmnpqrstvwxz2456789]"


def pod_regex(deployment: str) -> str:
    """Pods of exactly this Deployment: <name>-<pod-template-hash>-<suffix> (PromQL regexes are anchored).

    The alphabet keeps sibling workloads out (web-migrate-x7k2p Job, web-db-0, web-agent-k8s2z DaemonSet).
    The dot is escaped for a PromQL double-quoted string (`\\\\.` in the query is the regex `\\.`).
    shortcut: a sibling whose middle segment uses only that alphabet (CronJob "web" -> job web-29245678) still
    matches; join on kube_pod_owner/kube_replicaset_owner if that ever bites.
    """
    return deployment.replace(".", r"\\.") + f"-{_K8S_ALNUM}{{1,10}}-{_K8S_ALNUM}{{5}}"


def build_queries(namespace: str, deployment: str) -> dict[str, str]:
    """One PromQL per RAW_METRICS name (+ two rollout-progress series), scoped to this Deployment's pods, raw SI units."""
    pods = f'namespace="{namespace}",pod=~"{pod_regex(deployment)}"'

    def sel(*extra: str) -> str:
        return "{" + ",".join((pods, *extra)) + "}"

    ctr = sel('container!=""', 'container!="POD"')   # real containers only (no pause / pod aggregate)
    dep = f'{{namespace="{namespace}",deployment="{deployment}"}}'
    # Selectors built outside the f-strings: Python 3.11 (our venv) cannot nest the same quote type (v5 targets 3.13).
    cpu_res, mem_res, err_sel = sel('resource="cpu"'), sel('resource="memory"'), sel('status=~"5.."')
    req = f"sum(rate(http_requests_total{sel()}[1m]))"
    return {
        "cpu_usage_cores": f"sum(rate(container_cpu_usage_seconds_total{ctr}[1m]))",
        "cpu_limit_cores": f"sum(kube_pod_container_resource_limits{cpu_res})",
        "cpu_throttled_ratio": (f"sum(rate(container_cpu_cfs_throttled_periods_total{ctr}[1m]))"
                                f" / sum(rate(container_cpu_cfs_periods_total{ctr}[1m]))"),
        "memory_working_set_bytes": f"sum(container_memory_working_set_bytes{ctr})",
        "memory_limit_bytes": f"sum(kube_pod_container_resource_limits{mem_res})",
        "request_rate_rps": req,
        # `or ... * 0`: a real 0 when requests are instrumented but no 5xx happened; missing if not instrumented.
        "error_rate_rps": f"sum(rate(http_requests_total{err_sel}[1m])) or ({req} * 0)",
        "latency_p99_s": ("histogram_quantile(0.99, sum by (le) "
                          f"(rate(http_request_duration_seconds_bucket{sel()}[1m])))"),
        "restarts_total": f"sum(kube_pod_container_status_restarts_total{sel()})",
        "replicas_desired": f"max(kube_deployment_spec_replicas{dep})",
        "replicas_ready": f"max(kube_deployment_status_replicas_ready{dep})",
        # Not model features (not in RAW_METRICS): replicas_ready also counts pods of the old ReplicaSet,
        # these two show a stuck rollout.
        "replicas_updated": f"max(kube_deployment_status_replicas_updated{dep})",
        "replicas_unavailable": f"max(kube_deployment_status_replicas_unavailable{dep})",
    }


def parse_range(body: dict[str, Any]) -> list[float] | None:
    """query_range response -> samples of the first series; NaN/Inf dropped; None when no usable data."""
    if body.get("status") != "success":
        return None
    result = (body.get("data") or {}).get("result") or []
    if not result:
        return None
    out: list[float] = []
    for _, v in result[0].get("values") or []:
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if math.isfinite(f):
            out.append(f)
    return out or None


async def _query(session: aiohttp.ClientSession, base_url: str, promql: str,
                 start: float, end: float, step_s: int) -> list[float] | None:
    params = {"query": promql, "start": f"{start:.3f}", "end": f"{end:.3f}", "step": str(step_s)}
    async with session.get(f"{base_url}/api/v1/query_range", params=params,
                           timeout=aiohttp.ClientTimeout(total=QUERY_TIMEOUT_S)) as resp:
        if resp.status != 200:
            raise aiohttp.ClientResponseError(resp.request_info, (), status=resp.status,
                                              message=(await resp.text())[:200])
        return parse_range(await resp.json())


async def fetch_window(session: aiohttp.ClientSession, base_url: str, namespace: str, deployment: str,
                       start_s: float, end_s: float,
                       step_s: int = METRIC_STEP_S) -> dict[str, list[float] | None]:
    """The metrics of build_queries over [start_s, end_s] (epoch s) at step_s, queried concurrently.

    Pass start_s = when the change was seen and end_s = start_s + the assessment delay. One key per
    query; a failed or empty metric is None (missing, never 0), and one failing query does not discard
    the others. Concurrency is bounded by the fixed query count (13), each with a 10 s timeout.
    """
    queries = build_queries(namespace, deployment)
    results = await asyncio.gather(*(_query(session, base_url, q, start_s, end_s, step_s)
                                     for q in queries.values()), return_exceptions=True)
    window: dict[str, list[float] | None] = {}
    errors: list[str] = []
    for name, res in zip(queries, results, strict=True):
        if isinstance(res, BaseException):
            if not isinstance(res, Exception):
                raise res
            errors.append(f"{name}: {res!r}")
            window[name] = None
        else:
            window[name] = res
    if errors:
        log.warning("prometheus at %s: %d/%d queries failed for %s/%s (%s)", base_url, len(errors),
                    len(queries), namespace, deployment, errors[0])
    return window


def missing_metrics(window: dict[str, list[float] | None]) -> list[str]:
    """RAW_METRICS names (model features only) with no data in this window, in RAW_METRICS order."""
    return [name for name in RAW_METRICS if not window.get(name)]
