"""Prometheus metric window for one Deployment, in the raw SI units of features.health.RAW_METRICS."""

from __future__ import annotations

import asyncio
import logging
import math

import aiohttp

from kubeheal.features.health import METRIC_STEP_S

log = logging.getLogger("kubeheal.health.prometheus")

def pod_regex(deployment: str) -> str:
    """Pods of exactly this Deployment: <name>-<pod-template-hash>-<suffix> (PromQL regexes are anchored)."""
    return deployment.replace(".", r"\\.") + "-[a-z0-9]+-[a-z0-9]+"


def build_queries(namespace: str, deployment: str) -> dict[str, str]:
    """One PromQL per RAW_METRICS name, scoped to this Deployment's pods, in raw SI units."""
    pods = f'namespace="{namespace}",pod=~"{pod_regex(deployment)}"'

    def sel(*extra: str) -> str:
        return "{" + ",".join((pods, *extra)) + "}"

    ctr = sel('container!=""', 'container!="POD"')   # real containers only (no pause / pod aggregate)
    dep = f'{{namespace="{namespace}",deployment="{deployment}"}}'
    req = f"sum(rate(http_requests_total{sel()}[1m]))"
    return {
        "cpu_usage_cores": f"sum(rate(container_cpu_usage_seconds_total{ctr}[1m]))",
        "cpu_limit_cores": f"sum(kube_pod_container_resource_limits{sel('resource="cpu"')})",
        "cpu_throttled_ratio": (f"sum(rate(container_cpu_cfs_throttled_periods_total{ctr}[1m]))"
                                f" / sum(rate(container_cpu_cfs_periods_total{ctr}[1m]))"),
        "memory_working_set_bytes": f"sum(container_memory_working_set_bytes{ctr})",
        "memory_limit_bytes": f"sum(kube_pod_container_resource_limits{sel('resource="memory"')})",
        "request_rate_rps": req,
        # `or … * 0`: a real 0 when requests are instrumented but no 5xx happened; missing if not instrumented.
        "error_rate_rps": f"sum(rate(http_requests_total{sel('status=~"5.."')}[1m])) or ({req} * 0)",
        "latency_p99_s": ("histogram_quantile(0.99, sum by (le) "
                          f"(rate(http_request_duration_seconds_bucket{sel()}[1m])))"),
        "restarts_total": f"sum(kube_pod_container_status_restarts_total{sel()})",
        "replicas_desired": f"max(kube_deployment_spec_replicas{dep})",
        "replicas_ready": f"max(kube_deployment_status_replicas_ready{dep})",
    }


def parse_range(body: dict) -> list[float] | None:
    """query_range response → samples of the first series; NaN/Inf dropped; None when no usable data."""
    if body.get("status") != "success":
        return None
    result = (body.get("data") or {}).get("result") or []
    if not result:
        return None
    out = []
    for _, v in result[0].get("values") or []:
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if math.isfinite(f):
            out.append(f)
    return out or None


async def _query(session: aiohttp.ClientSession, base_url: str, promql: str,
                 start: float, end: float) -> list[float] | None:
    params = {"query": promql, "start": f"{start:.3f}", "end": f"{end:.3f}", "step": str(METRIC_STEP_S)}
    async with session.get(f"{base_url}/api/v1/query_range", params=params,
                           timeout=aiohttp.ClientTimeout(total=10)) as resp:
        if resp.status != 200:
            raise aiohttp.ClientResponseError(resp.request_info, (), status=resp.status,
                                              message=(await resp.text())[:200])
        return parse_range(await resp.json())


async def fetch_window(session: aiohttp.ClientSession, base_url: str, namespace: str, deployment: str,
                       start: float, end: float) -> dict[str, list[float]]:
    """RAW_METRICS over [start, end] (epoch s) at METRIC_STEP_S, queried concurrently.

    The single window definition for serving and training: the health agent and
    training/collect/drift_lab.py both call this with start = when the change was
    seen and end = start + the assessment delay. A failed or empty metric is left
    out (missing, never 0).
    """
    queries = build_queries(namespace, deployment)
    results = await asyncio.gather(*(_query(session, base_url, q, start, end)
                                     for q in queries.values()), return_exceptions=True)
    window, errors = {}, []
    for name, res in zip(queries, results, strict=True):
        if isinstance(res, BaseException):
            if not isinstance(res, Exception):
                raise res
            errors.append(f"{name}: {res!r}")
        elif res is not None:
            window[name] = res
    if errors:
        log.warning("prometheus at %s: %d/%d queries failed for %s/%s (%s)", base_url, len(errors),
                    len(queries), namespace, deployment, errors[0])
    return window
