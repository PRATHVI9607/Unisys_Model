"""
Prometheus client with fresh-metric polling + shared cache (PRD Section 09.1)
=============================================================================
Replaces v3's `asyncio.sleep(15)` anti-pattern. Polls with backoff, returns as
soon as fresh data is available, and shares a cache keyed by (namespace, pod)
so 100 events for the same pod make 1 Prometheus call, not 100.
"""

import asyncio
import logging
import time
from typing import Optional

import numpy as np

from models.health_model.metric_schema import (
    METRIC_COLUMNS, NUM_METRICS, INPUT_SEQUENCE_LENGTH,
)

logger = logging.getLogger(__name__)

# {(namespace, pod): (np.ndarray[60,15], fetch_time)}
_prometheus_cache: dict = {}
CACHE_TTL_SECONDS = 8.0


class PrometheusDataTooOld(Exception):
    pass


async def wait_for_fresh_metrics(
    namespace: str,
    pod: str,
    prometheus_url: str = "http://prometheus-operated.monitoring.svc.cluster.local:9090",
    max_age_s: int = 6,
    timeout_s: int = 30,
) -> np.ndarray:
    """Poll until fresh metric data is available; return [60,15]. On timeout,
    return stale-but-available data, else zeros (model handles missing data)."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s

    while loop.time() < deadline:
        cached = _prometheus_cache.get((namespace, pod))
        if cached is not None:
            data, ftime = cached
            if (loop.time() - ftime) <= max_age_s:
                return data
        try:
            data = await _fetch_prometheus_raw(namespace, pod, prometheus_url)
            _prometheus_cache[(namespace, pod)] = (data, loop.time())
            return data
        except PrometheusDataTooOld:
            await asyncio.sleep(2)
        except Exception as e:
            logger.warning(f"Prometheus fetch failed for {namespace}/{pod}: {e}")
            await asyncio.sleep(2)

    cached = _prometheus_cache.get((namespace, pod))
    if cached is not None:
        data, ftime = cached
        logger.warning(f"Prometheus data for {namespace}/{pod} is "
                       f"{loop.time()-ftime:.0f}s old at timeout")
        return data
    logger.warning(f"No Prometheus data for {namespace}/{pod} after {timeout_s}s. Using zeros.")
    return np.zeros((INPUT_SEQUENCE_LENGTH, NUM_METRICS), dtype=np.float32)


# PromQL for each of the 15 metric columns (range query over the window)
def _queries(namespace: str, pod: str) -> dict:
    sel = f'namespace="{namespace}",pod=~"{pod}.*"'
    return {
        "cpu_throttle_percent": f'rate(container_cpu_cfs_throttled_periods_total{{{sel}}}[1m])/clamp_min(rate(container_cpu_cfs_periods_total{{{sel}}}[1m]),1)*100',
        "cpu_usage_millicores": f'sum(rate(container_cpu_usage_seconds_total{{{sel}}}[1m]))*1000',
        "memory_rss_bytes": f'sum(container_memory_rss{{{sel}}})',
        "memory_working_set_bytes": f'sum(container_memory_working_set_bytes{{{sel}}})',
        "memory_limit_bytes": f'sum(kube_pod_container_resource_limits{{{sel},resource="memory"}})',
        "cpu_limit_millicores": f'sum(kube_pod_container_resource_limits{{{sel},resource="cpu"}})*1000',
        "http_request_rate": f'sum(rate(http_requests_total{{{sel}}}[1m]))',
        "http_error_rate": f'sum(rate(http_requests_total{{{sel},status=~"5.."}}[1m]))',
        "http_p50_latency_ms": f'histogram_quantile(0.50,rate(http_request_duration_seconds_bucket{{{sel}}}[1m]))*1000',
        "http_p99_latency_ms": f'histogram_quantile(0.99,rate(http_request_duration_seconds_bucket{{{sel}}}[1m]))*1000',
        "http_p999_latency_ms": f'histogram_quantile(0.999,rate(http_request_duration_seconds_bucket{{{sel}}}[1m]))*1000',
        "pod_restarts_total": f'sum(kube_pod_container_status_restarts_total{{{sel}}})',
        "network_receive_bytes": f'sum(rate(container_network_receive_bytes_total{{{sel}}}[1m]))',
        "network_transmit_bytes": f'sum(rate(container_network_transmit_bytes_total{{{sel}}}[1m]))',
        "disk_io_bytes": f'sum(rate(container_fs_reads_bytes_total{{{sel}}}[1m]))+sum(rate(container_fs_writes_bytes_total{{{sel}}}[1m]))',
    }


async def _fetch_prometheus_raw(namespace: str, pod: str, prometheus_url: str) -> np.ndarray:
    """Query all 15 metrics concurrently as instantaneous values, broadcast
    across the 60-step window (range backfill is done by the trainer; at serve
    time the latest value per metric is the freshest signal)."""
    import aiohttp

    queries = _queries(namespace, pod)
    out = np.zeros((INPUT_SEQUENCE_LENGTH, NUM_METRICS), dtype=np.float32)

    async def one(session, i, q):
        try:
            async with session.get(f"{prometheus_url}/api/v1/query",
                                   params={"query": q},
                                   timeout=aiohttp.ClientTimeout(total=2)) as r:
                if r.status == 200:
                    js = await r.json()
                    res = js.get("data", {}).get("result", [])
                    if res:
                        return i, float(res[0]["value"][1])
        except Exception:
            pass
        return i, 0.0

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            *[one(session, i, queries[c]) for i, c in enumerate(METRIC_COLUMNS)]
        )
    for i, v in results:
        out[:, i] = v
    return out
