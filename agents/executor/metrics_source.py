"""
Default canary metric source: p99 latency and CPU throttling from Prometheus.
=============================================================================
The drift path takes any `async (namespace, deployment, window_s) -> {metric: float | None}` callable;
tests inject a fake. This is the production one. The two PromQL expressions use the metric names the
Health Agent already queries (`http_request_duration_seconds_bucket`, `container_cpu_cfs_*`), over a
range of `window_s` seconds. `None` means Prometheus returned no sample, which the canary rule treats
as "not improved" (it never turns a missing value into 0).
"""

import logging
import math
from typing import Awaitable, Callable, Dict, Optional

logger = logging.getLogger(__name__)


def queries(namespace: str, deployment: str, window_s: float) -> Dict[str, str]:
    w = f"{int(window_s)}s"
    sel = f'namespace="{namespace}",pod=~"{deployment}-.*"'
    return {
        "http_p99_latency_ms": (f"histogram_quantile(0.99,sum by (le)"
                                f"(rate(http_request_duration_seconds_bucket{{{sel}}}[{w}])))*1000"),
        "cpu_throttle_percent": (f"sum(rate(container_cpu_cfs_throttled_periods_total{{{sel}}}[{w}]))"
                                 f"/clamp_min(sum(rate(container_cpu_cfs_periods_total{{{sel}}}[{w}])),1)*100"),
    }


async def _aiohttp_get(url: str, params: dict) -> dict:
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.get(url, params=params, timeout=aiohttp.ClientTimeout(total=5)) as r:
            r.raise_for_status()
            return await r.json()


class PrometheusMetricSource:
    def __init__(self, base_url: str, http_get: Optional[Callable[[str, dict], Awaitable[dict]]] = None):
        self.base_url = base_url.rstrip("/")
        self.http_get = http_get or _aiohttp_get

    async def __call__(self, namespace: str, deployment: str, window_s: float) -> Dict[str, Optional[float]]:
        out: Dict[str, Optional[float]] = {}
        for key, q in queries(namespace, deployment, window_s).items():
            try:
                js = await self.http_get(f"{self.base_url}/api/v1/query", {"query": q})
                res = (js.get("data") or {}).get("result") or []
                val = float(res[0]["value"][1]) if res else None
                out[key] = None if val is None or math.isnan(val) else val
            except Exception as e:
                logger.warning(f"prometheus query for {key} failed: {e}")
                out[key] = None
        return out
