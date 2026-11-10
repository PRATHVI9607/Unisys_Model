"""
Prometheus client: real 60-step range window + shared cache (PRD Section 09.1, plan P5-H1)
========================================================================================
`fetch_metric_window` asks Prometheus for a real `query_range` per metric (60 steps of 5 s ending at
"now") and returns a `MetricWindow`: the [60, 15] array the Health Model expects plus an explicit record
of what is missing. The PromQL per metric lives in `metric_queries.METRIC_SPECS`.

Missing data is never silent:
  * a metric with no usable sample in the window (no series, empty result, only NaN) is listed in
    `MetricWindow.missing`; its column in `values` holds 0.0 only as a model input placeholder and
    `MetricWindow.mask[i]` is False. Consumers must use the mask or the list, not the zeros.
  * a metric with fewer than 60 usable samples is listed in `MetricWindow.short` with its count in
    `observed`. Gaps inside the window are forward-filled from the last real sample, leading gaps are
    back-filled from the first real sample; the fill never invents a value for a metric with no sample.
  * if nothing at all can be read (Prometheus down or every metric empty) `PrometheusUnavailable` is
    raised: no window, no assessment (fail closed, see the P1 review).

`wait_for_fresh_metrics` keeps its public name and still returns an `np.ndarray[60, 15]` (used by
`models/generate_health_training_data.py`). It now logs which metrics were missing and raises
`PrometheusUnavailable` instead of returning an all-zero array when no data exists.
`wait_for_fresh_metric_window` is the same polling loop returning the full `MetricWindow`.
"""

import asyncio
import logging
import math
import os
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional

import numpy as np

from agents.health_agent.metric_queries import SPEC_BY_COLUMN, build_queries
from models.health_model.metric_schema import (
    METRIC_COLUMNS, NUM_METRICS, INPUT_SEQUENCE_LENGTH,
)

logger = logging.getLogger(__name__)

STEP_SECONDS = 5                      # 60 steps x 5 s = the 5 minute window of the Health Model
QUERY_TIMEOUT_S = float(os.environ.get("PROMETHEUS_QUERY_TIMEOUT_S", "5"))

# {(namespace, pod): (MetricWindow, fetch_time)}
_prometheus_cache: dict = {}
CACHE_TTL_SECONDS = 8.0


class PrometheusDataTooOld(Exception):
    pass


class PrometheusUnavailable(Exception):
    """Prometheus could not be read, or returned no usable sample for any of the 15 metrics."""


@dataclass
class MetricWindow:
    values: np.ndarray                                     # [60, 15] float32, 0.0 placeholder where missing
    missing: List[str]                                     # columns with no usable sample
    observed: Dict[str, int]                               # usable samples per column (0..60)
    short: List[str] = field(default_factory=list)         # columns with 0 < observed < 60
    start: float = 0.0                                     # unix seconds of step 0
    end: float = 0.0                                       # unix seconds of the last step
    step: int = STEP_SECONDS
    newest_sample_ts: Optional[float] = None               # newest real sample over all metrics

    @property
    def mask(self) -> np.ndarray:
        """bool[15], True where the column holds real data."""
        return np.array([c not in self.missing for c in METRIC_COLUMNS], dtype=bool)

    @property
    def complete(self) -> bool:
        return not self.missing and not self.short

    def summary(self) -> Dict:
        return {"missing": list(self.missing), "short": list(self.short),
                "observed": dict(self.observed), "start": self.start, "end": self.end}


# query_fn(promql, start, end, step) -> Prometheus /api/v1/query_range JSON body (dict)
QueryRangeFn = Callable[[str, float, float, int], Awaitable[dict]]


def _queries(namespace: str, pod: str) -> dict:
    """Kept for callers of the pre-P5 name; the table is in metric_queries.py."""
    return build_queries(namespace, pod)


def _series_to_grid(result: List[dict], start: float, step: int, agg: str) -> Dict[int, float]:
    """Reduce the series of one query_range response onto grid index -> value.

    Samples that are NaN or Inf (for example histogram_quantile with no traffic) are not usable."""
    per_idx: Dict[int, List[float]] = {}
    for series in result:
        for ts, raw in series.get("values", []):
            try:
                v = float(raw)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(v):
                continue
            idx = int(round((float(ts) - start) / step))
            if 0 <= idx < INPUT_SEQUENCE_LENGTH:
                per_idx.setdefault(idx, []).append(v)
    reduce = max if agg == "max" else sum
    return {i: reduce(vs) for i, vs in per_idx.items()}


def _fill_column(points: Dict[int, float]) -> np.ndarray:
    """Forward fill gaps from the last real sample, back fill the leading gap from the first."""
    col = np.zeros(INPUT_SEQUENCE_LENGTH, dtype=np.float32)
    first = min(points)
    last_val = points[first]
    for i in range(INPUT_SEQUENCE_LENGTH):
        if i in points:
            last_val = points[i]
        elif i < first:
            last_val = points[first]
        col[i] = last_val
    return col


async def _http_query_range(prometheus_url: str, promql: str, start: float, end: float, step: int) -> dict:
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{prometheus_url}/api/v1/query_range",
            params={"query": promql, "start": f"{start:.3f}", "end": f"{end:.3f}", "step": str(step)},
            timeout=aiohttp.ClientTimeout(total=QUERY_TIMEOUT_S),
        ) as r:
            if r.status != 200:
                raise RuntimeError(f"Prometheus returned HTTP {r.status}")
            return await r.json()


async def fetch_metric_window(
    namespace: str,
    pod: str,
    prometheus_url: str = "http://prometheus-operated.monitoring.svc.cluster.local:9090",
    *,
    now: Optional[float] = None,
    query_fn: Optional[QueryRangeFn] = None,
) -> MetricWindow:
    """One real `query_range` per metric (15 concurrent), 60 steps of 5 s ending at `now`.

    `query_fn` and `now` are injectable for tests. Raises PrometheusUnavailable when no metric has a
    single usable sample."""
    end = float(now if now is not None else time.time())
    start = end - (INPUT_SEQUENCE_LENGTH - 1) * STEP_SECONDS
    queries = build_queries(namespace, pod)
    if query_fn is None:
        async def query_fn(q, s, e, st):          # noqa: E306
            return await _http_query_range(prometheus_url, q, s, e, st)

    async def one(column: str):
        try:
            body = await query_fn(queries[column], start, end, STEP_SECONDS)
            if body.get("status") != "success":
                raise RuntimeError(f"status={body.get('status')} error={body.get('error')}")
            result = body.get("data", {}).get("result", [])
            return column, _series_to_grid(result, start, STEP_SECONDS, SPEC_BY_COLUMN[column].agg), None
        except Exception as e:                       # one metric failing must not hide the others
            return column, {}, e

    results = await asyncio.gather(*[one(c) for c in METRIC_COLUMNS])

    values = np.zeros((INPUT_SEQUENCE_LENGTH, NUM_METRICS), dtype=np.float32)
    missing: List[str] = []
    short: List[str] = []
    observed: Dict[str, int] = {}
    errors: List[str] = []
    newest: Optional[float] = None
    for i, (column, points, err) in enumerate(results):
        observed[column] = len(points)
        if err is not None:
            errors.append(f"{column}: {err}")
        if not points:
            missing.append(column)
            continue
        values[:, i] = _fill_column(points)
        if len(points) < INPUT_SEQUENCE_LENGTH:
            short.append(column)
        ts = start + max(points) * STEP_SECONDS
        newest = ts if newest is None else max(newest, ts)

    if len(missing) == NUM_METRICS:
        detail = "; ".join(errors[:3]) if errors else "all queries returned no samples"
        raise PrometheusUnavailable(f"no usable metric for {namespace}/{pod}: {detail}")
    if errors:
        logger.warning("Prometheus query errors for %s/%s: %s", namespace, pod, "; ".join(errors[:5]))
    if missing:
        logger.warning("Metrics missing for %s/%s (flagged, placeholder 0.0 in the window): %s",
                       namespace, pod, ", ".join(missing))
    return MetricWindow(values=values, missing=missing, observed=observed, short=short,
                        start=start, end=end, step=STEP_SECONDS, newest_sample_ts=newest)


async def wait_for_fresh_metric_window(
    namespace: str,
    pod: str,
    prometheus_url: str = "http://prometheus-operated.monitoring.svc.cluster.local:9090",
    max_age_s: int = 6,
    timeout_s: int = 30,
    *,
    max_sample_age_s: Optional[float] = None,
    query_fn: Optional[QueryRangeFn] = None,
    clock: Optional[Callable[[], float]] = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> MetricWindow:
    """Poll until a window is available; return it with its missing flags.

    `max_age_s` is the shared-cache TTL (as before). `max_sample_age_s`, when set, additionally requires
    the newest real sample to be at most that old; otherwise the poll retries until `timeout_s`, then the
    last window is returned (it is stale, and a warning says so). Unset by default because the scrape
    interval of the target Prometheus is not known to this repo. Raises PrometheusUnavailable if no
    window could be read before the timeout."""
    clock = clock or time.time
    deadline = clock() + timeout_s
    last_error: Optional[Exception] = None
    stale: Optional[MetricWindow] = None

    while True:
        cached = _prometheus_cache.get((namespace, pod))
        if cached is not None:
            win, ftime = cached
            if (clock() - ftime) <= max_age_s:
                return win
        try:
            win = await fetch_metric_window(namespace, pod, prometheus_url,
                                            now=clock(), query_fn=query_fn)
            _prometheus_cache[(namespace, pod)] = (win, clock())
            if (max_sample_age_s is not None and win.newest_sample_ts is not None
                    and clock() - win.newest_sample_ts > max_sample_age_s):
                stale = win
                raise PrometheusDataTooOld(
                    f"newest sample is {clock() - win.newest_sample_ts:.0f}s old")
            return win
        except PrometheusDataTooOld as e:
            last_error = e
        except Exception as e:
            last_error = e
            logger.warning(f"Prometheus fetch failed for {namespace}/{pod}: {e}")
        if clock() >= deadline:
            break
        await sleep(2)

    if stale is not None:
        logger.warning(f"Prometheus data for {namespace}/{pod} is still older than "
                       f"{max_sample_age_s}s at timeout; returning it flagged as stale")
        return stale
    raise PrometheusUnavailable(f"no metric window for {namespace}/{pod} after {timeout_s}s: {last_error}")


async def wait_for_fresh_metrics(
    namespace: str,
    pod: str,
    prometheus_url: str = "http://prometheus-operated.monitoring.svc.cluster.local:9090",
    max_age_s: int = 6,
    timeout_s: int = 30,
) -> np.ndarray:
    """Backward compatible wrapper: poll until data is available, return `[60, 15]`.

    Behaviour change from pre-P5: no all-zero array on failure (PrometheusUnavailable is raised), and
    missing metrics are logged. Callers that need the missing flags use `wait_for_fresh_metric_window`."""
    win = await wait_for_fresh_metric_window(namespace, pod, prometheus_url, max_age_s, timeout_s)
    return win.values
