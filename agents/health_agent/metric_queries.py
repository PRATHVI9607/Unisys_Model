"""
PromQL mapping table for the 15 Health Model metric columns (P5-H1).
====================================================================
One file, one table: `METRIC_SPECS`. The column names and their order come from
`models/health_model/metric_schema.py` (METRIC_COLUMNS) and are not redefined here. The PromQL
expressions are the ones the repo already used before P5 (`prometheus_client._queries`), moved here
unchanged so the serving window keeps the same meaning as the data the trainer pairs it with.

Each row says where the metric name comes from and what the cluster must provide, so a missing
column in a result can be traced to its cause:

  basis "standard"   metric exposed by a standard exporter (cAdvisor via the kubelet, kube-state-metrics v2).
  basis "app-guess"  metric the workload itself must expose. The names `http_requests_total` (label
                     `status`) and `http_request_duration_seconds_bucket` appear only in this table; no
                     sample app, ServiceMonitor or scrape config in the repo defines them. They are
                     guesses (conventional names). Where the workload does not export them the columns come
                     back empty and are flagged in `MetricWindow.missing`, never silently 0.

Known caveats of the pre-P5 expressions, kept unchanged on purpose and not fixed here (changing them
would change the input distribution the model is trained on; decide together with retraining, P12):
  * `pod=~"<deployment>.*"` is a prefix match, so a Deployment `app` also matches pods of `app-2`.
  * container_cpu / memory / fs series exist once per container and once as a pod-level aggregate
    (container=""), so `sum(...)` over them can count a pod twice on some cAdvisor versions.
  * The http_* metrics also need `namespace` and `pod` labels on the application series.

`agg` says how several returned series are reduced per timestamp when the expression does not already
aggregate: "max" takes the worst series (throttle ratio and latency quantiles come back per pod or
container); "sum" is used where the PromQL already ends in `sum(...)` and returns one series.
"""

from dataclasses import dataclass
from typing import Dict, List

from models.health_model.metric_schema import METRIC_COLUMNS


@dataclass(frozen=True)
class MetricSpec:
    column: str
    promql: str          # template, `{sel}` is replaced by the label selector
    basis: str           # "standard" or "app-guess"
    needs: str           # exporter or application requirement
    agg: str = "sum"     # reduction when several series are returned: "sum" or "max"


def selector(namespace: str, pod: str) -> str:
    return f'namespace="{namespace}",pod=~"{pod}.*"'


_R = "{sel}"  # readability only

METRIC_SPECS: List[MetricSpec] = [
    MetricSpec("cpu_throttle_percent",
               'rate(container_cpu_cfs_throttled_periods_total{%s}[1m])/clamp_min(rate(container_cpu_cfs_periods_total{%s}[1m]),1)*100' % (_R, _R),
               "standard", "cAdvisor (kubelet); needs a CPU limit to produce CFS periods", "max"),
    MetricSpec("cpu_usage_millicores",
               'sum(rate(container_cpu_usage_seconds_total{%s}[1m]))*1000' % _R,
               "standard", "cAdvisor (kubelet)"),
    MetricSpec("memory_rss_bytes",
               'sum(container_memory_rss{%s})' % _R,
               "standard", "cAdvisor (kubelet)"),
    MetricSpec("memory_working_set_bytes",
               'sum(container_memory_working_set_bytes{%s})' % _R,
               "standard", "cAdvisor (kubelet)"),
    MetricSpec("memory_limit_bytes",
               'sum(kube_pod_container_resource_limits{%s,resource="memory"})' % _R,
               "standard", "kube-state-metrics v2; empty when the pod has no memory limit"),
    MetricSpec("cpu_limit_millicores",
               'sum(kube_pod_container_resource_limits{%s,resource="cpu"})*1000' % _R,
               "standard", "kube-state-metrics v2; empty when the pod has no CPU limit"),
    MetricSpec("http_request_rate",
               'sum(rate(http_requests_total{%s}[1m]))' % _R,
               "app-guess", "application exports http_requests_total with namespace and pod labels"),
    MetricSpec("http_error_rate",
               'sum(rate(http_requests_total{%s,status=~"5.."}[1m]))' % _R,
               "app-guess", "application exports http_requests_total with a `status` label"),
    MetricSpec("http_p50_latency_ms",
               'histogram_quantile(0.50,rate(http_request_duration_seconds_bucket{%s}[1m]))*1000' % _R,
               "app-guess", "application exports http_request_duration_seconds histogram", "max"),
    MetricSpec("http_p99_latency_ms",
               'histogram_quantile(0.99,rate(http_request_duration_seconds_bucket{%s}[1m]))*1000' % _R,
               "app-guess", "application exports http_request_duration_seconds histogram", "max"),
    MetricSpec("http_p999_latency_ms",
               'histogram_quantile(0.999,rate(http_request_duration_seconds_bucket{%s}[1m]))*1000' % _R,
               "app-guess", "application exports http_request_duration_seconds histogram", "max"),
    MetricSpec("pod_restarts_total",
               'sum(kube_pod_container_status_restarts_total{%s})' % _R,
               "standard", "kube-state-metrics v2"),
    MetricSpec("network_receive_bytes",
               'sum(rate(container_network_receive_bytes_total{%s}[1m]))' % _R,
               "standard", "cAdvisor (kubelet)"),
    MetricSpec("network_transmit_bytes",
               'sum(rate(container_network_transmit_bytes_total{%s}[1m]))' % _R,
               "standard", "cAdvisor (kubelet)"),
    MetricSpec("disk_io_bytes",
               'sum(rate(container_fs_reads_bytes_total{%s}[1m]))+sum(rate(container_fs_writes_bytes_total{%s}[1m]))' % (_R, _R),
               "standard", "cAdvisor (kubelet)"),
]

SPEC_BY_COLUMN: Dict[str, MetricSpec] = {s.column: s for s in METRIC_SPECS}

# The table must cover exactly the Health Model columns, in the model's order.
assert [s.column for s in METRIC_SPECS] == list(METRIC_COLUMNS), \
    "METRIC_SPECS must match models.health_model.metric_schema.METRIC_COLUMNS"


def build_queries(namespace: str, pod: str) -> Dict[str, str]:
    """column -> PromQL for one workload."""
    sel = selector(namespace, pod)
    return {s.column: s.promql.replace("{sel}", sel) for s in METRIC_SPECS}
