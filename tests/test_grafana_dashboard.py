import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_is_valid_and_queries_defined_metrics():
    dashboard = json.loads((ROOT / "deploy/grafana/kubeheal-overview.json").read_text())
    metric_names = set(re.findall(
        r'"(kubeheal_[a-z_]+)"\s*,',
        (ROOT / "agents/common/metrics.py").read_text(),
    ))
    metric_names.update({
        "kubeheal_model_latency_seconds_bucket",
        "kubeheal_model_latency_seconds_sum",
        "kubeheal_model_latency_seconds_count",
    })
    metric_names.add("kube_deployment_status_replicas_available")
    expressions = [target["expr"] for panel in dashboard["panels"] for target in panel["targets"]]
    used = {name for expression in expressions for name in re.findall(r"\b[a-z][a-z0-9_]*\b", expression)
            if name.startswith(("kubeheal_", "kube_deployment_"))}

    assert dashboard["title"] == "KubeHeal Overview"
    assert all(panel["datasource"]["uid"] == "prometheus" for panel in dashboard["panels"])
    assert used <= metric_names
    assert {"kubeheal_decisions_total", "kubeheal_actions_total", "kubeheal_model_latency_seconds_bucket",
            "kubeheal_queue_depth", "kubeheal_model_inflight_requests",
            "kube_deployment_status_replicas_available"} <= used
