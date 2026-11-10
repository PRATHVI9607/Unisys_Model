from urllib.request import urlopen
from pathlib import Path

from fastapi import FastAPI
from prometheus_client.parser import text_string_to_metric_families
import yaml

from agents.common.metrics import KubeHealMetrics, add_metrics_route


def test_metrics_helper_exposes_each_required_metric():
    metrics = KubeHealMetrics()
    metrics.record_decision("HUMAN")
    metrics.record_action("PATCH", "success")
    metrics.record_escalation("model_timeout")
    metrics.record_dry_run_action("CONTAIN")
    metrics.observe_model_latency("health", 0.25)
    metrics.set_queue_depth("kubeheal.exec", 3)
    metrics.set_stream_lag("kubeheal.exec", 2)

    samples = {
        sample.name: sample
        for family in text_string_to_metric_families(metrics.render().decode())
        for sample in family.samples
    }

    assert samples["kubeheal_decisions_total"].value == 1
    assert samples["kubeheal_actions_total"].value == 1
    assert samples["kubeheal_escalations_total"].value == 1
    assert samples["kubeheal_dry_run_actions_total"].value == 1
    assert samples["kubeheal_model_latency_seconds_count"].value == 1
    assert samples["kubeheal_queue_depth"].value == 3
    assert samples["kubeheal_stream_lag"].value == 2


def test_metrics_instances_have_independent_registries():
    first = KubeHealMetrics()
    second = KubeHealMetrics()
    first.record_decision("BENIGN")

    assert b'kubeheal_decisions_total{decision="BENIGN"} 1.0' in first.render()
    second_samples = [
        sample
        for family in text_string_to_metric_families(second.render().decode())
        for sample in family.samples
    ]
    assert not any(sample.name == "kubeheal_decisions_total" for sample in second_samples)


def test_metrics_route_exposes_component_registry():
    from fastapi.testclient import TestClient

    metrics = KubeHealMetrics()
    metrics.record_decision("BENIGN")
    app = FastAPI()
    add_metrics_route(app, metrics)

    response = TestClient(app).get("/metrics")
    assert response.status_code == 200
    assert 'kubeheal_decisions_total{decision="BENIGN"} 1.0' in response.text
    assert response.headers["content-type"].startswith("text/plain")


def test_standalone_metrics_listener_serves_registry():
    metrics = KubeHealMetrics()
    metrics.record_escalation("test")
    server, thread = metrics.start_server(0, addr="127.0.0.1")
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/metrics", timeout=3) as response:
            body = response.read().decode()
        assert response.status == 200
        assert 'kubeheal_escalations_total{reason="test"} 1.0' in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_prometheus_config_discovers_every_kubeheal_component():
    documents = list(yaml.safe_load_all(Path("k8s/prometheus-config.yaml").read_text()))
    configmap = next(doc for doc in documents if doc.get("metadata", {}).get("name") == "prometheus-kubeheal-scrape-config")
    config = yaml.safe_load(configmap["data"]["config.yaml"])
    jobs = {job["job_name"] for job in config["scrape_configs"]}

    components = {
        "kubeheal-health-agent",
        "kubeheal-security-agent",
        "kubeheal-fusion-agent",
        "kubeheal-executor",
        "kubeheal-health-model",
        "kubeheal-security-model",
        "kubeheal-dcm",
        "kubeheal-dashboard",
    }
    assert components <= jobs

    expected_ports = {
        "health-agent": 8080,
        "security-agent": 9100,
        "fusion-agent": 8081,
        "executor": 9100,
        "kubeheal-health-model": 8001,
        "kubeheal-security-model": 8002,
        "kubeheal-dcm": 8003,
        "kubeheal-dashboard": 5000,
    }
    workloads = {}
    for path in Path("k8s").glob("*.yaml"):
        for doc in yaml.safe_load_all(path.read_text()):
            if not isinstance(doc, dict):
                continue
            template = doc.get("spec", {}).get("template", {})
            pod_spec = template.get("spec", {})
            if pod_spec:
                workloads[doc.get("metadata", {}).get("name")] = pod_spec
    for name, port in expected_ports.items():
        declared = {
            container_port
            for container in workloads[name]["containers"]
            for item in container.get("ports", [])
            if (container_port := item.get("containerPort")) is not None
        }
        assert port in declared


def test_all_agent_and_fastapi_entrypoints_wire_metrics():
    agents = [
        "agents/health_agent/agent.py",
        "agents/security_agent/agent.py",
        "agents/fusion_agent/agent.py",
        "agents/executor/main.py",
    ]
    apps = [
        "services/health_model_server/main.py",
        "services/security_model_server/main.py",
        "services/dcm_server/main.py",
        "dashboard/fastapi_app.py",
    ]
    for path in agents:
        source = Path(path).read_text()
        assert "METRICS.start_server(" in source
    for path in apps:
        source = Path(path).read_text()
        assert "add_metrics_route(app, METRICS)" in source

