from prometheus_client.parser import text_string_to_metric_families

from agents.common.metrics import KubeHealMetrics


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

