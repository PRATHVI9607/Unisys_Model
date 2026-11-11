import json
import subprocess
from datetime import datetime, timezone

import pytest

from eval.p11_harness import (
    apply_k6_job,
    baseline_scenarios,
    chaos_command,
    database_pod_delete_command,
    k6_job_manifest,
    k6_script,
    kubectl,
    model_precision_rows,
    result_metadata,
    write_results,
)


class FakeRunner:
    def __init__(self, outputs=()):
        self.calls = []
        self.outputs = list(outputs)

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        output = self.outputs.pop(0) if self.outputs else "ok"
        return subprocess.CompletedProcess(command, 0, output, "")


def test_k6_enforces_range_and_has_bounded_scenario():
    script = k6_script("http://victim.prod.svc/", 10)
    assert "vus: 10" in script
    assert 'duration: "2m"' in script
    with pytest.raises(ValueError):
        k6_script("http://victim/", 9)


def test_k6_job_is_pinned_limited_and_uses_pinned_image():
    manifest = k6_job_manifest("load-10", "kubeheal", "http://victim/", 10)
    cfg, job = manifest["objects"]
    assert cfg["data"]["load.js"] == manifest["_script"]
    spec = job["spec"]["template"]["spec"]
    anti = spec["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
    assert anti["labelSelector"]["matchExpressions"][0]["values"] == [
        "kubeheal-health-model", "kubeheal-security-model", "kubeheal-dcm"]
    container = spec["containers"][0]
    assert container["image"] == "grafana/k6:0.54.0"
    assert container["resources"]["limits"] == {"cpu": "1", "memory": "512Mi"}
    assert container["args"] == ["run", "/scripts/load.js"]


def test_apply_k6_job_uses_fake_runner_and_explicit_context():
    fake = FakeRunner(["applied", "job/load-10 condition met", "k6 summary"])
    out = apply_k6_job("k3d-kubeheal", k6_job_manifest("load-10", "kubeheal", "http://victim/", 10), runner=fake)
    assert out == "k6 summary"
    assert len(fake.calls) == 3
    assert all(call[0][1:3] == ["--context", "k3d-kubeheal"] for call in fake.calls)
    assert "load.js" in fake.calls[0][1]["input"]


def test_context_required_and_forwarded():
    fake = FakeRunner(["yes"])
    assert kubectl("k3d-kubeheal", ["get", "pods"], runner=fake) == "yes"
    assert fake.calls[0][0] == ["kubectl", "--context", "k3d-kubeheal", "get", "pods"]
    with pytest.raises(ValueError):
        kubectl("", ["get", "pods"], runner=fake)


def test_chaos_and_pod_delete_are_injectable_and_bounded():
    fake = FakeRunner(['{"items":[{"metadata":{"name":"model-0"}}]}', "deleted"])
    assert chaos_command("k3d-kubeheal", "kubeheal", "health-model", action="delete-one-pod", runner=fake) == "deleted"
    assert fake.calls[-1][0][-6:] == ["delete", "pod", "model-0", "-n", "kubeheal", "--wait=false"]
    fake2 = FakeRunner(["deleted"])
    database_pod_delete_command("k3d-kubeheal", "prod", "db-0", runner=fake2)
    assert fake2.calls[0][0][-1] == "--wait=false"
    with pytest.raises(ValueError):
        chaos_command("k3d-kubeheal", "kubeheal", "x", action="delete-all", runner=fake)


def test_results_stamp_metadata_and_empty_run_is_not_measured(tmp_path):
    now = datetime(2026, 11, 11, tzinfo=timezone.utc)
    csv_path, meta_path = write_results(tmp_path, "latency", [{"replicas": 2, "p50_ms": 12.5}],
                                       cluster="k3d-kubeheal", machine="test-host", now=now)
    meta = json.loads(meta_path.read_text())
    assert meta["status"] == "measured"
    assert meta["machine"] == "test-host"
    assert meta["cluster"] == "k3d-kubeheal"
    assert meta["date_utc"] == "2026-11-11T00:00:00+00:00"
    assert "p50_ms" in csv_path.read_text()
    _, empty_meta = write_results(tmp_path, "chaos", [], cluster="k3d-kubeheal", now=now)
    assert json.loads(empty_meta.read_text())["status"] == "not measured"


def test_baselines_and_precision_missing_values_are_explicit():
    assert baseline_scenarios() == ("falco-rules-only", "fixed-entropy-threshold", "diff-only-drift", "single-replica", "pod-delete-only")
    assert model_precision_rows() == []
    rows = model_precision_rows(fp32_latency_ms=10.0)
    assert rows[0]["latency_ms"] == 10.0
    assert rows[1]["latency_ms"] == "not measured"


def test_metadata_requires_timezone_aware_clock():
    with pytest.raises(ValueError):
        result_metadata("k3d", "scenario", now=datetime(2026, 11, 11))
