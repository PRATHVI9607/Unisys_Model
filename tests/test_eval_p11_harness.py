import json
import subprocess
from datetime import datetime, timezone

import pytest

from eval.p11_harness import (
    apply_k6_job,
    baseline_scenarios,
    assert_test_mode,
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
    assert cfg["data"]["load.js"] == manifest["script"]
    assert not any(key.startswith("_") for key in job)
    assert not any(key.startswith("_") for key in cfg)
    spec = job["spec"]["template"]["spec"]
    affinity = spec["affinity"]["podAntiAffinity"]
    assert "requiredDuringSchedulingIgnoredDuringExecution" not in affinity
    term = affinity["preferredDuringSchedulingIgnoredDuringExecution"][0]
    assert term["weight"] == 100
    assert term["podAffinityTerm"]["labelSelector"]["matchExpressions"][0]["values"] == [
        "kubeheal-health-model", "kubeheal-security-model", "kubeheal-dcm", "kubeheal-inference"]
    assert job["spec"]["activeDeadlineSeconds"] == 900
    container = spec["containers"][0]
    assert container["image"] == "grafana/k6:0.54.0"
    assert container["resources"]["limits"] == {"cpu": "1", "memory": "512Mi"}
    assert container["args"] == ["run", "/scripts/load.js"]


def test_apply_k6_job_uses_fake_runner_and_explicit_context():
    fake = FakeRunner(["applied", "Complete", "k6 summary"])
    out = apply_k6_job("k3d-kubeheal", k6_job_manifest("load-10", "kubeheal", "http://victim/", 10),
                       runner=fake, sleep=lambda _s: None)
    assert out == "k6 summary"
    assert len(fake.calls) == 3
    assert all(call[0][1:3] == ["--context", "k3d-kubeheal"] for call in fake.calls)
    rendered = fake.calls[0][1]["input"]
    assert "load.js" in rendered
    assert "_script" not in rendered
    assert "preferredDuringSchedulingIgnoredDuringExecution" in rendered
    assert "requiredDuringSchedulingIgnoredDuringExecution" not in rendered


def test_apply_k6_job_failed_job_ends_wait_immediately():
    fake = FakeRunner(["applied", "Failed"])
    sleeps = []
    with pytest.raises(RuntimeError):
        apply_k6_job("k3d-kubeheal", k6_job_manifest("load-10", "kubeheal", "http://victim/", 10),
                     runner=fake, sleep=sleeps.append)
    assert sleeps == []
    assert len(fake.calls) == 2


def test_apply_k6_job_polls_until_complete_and_times_out():
    fake = FakeRunner(["applied", "", "", "Complete", "logs"])
    sleeps = []
    out = apply_k6_job("k3d-kubeheal", k6_job_manifest("load-10", "kubeheal", "http://victim/", 10),
                       runner=fake, sleep=sleeps.append, poll_seconds=5)
    assert out == "logs"
    assert sleeps == [5, 5]
    ticks = iter([0, 1, 100, 100])
    fake2 = FakeRunner(["applied", "", ""])
    with pytest.raises(TimeoutError):
        apply_k6_job("k3d-kubeheal", k6_job_manifest("load-10", "kubeheal", "http://victim/", 10),
                     runner=fake2, sleep=lambda _s: None, clock=lambda: next(ticks), wait_seconds=60)


def test_k6_job_namespace_is_allow_listed():
    with pytest.raises(ValueError):
        k6_job_manifest("load-10", "kube-system", "http://victim/", 10)


def test_context_required_and_forwarded():
    fake = FakeRunner(["yes"])
    assert kubectl("k3d-kubeheal", ["get", "pods"], runner=fake) == "yes"
    assert fake.calls[0][0] == ["kubectl", "--context", "k3d-kubeheal", "get", "pods"]
    with pytest.raises(ValueError):
        kubectl("", ["get", "pods"], runner=fake)


def test_context_allow_list_rejects_hybrid_demo_and_others():
    fake = FakeRunner()
    for bad in ("hybrid-demo", "k3d-other", "minikube", " k3d-kubeheal"):
        with pytest.raises(ValueError):
            kubectl(bad, ["get", "pods"], runner=fake)
    assert fake.calls == []


def test_namespace_allow_list_for_chaos_delete_restart():
    fake = FakeRunner(["test", "ok"] * 4)
    for bad in ("kube-system", "default", ""):
        with pytest.raises(ValueError):
            chaos_command("k3d-kubeheal", bad, "x", action="restart", runner=fake)
        with pytest.raises(ValueError):
            chaos_command("k3d-kubeheal", bad, "x", action="delete-one-pod", runner=fake)
        with pytest.raises(ValueError):
            database_pod_delete_command("k3d-kubeheal", bad, "db-0", runner=fake)
    assert fake.calls == []
    for ok in ("prod", "staging", "dev", "kubeheal"):
        chaos_command("k3d-kubeheal", ok, "x", action="restart", runner=fake)
    assert len(fake.calls) == 8   # a mode read plus the restart, for each namespace


def test_chaos_and_pod_delete_are_injectable_and_bounded():
    fake = FakeRunner(["test", '{"items":[{"metadata":{"name":"model-0"}}]}', "deleted"])
    assert chaos_command("k3d-kubeheal", "kubeheal", "health-model", action="delete-one-pod", runner=fake) == "deleted"
    assert fake.calls[-1][0][-6:] == ["delete", "pod", "model-0", "-n", "kubeheal", "--wait=false"]
    fake2 = FakeRunner(["test", "deleted"])
    database_pod_delete_command("k3d-kubeheal", "prod", "db-0", runner=fake2)
    assert fake2.calls[-1][0][-1] == "--wait=false"
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


def test_write_results_refuses_overwrite_unless_explicit(tmp_path):
    now = datetime(2026, 11, 11, tzinfo=timezone.utc)
    write_results(tmp_path, "latency", [{"a": 1}], cluster="k3d-kubeheal", now=now)
    with pytest.raises(FileExistsError):
        write_results(tmp_path, "latency", [{"a": 2}], cluster="k3d-kubeheal", now=now)
    assert "1" in (tmp_path / "latency.csv").read_text()
    write_results(tmp_path, "latency", [{"a": 2}], cluster="k3d-kubeheal", now=now, overwrite=True)
    assert "2" in (tmp_path / "latency.csv").read_text()


def test_baselines_and_precision_missing_values_are_explicit():
    assert baseline_scenarios() == ("falco-rules-only", "fixed-entropy-threshold", "diff-only-drift", "single-replica", "pod-delete-only")
    assert model_precision_rows() == []
    rows = model_precision_rows(fp32_latency_ms=10.0)
    assert rows[0]["latency_ms"] == 10.0
    assert rows[1]["latency_ms"] == "not measured"


def test_metadata_requires_timezone_aware_clock():
    with pytest.raises(ValueError):
        result_metadata("k3d", "scenario", now=datetime(2026, 11, 11))


@pytest.mark.parametrize("mode", ["enforce", "", "Test", "enforce\n"])
def test_chaos_and_delete_refuse_unless_mode_is_exactly_test(mode):
    fake = FakeRunner([mode])
    with pytest.raises(RuntimeError, match="kubeheal-mode"):
        chaos_command("k3d-kubeheal", "prod", "x", action="restart", runner=fake)
    assert len(fake.calls) == 1        # only the mode read happened, no write
    fake = FakeRunner([mode])
    with pytest.raises(RuntimeError):
        database_pod_delete_command("k3d-kubeheal", "prod", "db-0", runner=fake)
    assert len(fake.calls) == 1


def test_assert_test_mode_accepts_test_with_trailing_newline():
    assert assert_test_mode("k3d-kubeheal", runner=FakeRunner(["test\n"])) is None
