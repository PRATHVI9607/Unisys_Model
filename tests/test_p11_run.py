import json

from eval import p11_run


def test_scoring_load_script_uses_shipped_feature_names_and_exports_default():
    script = p11_run._load_script(p11_run.DEFAULT_URL, 10, "30s")
    meta = json.loads((p11_run.ROOT / "models/bundles/health/meta.json").read_text(encoding="utf-8"))
    assert "export default function" in script
    assert "http.post(endpoint, body" in script
    assert all(feature in script for feature in meta["features"])
    assert 'duration: "30s"' in script
    assert "WARM-UP START" in script and "sleep(5)" in script
    assert "WARM-UP COMPLETE" in script
    assert "setup requests remain in aggregate metrics" in script
    assert "warm-up request ${i + 1}/${count}" in script


def test_k6_duration_parser_converts_milliseconds_and_seconds():
    logs = "http_req_failed............: 0.00% 0 out of 10\nhttp_req_duration..............: avg=24.1ms min=2ms med=19.5ms max=90ms p(90)=50ms p(95)=62.5ms\n"
    assert p11_run._parse_k6_latency(logs) == (19.5, 62.5)
    logs = "http_req_failed............: 0.00% 0 out of 10\nhttp_req_duration..............: avg=0.2s min=0.1s med=0.15s max=1s p(95)=0.5s\n"
    assert p11_run._parse_k6_latency(logs) == (150.0, 500.0)


def test_failed_k6_summary_is_not_reported_as_a_measurement():
    logs = """checks.....................: 0.00%   0 out of 297
http_req_duration..........: med=0s    p(95)=0s
http_req_failed............: 100.00% 297 out of 297
http_reqs..................: 297     2.638763/s
"""
    assert p11_run._parse_k6_rate(logs, "checks") == (0.0, 0, 297)
    assert p11_run._parse_k6_rate(logs, "http_req_failed") == (100.0, 297, 297)
    assert not p11_run._k6_succeeded(logs)
    assert p11_run._parse_k6_latency(logs) == ("not measured", "not measured")


def test_load_cleanup_removes_only_the_named_job_and_its_configmap(monkeypatch):
    calls = []
    owner = {"metadata": {"labels": {"kubeheal.ai/p11-run-id": "p11-load-10-test"}}}

    def owned_kubectl(context, args, **kwargs):
        calls.append((context, args))
        if args[0] == "get":
            return json.dumps(owner)
        return "deleted"

    monkeypatch.setattr(p11_run.harness, "kubectl", owned_kubectl)
    assert p11_run._cleanup_load("p11-load-10-test") == [
        "job/p11-load-10-test: deleted", "configmap/p11-load-10-test-script: deleted"]
    assert calls == [
        ("k3d-kubeheal", ["get", "job", "p11-load-10-test", "-n", "kubeheal", "-o", "json", "--ignore-not-found=true"]),
        ("k3d-kubeheal", ["delete", "job", "p11-load-10-test", "-n", "kubeheal", "--ignore-not-found=true"]),
        ("k3d-kubeheal", ["get", "configmap", "p11-load-10-test-script", "-n", "kubeheal", "-o", "json", "--ignore-not-found=true"]),
        ("k3d-kubeheal", ["delete", "configmap", "p11-load-10-test-script", "-n", "kubeheal", "--ignore-not-found=true"]),
    ]


def test_chaos_runner_rejects_services_outside_the_safe_allowlist():
    import pytest

    with pytest.raises(ValueError, match="restricted"):
        p11_run.run_pod_chaos("kubeheal", "redis", "delete-one-pod")


def test_chaos_runner_rejects_unapproved_action_before_cluster_call(monkeypatch):
    import pytest
    called = []
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: called.append(context))
    with pytest.raises(ValueError, match="only delete-one-pod"):
        p11_run.run_pod_chaos("kubeheal", "kubeheal-inference", "restart")
    assert called == []


def test_coverage_report_lists_every_p11_item_and_v5_e1_with_reasons():
    report = p11_run._coverage_markdown([])
    for item in ("P11-E1", "P11-E2", "P11-E3", "P11-E4", "P11-E5", "P11-E6", "P11-E7", "V5-E1"):
        assert f"| {item}" in report
    assert "not measured" in report
    assert "no disposable database-volume scenario" in report
    assert "no live result sidecar exists yet" in report


def test_load_target_is_fixed_before_any_cluster_call(monkeypatch):
    called = []
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: called.append(context))
    import pytest
    with pytest.raises(ValueError, match="restricted"):
        p11_run.run_load(10, "30s", "http://example.invalid/")
    assert called == []


def test_load_duration_is_bounded_before_any_cluster_call(monkeypatch):
    called = []
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: called.append(context))
    import pytest
    with pytest.raises(ValueError, match="capped at 10 minutes"):
        p11_run.run_load(10, "11m", p11_run.DEFAULT_URL)
    assert called == []


def test_namespace_is_validated_before_deployment_read(monkeypatch):
    called = []
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: called.append(context))
    import pytest
    with pytest.raises(ValueError, match="allowlist"):
        p11_run.run_pod_chaos("kube-system", "kubeheal-inference", "delete-one-pod")
    assert called == []


def test_cleanup_continues_after_one_resource_failure(monkeypatch):
    calls = []
    owner = {"metadata": {"labels": {"kubeheal.ai/p11-run-id": "owned-run"}}}

    def fake_kubectl(context, args, **kwargs):
        calls.append(args)
        if args[:2] == ["get", "job"]:
            raise RuntimeError("temporary API error")
        if args[:2] == ["get", "configmap"]:
            return json.dumps(owner)
        return "deleted"

    monkeypatch.setattr(p11_run.harness, "kubectl", fake_kubectl)
    result = p11_run._cleanup_load("owned-run")
    assert "job/owned-run: cleanup failed" in result[0]
    assert result[1] == "configmap/owned-run-script: deleted"
    assert any(args[:2] == ["delete", "configmap"] for args in calls)


def test_cleanup_retains_foreign_objects(monkeypatch):
    calls = []
    foreign = {"metadata": {"labels": {"kubeheal.ai/p11-run-id": "another-run"}}}
    monkeypatch.setattr(p11_run.harness, "kubectl", lambda context, args, **kwargs: calls.append(args) or json.dumps(foreign))
    result = p11_run._cleanup_load("owned-run")
    assert all("ownership label mismatch" in row for row in result)
    assert not any(args[0] == "delete" for args in calls)


def test_run_names_use_full_uuid():
    name = p11_run._name("p11-load-200")
    assert len(name.rsplit("-", 1)[1]) == 32
    assert len(name) <= 63


def test_load_results_are_written_even_when_cleanup_reports_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(p11_run, "RESULTS", tmp_path)
    monkeypatch.setattr(p11_run, "_name", lambda prefix: "p11-load-10-owned-run")
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: None)
    monkeypatch.setattr(p11_run, "_hpa_state", lambda: {"current_replicas": 2, "desired_replicas": 2})
    monkeypatch.setattr(p11_run.harness, "apply_k6_job", lambda *args, **kwargs:
                        "checks.....................: 100.00% 10 out of 10\n"
                        "http_req_duration..........: med=2ms p(95)=4ms\n"
                        "http_req_failed............: 0.00% 0 out of 10")
    monkeypatch.setattr(p11_run, "_cleanup_load", lambda name: ["job cleanup failed", "configmap deleted"])

    result = p11_run.run_load(10, "30s", p11_run.DEFAULT_URL)

    assert result["cleanup"] == "job cleanup failed | configmap deleted"
    assert result["status"] == "measured"
    assert (tmp_path / "p11-load-10-owned-run.log").is_file()
    assert (tmp_path / "p11-load-10-owned-run.csv").is_file()


def test_run_load_records_failed_checks_as_not_measured(monkeypatch, tmp_path):
    monkeypatch.setattr(p11_run, "RESULTS", tmp_path)
    monkeypatch.setattr(p11_run, "_name", lambda prefix: "p11-load-10-failed-run")
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: None)
    monkeypatch.setattr(p11_run, "_hpa_state", lambda: {"current_replicas": 2, "desired_replicas": 2})
    failed_summary = """checks.....................: 0.00% 0 out of 12
http_req_duration..........: med=0s p(95)=0s
http_req_failed............: 100.00% 12 out of 12
"""
    monkeypatch.setattr(p11_run.harness, "apply_k6_job", lambda *args, **kwargs: failed_summary)
    monkeypatch.setattr(p11_run, "_cleanup_load", lambda name: ["job deleted", "configmap deleted"])

    result = p11_run.run_load(10, "30s", p11_run.DEFAULT_URL)

    assert result["status"] == "failed"
    assert result["latency_status"] == "not measured"
    assert result["p50_ms"] == "not measured"
    assert result["p95_ms"] == "not measured"
    assert result["checks_passed"] == 0
    assert result["checks_failed"] == 12
    assert result["requests_failed"] == 12
    assert result["request_count"] == 12


def test_pod_chaos_waits_for_old_uid_to_disappear_and_ready_count_to_recover(monkeypatch, tmp_path):
    monkeypatch.setattr(p11_run, "RESULTS", tmp_path)
    monkeypatch.setattr(p11_run, "_name", lambda prefix: "p11-chaos-owned-run")
    monkeypatch.setattr(p11_run.harness, "assert_test_mode", lambda context: None)
    monkeypatch.setattr(p11_run, "_deployment_counts", lambda namespace, deployment: (2, 2))
    pod_states = iter([
        [{"metadata": {"name": "inference-old", "uid": "old-uid"}}],
        [{"metadata": {"name": "inference-new", "uid": "new-uid"}}],
    ])
    monkeypatch.setattr(p11_run, "_ready_pods", lambda namespace, deployment: next(pod_states))
    deleted = []
    monkeypatch.setattr(p11_run, "_delete_pod_with_uid",
                        lambda namespace, pod_name, pod_uid: deleted.append((namespace, pod_name, pod_uid)) or "accepted")

    result = p11_run.run_pod_chaos("kubeheal", "kubeheal-inference", "delete-one-pod")

    assert result["status"] == "measured"
    assert deleted == [("kubeheal", "inference-old", "old-uid")]
    assert (tmp_path / "p11-chaos-owned-run.csv").is_file()


def test_uid_delete_uses_context_pinned_proxy_and_uid_precondition(monkeypatch):
    processes = []
    requests = []

    class Process:
        def __init__(self, command, **kwargs):
            self.command, self.terminated = command, False
            processes.append(self)

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            assert timeout == 5

        def kill(self):
            raise AssertionError("proxy should terminate without a kill")

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"accepted"

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        if isinstance(request, str):
            assert request == "http://127.0.0.1:12345/version"
            assert timeout == 1
            return Response()
        assert request.method == "DELETE"
        assert request.full_url == "http://127.0.0.1:12345/api/v1/namespaces/kubeheal/pods/inference-old"
        assert json.loads(request.data) == {
            "apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": "uid-123"}}
        assert timeout == 10
        return Response()

    monkeypatch.setattr(p11_run, "_free_local_port", lambda: 12345)
    monkeypatch.setattr(p11_run.subprocess, "Popen", Process)
    monkeypatch.setattr(p11_run, "urlopen", fake_urlopen)
    assert p11_run._delete_pod_with_uid("kubeheal", "inference-old", "uid-123") == "accepted"
    assert processes[0].command[:3] == ["kubectl", "--context", "k3d-kubeheal"]
    assert processes[0].command[3] == "proxy"
    assert processes[0].terminated is True
    assert len(requests) == 2


def test_ready_pods_use_deployment_selector_and_verify_replicaset_owner_chain(monkeypatch):
    deployment = {
        "metadata": {"uid": "deployment-uid"},
        "spec": {"selector": {"matchLabels": {"app": "kubeheal-inference", "track": "model"}}},
    }
    def pod(name, uid, rs_name, labels=None, statuses=None):
        return {"metadata": {"name": name, "uid": uid,
                              "labels": labels or {"app": "kubeheal-inference", "track": "model"},
                              "ownerReferences": [{"kind": "ReplicaSet", "name": rs_name, "controller": True}]},
                "status": {"phase": "Running", "containerStatuses": statuses if statuses is not None else [{"ready": True}]}}
    pods = [
        pod("owned", "pod-good", "rs-good"),
        pod("foreign-owner", "pod-foreign", "rs-foreign"),
        pod("unready-shape", "pod-empty-status", "rs-good", statuses=[]),
        pod("other-selector", "pod-other", "rs-good", labels={"app": "kubeheal-inference", "track": "other"}),
    ]
    replicasets = {
        "rs-good": {"metadata": {"ownerReferences": [{"kind": "Deployment", "name": "kubeheal-inference",
                                                        "uid": "deployment-uid", "controller": True}]}},
        "rs-foreign": {"metadata": {"ownerReferences": [{"kind": "Deployment", "name": "other-workload",
                                                           "uid": "other-uid", "controller": True}]}},
    }
    calls = []

    def fake_kubectl(context, args, **kwargs):
        calls.append(args)
        if args[:2] == ["get", "deployment/kubeheal-inference"]:
            return json.dumps(deployment)
        if args[:2] == ["get", "pods"]:
            return json.dumps({"items": pods})
        if args[0] == "get" and args[1].startswith("replicaset/"):
            return json.dumps(replicasets[args[1].split("/", 1)[1]])
        raise AssertionError(args)

    monkeypatch.setattr(p11_run.harness, "kubectl", fake_kubectl)
    ready = p11_run._ready_pods("kubeheal", "kubeheal-inference")
    assert [item["metadata"]["name"] for item in ready] == ["owned"]
    assert ["get", "pods", "-n", "kubeheal", "-o", "json"] in calls

