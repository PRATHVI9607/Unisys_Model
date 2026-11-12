import json

from eval import p11_run


def test_scoring_load_script_uses_shipped_feature_names_and_exports_default():
    script = p11_run._load_script(p11_run.DEFAULT_URL, 10, "30s")
    meta = json.loads((p11_run.ROOT / "models/bundles/health/meta.json").read_text(encoding="utf-8"))
    assert "export default function" in script
    assert "http.post(endpoint, body" in script
    assert all(feature in script for feature in meta["features"])
    assert 'duration: "30s"' in script


def test_k6_duration_parser_converts_milliseconds_and_seconds():
    logs = "http_req_duration..............: avg=24.1ms min=2ms med=19.5ms max=90ms p(90)=50ms p(95)=62.5ms\n"
    assert p11_run._parse_k6_latency(logs) == (19.5, 62.5)
    logs = "http_req_duration..............: avg=0.2s min=0.1s med=0.15s max=1s p(95)=0.5s\n"
    assert p11_run._parse_k6_latency(logs) == (150.0, 500.0)


def test_load_cleanup_removes_only_the_named_job_and_its_configmap(monkeypatch):
    calls = []

    def fake_kubectl(context, args, **kwargs):
        calls.append((context, args))
        return "deleted"

    monkeypatch.setattr(p11_run.harness, "kubectl", fake_kubectl)
    assert p11_run._cleanup_load("p11-load-10-test") == ["deleted", "deleted"]
    assert calls == [
        ("k3d-kubeheal", ["delete", "job", "p11-load-10-test", "-n", "kubeheal", "--ignore-not-found=true"]),
        ("k3d-kubeheal", ["delete", "configmap", "p11-load-10-test-script", "-n", "kubeheal", "--ignore-not-found=true"]),
    ]


def test_chaos_runner_rejects_services_outside_the_safe_allowlist():
    import pytest

    with pytest.raises(ValueError, match="restricted"):
        p11_run.run_pod_chaos("kubeheal", "redis", "restart")

