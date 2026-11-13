"""Static regression checks for the demo k6 script ConfigMap staging path."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_hpa_load_stages_labeled_configmap_without_unsupported_create_labels_flag():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    normalized = " ".join(source.split())

    assert "[Convert]::ToBase64String([IO.File]::ReadAllBytes($scriptPath))" in normalized
    assert "binaryData:" in source and "health.js: $scriptBase64" in source
    assert "kubeheal.k8s.io/run-id: $runId" in source
    assert "--labels=" not in source
    assert "Set-Content -LiteralPath $cmPath -Value $configMap -Encoding utf8" in normalized
    assert "K create -f $cmPath" in source
    assert "configMap: {name: $cmName}" in source
    assert "mountPath: /scripts, readOnly: true" in source
    assert 'command: ["k6", "run", "/scripts/health.js"]' in source


def test_hpa_load_does_not_flatten_the_javascript_lines():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    assert re.search(r"\|\s*Out-String\s+-NoNewline", source, flags=re.IGNORECASE) is None


def test_hpa_load_resources_are_unique_and_cleanup_checks_run_ownership():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    for name, suffix in (("cmName", "script"), ("policyName", "net"), ("jobName", "load")):
        assert f'${name} = "kubeheal-k6-{suffix}-$runId"' in source

    assert "[Guid]::NewGuid().ToString('N')" in source
    assert "kubeheal.k8s.io/run-id: $runId" in source
    assert "ConvertFrom-Json -AsHashtable" in source
    assert "resource.metadata.labels['kubeheal.k8s.io/run-id'] -ne $runId" in source
    assert "K create -f $cmPath" in source and "K create -f $policyPath" in source
    assert "K create -f $jobPath" in source
    assert "K apply -f $cmPath" not in source and "K apply -f $policyPath" not in source


def test_hpa_load_cleanup_continues_after_api_failures_and_removes_temp_files():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    cleanup = source.split("finally {", 1)[1]
    assert "Remove-RunResource 'job'" in cleanup
    assert "Remove-RunResource 'networkpolicy'" in cleanup
    assert "Remove-RunResource 'configmap'" in cleanup
    assert "Could not clean up $kind/$name" in source
    assert "if ($message -match '(?i)not.?found') { return }" in source
    assert "Remove-Item -LiteralPath $cmPath, $policyPath, $jobPath" in cleanup
    assert "Could not remove local k6 staging files" in cleanup


def test_hpa_load_waits_for_ready_deployment_and_service_endpoints():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    assert "status.readyReplicas" in source and "status.observedGeneration" in source
    assert "endpointObject.subsets" in source and "readyEndpointCount -ge $desired" in source
    assert "Inference pod readiness:" in source and "lastTransitionTime" in source
    assert source.index("K create -f $policyPath") < source.index("NETWORKPOLICY SETTLING")
    assert source.index("NETWORKPOLICY SETTLING") < source.index("K create -f $jobPath")


def test_hpa_k6_setup_warmup_is_explicit_and_does_not_retry():
    source = (ROOT / "demo" / "scripts" / "k6_health_model.js").read_text(encoding="utf-8")
    assert "WARM-UP START" in source and "WARM-UP COMPLETE" in source
    assert "WARM-UP FAILED" in source and "throw new Error" in source
    assert "retry" not in source.lower()
    assert "aggregate k6 metrics" in source
    assert "5s network settling delay" in source and "sleep(5)" in source

