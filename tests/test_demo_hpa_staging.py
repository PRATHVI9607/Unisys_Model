"""Static regression checks for the demo k6 script ConfigMap staging path."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_hpa_load_stages_javascript_as_a_file_and_mounts_the_same_key():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    normalized = " ".join(source.split())

    assert '"--from-file=health.js=$scriptPath"' in normalized
    assert "--dry-run=client -o yaml | Set-Content -LiteralPath $cmPath -Encoding utf8" in normalized
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
    assert "Remove-Item -LiteralPath $cmPath, $policyPath, $jobPath" in cleanup
    assert "Could not remove local k6 staging files" in cleanup

