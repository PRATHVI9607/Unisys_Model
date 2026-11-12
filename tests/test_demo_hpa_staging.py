"""Static regression checks for the demo k6 script ConfigMap staging path."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_hpa_load_stages_javascript_as_a_file_and_mounts_the_same_key():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    normalized = " ".join(source.split())

    assert '"--from-file=health.js=$scriptPath"' in normalized
    assert "--dry-run=client -o yaml | Set-Content -LiteralPath $cmPath -Encoding utf8" in normalized
    assert "configMap: {name: kubeheal-k6-health-load}" in source
    assert "mountPath: /scripts, readOnly: true" in source
    assert 'command: ["k6", "run", "/scripts/health.js"]' in source


def test_hpa_load_does_not_flatten_the_javascript_lines():
    source = (ROOT / "demo" / "scripts" / "hpa_load.ps1").read_text(encoding="utf-8")
    assert re.search(r"\|\s*Out-String\s+-NoNewline", source, flags=re.IGNORECASE) is None

