"""Alert rules: structure and only metrics the code exports. Syntax: deploy/scripts/promtool-check.sh (promtool in Docker)."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "deploy/k8s/base/alerts/kubeheal-rules.yaml"
EXTERNAL = {"up", "redis_memory_used_bytes", "redis_memory_max_bytes"}   # Prometheus itself, a redis_exporter
WANT = {"KubeHealPodKilled": "info", "KubeHealWorkloadPatched": "info", "KubeHealApprovalPending": "warning",
        "KubeHealSensorDown": "critical", "KubeHealEventLagHigh": "critical", "KubeHealFusionDown": "critical",
        "KubeHealDetectionSlow": "warning", "KubeHealRedisMemoryHigh": "warning", "KubeHealCircuitOpen": "warning",
        "KubeHealFrozenOverdue": "critical"}


def rules() -> list[dict]:
    doc = yaml.safe_load(RULES.read_text())
    assert doc["kind"] == "PrometheusRule"
    return [r for g in doc["spec"]["groups"] for r in g["rules"]]


def code() -> str:
    return "".join(p.read_text() for d in ("agents", "kubeheal", "dashboard") for p in (ROOT / d).rglob("*.py"))


def test_rules_and_severities():
    got = {r["alert"]: r["labels"]["severity"] for r in rules()}
    assert got == WANT
    assert all(r["expr"] and r["annotations"]["summary"] and r["annotations"]["description"] for r in rules())


def test_every_metric_exists_in_code():
    src, names = code(), set()
    for r in rules():
        for m in re.findall(r"\b[a-z][a-z0-9_]*(?=\s*[{\[(]|\s*[<>=/)]|\s*$)", re.sub(r'"[^"]*"|\[[^\]]*\]', "", r["expr"])):
            names.add(m)
    metrics = {re.sub(r"_(bucket|sum|count)$", "", n) for n in names if n.startswith(("kubeheal_", "up", "redis_"))}
    assert {m for m in metrics if m.startswith("kubeheal_")}, "no kubeheal_ metric parsed"
    missing = {m for m in metrics - EXTERNAL if f'"{m}"' not in src}
    assert not missing, f"rules use metrics no code exports: {missing}"


def test_redis_exporter_in_production_only():
    import subprocess
    out = {n: list(yaml.safe_load_all(subprocess.run(c, capture_output=True, text=True, check=True).stdout)) for n, c in
           {"dev": ["kubectl", "kustomize", str(ROOT / "deploy/k8s")], "prod": ["kubectl", "kustomize", str(ROOT / "deploy/k8s/overlays/production")]}.items()}
    ctr = lambda docs: [c for d in docs if d and d["kind"] == "StatefulSet" and d["metadata"]["name"] == "redis" for c in d["spec"]["template"]["spec"]["containers"]]  # noqa: E731
    assert [c["name"] for c in ctr(out["prod"])] == ["redis", "redis-exporter"] and "@sha256:" in ctr(out["prod"])[1]["image"]
    assert "user exporter on" in ctr(out["prod"])[0]["args"][0] and not ctr(out["dev"])
