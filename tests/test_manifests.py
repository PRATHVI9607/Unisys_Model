"""Static checks that keep the manifests, the code and the docs in step (no cluster needed)."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "deploy/k8s/base"
CODE_DIRS = ("agents", "kubeheal", "dashboard")
OUR_IMAGES = ("/agents:", "/inference:", "/dashboard:")   # Python images; env is read by code in CODE_DIRS


def docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text()) if d]


def base_docs() -> list[dict]:
    return [d for p in sorted(BASE.rglob("*.yaml")) for d in docs(p)]


def code_text() -> str:
    return "\n".join(p.read_text() for d in CODE_DIRS for p in sorted((ROOT / d).rglob("*.py")))


def manifest_env() -> set[str]:
    out = set()
    for d in base_docs():
        for c in ((d.get("spec") or {}).get("template") or {}).get("spec", {}).get("containers", []):
            if any(t in c["image"] for t in OUR_IMAGES):
                out |= {e["name"] for e in c.get("env", [])}
    return out


def table_env() -> set[str]:
    """Env var names in the docs/architecture.md table (rows start with | `NAME`)."""
    rows = [ln for ln in (ROOT / "docs/architecture.md").read_text().splitlines() if re.match(r"\| `[A-Z_]+`", ln)]
    return {n for ln in rows for n in re.findall(r"`([A-Z][A-Z0-9_]+)`", ln.split("|")[1])}


def test_manifest_env_is_read_by_code_and_documented():
    code, env, table = code_text(), manifest_env(), table_env()
    assert env, "no env found: OUR_IMAGES out of date?"
    assert not {n for n in env if f'"{n}"' not in code}, "manifest sets env vars no code reads"
    assert not env - table, "manifest env vars missing from the docs/architecture.md table"
    assert not {n for n in table if f'"{n}"' not in code}, "documented env vars no code reads"


# kubernetes_asyncio method suffix -> (API group, resource)
RESOURCES = {
    "pod": ("", "pods"), "namespace": ("", "namespaces"), "secret": ("", "secrets"),
    "deployment": ("apps", "deployments"), "replica_set": ("apps", "replicasets"),
    "stateful_set": ("apps", "statefulsets"), "daemon_set": ("apps", "daemonsets"),
    "job": ("batch", "jobs"), "network_policy": ("networking.k8s.io", "networkpolicies"),
    "horizontal_pod_autoscaler": ("autoscaling", "horizontalpodautoscalers"),
}
KUBE_CALL = re.compile(r"\b(read|list|patch|delete|create|replace)_"
                       r"(?:namespaced_(\w+?)|(\w+?)_for_all_namespaces|(namespace))\b(\()?")
AGENT_SA = {"health_agent": "kubeheal-health", "security_agent": "kubeheal-security", "fusion_agent": "kubeheal-fusion"}


def required_permissions(src: str) -> set[tuple[str, str, str]]:
    """(group, resource, verb) for every API call; a list_* referenced without a call is a watch target."""
    need = set()
    for m in KUBE_CALL.finditer(src):
        verb, res = m.group(1), next(g for g in m.groups()[1:4] if g)
        assert res in RESOURCES, f"unknown resource {res!r}: extend RESOURCES"
        group, plural = RESOURCES[res]
        need.add((group, plural, verb))
        if verb == "list" and not m.group(5):
            need.add((group, plural, "watch"))
    return need


def test_required_permissions_parser():
    src = "x.read_namespaced_pod(n, ns)\nfn = apps.list_deployment_for_all_namespaces\n'read_namespaced_replica_set'"
    assert required_permissions(src) == {("", "pods", "read"), ("apps", "deployments", "list"),
                                         ("apps", "deployments", "watch"), ("apps", "replicasets", "read")}


def test_rbac_covers_every_kube_call():
    rbac = docs(BASE / "rbac/rbac.yaml")
    bound = {d["roleRef"]["name"]: d["subjects"][0]["name"] for d in rbac if d["kind"] == "ClusterRoleBinding"}
    rules = {bound[d["metadata"]["name"]]: d["rules"] for d in rbac if d["kind"] == "ClusterRole"}
    verb = {"read": "get"}
    for agent, sa in AGENT_SA.items():
        src = "\n".join(p.read_text() for p in sorted((ROOT / "agents" / agent).glob("*.py")))
        missing = [(g, r, verb.get(v, v)) for g, r, v in sorted(required_permissions(src))
                   if not any(g in rule["apiGroups"] and r in rule["resources"] and verb.get(v, v) in rule["verbs"]
                              for rule in rules[sa])]
        assert not missing, f"{sa} ClusterRole lacks {missing}"
    assert not required_permissions((ROOT / "agents/common.py").read_text()), "common.py calls the API: map it"


def test_falco_base_syscalls_cover_the_rule():
    def find(o, key):
        if isinstance(o, dict):
            return o[key] if key in o else next((v for x in o.values() if (v := find(x, key)) is not None), None)
        return None
    custom = set(find(yaml.safe_load((ROOT / "deploy/k8s/helm/falco-values.yaml").read_text()), "custom_set"))
    cond = " ".join(r.get("condition", "") for r in docs(ROOT / "deploy/k8s/falco-kubeheal-rules.yaml")[0]
                    if isinstance(r, dict))
    rule = {s.strip() for m in re.findall(r"evt\.type in \(([^)]*)\)", cond) for s in m.split(",")}
    assert rule and rule <= custom, f"base_syscalls.custom_set misses {rule - custom}"


def render(path: str) -> list[dict]:
    r = subprocess.run(["kubectl", "kustomize", str(ROOT / path)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return [d for d in yaml.safe_load_all(r.stdout) if d]


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl not on PATH")
def test_kustomize_renders_dev_and_production():
    dev = render("deploy/k8s")
    redis = next(d for d in dev if d["kind"] == "Deployment" and d["metadata"]["name"] == "redis")
    assert any(v.get("persistentVolumeClaim") for v in redis["spec"]["template"]["spec"]["volumes"])
    assert {d["metadata"]["name"] for d in dev if d["kind"] == "NetworkPolicy"} >= {
        "redis-agents-only", "kubeheal-inference-clients"}
    prod = render("deploy/k8s/overlays/production")
    work = {d["metadata"]["name"]: d for d in prod if d["kind"] in ("Deployment", "DaemonSet")}
    assert "kubeheal-dashboard" not in work
    assert "replicas" not in work["kubeheal-inference"]["spec"], "the HPA owns inference replicas"
    assert all(d["spec"]["template"]["spec"].get("priorityClassName") == "kubeheal-security" for d in work.values())
