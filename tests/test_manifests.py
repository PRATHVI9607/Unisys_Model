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


# ── cluster guard (deploy/scripts/lib/guard.sh) ──────────────────────────────
GUARD = ROOT / "deploy/scripts/lib/guard.sh"
GUARDED = ["deploy/scripts/install.sh", "deploy/scripts/demo.sh", "deploy/scripts/reset.sh",
           "deploy/scripts/seed_demo.sh", "deploy/scripts/smoke.sh", "training/collect/run_lab.sh"]


def run_guard(tmp_path: Path, ctx: str, *args: str) -> subprocess.CompletedProcess:
    fake = tmp_path / "kubectl"   # `kubectl config current-context` is the only call the guard makes
    fake.write_text(f"#!/bin/sh\n[ \"$1 $2\" = 'config current-context' ] && echo {ctx}\n")
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}
    return subprocess.run(["bash", str(GUARD), *args], capture_output=True, text=True, env=env)


@pytest.mark.parametrize("ctx", ["minikube", "k3d-kubeheal"])
def test_guard_allows_lab_contexts_and_prints_them(tmp_path, ctx):
    r = run_guard(tmp_path, ctx)
    assert r.returncode == 0 and f"kubectl context: {ctx}" in r.stderr


def test_guard_refuses_other_contexts_unless_forced_by_name(tmp_path):
    r = run_guard(tmp_path, "kind-asgard")
    assert r.returncode == 2 and "kubectl context: kind-asgard" in r.stderr and "refusing" in r.stderr
    assert run_guard(tmp_path, "kind-asgard", "--force-context", "other").returncode == 2   # must equal the current one
    assert run_guard(tmp_path, "kind-asgard", "--force-context", "kind-asgard").returncode == 0


def test_every_cluster_script_is_guarded():
    for p in GUARDED:
        assert "lib/guard.sh" in (ROOT / p).read_text(), p
    assert "lib/guard.sh" in (ROOT / "deploy/scripts/evaluate.py").read_text()


def test_grafana_dashboard_queries_only_existing_metrics():
    import json
    dash = json.loads((BASE / "grafana/kubeheal-overview.json").read_text())
    exprs = [t["expr"] for p in dash["panels"] for t in p["targets"]]
    used = {m for e in exprs for m in re.findall(r"\b(?:kubeheal|container)_[a-z_]+", e)}
    code = "\n".join(p.read_text() for d in ("agents", "kubeheal") for p in sorted((ROOT / d).rglob("*.py")))
    keep = (ROOT / "deploy/k8s/helm/monitoring-values.yaml").read_text()   # cAdvisor keep-list
    missing = [m for m in used if (f'"{re.sub(r"_(bucket|sum|count)$", "", m)}"' not in code if m.startswith("kubeheal_") else m not in keep)]
    assert used and not missing, f"dashboard queries metrics nothing exports: {missing}"
    assert all(p["datasource"]["uid"] == "prometheus" for p in dash["panels"])


def test_smoke_acted_reads_whole_stream():
    # an early awk `exit` SIGPIPEs the Redis pipe once the actions stream outgrows the pipe buffer; with pipefail
    # `acted` then fails although the action is there (found live: smoke "kill" step timed out on a busy stream)
    body = Path("deploy/scripts/smoke.sh").read_text().split("acted() {", 1)[1].split("\n}\n", 1)[0]
    assert "exit" not in body


def test_demo_script_dry_run_and_stream_parser():
    demo = ROOT / "deploy/scripts/demo.sh"
    out = subprocess.run(["bash", str(demo), "--dry-run"], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0 and out.stdout.count("plan: s_") == 9, out.stdout + out.stderr
    fixture = "1-0\nnamespace\nkhe-demo-kill\ndecision\nAUTO_KILL\noutcome\npod killed\nrationale\n\n0-1\nnamespace\nx\n"
    parse = f'source {demo}; parse_stream "namespace decision outcome" <<<"$1"; field "$(parse_stream "outcome" <<<"$1" | head -1)" outcome'
    out = subprocess.run(["bash", "-c", parse, "_", fixture], capture_output=True, text=True, timeout=30)
    assert out.stdout.splitlines() == ["1-0 namespace=khe-demo-kill decision=AUTO_KILL outcome=pod_killed", "0-1 namespace=x", "pod_killed"], out.stdout + out.stderr


def test_sensor_stats_path_matches_manifests():
    for p in ("deploy/k8s/base/security-agent-daemonset.yaml", "deploy/helm/kubeheal/templates/security-agent.yaml"):
        assert "SENSOR_STATS_PATH" in (ROOT / p).read_text(), p
    assert "/var/run/kubeheal/sensor-stats.json" in (ROOT / "sensor/src/main.rs").read_text()


def _final_stage(df: Path) -> tuple[str, str]:
    """(base image, text of the final stage) of a Dockerfile."""
    parts = re.split(r"(?m)^(?=FROM )", df.read_text())
    last = [p for p in parts if p.startswith("FROM ")][-1]
    return last.split()[1], last


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl not on PATH")
def test_exec_probe_binaries_exist_in_their_image():
    """Distroless final stages have no sh/stat/date: an exec probe through them fails forever (CrashLoop on liveness)."""
    checked = 0
    for path in ("deploy/k8s", "deploy/k8s/overlays/production"):
        for d in render(path):
            if d["kind"] not in ("Deployment", "DaemonSet", "StatefulSet"):
                continue
            for c in d["spec"]["template"]["spec"]["containers"]:
                name = re.sub(r"[:@].*", "", c["image"]).rsplit("/", 1)[-1]
                df = ROOT / ("sensor/Dockerfile" if name == "sensor" else f"deploy/docker/Dockerfile.{name}")
                if not df.exists():
                    continue   # third-party image (redis, oauth2-proxy, ...)
                base, stage = _final_stage(df)
                for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
                    cmd = (c.get(probe) or {}).get("exec", {}).get("command")
                    if not cmd:
                        continue
                    checked += 1
                    if "distroless" in base:
                        assert cmd[0] not in ("sh", "bash", "/bin/sh", "test", "stat", "date"), (c["name"], probe, cmd)
                        if cmd[0].startswith("/"):
                            assert f" {cmd[0]}" in stage, (c["name"], probe, cmd)   # COPY'd or ENTRYPOINT in the final stage
    assert checked >= 1


def test_sensor_probe_uses_the_binary_itself():
    for p in ("deploy/k8s/base/security-agent-daemonset.yaml", "deploy/helm/kubeheal/templates/security-agent.yaml"):
        assert "[/kubeheal-sensor, --check-stats," in (ROOT / p).read_text(), p


def test_release_workflow_pins_actions_by_sha_gates_on_ci_and_keeps_actor_out_of_shell():
    wf = (ROOT / ".github/workflows/release.yml").read_text()
    uses = re.findall(r"uses: (\S+)", wf)
    assert uses and all(u.startswith("./") or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses
    parsed = yaml.safe_load(wf)["jobs"]
    assert parsed["ci"]["uses"] == "./.github/workflows/ci.yml" and parsed["images"]["needs"] == "ci"
    assert "workflow_call" in yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())[True]
    assert not re.search(r"run:[^\n]*\$\{\{\s*github\.actor", wf) and '-u "${{ github.actor' not in wf
