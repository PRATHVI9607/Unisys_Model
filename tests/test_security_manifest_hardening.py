"""Static safety checks over every render of the deployment: kustomize (dev, production) and Helm (dev, production, k3d).

No cluster needed, only kubectl/helm binaries (the tests fail without them: CI has both). Justified exceptions are listed once, below,
and documented in docs/testing.md; anything not listed must be locked down.
"""

import re
import subprocess
from functools import cache
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/kubeheal"
RENDERS = {
    "kustomize-dev": ["kubectl", "kustomize", str(ROOT / "deploy/k8s")],
    "kustomize-production": ["kubectl", "kustomize", str(ROOT / "deploy/k8s/overlays/production")],
    "helm-dev": ["helm", "template", "kubeheal", str(CHART), "-n", "kubeheal"],
    "helm-production": ["helm", "template", "kubeheal", str(CHART), "-n", "kubeheal", "-f", str(CHART / "values-production.yaml")],
    "helm-k3d": ["helm", "template", "kubeheal", str(CHART), "-n", "kubeheal", "-f", str(CHART / "values-k3d.yaml")],
}
WORKLOADS = ("Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob")

# Justified exceptions (workload name -> container -> capabilities that may be ADDED after drop ALL).
CAP_ADD = {"kubeheal-security-agent": {"agent": {"SYS_PTRACE", "DAC_READ_SEARCH"},   # read other containers' /proc/<pid>/root to sample entropy
                                       "sensor": {"BPF", "PERFMON"}}}                 # load + attach the eBPF programs
ROOT_OK = {"kubeheal-security-agent"}     # needs uid 0 for ptrace / setns into pod mount namespaces
HOST_PID_OK = {"kubeheal-security-agent"}  # maps eBPF pids to /host/proc/<pid>
NO_LIVENESS = {("kubeheal-redis-secret", "create")}   # Job: runs to completion
NEEDS_READINESS = {"kubeheal-inference", "kubeheal-dashboard", "redis"}   # fronted by a Service that routes traffic to them
HOST_RW_OK = {"host-cgroup"}   # containment writes cgroup.freeze of the attacked pod (the cgroup tree is mounted rw)
API_CLIENTS = {"kubeheal-health-agent", "kubeheal-security-agent", "kubeheal-fusion-agent", "kubeheal-redis-secret"}   # the rest need no API token


@cache
def render(name: str) -> tuple[dict, ...]:
    r = subprocess.run(RENDERS[name], capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    return tuple(d for d in yaml.safe_load_all(r.stdout) if d)


@pytest.fixture(params=sorted(RENDERS))
def objs(request):
    return list(render(request.param))


def renders_where(pred):
    """Render names for which `pred(objs)` holds, so a check is parametrized only where it applies."""
    return [n for n in sorted(RENDERS) if pred(list(render(n)))]


def pods(objs):
    """(workload name, pod template spec, pod labels) for every workload."""
    for d in objs:
        if d["kind"] in WORKLOADS:
            t = d["spec"]["template"] if d["kind"] != "CronJob" else d["spec"]["jobTemplate"]["spec"]["template"]
            yield d["metadata"]["name"], t["spec"], t.get("metadata", {}).get("labels", {})


def containers(objs):
    for name, spec, _ in pods(objs):
        for c in spec.get("containers", []) + spec.get("initContainers", []):
            yield name, spec, c


def test_something_was_rendered(objs):
    assert {n for n, _, _ in pods(objs)} >= {"kubeheal-inference", "kubeheal-fusion-agent", "kubeheal-health-agent", "redis", "kubeheal-security-agent"}


def test_every_container_has_requests_and_limits(objs):
    for name, _, c in containers(objs):
        res = c.get("resources", {})
        for kind in ("requests", "limits"):
            assert {"cpu", "memory"} <= set(res.get(kind, {})), f"{name}/{c['name']} lacks {kind} cpu+memory"


def test_container_security_context(objs):
    for name, _, c in containers(objs):
        sc, who = c.get("securityContext", {}), f"{name}/{c['name']}"
        assert not sc.get("privileged"), who
        assert sc.get("allowPrivilegeEscalation") is False, who
        assert sc.get("readOnlyRootFilesystem") is True, who
        assert sc.get("capabilities", {}).get("drop") == ["ALL"], who
        assert set(sc.get("capabilities", {}).get("add", [])) <= CAP_ADD.get(name, {}).get(c["name"], set()), f"{who} adds capabilities"
        assert "hostPort" not in str(c.get("ports", "")), who


def test_non_root_and_seccomp(objs):
    for name, spec, c in containers(objs):
        psc, sc = spec.get("securityContext", {}), c.get("securityContext", {})
        user = sc.get("runAsUser", psc.get("runAsUser"))
        if name in ROOT_OK:
            assert user == 0, f"{name} should document root explicitly (runAsUser: 0)"
        else:
            assert (sc.get("runAsNonRoot") or psc.get("runAsNonRoot")) is True and user not in (None, 0), f"{name}/{c['name']}"
        assert (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type") in ("RuntimeDefault", "Localhost"), name


def test_host_namespaces_and_host_paths(objs):
    for name, spec, _ in pods(objs):
        assert not spec.get("hostNetwork") and not spec.get("hostIPC"), name
        assert not spec.get("hostPID") or name in HOST_PID_OK, name
        host_vols = {v["name"] for v in spec.get("volumes", []) if "hostPath" in v}
        assert not host_vols or name in HOST_PID_OK, f"{name} mounts hostPath"
        for c in spec["containers"]:
            for m in c.get("volumeMounts", []):
                assert m["name"] not in host_vols or m["name"] in HOST_RW_OK or m.get("readOnly") is True, f"{name}: hostPath {m['name']} must be mounted read-only"
        assert not any(v.get("hostPath", {}).get("path") in ("/", "/var/run/docker.sock", "/var/run/containerd/containerd.sock", "/etc")
                       for v in spec.get("volumes", []))


def test_liveness_and_readiness_probes(objs):
    for name, _, c in containers(objs):
        if (name, c["name"]) in NO_LIVENESS:
            continue
        assert c.get("livenessProbe"), f"{name}/{c['name']} has no livenessProbe"
        if name in NEEDS_READINESS:
            assert c.get("readinessProbe"), f"{name}/{c['name']} has no readinessProbe"


def test_sensor_has_a_liveness_probe():
    for r in RENDERS:
        for _, _, c in containers(list(render(r))):
            if c["name"] == "sensor":
                assert c.get("livenessProbe")


def test_images_are_pinned(objs):
    for name, _, c in containers(objs):
        image = c["image"]
        tag = image.rsplit("/", 1)[-1].partition("@")[0].partition(":")[2]
        assert "@sha256:" in image or (tag and tag != "latest"), f"{name}/{c['name']}: {image} is not pinned"
        assert c.get("imagePullPolicy") != "Always" or "@sha256:" in image or tag != "latest"


def test_third_party_images_are_digest_pinned(objs):
    for name, _, c in containers(objs):
        if "kubeheal" not in c["image"].split("/")[0] and not re.search(r"/(agents|inference|dashboard|sensor):", c["image"]):
            assert "@sha256:" in c["image"], f"{name}: third-party image {c['image']} needs a digest"


def test_api_token_only_for_workloads_that_call_the_api(objs):
    sas = {d["metadata"]["name"]: d for d in objs if d["kind"] == "ServiceAccount"}
    for name, spec, _ in pods(objs):
        if name in API_CLIENTS:
            continue
        sa = spec.get("serviceAccountName", "default")
        assert spec.get("automountServiceAccountToken") is False or sas.get(sa, {}).get("automountServiceAccountToken") is False, name


# ── network policies ─────────────────────────────────────────────────────────────────────────────
def selects(selector: dict, labels: dict) -> bool:
    ok = all(labels.get(k) == v for k, v in selector.get("matchLabels", {}).items())
    for e in selector.get("matchExpressions", []):
        ok &= e["operator"] == "In" and labels.get(e["key"]) in e["values"]
    return ok


def policies_for(objs, labels, ns="kubeheal"):
    return [d for d in objs if d["kind"] == "NetworkPolicy" and d["metadata"]["namespace"] == ns and selects(d["spec"]["podSelector"], labels)]


def test_redis_and_inference_are_behind_ingress_policies(objs):
    by_name = {n: lab for n, _, lab in pods(objs)}
    for target, allowed in (("redis", {"kubeheal-health-agent", "kubeheal-security-agent", "kubeheal-fusion-agent", "kubeheal-dashboard"}),
                            ("kubeheal-inference", {"kubeheal-health-agent", "kubeheal-security-agent", "kubeheal-dashboard"})):
        pols = policies_for(objs, by_name[target])
        assert pols and all("Ingress" in p["spec"]["policyTypes"] for p in pols), f"{target} has no ingress NetworkPolicy"
        for p in pols:
            for rule in p["spec"]["ingress"]:
                assert rule.get("from"), f"{target}: rule without `from` admits everyone"
                for peer in rule["from"]:
                    assert peer.get("podSelector", {}).get("matchExpressions") or peer.get("podSelector", {}).get("matchLabels") or "namespaceSelector" in peer
                    if "namespaceSelector" in peer and "podSelector" not in peer:
                        assert peer["namespaceSelector"].get("matchLabels"), f"{target}: empty namespaceSelector admits every namespace"
        # a random pod in the same namespace is not admitted: no rule selects it
        stranger = {"app": "intruder"}
        assert not any(selects(peer.get("podSelector", {}), stranger) and "namespaceSelector" not in peer
                       for p in pols for rule in p["spec"]["ingress"] for peer in rule["from"])
        # exactly the documented clients are admitted
        admitted = {v for p in pols for rule in p["spec"]["ingress"] for peer in rule["from"]
                    for e in peer.get("podSelector", {}).get("matchExpressions", []) for v in e["values"]}
        assert admitted <= allowed, f"{target} admits unexpected clients: {admitted - allowed}"


@pytest.mark.parametrize("name", renders_where(lambda o: "kubeheal-dashboard" in {n for n, _, _ in pods(o)}))
def test_dashboard_has_an_ingress_policy(name):
    objs = list(render(name))
    by_name = {n: lab for n, _, lab in pods(objs)}
    assert policies_for(objs, by_name["kubeheal-dashboard"])


# ── RBAC ─────────────────────────────────────────────────────────────────────────────────────────
def rules(objs):
    for d in objs:
        if d["kind"] in ("Role", "ClusterRole"):
            for r in d.get("rules", []):
                yield d, r


def test_rbac_has_no_wildcards_or_escalation_verbs(objs):
    for d, r in rules(objs):
        for key in ("apiGroups", "resources", "verbs"):
            assert "*" not in r.get(key, []), f"{d['metadata']['name']}: wildcard in {key}"
        assert not {"escalate", "bind", "impersonate", "deletecollection"} & set(r["verbs"]), d["metadata"]["name"]
        assert "nonResourceURLs" not in r, d["metadata"]["name"]


def test_secrets_are_touched_only_by_the_secret_job(objs):
    for d, r in rules(objs):
        if {"secrets", "serviceaccounts/token", "pods/exec", "pods/attach", "pods/portforward", "roles", "clusterroles",
                "rolebindings", "clusterrolebindings"} & set(r["resources"]):
            assert d["kind"] == "Role" and d["metadata"]["name"] == "kubeheal-redis-secret", f"{d['metadata']['name']} reaches {r['resources']}"
            assert r["resources"] == ["secrets"] and r["verbs"] == ["create"], "the secret Job may only create (no read, no list)"


def test_bindings_are_least_privilege(objs):
    roles = {(d["kind"], d["metadata"]["name"]) for d in objs if d["kind"] in ("Role", "ClusterRole")}
    for d in objs:
        if d["kind"] in ("RoleBinding", "ClusterRoleBinding"):
            ref = d["roleRef"]
            assert ref["name"] not in ("cluster-admin", "admin", "edit"), d["metadata"]["name"]
            assert (ref["kind"], ref["name"]) in roles, f"{d['metadata']['name']} binds a role this install does not define"
            for s in d["subjects"]:
                assert s["kind"] == "ServiceAccount" and s["namespace"] == "kubeheal"


def test_fusion_is_the_only_mutating_identity(objs):
    for d, r in rules(objs):
        if d["kind"] == "ClusterRole" and d["metadata"]["name"] != "kubeheal-fusion":
            assert not {"create", "update", "patch", "delete"} & set(r["verbs"]), f"{d['metadata']['name']} mutates {r['resources']}"


def test_dashboard_has_no_api_access(objs):
    bound = {s["name"] for d in objs if d["kind"] in ("RoleBinding", "ClusterRoleBinding") for s in d["subjects"]}
    assert "kubeheal-dashboard" not in bound and "kubeheal-inference" not in bound


# ── Pod Security Standards ───────────────────────────────────────────────────────────────────────
LEVELS = ("privileged", "baseline", "restricted")
BASELINE_CAPS = {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID",
                 "SETPCAP", "SETUID", "SYS_CHROOT"}
RESTRICTED_VOLUMES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "persistentVolumeClaim", "projected", "secret"}


def pss_level(spec: dict) -> str:
    """Strictest Pod Security Standard the pod spec satisfies (the fields the standards inspect; not exhaustive)."""
    cs = spec.get("containers", []) + spec.get("initContainers", [])
    scs = [c.get("securityContext", {}) for c in cs]
    if (spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC") or any("hostPath" in v for v in spec.get("volumes", []))
            or any(s.get("privileged") or set(s.get("capabilities", {}).get("add", [])) - BASELINE_CAPS for s in scs)
            or any(p.get("hostPort") for c in cs for p in c.get("ports", []))):
        return "privileged"
    psc = spec.get("securityContext", {})
    restricted = (
        all(set(v) - {"name"} <= RESTRICTED_VOLUMES for v in spec.get("volumes", []))
        and all(s.get("allowPrivilegeEscalation") is False and s.get("capabilities", {}).get("drop") == ["ALL"]
                and (s.get("runAsNonRoot") or psc.get("runAsNonRoot")) is True
                and (s.get("runAsUser", psc.get("runAsUser")) != 0)
                and (s.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type") in ("RuntimeDefault", "Localhost")
                and not set(s.get("capabilities", {}).get("add", [])) - {"NET_BIND_SERVICE"} for s in scs))
    return "restricted" if restricted else "baseline"


def test_pod_security_level_per_workload(objs):
    levels = {n: pss_level(s) for n, s, _ in pods(objs)}
    assert {n: lv for n, lv in levels.items() if lv != "restricted"} == {"kubeheal-security-agent": "privileged"}, levels


def _kubeheal_ns(objs):
    return next((d for d in objs if d["kind"] == "Namespace" and d["metadata"]["name"] == "kubeheal"), None)


@pytest.mark.parametrize("name", renders_where(lambda o: _kubeheal_ns(o) is not None))
def test_namespace_pss_labels_admit_what_we_deploy(name):
    objs = list(render(name))
    ns = _kubeheal_ns(objs)
    lab = ns["metadata"].get("labels", {})
    needed = min(LEVELS.index(pss_level(s)) for _, s, _ in pods(objs))   # the most privileged workload decides the namespace level
    for mode in ("enforce", "audit", "warn"):
        level = lab.get(f"pod-security.kubernetes.io/{mode}")
        if mode == "enforce" and level:
            assert LEVELS.index(level) <= needed, f"enforce={level} would reject the security agent (needs {LEVELS[needed]})"
