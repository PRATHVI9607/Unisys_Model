"""P9: the kubeheal Helm chart renders for all four values files and keeps its key properties.

Needs the helm binary (PATH, or the winget install path); skipped with a reason when absent.
dev, staging and prod deliberately leave the owner decisions (quota, limit range, Redis volume size, HPA
target) unset, so those three render only together with the TEST FIXTURE below. The fixture numbers are
arbitrary test inputs, not recommendations and never used outside this file.
"""
import copy
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "kubeheal"
ENVS = ["dev", "staging", "prod", "k3d-demo"]
TIERS = ["prod", "staging", "dev"]

_WINGET = Path(os.environ.get("LOCALAPPDATA", "")) / (
    "Microsoft/WinGet/Packages/Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe/windows-amd64/helm.exe")
HELM = shutil.which("helm") or (str(_WINGET) if _WINGET.exists() else None)
pytestmark = pytest.mark.skipif(HELM is None, reason="helm binary not found on PATH or in the winget location")

# TEST FIXTURE ONLY: arbitrary inputs so the REQUIRED owner values exist. Not recommendations.
OWNER_FIXTURE = {
    "namespaces": {"quotas": {t: {"hard": {"pods": "7"},
                                  "limits": [{"type": "Container", "default": {"memory": "11Mi"}}]}
                              for t in TIERS}},
    "redis": {"persistence": {"size": "3Gi"}},
    "hpa": {"queue": {"targetAverageValue": "5"}},
}


def values_path(env):
    return CHART / f"values-{env}.yaml"


def helm(*args, check=True):
    res = subprocess.run([HELM, *args], capture_output=True, text=True, timeout=120)
    if check and res.returncode != 0:
        raise AssertionError(f"helm {' '.join(args)} failed:\n{res.stderr}")
    return res


@pytest.fixture(scope="module")
def fixture_file(tmp_path_factory):
    p = tmp_path_factory.mktemp("helm") / "owner_fixture.yaml"
    p.write_text("# TEST FIXTURE, arbitrary numbers\n" + yaml.safe_dump(OWNER_FIXTURE), encoding="utf-8")
    return p


def render(env, fixture, *sets, extra_values=()):
    args = ["template", "kubeheal", str(CHART), "-f", str(values_path(env))]
    if env != "k3d-demo":
        args += ["-f", str(fixture)]
    for v in extra_values:
        args += ["-f", str(v)]
    for s in sets:
        args += ["--set", s]
    docs = [d for d in yaml.safe_load_all(helm(*args).stdout) if d]
    return docs


def by_kind(docs, kind):
    return [d for d in docs if d["kind"] == kind]


def get(docs, kind, name, namespace=None):
    for d in docs:
        if d["kind"] == kind and d["metadata"]["name"] == name and \
                (namespace is None or d["metadata"].get("namespace") == namespace):
            return d
    raise AssertionError(f"{kind}/{name} not rendered")


def containers(docs):
    for d in docs:
        if d["kind"] in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            for c in d["spec"]["template"]["spec"]["containers"]:
                yield d, c


MODEL_SERVERS = {"kubeheal-health-model": 8001, "kubeheal-security-model": 8002, "kubeheal-dcm": 8003}


# ---- lint and template for all four values files ----------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_lint_and_template_pass(env, fixture_file):
    args = ["-f", str(values_path(env))] + ([] if env == "k3d-demo" else ["-f", str(fixture_file)])
    lint = helm("lint", str(CHART), *args)
    assert "1 chart(s) linted, 0 chart(s) failed" in lint.stdout
    assert len(render(env, fixture_file)) > 40


@pytest.mark.parametrize("env", ["dev", "staging", "prod"])
def test_owner_decisions_are_required_not_defaulted(env):
    res = helm("template", "kubeheal", str(CHART), "-f", str(values_path(env)), check=False)
    assert res.returncode != 0
    assert "is required" in res.stderr and "owner decision" in res.stderr


@pytest.mark.parametrize("missing,needle", [
    ("quota", "namespaces.quotas.prod.hard is required"),
    ("limits", "namespaces.quotas.prod.limits is required"),
    ("redis", "redis.persistence.size is required"),
    ("hpa", "hpa.queue.targetAverageValue is required"),
])
def test_each_required_value_has_a_clear_error(missing, needle, tmp_path):
    fx = copy.deepcopy(OWNER_FIXTURE)
    if missing == "quota":
        fx["namespaces"]["quotas"]["prod"]["hard"] = {}
    if missing == "limits":
        fx["namespaces"]["quotas"]["prod"]["limits"] = []
    if missing == "redis":
        fx["redis"]["persistence"]["size"] = ""
    if missing == "hpa":
        fx["hpa"]["queue"]["targetAverageValue"] = ""
    f = tmp_path / "f.yaml"
    f.write_text(yaml.safe_dump(fx), encoding="utf-8")
    res = helm("template", "kubeheal", str(CHART), "-f", str(values_path("prod")), "-f", str(f), check=False)
    assert res.returncode != 0 and needle in res.stderr


def test_no_invented_numbers_in_env_values_files():
    """dev, staging and prod set no resources, quotas, sizes or targets."""
    forbidden = {"resources", "requests", "limits", "hard", "size", "targetAverageValue",
                 "targetAverageUtilization", "quotas"}

    def keys(node):
        if isinstance(node, dict):
            for k, v in node.items():
                yield k
                yield from keys(v)
        elif isinstance(node, list):
            for v in node:
                yield from keys(v)

    for env in ("dev", "staging", "prod"):
        data = yaml.safe_load(values_path(env).read_text(encoding="utf-8"))
        assert not (set(keys(data)) & forbidden), env
    defaults = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert defaults["redis"]["persistence"]["size"] == "" and defaults["hpa"]["queue"]["targetAverageValue"] == ""
    assert all(q == {"hard": {}, "limits": []} for q in defaults["namespaces"]["quotas"].values())


def test_k3d_placeholders_are_labelled():
    text = values_path("k3d-demo").read_text(encoding="utf-8")
    assert "demo choice, not measured, owner to confirm" in text
    for line in text.splitlines():
        stripped = line.split("#")[0]
        if any(k in stripped for k in ("requests.cpu", "defaultRequest", "default:", "size:", "targetAverageValue")):
            assert "demo choice, not measured, owner to confirm" in line, line


# ---- namespaces, quota, limit range -----------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_tier_namespaces_quota_limitrange(env, fixture_file):
    docs = render(env, fixture_file)
    ns = {d["metadata"]["name"]: d for d in by_kind(docs, "Namespace")}
    assert set(ns) == set(TIERS)    # the release namespace is created by `helm install --create-namespace`
    for t in TIERS:
        assert ns[t]["metadata"]["labels"]["kubeheal/tier"] == t
        q = get(docs, "ResourceQuota", "kubeheal-quota", t)
        lr = get(docs, "LimitRange", "kubeheal-limits", t)
        assert q["spec"]["hard"] and lr["spec"]["limits"]
    if env != "k3d-demo":   # numbers come from values only
        assert get(docs, "ResourceQuota", "kubeheal-quota", "prod")["spec"]["hard"] == {"pods": "7"}


def test_namespaces_create_false_keeps_policy(fixture_file):
    docs = render("prod", fixture_file, "namespaces.create=false")
    assert not by_kind(docs, "Namespace") and len(by_kind(docs, "ResourceQuota")) == 3


def test_release_namespace_is_opt_in(fixture_file):
    docs = render("k3d-demo", fixture_file, "namespaces.createReleaseNamespace=true")
    assert {d["metadata"]["name"] for d in by_kind(docs, "Namespace")} == {"kubeheal", *TIERS}


# ---- model servers ------------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_model_server_ha(env, fixture_file):
    docs = render(env, fixture_file)
    for name, port in MODEL_SERVERS.items():
        dep = get(docs, "Deployment", name)
        assert dep["spec"]["replicas"] >= 2
        spread = dep["spec"]["template"]["spec"]["topologySpreadConstraints"]
        assert spread and spread[0]["labelSelector"]["matchLabels"] == {"app": name}
        pdb = get(docs, "PodDisruptionBudget", name)
        assert pdb["spec"]["minAvailable"] == 1 and pdb["spec"]["selector"]["matchLabels"] == {"app": name}
        hpa = get(docs, "HorizontalPodAutoscaler", name)
        assert (hpa["spec"]["minReplicas"], hpa["spec"]["maxReplicas"]) == (2, 8)
        metric = hpa["spec"]["metrics"][0]
        assert metric["type"] == "Pods" and metric["pods"]["metric"]["name"] == "kubeheal_model_inflight_requests"
        assert hpa["spec"]["scaleTargetRef"]["name"] == name
        assert dep["spec"]["template"]["metadata"]["annotations"]["prometheus.io/port"] == str(port)


def test_prod_topology_spread_is_hard(fixture_file):
    dep = get(render("prod", fixture_file), "Deployment", "kubeheal-dcm")
    assert dep["spec"]["template"]["spec"]["topologySpreadConstraints"][0]["whenUnsatisfiable"] == "DoNotSchedule"


def test_cpu_hpa_is_a_switch_and_needs_its_target(fixture_file):
    docs = render("k3d-demo", fixture_file, "hpa.mode=cpu", "hpa.cpu.targetAverageUtilization=50")
    hpa = get(docs, "HorizontalPodAutoscaler", "kubeheal-dcm")
    assert hpa["spec"]["metrics"][0]["type"] == "Resource"
    res = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "hpa.mode=cpu", check=False)
    assert res.returncode != 0 and "hpa.cpu.targetAverageUtilization is required" in res.stderr
    assert not by_kind(render("k3d-demo", fixture_file, "hpa.mode=none"), "HorizontalPodAutoscaler")
    bad = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "hpa.mode=bogus", check=False)
    assert bad.returncode != 0


def test_adapter_rule_and_scrape_snippet(fixture_file):
    docs = render("k3d-demo", fixture_file)
    cm = get(docs, "ConfigMap", "kubeheal-prometheus-adapter-rule")
    rule = yaml.safe_load(cm["data"]["rule.yaml"])[0]
    assert rule["name"]["as"] == "kubeheal_model_inflight_requests"
    assert rule["seriesQuery"].startswith("kubeheal_model_latency_seconds_sum")
    assert "rate(<<.Series>>" in rule["metricsQuery"]
    scrape = yaml.safe_load(get(docs, "ConfigMap", "kubeheal-prometheus-scrape-snippet")["data"]["scrape-job.yaml"])
    assert scrape[0]["job_name"] == "kubeheal-pods"
    assert not by_kind(docs, "ServiceMonitor")


def test_every_pod_carries_scrape_annotations_matching_a_declared_port(fixture_file):
    docs = render("k3d-demo", fixture_file)
    seen = set()
    for d in docs:
        if d["kind"] in ("Deployment", "DaemonSet") and d["metadata"]["name"] != "minio":
            ann = d["spec"]["template"]["metadata"]["annotations"]
            ports = {str(p["containerPort"]) for c in d["spec"]["template"]["spec"]["containers"]
                     for p in c.get("ports", [])}
            assert ann["prometheus.io/scrape"] == "true" and ann["prometheus.io/path"] == "/metrics"
            assert ann["prometheus.io/port"] in ports, d["metadata"]["name"]
            seen.add(d["metadata"]["name"])
    assert seen == {"health-agent", "security-agent", "fusion-agent", "executor", "kubeheal-dashboard",
                    *MODEL_SERVERS}


# ---- workloads present, resources unset ---------------------------------------------------------

def k8s_workload_names():
    names = set()
    for f in (ROOT / "k8s").glob("*.yaml"):
        if f.name.startswith("falco"):   # Falco is installed from its own chart (k8s/falco.yaml values)
            continue
        for d in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(d, dict) and d.get("kind") in ("Deployment", "DaemonSet"):
                names.add(d["metadata"]["name"])
    return names


def test_chart_covers_every_k8s_workload(fixture_file):
    docs = render("k3d-demo", fixture_file)
    rendered = {d["metadata"]["name"] for d in docs if d["kind"] in ("Deployment", "DaemonSet")}
    assert k8s_workload_names() <= rendered
    assert get(docs, "DaemonSet", "security-agent")["spec"]["template"]["spec"]["hostPID"] is True
    assert get(docs, "Deployment", "fusion-agent")["spec"]["replicas"] == 2
    for kind, name in (("Deployment", "executor"), ("Deployment", "kubeheal-dashboard"), ("StatefulSet", "redis"),
                       ("Deployment", "minio")):
        get(docs, kind, name)


@pytest.mark.parametrize("env", ENVS)
def test_resources_unset_by_default_and_settable(env, fixture_file):
    docs = render(env, fixture_file)
    assert all("resources" not in c for _, c in containers(docs))
    docs = render(env, fixture_file, "healthAgent.resources.requests.cpu=1m")
    ha = get(docs, "Deployment", "health-agent")["spec"]["template"]["spec"]["containers"][0]
    assert ha["resources"] == {"requests": {"cpu": "1m"}}


# ---- Executor ----------------------------------------------------------------------------------

EXEC_VARS = ["PROMETHEUS_URL", "SNAPSHOT_CLASS", "CANARY_WINDOW_S", "ROLLOUT_TIMEOUT_S", "ROLLOUT_POLL_S"]


def exec_env(docs):
    dep = get(docs, "Deployment", "executor")
    c = dep["spec"]["template"]["spec"]["containers"][0]
    return dep, c, {e["name"]: e.get("value") for e in c["env"]}


@pytest.mark.parametrize("env", ENVS)
def test_executor_defaults_rendered(env, fixture_file):
    dep, c, e = exec_env(render(env, fixture_file))
    assert e["PROMETHEUS_URL"] == "http://prometheus-operated.monitoring.svc.cluster.local:9090"
    assert e["SNAPSHOT_CLASS"] == "csi-hostpath-snapclass"
    assert (e["CANARY_WINDOW_S"], e["ROLLOUT_TIMEOUT_S"], e["ROLLOUT_POLL_S"]) == ("30", "180", "5")
    assert dep["spec"]["template"]["spec"]["serviceAccountName"] == "executor"
    assert c["image"] == "kubeheal/executor:v4"
    assert c["readinessProbe"] and c["livenessProbe"]
    sc = c["securityContext"]
    assert sc["readOnlyRootFilesystem"] is True and sc["runAsNonRoot"] is True
    assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"] == {"drop": ["ALL"]}


def test_executor_env_can_be_emptied_and_still_renders(fixture_file):
    sets = [f"executor.env.{n}=" for n in EXEC_VARS]
    _dep, _c, e = exec_env(render("k3d-demo", fixture_file, *sets))
    assert all(n in e and e[n] == "" for n in EXEC_VARS)       # rendered, empty: Executor escalates
    _dep, _c, e = exec_env(render("k3d-demo", fixture_file, "executor.env=null"))
    assert all(e[n] == "" for n in EXEC_VARS)
    _dep, _c, e = exec_env(render("k3d-demo", fixture_file, "executor.env.CANARY_WINDOW_S=60"))
    assert e["CANARY_WINDOW_S"] == "60" and e["ROLLOUT_POLL_S"] == "5"


# ---- Redis ---------------------------------------------------------------------------------------

REDIS_CLIENTS = [("Deployment", "health-agent"), ("DaemonSet", "security-agent"), ("Deployment", "fusion-agent"),
                 ("Deployment", "executor"), ("Deployment", "kubeheal-dashboard")]


@pytest.mark.parametrize("env", ENVS)
def test_redis_aof_pvc_and_auth(env, fixture_file):
    docs = render(env, fixture_file)
    sts = get(docs, "StatefulSet", "redis")
    c = sts["spec"]["template"]["spec"]["containers"][0]
    assert "--appendonly" in c["args"] and c["args"][c["args"].index("--appendonly") + 1] == "yes"
    assert "--requirepass" in c["args"] and "$(REDIS_PASSWORD)" in c["args"]
    pvc = sts["spec"]["volumeClaimTemplates"][0]
    assert pvc["spec"]["resources"]["requests"]["storage"]
    assert get(docs, "Service", "redis-master")["spec"]["selector"] == {"app": "redis"}
    for kind, name in REDIS_CLIENTS:
        envs = get(docs, kind, name)["spec"]["template"]["spec"]["containers"][0]["env"]
        names = [e["name"] for e in envs]
        assert names.index("REDIS_PASSWORD") < names.index("REDIS_URL")     # needed for $(...) expansion
        url = next(e for e in envs if e["name"] == "REDIS_URL")["value"]
        assert url == "redis://:$(REDIS_PASSWORD)@redis-master:6379"
        sec = next(e for e in envs if e["name"] == "REDIS_PASSWORD")["valueFrom"]["secretKeyRef"]
        assert sec == {"name": "kubeheal-redis", "key": "password"}


def test_redis_secret_created_only_when_password_given(fixture_file):
    assert not by_kind(render("k3d-demo", fixture_file), "Secret")
    docs = render("k3d-demo", fixture_file, "redis.auth.password=testonly")
    assert get(docs, "Secret", "kubeheal-redis")["stringData"] == {"password": "testonly"}


# ---- Dashboard -----------------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_dashboard_env(env, fixture_file):
    dep = get(render(env, fixture_file), "Deployment", "kubeheal-dashboard")
    assert dep["spec"]["template"]["spec"]["serviceAccountName"] == "dashboard"
    envs = {e["name"]: e for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
    tok = envs["KUBEHEAL_ADMIN_TOKEN"]
    assert "value" not in tok                                  # never a literal token
    assert tok["valueFrom"]["secretKeyRef"] == {"name": "kubeheal-dashboard-admin", "key": "token"}
    assert "optional" not in tok["valueFrom"]["secretKeyRef"]  # the Secret is required
    assert "KUBEHEAL_ADMIN_IDENTITY" not in envs               # optional, only when set
    assert envs["LEDGER_BACKEND"]["value"] == "minio"
    assert envs["MINIO_ENDPOINT"]["value"] == "minio:9000"
    assert envs["MINIO_BUCKET"]["value"] == "kubeheal-ledger"
    for k, key in (("MINIO_ACCESS_KEY", "access-key"), ("MINIO_SECRET_KEY", "secret-key")):
        assert envs[k]["valueFrom"]["secretKeyRef"] == {"name": "kubeheal-minio-client", "key": key}
    assert envs["REDIS_URL"]["value"] == "redis://:$(REDIS_PASSWORD)@redis-master:6379"


def test_dashboard_admin_identity_and_secret_override(fixture_file):
    docs = render("k3d-demo", fixture_file, "dashboard.adminIdentity=ops-team",
                  "dashboard.adminTokenSecret.name=other", "dashboard.adminTokenSecret.key=k")
    c = get(docs, "Deployment", "kubeheal-dashboard")["spec"]["template"]["spec"]["containers"][0]
    envs = {e["name"]: e for e in c["env"]}
    assert envs["KUBEHEAL_ADMIN_IDENTITY"]["value"] == "ops-team"
    assert envs["KUBEHEAL_ADMIN_TOKEN"]["valueFrom"]["secretKeyRef"] == {"name": "other", "key": "k"}


def test_chart_never_creates_the_admin_token_secret(fixture_file):
    for d in by_kind(render("k3d-demo", fixture_file, "redis.auth.password=x"), "Secret"):
        assert d["metadata"]["name"] == "kubeheal-redis"


# ---- NetworkPolicy -----------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_network_policy(env, fixture_file):
    docs = render(env, fixture_file)
    deny = get(docs, "NetworkPolicy", "default-deny-ingress")
    assert deny["spec"]["podSelector"] == {} and deny["spec"]["policyTypes"] == ["Ingress"]
    allow = get(docs, "NetworkPolicy", "allow-model-servers-from-agents-dashboard-prometheus")
    sel = allow["spec"]["podSelector"]["matchExpressions"][0]
    assert set(sel["values"]) == set(MODEL_SERVERS)
    frm = allow["spec"]["ingress"][0]["from"]
    pods = next(f for f in frm if "podSelector" in f)["podSelector"]["matchExpressions"][0]["values"]
    assert set(pods) == {"health-agent", "security-agent", "fusion-agent", "kubeheal-dashboard"}
    assert any(f.get("namespaceSelector", {}).get("matchLabels", {}).get("kubernetes.io/metadata.name")
               == "monitoring" for f in frm)
    ports = {p["port"] for p in allow["spec"]["ingress"][0]["ports"]}
    assert ports == set(MODEL_SERVERS.values())
    assert all("Egress" not in p["spec"]["policyTypes"] for p in by_kind(docs, "NetworkPolicy"))
    redis = get(docs, "NetworkPolicy", "allow-redis-from-kubeheal-components")
    allowed = redis["spec"]["ingress"][0]["from"][0]["podSelector"]["matchExpressions"][0]["values"]
    assert set(allowed) == {n for _, n in REDIS_CLIENTS}


def test_network_policy_can_be_disabled(fixture_file):
    assert not by_kind(render("k3d-demo", fixture_file, "networkPolicy.enabled=false"), "NetworkPolicy")


# ---- Ingress -------------------------------------------------------------------------------------

def test_ingress_classes(fixture_file):
    for env, cls, ctrl in (("k3d-demo", "traefik", "kube-system"), ("dev", "nginx", "ingress-nginx"),
                           ("staging", "nginx", "ingress-nginx"), ("prod", "nginx", "ingress-nginx")):
        docs = render(env, fixture_file)
        ing = get(docs, "Ingress", "kubeheal-dashboard")
        assert ing["spec"]["ingressClassName"] == cls
        assert ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] == "kubeheal-dashboard"
        np_ = get(docs, "NetworkPolicy", "allow-dashboard-from-ingress-and-prometheus")
        got = [f["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
               for f in np_["spec"]["ingress"][0]["from"]]
        assert ctrl in got
    assert not by_kind(render("k3d-demo", fixture_file, "ingress.enabled=false"), "Ingress")


# ---- kill switch and RBAC ------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_kill_switch_defaults_to_test(env, fixture_file):
    assert get(render(env, fixture_file), "ConfigMap", "kubeheal-mode")["data"] == {"mode": "test"}


def test_kill_switch_rejects_unknown_mode(fixture_file):
    res = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "killSwitch.mode=maybe",
               check=False)
    assert res.returncode != 0 and "killSwitch.mode must be test or enforce" in res.stderr


def _norm(doc):
    """What matters for parity: kind, name, namespace and the permissions (not labels or comments)."""
    meta = doc["metadata"]
    out = {"kind": doc["kind"], "name": meta["name"], "ns": meta.get("namespace")}
    for k in ("rules", "roleRef", "subjects", "automountServiceAccountToken"):
        if k in doc:
            out[k] = doc[k]
    return out


def _key(n):
    return (n["kind"], n["ns"] or "", n["name"])


def test_rbac_rendered_by_chart_matches_k8s_rbac_yaml(fixture_file):
    """The chart renders its own RBAC. It must stay identical to the reference k8s/rbac/rbac.yaml and
    k8s/kill-switch.yaml, otherwise this test fails (fix the template or the reference, not the test)."""
    ref_docs = []
    for f in ("rbac/rbac.yaml", "kill-switch.yaml"):
        ref_docs += [d for d in yaml.safe_load_all((ROOT / "k8s" / f).read_text(encoding="utf-8")) if d]
    rbac_kinds = {"ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}
    ref = sorted((_norm(d) for d in ref_docs if d["kind"] in rbac_kinds), key=_key)
    got_docs = render("k3d-demo", fixture_file)
    got = sorted((_norm(d) for d in got_docs if d["kind"] in rbac_kinds), key=_key)
    assert [_key(n) for n in got] == [_key(n) for n in ref]
    for g, r in zip(got, ref):
        assert g == r, f"{_key(g)} diverges from the k8s reference"
    # Namespaces in the reference: same names and tier labels as the chart.
    ref_ns = {d["metadata"]["name"]: d["metadata"].get("labels", {}) for d in ref_docs if d["kind"] == "Namespace"}
    got_ns = {d["metadata"]["name"]: d["metadata"].get("labels", {})
              for d in render("k3d-demo", fixture_file, "namespaces.createReleaseNamespace=true")
              if d["kind"] == "Namespace"}
    assert ref_ns == got_ns
    assert get(got_docs, "ConfigMap", "kubeheal-mode")["data"] == \
        next(d for d in ref_docs if d["kind"] == "ConfigMap")["data"]


def test_rbac_create_false_renders_no_rbac(fixture_file):
    docs = render("k3d-demo", fixture_file, "rbac.create=false")
    for kind in ("ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"):
        assert not by_kind(docs, kind)


def test_model_server_service_accounts_do_not_mount_tokens(fixture_file):
    docs = render("k3d-demo", fixture_file)
    for sa in ("health-model", "security-model", "dcm"):
        assert get(docs, "ServiceAccount", sa)["automountServiceAccountToken"] is False


# ---- chart files hygiene -----------------------------------------------------------------------

def test_no_em_dashes_in_chart_and_eval_files():
    files = [p for p in CHART.rglob("*") if p.is_file()] + [ROOT / "eval" / "resource_profile.py"]
    for p in files:
        assert "—" not in p.read_text(encoding="utf-8"), p
