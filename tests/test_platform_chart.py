"""P9: the kubeheal Helm chart renders for all four values files and keeps its key properties.

Needs the helm binary (PATH, or the winget install path); skipped with a reason when absent.
dev, staging and prod deliberately leave the owner decisions (quota, limit range, Redis volume size)
unset, so those three render only together with values-lab-example.yaml (an example, not a
recommendation; every number in it is labelled as chosen, not measured).
"""
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

LAB_EXAMPLE = CHART / "values-lab-example.yaml"


def values_path(env):
    return CHART / f"values-{env}.yaml"


def helm(*args, check=True):
    res = subprocess.run([HELM, *args], capture_output=True, text=True, timeout=120)
    if check and res.returncode != 0:
        raise AssertionError(f"helm {' '.join(args)} failed:\n{res.stderr}")
    return res


@pytest.fixture(scope="module")
def fixture_file():
    """The owner-values layer used for dev, staging and prod: the lab example file."""
    return LAB_EXAMPLE


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
# V5-I2: the neural model servers are legacy and off by default; the LightGBM inference service is on.
LEGACY = "modelServers.legacy.enabled=true"
INFERENCE = "kubeheal-inference"


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


@pytest.mark.parametrize("missing,override,needle", [
    ("quota", {"namespaces": {"quotas": {"prod": {"hard": None}}}}, "namespaces.quotas.prod.hard is required"),
    ("limits", {"namespaces": {"quotas": {"prod": {"limits": None}}}}, "namespaces.quotas.prod.limits is required"),
    ("redis", {"redis": {"persistence": {"size": ""}}}, "redis.persistence.size is required"),
])
def test_each_required_value_has_a_clear_error(missing, override, needle, tmp_path):
    f = tmp_path / "f.yaml"
    f.write_text(yaml.safe_dump(override), encoding="utf-8")      # null deletes the key from the layer below
    res = helm("template", "kubeheal", str(CHART), "-f", str(values_path("prod")), "-f", str(LAB_EXAMPLE),
               "-f", str(f), check=False)
    assert res.returncode != 0 and needle in res.stderr


def test_lab_example_labels_every_number_and_sets_no_resources():
    label = "chosen configuration for the lab cluster, not measured"
    text = LAB_EXAMPLE.read_text(encoding="utf-8")
    numbered = 0
    for line in text.splitlines():
        body = line.split("#")[0]
        if ":" in body and any(ch.isdigit() for ch in body.split(":", 1)[1]):
            numbered += 1
            assert label in line, line
    assert numbered >= 30
    data = yaml.safe_load(text)
    assert set(data) == {"namespaces", "redis"}
    assert "resources" not in text.split("\n", 12)[-1].replace("Requests and limits", "")


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
    assert defaults["redis"]["persistence"]["size"] == ""
    assert defaults["hpa"]["latency"]["targetAverageValue"] == "" and \
        defaults["hpa"]["cpu"]["targetAverageUtilization"] == ""
    assert all(q == {"hard": {}, "limits": []} for q in defaults["namespaces"]["quotas"].values())


def test_k3d_placeholders_are_labelled():
    text = values_path("k3d-demo").read_text(encoding="utf-8")
    assert "demo choice, not measured, owner to confirm" in text
    for line in text.splitlines():
        stripped = line.split("#")[0]
        if any(k in stripped for k in ("requests.cpu", "defaultRequest", "default:", "size:")):
            assert "demo choice, not measured, owner to confirm" in line, line


# ---- namespaces, quota, limit range -----------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_tier_namespaces_quota_limitrange(env, fixture_file):
    docs = render(env, fixture_file)
    ns = {d["metadata"]["name"]: d for d in by_kind(docs, "Namespace")}
    expected_namespaces = set(TIERS) | ({"demo"} if env == "k3d-demo" else set())
    assert set(ns) == expected_namespaces    # the release namespace is created by `helm install --create-namespace`
    for t in TIERS:
        assert ns[t]["metadata"]["labels"]["kubeheal/tier"] == t
        q = get(docs, "ResourceQuota", "kubeheal-quota", t)
        lr = get(docs, "LimitRange", "kubeheal-limits", t)
        assert q["spec"]["hard"] and lr["spec"]["limits"]
    if env != "k3d-demo":   # numbers come from values only (the lab example layer)
        lab = yaml.safe_load(LAB_EXAMPLE.read_text(encoding="utf-8"))["namespaces"]["quotas"]
        for t in TIERS:
            assert get(docs, "ResourceQuota", "kubeheal-quota", t)["spec"]["hard"] == lab[t]["hard"]
            assert get(docs, "LimitRange", "kubeheal-limits", t)["spec"]["limits"] == lab[t]["limits"]


def test_namespaces_create_false_keeps_policy(fixture_file):
    docs = render("prod", fixture_file, "namespaces.create=false")
    assert not by_kind(docs, "Namespace") and len(by_kind(docs, "ResourceQuota")) == 3


def test_release_namespace_is_opt_in(fixture_file):
    docs = render("k3d-demo", fixture_file, "namespaces.createReleaseNamespace=true")
    assert {d["metadata"]["name"] for d in by_kind(docs, "Namespace")} == {"kubeheal", *TIERS, "demo"}


def test_k3d_demo_watches_demo_and_grants_health_agent_read_access(fixture_file):
    docs = render("k3d-demo", fixture_file)
    health = get(docs, "Deployment", "health-agent")
    env = {entry["name"]: entry.get("value") for entry in health["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["WATCH_NAMESPACES"] == "prod,staging,dev,demo"
    assert get(docs, "Namespace", "demo")["metadata"]["labels"]["kubeheal.io/watch"] == "true"
    binding = get(docs, "RoleBinding", "kubeheal-health-agent-read", "demo")
    assert binding["roleRef"]["name"] == "kubeheal-health-agent-read"
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "health-agent", "namespace": "kubeheal"}]


# ---- model servers ------------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_model_server_ha(env, fixture_file):
    docs = render(env, fixture_file, LEGACY)
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
    docs = render("prod", fixture_file, LEGACY)
    for name in ("kubeheal-dcm", INFERENCE):
        dep = get(docs, "Deployment", name)
        assert dep["spec"]["template"]["spec"]["topologySpreadConstraints"][0]["whenUnsatisfiable"] == "DoNotSchedule"


def hpas(docs):
    return by_kind(docs, "HorizontalPodAutoscaler")


def test_default_hpa_is_queue_depth_with_a_chosen_default_target(fixture_file):
    docs = render("k3d-demo", fixture_file)
    assert [h["metadata"]["name"] for h in hpas(docs)] == [INFERENCE]       # legacy servers are off by default
    docs = render("k3d-demo", fixture_file, LEGACY)
    assert len(hpas(docs)) == 4                        # inference plus one per legacy model server
    for h in hpas(docs):
        pods = h["spec"]["metrics"][0]["pods"]
        assert pods["metric"]["name"] == "kubeheal_model_inflight_requests"
        assert pods["target"] == {"type": "AverageValue", "averageValue": "4"}
    text = (CHART / "values.yaml").read_text(encoding="utf-8")
    assert "CHOSEN DEFAULT, not a measurement" in text and "P11" in text
    # the env files no longer need the HPA target supplied: they render with only the lab example layered
    assert len(hpas(render("prod", fixture_file))) == 1


def test_latency_fallback_replaces_queue_and_never_both(fixture_file):
    docs = render("k3d-demo", fixture_file, LEGACY, "hpa.mode=latency", "hpa.latency.targetAverageValue=3")
    assert len(hpas(docs)) == 4                        # still exactly one per server
    for h in hpas(docs):
        assert h["spec"]["metrics"][0]["pods"]["metric"]["name"] == "kubeheal_model_latency_concurrency"
    rule = yaml.safe_load(get(docs, "ConfigMap", "kubeheal-prometheus-adapter-rule")["data"]["rule.yaml"])
    assert [r["name"]["as"] for r in rule] == ["kubeheal_model_latency_concurrency"]
    assert "rate(<<.Series>>" in rule[0]["metricsQuery"]
    res = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "hpa.mode=latency",
               check=False)
    assert res.returncode != 0 and "hpa.latency.targetAverageValue is required" in res.stderr


def test_cpu_hpa_is_the_weakest_fallback_and_needs_its_target(fixture_file):
    docs = render("k3d-demo", fixture_file, LEGACY, "hpa.mode=cpu", "hpa.cpu.targetAverageUtilization=50")
    assert len(hpas(docs)) == 4 and hpas(docs)[0]["spec"]["metrics"][0]["type"] == "Resource"
    assert not by_kind(docs, "ConfigMap") or "kubeheal-prometheus-adapter-rule" not in \
        {d["metadata"]["name"] for d in by_kind(docs, "ConfigMap")}
    res = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "hpa.mode=cpu", check=False)
    assert res.returncode != 0 and "hpa.cpu.targetAverageUtilization is required" in res.stderr
    assert not hpas(render("k3d-demo", fixture_file, "hpa.mode=none"))
    bad = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "hpa.mode=bogus", check=False)
    assert bad.returncode != 0


def test_adapter_rule_and_scrape_snippet(fixture_file):
    docs = render("k3d-demo", fixture_file)
    cm = get(docs, "ConfigMap", "kubeheal-prometheus-adapter-rule")
    rule = yaml.safe_load(cm["data"]["rule.yaml"])
    assert len(rule) == 1
    assert rule[0]["name"]["as"] == "kubeheal_model_inflight_requests"
    assert rule[0]["seriesQuery"].startswith("kubeheal_model_inflight_requests{")
    assert rule[0]["resources"]["overrides"] == {"namespace": {"resource": "namespace"}, "pod": {"resource": "pod"}}
    assert rule[0]["metricsQuery"].startswith("avg(<<.Series>>") and "rate(" not in rule[0]["metricsQuery"]
    scrape = yaml.safe_load(get(docs, "ConfigMap", "kubeheal-prometheus-scrape-snippet")["data"]["scrape-job.yaml"])
    assert scrape[0]["job_name"] == "kubeheal-pods"
    assert not by_kind(docs, "ServiceMonitor")


def test_every_pod_carries_scrape_annotations_matching_a_declared_port(fixture_file):
    docs = render("k3d-demo", fixture_file, LEGACY)
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
                    INFERENCE, *MODEL_SERVERS}


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
    docs = render("k3d-demo", fixture_file, LEGACY)     # k8s/ still holds the legacy model server manifests
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

EXEC_VARS = ["PROMETHEUS_URL", "SNAPSHOT_CLASS", "CANARY_WINDOW_S", "ROLLOUT_TIMEOUT_S",
             "ROLLOUT_POLL_S", "RESTORE_ENTROPY_IMAGE_PULL_SECRETS"]


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
    assert e["RESTORE_ENTROPY_IMAGE_PULL_SECRETS"] == ""
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
    docs = render(env, fixture_file, LEGACY)
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
    # k3d-demo has one intentional extra read-only RoleBinding for its demo-only namespace;
    # test_k3d_demo_watches_and_grants_health_agent_read_access covers that extension.
    got = sorted((_norm(d) for d in got_docs if d["kind"] in rbac_kinds and not (
        d["kind"] == "RoleBinding" and d["metadata"].get("namespace") == "demo" and
        d["metadata"]["name"] == "kubeheal-health-agent-read")), key=_key)
    assert [_key(n) for n in got] == [_key(n) for n in ref]
    for g, r in zip(got, ref):
        assert g == r, f"{_key(g)} diverges from the k8s reference"
    # Namespaces in the reference: same names and tier labels as the chart.
    ref_ns = {d["metadata"]["name"]: d["metadata"].get("labels", {}) for d in ref_docs if d["kind"] == "Namespace"}
    got_ns = {d["metadata"]["name"]: d["metadata"].get("labels", {})
              for d in render("k3d-demo", fixture_file, "namespaces.createReleaseNamespace=true")
              if d["kind"] == "Namespace" and d["metadata"]["name"] != "demo"}
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


# ---- queue-depth chain: the series the chart reads exists on every server --------------------------

def test_series_used_by_the_chart_is_exported_by_each_model_server():
    import importlib
    from fastapi.testclient import TestClient
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    series = values["hpa"]["queue"]["seriesName"]
    assert series == values["hpa"]["queue"]["metricName"] == "kubeheal_model_inflight_requests"
    for mod in ("services.health_model_server.main", "services.security_model_server.main",
                "services.dcm_server.main"):
        text = TestClient(importlib.import_module(mod).app).get("/metrics").text
        assert any(line.startswith(series + " ") for line in text.splitlines()), mod


def test_scoring_paths_counted_not_health_or_metrics():
    import re
    for f, path in (("health_model_server", "/health/score"), ("security_model_server", "/security/score"),
                    ("dcm_server", "/dcm/correlate")):
        text = (ROOT / "services" / f / "main.py").read_text(encoding="utf-8")
        assert f'add_inflight_middleware(app, METRICS, ["{path}"])' in text
        assert not re.search(r'add_inflight_middleware\([^)]*"/(health|metrics)"', text)


# ---- optional egress lockdown ---------------------------------------------------------------------

def test_egress_policy_off_by_default_and_on_when_asked(fixture_file):
    docs = render("k3d-demo", fixture_file)
    assert not any("Egress" in p["spec"]["policyTypes"] for p in by_kind(docs, "NetworkPolicy"))
    docs = render("k3d-demo", fixture_file, LEGACY, "networkPolicy.egress.enabled=true",
                  "networkPolicy.egress.apiServerCIDR=192.0.2.1/32")
    pols = {p["metadata"]["name"]: p for p in by_kind(docs, "NetworkPolicy")
            if "Egress" in p["spec"]["policyTypes"]}
    assert set(pols) == {"default-deny-egress", "allow-dns-egress", "allow-api-server-egress",
                         "allow-redis-egress", "allow-minio-egress", "allow-model-server-egress",
                         "allow-inference-egress", "allow-prometheus-egress"}
    assert pols["default-deny-egress"]["spec"]["podSelector"] == {} and "egress" not in pols["default-deny-egress"]["spec"]
    dns = pols["allow-dns-egress"]["spec"]["egress"][0]
    assert {(p["protocol"], p["port"]) for p in dns["ports"]} == {("UDP", 53), ("TCP", 53)}
    assert dns["to"][0]["podSelector"]["matchLabels"] == {"k8s-app": "kube-dns"}
    api = pols["allow-api-server-egress"]["spec"]["egress"][0]
    assert api["to"][0]["ipBlock"]["cidr"] == "192.0.2.1/32"
    assert pols["allow-redis-egress"]["spec"]["egress"][0]["ports"] == [{"protocol": "TCP", "port": 6379}]
    assert {p["port"] for p in pols["allow-model-server-egress"]["spec"]["egress"][0]["ports"]} == \
        set(MODEL_SERVERS.values())
    inf = pols["allow-inference-egress"]["spec"]
    assert inf["podSelector"]["matchExpressions"][0]["values"] == ["health-agent", "security-agent"]
    assert inf["egress"][0]["to"][0]["podSelector"]["matchLabels"] == {"app": INFERENCE}
    assert inf["egress"][0]["ports"] == [{"protocol": "TCP", "port": 8000}]
    # without the legacy servers only the inference egress rule exists for the scorers
    docs = render("k3d-demo", fixture_file, "networkPolicy.egress.enabled=true",
                  "networkPolicy.egress.apiServerCIDR=192.0.2.1/32")
    names = {p["metadata"]["name"] for p in by_kind(docs, "NetworkPolicy")}
    assert "allow-inference-egress" in names and "allow-model-server-egress" not in names


def test_egress_needs_the_api_server_address(fixture_file):
    res = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")),
               "--set", "networkPolicy.egress.enabled=true", check=False)
    assert res.returncode != 0 and "networkPolicy.egress.apiServerCIDR is required" in res.stderr


def test_networkpolicy_documents_the_probe_assumption():
    text = (CHART / "templates" / "networkpolicy.yaml").read_text(encoding="utf-8")
    assert "node-to-pod" in text and "kubelet probes" in text and "P10" in text


# ---- optional securityContext hardening -----------------------------------------------------------

HARDENED = [("Deployment", "health-agent", "healthAgent"), ("Deployment", "fusion-agent", "fusionAgent"),
            ("Deployment", "kubeheal-dashboard", "dashboard"),
            ("Deployment", "kubeheal-health-model", "modelServers.health"),
            ("Deployment", "kubeheal-security-model", "modelServers.security"),
            ("Deployment", "kubeheal-dcm", "modelServers.dcm")]


def test_hardening_switches_are_off_by_default_and_render_when_on(fixture_file):
    off = render("k3d-demo", fixture_file, LEGACY)
    for kind, name, _key in HARDENED:
        sc = get(off, kind, name)["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        assert "runAsNonRoot" not in sc and "readOnlyRootFilesystem" not in sc
        assert "volumes" not in get(off, kind, name)["spec"]["template"]["spec"]
    sets = []
    for _k, _n, key in HARDENED:
        sets += [f"{key}.hardening.runAsNonRoot=true", f"{key}.hardening.readOnlyRootFilesystem=true",
                 f"{key}.hardening.runAsUser=1000"]
    on = render("k3d-demo", fixture_file, LEGACY, *sets)
    for kind, name, _key in HARDENED:
        pod = get(on, kind, name)["spec"]["template"]["spec"]
        c = pod["containers"][0]
        assert c["securityContext"]["runAsNonRoot"] is True and c["securityContext"]["runAsUser"] == 1000
        assert c["securityContext"]["readOnlyRootFilesystem"] is True
        assert c["securityContext"]["allowPrivilegeEscalation"] is False      # baseline kept
        assert {"name": "tmp", "mountPath": "/tmp"} in c["volumeMounts"]
        assert {"name": "tmp", "emptyDir": {}} in pod["volumes"]


def test_model_server_probes_are_labelled_as_copied_not_measured():
    text = (CHART / "templates" / "model-servers.yaml").read_text(encoding="utf-8")
    assert "copied from k8s/*-deployment.yaml, chosen, not measured" in text


# ---- requirements and Executor defaults drift -----------------------------------------------------

def test_onnxruntime_is_pinned_with_both_bounds():
    reqs = (ROOT / "services" / "dcm_server" / "requirements.txt").read_text(encoding="utf-8")
    line = next(l for l in reqs.splitlines() if l.startswith("onnxruntime"))
    spec = line.split("#")[0].strip()
    assert ">=" in spec and "<" in spec


def test_executor_env_matches_config_defaults():
    """The chart values must not drift from agents/executor/config.py DEFAULTS (the owner's chosen defaults)."""
    config = ROOT / "agents" / "executor" / "config.py"
    if "DEFAULTS" not in config.read_text(encoding="utf-8"):
        pytest.skip("agents/executor/config.py has no DEFAULTS on this branch (they arrive with the P7 fix on work)")
    import importlib.util
    spec = importlib.util.spec_from_file_location("exec_config_for_chart_test", config)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for f in ("values.yaml", "values-k3d-demo.yaml"):
        env = yaml.safe_load((CHART / f).read_text(encoding="utf-8"))["executor"]["env"]
        assert env == mod.DEFAULTS, f


def test_images_that_write_the_ledger_install_the_minio_client():
    """ledger_from_env imports `minio` when LEDGER_BACKEND=minio. A cluster run (P10) found the Executor and Fusion
    images without it: both crash-looped at start. Every image whose component writes the ledger must install it."""
    for name in ("Dockerfile.executor", "Dockerfile.fusion", "Dockerfile.dashboard"):
        text = (ROOT / "dockerfiles" / name).read_text(encoding="utf-8")
        assert "minio" in text, name


# ---- V5-I2: the LightGBM inference service and the legacy gate -----------------------------------------

def inference_docs(env, fixture, *sets):
    docs = render(env, fixture, *sets)
    return docs, get(docs, "Deployment", INFERENCE)


@pytest.mark.parametrize("env", ENVS)
def test_inference_is_on_and_legacy_is_off_by_default(env, fixture_file):
    docs, dep = inference_docs(env, fixture_file)
    for name in MODEL_SERVERS:
        assert not [d for d in docs if d["metadata"]["name"] == name and d["kind"] != "ServiceAccount"], name
    assert dep["spec"]["replicas"] >= 2
    spec = dep["spec"]["template"]["spec"]
    assert spec["topologySpreadConstraints"][0]["labelSelector"]["matchLabels"] == {"app": INFERENCE}
    assert spec["automountServiceAccountToken"] is False
    c = spec["containers"][0]
    assert c["image"] == "kubeheal/inference-server:v5" and c["ports"][0]["containerPort"] == 8000
    assert c["livenessProbe"]["httpGet"] == {"path": "/healthz", "port": 8000}
    assert c["readinessProbe"]["httpGet"] == {"path": "/readyz", "port": 8000}
    assert c["startupProbe"]["httpGet"] == {"path": "/healthz", "port": 8000}
    assert "resources" not in c                                       # unset until measured
    sc = c["securityContext"]
    assert sc["runAsNonRoot"] is True and sc["runAsUser"] == 10001 and sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"] == {"drop": ["ALL"]}
    assert {"name": "tmp", "mountPath": "/tmp"} in c["volumeMounts"]
    assert {"name": "tmp", "emptyDir": {}} in spec["volumes"]
    ann = dep["spec"]["template"]["metadata"]["annotations"]
    assert ann["prometheus.io/scrape"] == "true" and ann["prometheus.io/path"] == "/metrics"
    assert ann["prometheus.io/port"] == "8000"
    svc = get(docs, "Service", INFERENCE)
    assert svc["spec"]["selector"] == {"app": INFERENCE} and svc["spec"]["ports"][0]["port"] == 8000
    pdb = get(docs, "PodDisruptionBudget", INFERENCE)
    assert pdb["spec"]["minAvailable"] == 1 and pdb["spec"]["selector"]["matchLabels"] == {"app": INFERENCE}
    hpa = get(docs, "HorizontalPodAutoscaler", INFERENCE)
    assert (hpa["spec"]["minReplicas"], hpa["spec"]["maxReplicas"]) == (2, 8)
    assert hpa["spec"]["scaleTargetRef"]["name"] == INFERENCE
    metric = hpa["spec"]["metrics"][0]
    assert metric["type"] == "Pods" and metric["pods"]["metric"]["name"] == "kubeheal_model_inflight_requests"


def test_legacy_gate_renders_the_neural_servers_again(fixture_file):
    docs = render("k3d-demo", fixture_file, LEGACY)
    for name in MODEL_SERVERS:
        get(docs, "Deployment", name)
        get(docs, "Service", name)
        get(docs, "PodDisruptionBudget", name)
        get(docs, "HorizontalPodAutoscaler", name)
    get(docs, "Deployment", INFERENCE)


def test_inference_can_be_switched_off(fixture_file):
    docs = render("k3d-demo", fixture_file, "inference.enabled=false")
    assert not [d for d in docs if d["metadata"]["name"] == INFERENCE]
    envs = {e["name"] for e in get(docs, "Deployment", "health-agent")["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert "INFERENCE_URL" not in envs
    names = {d["metadata"]["name"] for d in by_kind(docs, "NetworkPolicy")}
    assert "allow-inference-from-agents-and-prometheus" not in names


def test_agents_get_inference_url_next_to_the_legacy_urls(fixture_file):
    docs = render("k3d-demo", fixture_file)
    for kind, name, legacy in (("Deployment", "health-agent", "HEALTH_MODEL_URL"),
                               ("DaemonSet", "security-agent", "SECURITY_MODEL_URL")):
        envs = {e["name"]: e.get("value") for e in
                get(docs, kind, name)["spec"]["template"]["spec"]["containers"][0]["env"]}
        assert envs["INFERENCE_URL"] == "http://kubeheal-inference:8000"
        assert legacy in envs                                       # legacy URL kept; agent code is unchanged
    fusion = get(docs, "Deployment", "fusion-agent")["spec"]["template"]["spec"]["containers"][0]["env"]
    assert "INFERENCE_URL" not in {e["name"] for e in fusion}


@pytest.mark.parametrize("env", ENVS)
def test_inference_network_policy(env, fixture_file):
    docs = render(env, fixture_file)
    pol = get(docs, "NetworkPolicy", "allow-inference-from-agents-and-prometheus")["spec"]
    assert pol["podSelector"]["matchLabels"] == {"app": INFERENCE} and pol["policyTypes"] == ["Ingress"]
    frm = pol["ingress"][0]["from"]
    pods = next(f for f in frm if "podSelector" in f)["podSelector"]["matchExpressions"][0]["values"]
    assert pods == ["health-agent", "security-agent"]
    assert any(f.get("namespaceSelector", {}).get("matchLabels", {}).get("kubernetes.io/metadata.name")
               == "monitoring" for f in frm)
    assert pol["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 8000}]
    # the legacy ingress policy is gone while the legacy servers are off
    names = {d["metadata"]["name"] for d in by_kind(docs, "NetworkPolicy")}
    assert "allow-model-servers-from-agents-dashboard-prometheus" not in names
    # MinIO ingress no longer lists names of servers that do not exist
    minio = get(docs, "NetworkPolicy", "allow-minio-from-ledger-writers")
    allowed = minio["spec"]["ingress"][0]["from"][0]["podSelector"]["matchExpressions"][0]["values"]
    assert not (set(allowed) & set(MODEL_SERVERS))
    legacy_minio = get(render(env, fixture_file, LEGACY), "NetworkPolicy", "allow-minio-from-ledger-writers")
    allowed = legacy_minio["spec"]["ingress"][0]["from"][0]["podSelector"]["matchExpressions"][0]["values"]
    assert set(MODEL_SERVERS) <= set(allowed)


def test_inference_hpa_modes_follow_the_global_mode(fixture_file):
    docs = render("k3d-demo", fixture_file, "hpa.mode=latency", "hpa.latency.targetAverageValue=3")
    metric = get(docs, "HorizontalPodAutoscaler", INFERENCE)["spec"]["metrics"][0]
    assert metric["pods"]["metric"]["name"] == "kubeheal_model_latency_concurrency"
    docs = render("k3d-demo", fixture_file, "hpa.mode=cpu", "hpa.cpu.targetAverageUtilization=50")
    assert get(docs, "HorizontalPodAutoscaler", INFERENCE)["spec"]["metrics"][0]["type"] == "Resource"
    assert not hpas(render("k3d-demo", fixture_file, "hpa.mode=none"))
    assert not hpas(render("k3d-demo", fixture_file, "inference.hpa.enabled=false"))
    res = helm("template", "k", str(CHART), "-f", str(values_path("k3d-demo")), "--set", "hpa.mode=bogus", check=False)
    assert res.returncode != 0 and "hpa.mode must be" in res.stderr       # still validated with legacy off


def test_inference_resources_and_model_dir_are_settable(fixture_file):
    _docs, dep = inference_docs("k3d-demo", fixture_file, "inference.resources.requests.cpu=1m",
                                "inference.modelDir=/data/bundles", "inference.extraEnv.FOO=bar")
    c = dep["spec"]["template"]["spec"]["containers"][0]
    assert c["resources"] == {"requests": {"cpu": "1m"}}
    envs = {e["name"]: e["value"] for e in c["env"]}
    assert envs["KUBEHEAL_MODEL_DIR"] == "/data/bundles" and envs["FOO"] == "bar"
    _docs, dep = inference_docs("k3d-demo", fixture_file, "inference.hardening.readOnlyRootFilesystem=false",
                                "inference.hardening.runAsNonRoot=false")
    sc = dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert "readOnlyRootFilesystem" not in sc and "runAsNonRoot" not in sc


def test_inference_values_exist_in_every_environment_file():
    for env in ENVS:
        data = yaml.safe_load(values_path(env).read_text(encoding="utf-8"))
        assert data["inference"]["enabled"] is True, env
        assert "whenUnsatisfiable" in data["inference"]["topologySpread"], env
    defaults = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert defaults["modelServers"]["legacy"]["enabled"] is False
    inf = defaults["inference"]
    assert inf["enabled"] is True and inf["image"]["repository"] == "kubeheal/inference-server"
    assert inf["image"]["tag"] and inf["replicas"] >= 2 and inf["hpa"]["enabled"] is True
    assert inf["resources"] == {}


def test_inference_dockerfile_and_dockerignore():
    import fnmatch
    text = (ROOT / "dockerfiles" / "Dockerfile.inference").read_text(encoding="utf-8")
    assert "python:3.11-slim" in text and "USER 10001" in text and "models/bundles" in text
    assert "kubeheal/requirements.txt" in text and "COPY services/inference_server/" in text
    assert "COPY agents/common/" in text and "COPY kubeheal/" in text
    reqs = (ROOT / "services" / "inference_server" / "requirements.txt").read_text(encoding="utf-8")
    for name in ("fastapi", "uvicorn", "prometheus-client"):
        assert name in reqs
    # no .dockerignore pattern may exclude the bundles (last matching pattern wins, a leading ! re-includes)
    patterns = [ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]

    def excluded(path):
        parts = path.split("/")
        state = False
        for pat in patterns:
            neg = pat.startswith("!")
            pat = pat.lstrip("!").rstrip("/")
            if any(fnmatch.fnmatchcase("/".join(parts[:i]), pat) for i in range(1, len(parts) + 1)):
                state = not neg
        return state

    for f in ("models/bundles/health/model.txt", "models/bundles/health/meta.json",
              "models/bundles/security/model.txt", "models/bundles/security/meta.json"):
        assert not excluded(f), f
    assert excluded("tests/test_platform_chart.py") and excluded("models/x.pt")      # the checker can say yes
    for f in ("models/bundles/health/model.txt", "models/bundles/security/model.txt"):
        assert b"\r\n" not in (ROOT / f).read_bytes(), f"{f} has CRLF; LightGBM refuses it"
