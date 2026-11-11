"""V5-D1: the Health Agent's own read-only role (pods list, horizontalpodautoscalers list).

Helm-free: the chart template is rendered by a tiny substitution (release namespace, tier loop) instead of
`helm template`, so this runs without the helm binary. The helm-rendered parity test in test_platform_chart.py
compares every RBAC document of the chart with k8s/rbac/rbac.yaml and therefore covers the same roles.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "k8s" / "rbac" / "rbac.yaml"
TEMPLATE = ROOT / "deploy" / "helm" / "kubeheal" / "templates" / "rbac.yaml"
TIERS = {"prod", "staging", "dev"}
ROLE = "kubeheal-health-agent-read"
SA = "health-agent"
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate", "*"}
RBAC_KINDS = {"ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}


def static_docs():
    return [d for d in yaml.safe_load_all(STATIC.read_text(encoding="utf-8")) if d]


def render_template_docs():
    """Substitute what the RBAC template uses: the release namespace, the tier range and the rbac.create guard."""
    text = TEMPLATE.read_text(encoding="utf-8")
    ns = '{{ include "kubeheal.namespace" . }}'
    nsd = '{{ include "kubeheal.namespace" $ }}'
    text = text.replace(ns, "kubeheal").replace(nsd, "kubeheal")
    rng = re.compile(r'\{\{- range \$tier := splitList " " \(include "kubeheal.tiers" \.\) \}\}(.*?)\{\{- end \}\}',
                     re.S)
    text = rng.sub(lambda m: "".join(m.group(1).replace("{{ $tier }}", t) for t in ("prod", "staging", "dev")), text)
    text = text.replace("{{- if .Values.rbac.create }}", "")
    text = re.sub(r"\{\{- end \}\}\s*$", "", text)
    assert "{{" not in text, "template uses a construct this mini-renderer does not know"
    return [d for d in yaml.safe_load_all(text) if d]


def norm(doc):
    meta = doc["metadata"]
    out = {"kind": doc["kind"], "name": meta["name"], "ns": meta.get("namespace")}
    for k in ("rules", "roleRef", "subjects", "automountServiceAccountToken"):
        if k in doc:
            out[k] = doc[k]
    return out


def key(n):
    return (n["kind"], n["ns"] or "", n["name"])


def permissions(role):
    return {(g, r, v) for rule in role["rules"] for g in rule["apiGroups"] for r in rule["resources"]
            for v in rule["verbs"]}


def check_health_agent_read(docs):
    role = next(d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"] == ROLE)
    # (a) exactly the two read verbs
    assert permissions(role) == {("", "pods", "list"), ("autoscaling", "horizontalpodautoscalers", "list")}
    # (b) no write verb, no wildcard, no resourceNames trick
    assert not {v for rule in role["rules"] for v in rule["verbs"]} & WRITE_VERBS
    # bound only through namespaced RoleBindings in the protected namespaces, only to the Health Agent
    assert not [d for d in docs if d["kind"] == "ClusterRoleBinding" and d["roleRef"]["name"] == ROLE]
    bindings = [d for d in docs if d["kind"] == "RoleBinding" and d["roleRef"]["name"] == ROLE]
    assert {d["metadata"]["namespace"] for d in bindings} == TIERS and len(bindings) == len(TIERS)
    for d in bindings:
        assert d["roleRef"]["kind"] == "ClusterRole"
        assert d["subjects"] == [{"kind": "ServiceAccount", "name": SA, "namespace": "kubeheal"}]


def test_static_manifest_grants_health_agent_read_only_pods_and_hpa_list():
    check_health_agent_read(static_docs())


def test_chart_template_grants_the_same():
    check_health_agent_read(render_template_docs())


def test_chart_template_matches_static_manifest_for_every_rbac_document():
    ref = sorted((norm(d) for d in static_docs() if d["kind"] in RBAC_KINDS), key=key)
    got = sorted((norm(d) for d in render_template_docs() if d["kind"] in RBAC_KINDS), key=key)
    assert [key(n) for n in got] == [key(n) for n in ref]
    for g, r in zip(got, ref):
        assert g == r, f"{key(g)} diverges between the chart and k8s/rbac/rbac.yaml"


def test_health_agent_gets_the_new_role_only_and_the_shared_roles_are_not_widened():
    for docs in (static_docs(), render_template_docs()):
        def perms(name):
            return permissions(next(d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"] == name))
        # the shared observer role was not widened: no autoscaling read, no write verb
        assert not any(g == "autoscaling" for g, _, _ in perms("kubeheal-observer"))
        assert not any(v in WRITE_VERBS for _, _, v in perms("kubeheal-observer"))
        # no other role grants autoscaling, so the Health Agent service account is the only one that can read it
        for d in docs:
            if d["kind"] == "ClusterRole" and d["metadata"]["name"] != ROLE:
                assert not any(g == "autoscaling" for g, _, _ in permissions(d)), d["metadata"]["name"]
        # the role is bound to the Health Agent and to nobody else
        subjects = {s["name"] for d in docs if d["kind"] in ("RoleBinding", "ClusterRoleBinding")
                    and d["roleRef"]["name"] == ROLE for s in d["subjects"]}
        assert subjects == {SA}


def test_health_agent_gains_no_write_verb_through_any_binding():
    """Every role bound to health-agent is read-only (get, list, watch)."""
    for docs in (static_docs(), render_template_docs()):
        roles = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ClusterRole"}
        for d in docs:
            if d["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
                continue
            if SA in {s["name"] for s in d["subjects"]}:
                verbs = {v for rule in roles[d["roleRef"]["name"]]["rules"] for v in rule["verbs"]}
                assert verbs <= {"get", "list", "watch"}, (d["metadata"]["name"], verbs)
