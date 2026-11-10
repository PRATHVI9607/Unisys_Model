"""
Static proof for the P7 write paths. Extends tests/test_killswitch.py (flat scan of agents/executor)
and tests/test_no_writes_outside_executor.py:

  * the scan here is RECURSIVE and also covers pods/PVC/VolumeSnapshot/scale/custom-object writes;
  * every write method is only ever passed (positionally) to the bare name `_write`, imported from
    actions, never called directly, never passed as a keyword, variable or partial;
  * the kill-switch gate is only queried through `_write` and `support.gate_open`;
  * the set of write methods used by the dispatched paths is pinned, which is also the list the RBAC
    role `kubeheal-executor-write` has to cover (see the report of P7).
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXEC = ROOT / "agents" / "executor"
WRITE = re.compile(r"^(create|patch|delete|replace|deletecollection|delete_collection)_"
                   r"(namespaced_\w+|namespace|node|persistent_volume\w*|cluster_\w+|custom_object\w*)$")
DISPATCHED = ["drift.py", "quarantine.py", "restore.py", "snapshots.py"]


def _files():
    return sorted(p for p in EXEC.rglob("*.py") if "__pycache__" not in p.parts)


def _parents(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _write_attrs(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = _parents(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and WRITE.match(node.attr):
            yield node, parents[node]


def test_every_write_method_is_only_passed_to_the_write_gate_recursively():
    seen = 0
    for f in _files():
        for node, parent in _write_attrs(f):
            seen += 1
            ok = (isinstance(parent, ast.Call) and node in parent.args and
                  isinstance(parent.func, ast.Name) and parent.func.id == "_write")
            assert ok, f"{f.relative_to(ROOT)}:{node.lineno} {node.attr} is not routed through _write"
    assert seen >= 15       # the scan really found the P7 write calls


def test_write_is_always_imported_from_actions_and_never_redefined():
    for f in _files():
        tree = ast.parse(f.read_text(encoding="utf-8"))
        defs = [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_write"]
        if f.name == "actions.py":
            assert len(defs) == 1
            continue
        assert not defs, f"{f.name} defines its own _write"
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_write":
                raise AssertionError(f"{f.name}:{n.lineno} calls actions._write as an attribute")


def test_the_gate_is_only_queried_through_write_or_gate_open():
    for f in _files():
        tree = ast.parse(f.read_text(encoding="utf-8"))
        funcs = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for n in ast.walk(fn):
                    if isinstance(n, ast.Attribute) and n.attr == "allow_write":
                        funcs.setdefault(fn.name, []).append(n.lineno)
        allowed = {"_write", "gate_open", "allow_write"}      # RequestGate itself defines allow_write
        extra = set(funcs) - allowed
        assert not extra, f"{f.name}: gate queried in {sorted(extra)}"


def test_no_raw_api_calls_or_process_kills_in_the_executor():
    for f in _files():
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                assert n.func.attr not in {"call_api", "kill", "killpg"}, f"{f.name}:{n.lineno} {n.func.attr}"


def test_dispatched_paths_use_exactly_these_write_methods():
    used = set()
    for name in DISPATCHED:
        used |= {n.attr for n, _ in _write_attrs(EXEC / name)}
    assert used == {
        "patch_namespaced_deployment", "patch_namespaced_stateful_set",
        "patch_namespaced_deployment_scale", "patch_namespaced_stateful_set_scale",
        "patch_namespaced_pod", "create_namespaced_network_policy", "delete_namespaced_network_policy",
        "create_namespaced_persistent_volume_claim",
        "create_namespaced_custom_object", "delete_namespaced_custom_object",
    }


def test_the_p2_interim_functions_are_gone():
    from agents.executor import actions
    for name in ("contain", "patch_to_baseline", "quarantine_policy_manifest"):
        assert not hasattr(actions, name), f"actions.{name} should have been removed"
    assert "actions." not in (EXEC / "main.py").read_text(encoding="utf-8")


def test_nothing_in_the_executor_can_delete_a_pod():
    """The design is quarantine, not delete (deleting a pod does not stop a ReplicaSet remount), and
    RBAC does not grant `delete pods`."""
    for f in _files():
        assert "delete_namespaced_pod" not in f.read_text(encoding="utf-8"), f.name


def test_no_namespace_wide_quarantine_policy_remains():
    from agents.executor import quarantine
    manifest = quarantine.quarantine_policy("inc-1")
    assert manifest["spec"]["podSelector"] != {}
    assert manifest["spec"]["podSelector"]["matchLabels"]["kubeheal/quarantine"] == "true"
    for f in _files():           # no dict literal {"podSelector": {}} anywhere in the Executor code
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    assert not (isinstance(k, ast.Constant) and k.value == "podSelector"
                                and isinstance(v, ast.Dict) and not v.keys), f"{f.name}:{n.lineno}"


def test_executor_write_rbac_matches_dispatched_write_verbs():
    import yaml

    path = ROOT / "k8s" / "rbac" / "rbac.yaml"
    docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    role = next(d for d in docs if d and d.get("kind") == "ClusterRole" and
                d.get("metadata", {}).get("name") == "kubeheal-executor-write")
    permissions = {
        (group, resource, verb)
        for rule in role["rules"]
        for group in rule["apiGroups"]
        for resource in rule["resources"]
        for verb in rule["verbs"]
    }
    assert permissions == {
        ("apps", "deployments", "patch"),
        ("apps", "statefulsets", "patch"),
        ("apps", "deployments/scale", "patch"),
        ("apps", "statefulsets/scale", "patch"),
        ("", "pods", "patch"),
        ("", "persistentvolumeclaims", "create"),
        ("networking.k8s.io", "networkpolicies", "create"),
        ("networking.k8s.io", "networkpolicies", "delete"),
        ("snapshot.storage.k8s.io", "volumesnapshots", "create"),
        ("snapshot.storage.k8s.io", "volumesnapshots", "delete"),
    }


# ---- integration audit (P7 merge): code write calls <-> RBAC, and who may write at all ----------------
METHOD_PERMISSION = {
    "patch_namespaced_deployment": ("apps", "deployments", "patch"),
    "patch_namespaced_stateful_set": ("apps", "statefulsets", "patch"),
    "patch_namespaced_deployment_scale": ("apps", "deployments/scale", "patch"),
    "patch_namespaced_stateful_set_scale": ("apps", "statefulsets/scale", "patch"),
    "patch_namespaced_pod": ("", "pods", "patch"),
    "create_namespaced_persistent_volume_claim": ("", "persistentvolumeclaims", "create"),
    "create_namespaced_network_policy": ("networking.k8s.io", "networkpolicies", "create"),
    "delete_namespaced_network_policy": ("networking.k8s.io", "networkpolicies", "delete"),
    # VolumeSnapshots go through the custom objects API (group snapshot.storage.k8s.io)
    "create_namespaced_custom_object": ("snapshot.storage.k8s.io", "volumesnapshots", "create"),
    "delete_namespaced_custom_object": ("snapshot.storage.k8s.io", "volumesnapshots", "delete"),
}
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "escalate", "bind",
               "impersonate", "*"}
# The only roles that may grant a write verb, with the ServiceAccounts they may be bound to.
WRITE_ROLES = {"kubeheal-executor-write": {"executor"}, "kubeheal-mode-admin": {"dashboard"}}


def _manifest_docs():
    import yaml
    docs = []
    for sub in ("k8s", "deploy"):
        base = ROOT / sub
        if not base.exists():
            continue
        for p in sorted(list(base.rglob("*.yaml")) + list(base.rglob("*.yml"))):
            if "templates" in p.parts:        # helm templates are not plain YAML
                continue
            try:
                docs += [d for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(d, dict)]
            except yaml.YAMLError:
                continue
    return docs


def test_every_dispatched_write_method_is_mapped_and_granted_exactly():
    used = set()
    for name in DISPATCHED:
        used |= {n.attr for n, _ in _write_attrs(EXEC / name)}
    assert used <= set(METHOD_PERMISSION), f"unmapped write methods: {sorted(used - set(METHOD_PERMISSION))}"
    needed = {METHOD_PERMISSION[m] for m in used}
    docs = _manifest_docs()
    role = next(d for d in docs if d.get("kind") == "ClusterRole" and
                d["metadata"]["name"] == "kubeheal-executor-write")
    granted = {(g, r, v) for rule in role["rules"] for g in rule["apiGroups"]
               for r in rule["resources"] for v in rule["verbs"]}
    assert needed == granted, f"missing: {sorted(needed - granted)} extra: {sorted(granted - needed)}"


def test_only_the_executor_and_the_mode_toggle_have_write_verbs():
    docs = _manifest_docs()
    for d in docs:
        if d.get("kind") not in ("Role", "ClusterRole"):
            continue
        name = d["metadata"]["name"]
        for rule in d.get("rules", []):
            if set(rule.get("verbs", [])) & WRITE_VERBS:
                assert name in WRITE_ROLES, f"role {name} grants write verbs {rule['verbs']}"
                if name == "kubeheal-mode-admin":      # one ConfigMap, nothing else
                    assert rule["resources"] == ["configmaps"] and rule["resourceNames"] == ["kubeheal-mode"]
    for d in docs:
        if d.get("kind") not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        role = d["roleRef"]["name"]
        if role in WRITE_ROLES:
            subjects = {s["name"] for s in d.get("subjects", [])}
            assert subjects <= WRITE_ROLES[role], f"{role} bound to {sorted(subjects)}"
            if role == "kubeheal-executor-write":
                assert d["kind"] == "RoleBinding", "executor write role must never be cluster-wide"
                assert d["metadata"]["namespace"] in {"prod", "staging", "dev"}


def test_no_write_method_is_referenced_outside_the_dispatched_modules():
    for f in _files():
        if f.name in DISPATCHED:
            continue
        assert not list(_write_attrs(f)), f"{f.name} references a Kubernetes write method"
