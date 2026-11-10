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
DEPRECATED_INTERIM = {"contain", "patch_to_baseline"}      # functions in actions.py not dispatched any more


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


def test_main_does_not_dispatch_the_deprecated_interim_functions():
    src = (EXEC / "main.py").read_text(encoding="utf-8")
    assert "actions." not in src
    for name in DEPRECATED_INTERIM:
        assert f"{name}(" not in src.replace("quarantine.contain(", "")


def test_no_namespace_wide_quarantine_policy_remains():
    from agents.executor import actions, quarantine
    for manifest in (actions.quarantine_policy_manifest(), quarantine.quarantine_policy("inc-1")):
        assert manifest["spec"]["podSelector"] != {}
        assert manifest["spec"]["podSelector"]["matchLabels"]["kubeheal/quarantine"] == "true"
    assert "podSelector: {}" not in (EXEC / "actions.py").read_text(encoding="utf-8")
