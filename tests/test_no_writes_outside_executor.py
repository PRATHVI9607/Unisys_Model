"""
Static check (P1 acceptance, kept for all later phases): no Kubernetes write call and no process
kill exists anywhere in the code base outside agents/executor/.

Read-only list/get/read/watch calls are fine. Everything that changes cluster state must live in
the Executor so that the kill switch (P3) and RBAC (P2) have exactly one place to guard.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ["agents", "services", "dashboard", "models", "kernel", "chaos", "eval", "scripts", "demo"]
ALLOWED = ROOT / "agents" / "executor"
# chaos/ simulators and dev tools are not part of the control plane but are scanned as well;
# anything legitimately writing there must be listed explicitly here.
EXTRA_ALLOWED = {ROOT / "chaos" / "ransomware-simulator.py"}
# Narrow exceptions: this file may contain exactly the listed write methods and nothing else (no other
# write, no kill). The dashboard's kill switch toggle patches the single ConfigMap kubeheal-mode (S-KS-6);
# its RBAC is the Role kubeheal-mode-admin. Pinned by test_single_write_exceptions_are_exactly_as_listed.
SINGLE_WRITE_ALLOWLIST = {
    ROOT / "dashboard" / "mode_admin.py": frozenset({"patch_namespaced_config_map"}),
}

WRITE_CALL = re.compile(
    r"^(create|patch|delete|replace|deletecollection|delete_collection)_"
    r"(namespaced_\w+|namespace|node|persistent_volume\w*|cluster_\w+|custom_object\w*|"
    r"\w+_for_all_namespaces|collection_\w+)$"
)
# Generic client entry points can issue any verb, so they are treated as writes too.
RAW_CALLS = {"call_api"}
KILL_CALLS = {("os", "kill"), ("os", "killpg")}


def _py_files():
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if "_archive_v3" in p.parts or ".venv" in p.parts or "__pycache__" in p.parts:
                continue
            yield p


def _violations(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            if WRITE_CALL.match(name) or name in RAW_CALLS:
                yield node.lineno, name
            base = node.func.value
            if isinstance(base, ast.Name) and (base.id, name) in KILL_CALLS:
                yield node.lineno, f"{base.id}.{name}"


def _unlisted_violations(path: Path, allowed_names=frozenset()):
    return [(lineno, name) for lineno, name in _violations(path) if name not in allowed_names]


def test_no_kubernetes_writes_or_kills_outside_executor():
    bad = []
    for p in _py_files():
        if ALLOWED in p.parents or p in EXTRA_ALLOWED:
            continue
        for lineno, name in _unlisted_violations(p, SINGLE_WRITE_ALLOWLIST.get(p, frozenset())):
            bad.append(f"{p.relative_to(ROOT)}:{lineno} {name}")
    assert not bad, "write calls outside agents/executor/:\n" + "\n".join(bad)


def test_detector_catches_a_violation(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("async def a(api):\n    await api.patch_namespaced_deployment('d','n',{})\n"
                 "import os\nos.kill(1, 9)\napi.call_api('/x', 'DELETE')\n")
    names = [n for _, n in _violations(f)]
    assert {"patch_namespaced_deployment", "os.kill", "call_api"} <= set(names)


def test_executor_package_exists():
    assert (ALLOWED / "actions.py").exists()


def test_single_write_exceptions_are_exactly_as_listed():
    for path, names in SINGLE_WRITE_ALLOWLIST.items():
        found = [name for _, name in _violations(path)]
        assert len(names) == 1
        assert found == sorted(names), f"{path.relative_to(ROOT)} must contain exactly one call to {sorted(names)}: {found}"
    allowed_files = set(SINGLE_WRITE_ALLOWLIST)
    for p in _py_files():
        if p not in allowed_files and ALLOWED not in p.parents and p not in EXTRA_ALLOWED:
            assert not list(_violations(p)), f"{p.relative_to(ROOT)} has a write call"


def test_a_second_write_method_in_an_allowlisted_file_is_caught(tmp_path):
    allowed = frozenset({"patch_namespaced_config_map"})
    one = "async def a(core):\n    await core.patch_namespaced_config_map('n','ns',{})\n"
    f = tmp_path / "mode_admin.py"
    f.write_text(one)
    assert _unlisted_violations(f, allowed) == []
    f.write_text(one + "    await core.delete_namespaced_config_map('n','ns')\n")
    assert [n for _, n in _unlisted_violations(f, allowed)] == ["delete_namespaced_config_map"]
    f.write_text("import os\nos.kill(1, 9)\n")
    assert [n for _, n in _unlisted_violations(f, allowed)] == ["os.kill"]
    # a repeated call of the same method passes the filter, which is why the pinning test counts calls
    f.write_text(one + "    await core.patch_namespaced_config_map(2)\n")
    assert len([n for _, n in _violations(f)]) == 2
