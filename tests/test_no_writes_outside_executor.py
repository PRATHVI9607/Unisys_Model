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


def test_no_kubernetes_writes_or_kills_outside_executor():
    bad = []
    for p in _py_files():
        if ALLOWED in p.parents or p in EXTRA_ALLOWED:
            continue
        for lineno, name in _violations(p):
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
