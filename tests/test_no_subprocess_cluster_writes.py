"""
Complements tests/test_no_writes_outside_executor.py, which only sees Kubernetes client calls.

A Python file can also change the cluster by running `kubectl apply|delete|patch|...` through subprocess, which
the client-call scan cannot see. This test scans every Python file outside agents/executor/ and tests/ for a
`kubectl` call or command list that contains a write verb. The only file allowed to do that is
eval/p11_harness.py, whose single kubectl() helper is pinned to the context k3d-kubeheal, the namespace
allow-list and the test-mode check (tests/test_eval_p11_harness.py).
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ["agents", "services", "dashboard", "models", "kernel", "chaos", "eval", "scripts", "demo", "deploy"]
ALLOWED_FILES = {ROOT / "eval" / "p11_harness.py"}
WRITE_VERBS = {
    "apply", "create", "delete", "patch", "replace", "scale", "rollout", "annotate", "label", "taint", "cordon",
    "uncordon", "drain", "edit", "set", "run", "cp", "exec", "debug",
}


def _py_files():
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if {"_archive_v3", ".venv", "__pycache__", "executor"} & set(p.parts):
                continue
            yield p


def _strings(node):
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


def _is_kubectl_name(node) -> bool:
    return (isinstance(node, ast.Name) and node.id == "kubectl") or (
        isinstance(node, ast.Attribute) and node.attr == "kubectl")


def find_kubectl_writes(source: str, filename: str = "<src>"):
    """(line, verb) for every `kubectl(...)` call or `["kubectl", ...]` literal that carries a write verb."""
    tree = ast.parse(source, filename=filename)
    hits = []
    for node in ast.walk(tree):
        carries_kubectl = False
        if isinstance(node, ast.Call) and _is_kubectl_name(node.func):
            carries_kubectl = True
        elif isinstance(node, (ast.List, ast.Tuple)) and any(
                isinstance(e, ast.Constant) and e.value == "kubectl" for e in node.elts):
            carries_kubectl = True
        if carries_kubectl:
            for text in _strings(node):
                if text in WRITE_VERBS:
                    hits.append((node.lineno, text))
    return hits


def test_scanner_catches_write_verbs_in_both_call_shapes():
    assert find_kubectl_writes('subprocess.run(["kubectl", "--context", c, "delete", "pod", p])') == [(1, "delete")]
    assert find_kubectl_writes('kubectl(ctx, ["rollout", "restart", "deployment/x"])') == [(1, "rollout")]
    assert find_kubectl_writes('subprocess.run(["kubectl", "get", "pods"])') == []
    assert find_kubectl_writes('kubectl(ctx, ["get", "configmap", "x"])') == []


def test_no_python_file_writes_through_kubectl_except_the_allow_listed_harness():
    violations = []
    for path in _py_files():
        if path in ALLOWED_FILES:
            continue
        for lineno, verb in find_kubectl_writes(path.read_text(encoding="utf-8"), str(path)):
            violations.append(f"{path.relative_to(ROOT)}:{lineno} kubectl {verb}")
    assert violations == []


def test_the_allow_listed_harness_still_pins_context_and_mode():
    text = (ROOT / "eval" / "p11_harness.py").read_text(encoding="utf-8")
    assert 'ALLOWED_CONTEXT = "k3d-kubeheal"' in text
    assert "assert_test_mode(context" in text
