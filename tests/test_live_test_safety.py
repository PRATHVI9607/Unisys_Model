"""Guard tests that can contact or mutate external services.

Live integrations are explicit commands, never an accidental side effect of pytest tests/.
Keep the opt-in inventory in sync when adding a test that contacts k3d, Redis, or MinIO.
"""
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIVE_TESTS = (
    ("tests/test_killswitch.py", "test_live_watch_follows_configmap_without_polling",
     "KUBEHEAL_LIVE_KILLSWITCH_TEST"),
    ("tests/test_rbac_k3d.py", "test_rbac_matrix", "KUBEHEAL_LIVE_RBAC_TEST"),
)
LIVE_IDENTITIES = {(path.replace("\\", "/"), name) for path, name, _ in LIVE_TESTS}


def _constant_strings(node):
    return {child.value for child in ast.walk(node) if isinstance(child, ast.Constant)
            and isinstance(child.value, str)}


def _live_call_reason(call):
    """Return a reason for calls that can initiate real integration I/O.

    This intentionally focuses on entry points used by tests, rather than generic
    names such as ``patch`` or ``from_url`` that also appear in fake-backed tests.
    """
    func = call.func
    if isinstance(func, ast.Name) and func.id in {"_cluster_ok", "_kubectl", "cluster_reachable", "run_checks"}:
        return func.id
    if isinstance(func, ast.Attribute):
        if func.attr in {"load_kube_config", "load_incluster_config"}:
            return func.attr
        if func.attr == "Minio":
            return "MinIO client constructor"
        if func.attr in {"Redis", "StrictRedis"} and ast.unparse(func.value).lower() in {
                "redis", "aioredis"}:
            return "Redis client constructor"
        if func.attr == "from_url":
            owner = ast.unparse(func.value).lower()
            if any(part in owner for part in ("redis", "aioredis")):
                return "Redis client constructor"
        if func.attr in {"patch_namespaced_config_map", "patch_namespaced_configmap"} and \
                "kubeheal-mode" in _constant_strings(call):
            return "live kubeheal-mode patch"
    if isinstance(func, ast.Name) and func.id == "Minio":
        return "MinIO client constructor"
    if isinstance(func, ast.Attribute) and func.attr in {
            "run", "Popen", "call", "check_call", "check_output"}:
        owner = ast.unparse(func.value)
        if owner == "subprocess":
            strings = {s.lower() for s in _constant_strings(call)}
            if "kubectl" in strings or ("docker" in strings and "exec" in strings):
                return "external cluster command"
    return None


def _test_functions(tree):
    """Yield pytest module functions and Test* class methods recursively."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            yield node
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_"):
                    yield member
                elif isinstance(member, ast.ClassDef):
                    yield from _test_functions(ast.Module(body=[member], type_ignores=[]))


def _called_local_names(function):
    names = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _live_helper_names(tree):
    """Find module-local helper names that reach a known integration entry point."""
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and not node.name.startswith("test_")]
    live = {fn.name for fn in functions
            if any(isinstance(node, ast.Call) and _live_call_reason(node)
                   for node in ast.walk(fn))}
    changed = True
    while changed:
        changed = False
        for fn in functions:
            if fn.name not in live and _called_local_names(fn) & live:
                live.add(fn.name)
                changed = True
    return live


def _unregistered_live_test_calls(test_root=ROOT):
    findings = []
    for path in sorted(test_root.glob("test_*.py")):
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        live_helpers = _live_helper_names(tree)
        for function in _test_functions(tree):
            reasons = sorted({reason for node in ast.walk(function) if isinstance(node, ast.Call)
                              if (reason := _live_call_reason(node))})
            if _called_local_names(function) & live_helpers:
                reasons.append("local helper reaches a live integration entry point")
            if reasons and (relative, function.name) not in LIVE_IDENTITIES:
                findings.append((relative, function.name, reasons))
    return findings


def _find_function(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return next((node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == name), None)


def test_every_registered_live_test_has_a_default_skip_opt_in():
    for relative, function_name, env_var in LIVE_TESTS:
        path = ROOT / relative
        function = _find_function(path, function_name)
        assert function is not None, f"missing live test {relative}:{function_name}"
        decorators = "\n".join(ast.unparse(item) for item in function.decorator_list)
        assert "pytest.mark.skipif" in decorators, f"{relative}:{function_name} must skip by default"
        assert env_var in decorators, f"{relative}:{function_name} must require {env_var}=1"


def test_live_cluster_probes_are_inside_opted_in_test_bodies():
    for relative, function_name, _env_var in LIVE_TESTS:
        path = ROOT / relative
        function = _find_function(path, function_name)
        assert function is not None
        decorators = "\n".join(ast.unparse(item) for item in function.decorator_list)
        assert "_cluster_ok" not in decorators and "cluster_reachable" not in decorators, \
            f"{relative}:{function_name} must not contact k3d while pytest imports the module"


def test_no_unregistered_test_can_open_a_live_service_connection():
    findings = _unregistered_live_test_calls()
    assert findings == [], (
        "tests with live cluster/Redis/MinIO entry points must be added to LIVE_TESTS and "
        "guarded by an opt-in skipif: " + repr(findings)
    )


def test_live_entry_point_guard_detects_regressions_in_test_source():
    examples = (
        "def test_new_cluster_probe():\n    _cluster_ok()\n",
        "def test_new_kubectl_helper():\n    _kubectl('get', 'pods')\n",
        "def test_new_kube_config():\n    config.load_kube_config()\n",
        "def test_new_kubectl():\n    subprocess.run(['kubectl', 'get', 'pods'])\n",
        "def test_new_redis_client():\n    redis.Redis.from_url('redis://redis:6379')\n",
        "def test_new_redis_constructor():\n    redis.Redis(host='redis')\n",
        "def test_new_minio_client():\n    minio.Minio('minio:9000')\n",
        "def test_new_mode_patch():\n    api.patch_namespaced_config_map('kubeheal-mode', 'kubeheal', {})\n",
    )
    expected = {"_cluster_ok", "_kubectl", "load_kube_config", "external cluster command",
                "Redis client constructor", "MinIO client constructor", "live kubeheal-mode patch"}
    found = set()
    for source in examples:
        tree = ast.parse(source)
        test = tree.body[0]
        found.update(reason for node in ast.walk(test) if isinstance(node, ast.Call)
                     if (reason := _live_call_reason(node)))
    assert found == expected


def test_guard_discovers_class_methods_and_local_live_helpers():
    source = """
import subprocess
class TestUnsafe:
    def test_cluster_through_method(self):
        self.probe()
    def probe(self):
        run_cluster_check()
def run_cluster_check():
    subprocess.run(['kubectl', 'get', 'pods'])
"""
    tree = ast.parse(source)
    test_method, = _test_functions(tree)
    helpers = _live_helper_names(tree)
    assert test_method.name == "test_cluster_through_method"
    assert {"run_cluster_check", "probe"} <= helpers
    assert _called_local_names(test_method) & helpers == {"probe"}

