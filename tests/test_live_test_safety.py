"""Guard the small set of tests allowed to contact or mutate external services.

Live integrations are explicit commands, never an accidental side effect of pytest tests/.
Keep this inventory in sync when adding a test that contacts k3d, Redis, or MinIO.
"""
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIVE_TESTS = (
    ("tests/test_killswitch.py", "test_live_watch_follows_configmap_without_polling",
     "KUBEHEAL_LIVE_KILLSWITCH_TEST"),
    ("tests/test_rbac_k3d.py", "test_rbac_matrix", "KUBEHEAL_LIVE_RBAC_TEST"),
)


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

