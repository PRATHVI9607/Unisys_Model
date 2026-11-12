import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "dockerfiles" / "Dockerfile.security"


def _module_file(name: str):
    base = ROOT.joinpath(*name.split("."))
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return None


def _imports_of(path: Path):
    """Yield (module name, module_level). Imports inside a function are lazy and optional (for example the gRPC
    stubs of the Falco client, guarded by a presence check), so only module-level imports must be installed."""
    tree = ast.parse(path.read_text(encoding="utf-8"))

    def walk(node, module_level):
        for child in ast.iter_child_nodes(node):
            level = module_level and not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            if isinstance(child, ast.Import):
                for alias in child.names:
                    yield alias.name, module_level
            elif isinstance(child, ast.ImportFrom) and child.level == 0 and child.module:
                yield child.module, module_level
                for alias in child.names:                      # `from pkg import submodule`
                    yield f"{child.module}.{alias.name}", module_level
            yield from walk(child, level)
    yield from walk(tree, True)


def _reachable_repo_modules():
    """Every repo module the Security Agent can import, followed transitively, and the external imports."""
    queue = sorted((ROOT / "agents" / "security_agent").glob("*.py"))
    seen, external = set(), set()
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        for name, module_level in _imports_of(path):
            top = name.split(".")[0]
            target = _module_file(name)
            if target is not None:
                queue.append(target)
                for parent in range(1, name.count(".") + 1):   # package __init__ files run too
                    init = _module_file(".".join(name.split(".")[:parent]))
                    if init is not None:
                        queue.append(init)
            elif (ROOT / top).is_dir() or _module_file(top) is not None:
                continue                                     # attribute of a repo module, not an import
            elif top not in sys.stdlib_module_names and module_level:
                external.add(top)
    return seen, external


def test_security_dockerfile_copies_every_top_level_package_the_agent_imports():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    seen, _external = _reachable_repo_modules()
    tops = {p.relative_to(ROOT).parts[0] for p in seen}
    assert {"agents", "kubeheal"} <= tops
    for top in sorted(tops):
        assert f"COPY {top}/ /app/{top}/" in dockerfile, f"{top}/ is imported by the Security Agent but not copied"


def test_security_dockerfile_installs_every_third_party_package_the_agent_imports():
    text = DOCKERFILE.read_text(encoding="utf-8").lower().replace("_", "-")
    _seen, external = _reachable_repo_modules()
    assert external, "the import scan found no third-party import at all"
    for name in sorted(external):
        assert name.lower().replace("_", "-") in text, f"{name} is imported but not installed in Dockerfile.security"
