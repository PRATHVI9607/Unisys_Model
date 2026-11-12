"""V5-S5a static guard: the freeze control file of a cgroup is named, and written, in exactly one place.

Scans agents/, dashboard/, kubeheal/ and services/ (text files, not tests). Outside
agents/security_agent/containment.py no file may contain the string `cgroup.freeze` (or name another cgroup
control file that moves processes or changes limits of a group), and inside that module every file-write call
must sit inside the function `write_cgroup_freeze`. Companion to tests/test_no_writes_outside_executor.py.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ["agents", "dashboard", "kubeheal", "services"]
TEXT_SUFFIXES = {".py", ".js", ".ts", ".html", ".sh", ".yaml", ".yml", ".json", ".md", ".txt", ".lua", ".go"}
SKIP_PARTS = {"__pycache__", ".venv", "node_modules", "_archive_v3", ".pytest-tmp"}
OWNER = ROOT / "agents" / "security_agent" / "containment.py"
WRITER = "write_cgroup_freeze"

CONTROL_FILES = re.compile(r"cgroup\.(freeze|kill|procs|threads|subtree_control|type|max\.depth|max\.descendants)")
WRITE_ATTRS = {"write_text", "write_bytes", "write", "writelines", "truncate", "unlink", "rename",
               "touch", "mkdir", "rmdir"}
WRITE_FUNCS = {"os.open", "os.write", "os.truncate", "os.remove", "os.unlink", "os.rename", "os.replace",
               "os.mkdir", "os.makedirs", "os.rmdir", "os.fdopen", "shutil.copy", "shutil.copyfile",
               "shutil.move", "shutil.rmtree", "shutil.copy2"}


def _files():
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in TEXT_SUFFIXES and not (set(p.parts) & SKIP_PARTS):
                yield p


def _mentions(text: str):
    return [m.group(0) for m in CONTROL_FILES.finditer(text)]


def _dotted(node) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return node.id if isinstance(node, ast.Name) else ""


def _open_mode_writes(call: ast.Call) -> bool:
    mode = None
    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
        mode = call.args[1].value
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    return isinstance(mode, str) and any(c in mode for c in "wax+")


def write_calls(source: str):
    """(line, description) of every call that can write a file, with the name of the enclosing function."""
    tree = ast.parse(source)
    out = []

    def visit(node, func):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else func
            if isinstance(child, ast.Call):
                name = _dotted(child.func)
                what = None
                if name in ("open", "io.open", "Path.open") and _open_mode_writes(child):
                    what = f"{name}(write mode)"
                elif name in WRITE_FUNCS:
                    what = name
                elif isinstance(child.func, ast.Attribute) and child.func.attr in WRITE_ATTRS:
                    what = f".{child.func.attr}()"
                elif isinstance(child.func, ast.Attribute) and child.func.attr == "open" \
                        and any(isinstance(a, ast.Constant) and isinstance(a.value, str) and any(c in a.value for c in "wax+")
                                for a in child.args):
                    what = ".open(write mode)"
                if what:
                    out.append((child.lineno, what, func))
            visit(child, inner)
    visit(tree, None)
    return out


def test_no_other_file_names_a_cgroup_control_file():
    bad = []
    for p in _files():
        if p == OWNER:
            continue
        hits = _mentions(p.read_text(encoding="utf-8", errors="replace"))
        if hits:
            bad.append(f"{p.relative_to(ROOT)}: {sorted(set(hits))}")
    assert not bad, "cgroup control files are named outside containment.py:\n" + "\n".join(bad)


def test_the_single_writer_is_the_only_write_in_containment_py():
    calls = write_calls(OWNER.read_text(encoding="utf-8"))
    outside = [(ln, what, fn) for ln, what, fn in calls if fn != WRITER]
    assert not outside, f"file writes outside {WRITER}: {outside}"
    inside = [what for _ln, what, fn in calls if fn == WRITER]
    assert sorted(inside) == ["os.open", "os.write"], inside      # one open (write only, no create) and one write


def test_the_freeze_file_name_appears_only_inside_the_writer_function():
    tree = ast.parse(OWNER.read_text(encoding="utf-8"))
    holders = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "cgroup.freeze" in node.value \
                    and node.value != ast.get_docstring(fn):
                holders.append(fn.name)
    assert set(holders) == {WRITER}, holders


def test_only_the_security_agent_module_imports_the_writer():
    bad = []
    for p in _files():
        if p.suffix == ".py" and p != OWNER and WRITER in p.read_text(encoding="utf-8", errors="replace"):
            bad.append(str(p.relative_to(ROOT)))
    assert not bad, f"{WRITER} referenced outside containment.py: {bad}"


def test_the_detector_catches_violations(tmp_path):
    assert _mentions("open('/sys/fs/cgroup/x/cgroup.freeze', 'w')") == ["cgroup.freeze"]
    assert _mentions("p / 'cgroup.kill'") == ["cgroup.kill"]
    assert _mentions("cgroup.events and /proc/1/cgroup") == []
    src = ("def a(p):\n    open(p, 'w').write('1')\n    open(p, mode='ab')\n    open(p)\n"
           "    os.open(p, 1)\n    p.write_text('1')\n    p.open('w')\n")
    kinds = [w for _l, w, _f in write_calls(src)]
    assert kinds == [".write()", "open(write mode)", "open(write mode)", "os.open", ".write_text()", ".open(write mode)"]
    assert write_calls("def a(p):\n    return open(p).read()\n") == []
