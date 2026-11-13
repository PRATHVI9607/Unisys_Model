"""V5-S5a static guard: the freeze control file of a cgroup is named, and written, in exactly one place.

Scans agents/, dashboard/, kubeheal/, services/, scripts/, deploy/ and k8s/ (text files; docs and tests are not
scanned). Outside agents/security_agent/containment.py no file may name `cgroup.freeze` or another cgroup control
file that moves processes or changes limits (also when the name is built by string concatenation, a format or a
join, or written by a shell redirect or `tee` in a shell string, a shell script or a YAML command), and inside
that module every file-write call must sit inside the function `write_cgroup_freeze`. In shell and YAML a `#`
comment may name a file. Companion to tests/test_no_writes_outside_executor.py.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ["agents", "dashboard", "kubeheal", "services", "scripts", "deploy", "k8s"]
TEXT_SUFFIXES = {".py", ".js", ".ts", ".html", ".sh", ".bash", ".yaml", ".yml", ".json", ".lua", ".go", ".tpl", ".ps1"}
SKIP_PARTS = {"__pycache__", ".venv", "node_modules", ".pytest-tmp"}
OWNER = ROOT / "agents" / "security_agent" / "containment.py"
WRITER = "write_cgroup_freeze"

CONTROL_FILES = re.compile(
    r"(?<![\w.])(?:cgroup\.(?:freeze|kill|procs|threads|subtree_control|type|max\.depth|max\.descendants)"
    r"|pids\.max|memory\.(?:max|high|low|min|swap\.max)|cpu\.(?:max|weight)|io\.(?:max|weight))(?![\w])")
SHELL_WRITE = re.compile(r"(?:>>?|\btee\b(?:\s+-a)?)\s*[\"']?\S*cgroup")
SHELL_CALLS = {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
               "subprocess.check_output", "os.system", "os.popen", "asyncio.create_subprocess_shell"}
FRAGMENTS = re.compile(r"^\.?(?:freeze|kill|procs|threads|subtree_control|max|high|weight)$")
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


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.split("\n"))


def _mentions(text: str):
    return [m.group(0) for m in CONTROL_FILES.finditer(text)]


def fold(node):
    """The string a constant expression builds (concatenation, %, format, join, f-string), else None."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = fold(node.left), fold(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = fold(node.left)
        right = node.right
        items = [fold(e) for e in right.elts] if isinstance(right, (ast.Tuple, ast.List)) else [fold(right)]
        if left is None or None in items:
            return None
        try:
            return left % tuple(items)
        except (TypeError, ValueError):
            return None
    if isinstance(node, ast.JoinedStr):
        parts = [fold(v.value) if isinstance(v, ast.FormattedValue) else fold(v) for v in node.values]
        return "".join(parts) if None not in parts else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        base = fold(node.func.value)
        args = [fold(a) for a in node.args]
        if base is None or None in args:
            return None
        if node.func.attr == "format":
            try:
                return base.format(*args)
            except (IndexError, KeyError, ValueError):
                return None
        if node.func.attr == "join" and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
            items = [fold(e) for e in node.args[0].elts]
            return base.join(items) if None not in items else None
    return None


def python_findings(source: str):
    """Violations a Python file hides from a plain text search: built names, shell writes, name fragments."""
    out = []
    tree = ast.parse(source)
    consts = []
    docstrings = set()          # a docstring cannot write anything: it must not count as a "cgroup string"
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)                     and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        folded = fold(node) if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call, ast.Constant)) else None
        if folded:
            for m in _mentions(folded):
                out.append(f"line {node.lineno}: builds {m}")
            if isinstance(node, ast.Constant) and id(node) not in docstrings:
                consts.append(folded)
        if isinstance(node, ast.Call) and _dotted(node.func) in SHELL_CALLS and node.args:
            cmd = fold(node.args[0])
            if cmd and "cgroup" in cmd and SHELL_WRITE.search(cmd):
                out.append(f"line {node.lineno}: shell string writes a cgroup file")
    if any("cgroup" in c for c in consts) and any(FRAGMENTS.match(c) for c in consts):
        out.append("a cgroup string and a control file fragment sit in one module")
    if any(c.endswith("cgroup.") for c in consts):
        out.append("a string ends in 'cgroup.', a control file name is built from it")
    return out


def text_findings(text: str, suffix: str):
    """Violations in a non-Python file: control file names and shell redirects to cgroup paths (comments skipped)."""
    code = _strip_comments(text)
    out = [f"names {m}" for m in _mentions(code)]
    out += ["shell redirect or tee to a cgroup path" for _ in SHELL_WRITE.finditer(code)]
    return out


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
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix == ".py":
            hits = sorted(set(_mentions(text))) + python_findings(text)       # a .py file: comments count too
        else:
            hits = sorted(set(text_findings(text, p.suffix)))
        if hits:
            bad.append(f"{p.relative_to(ROOT)}: {hits}")
    assert not bad, "cgroup control files are named or written outside containment.py:\n" + "\n".join(bad)


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


def test_the_scan_covers_the_added_directories():
    assert {"scripts", "deploy", "k8s"} <= set(SCAN_DIRS)
    assert any(p.parts[len(ROOT.parts)] in ("deploy", "k8s", "scripts") for p in _files())


def test_detector_catches_built_names_shell_writes_other_control_files_and_yaml():
    built = ["p = 'cgroup.' + 'freeze'", "p = 'cgroup%s' % '.freeze'", "p = '{}.{}'.format('cgroup', 'freeze')",
             "p = ''.join(['cgroup', '.', 'kill'])", "p = f'cgroup.{x}'", "p = 'cgroup.' + name",
             "p = 'pids.' + 'max'", "p = 'memory.high'"]
    for src in built:
        assert python_findings(src) or _mentions(src), src
    shell = ["subprocess.run('echo 1 > /sys/fs/cgroup/x/foo', shell=True)",
             "os.system('echo ' + '1 | tee -a /sys/fs/cgroup/x/foo')"]
    for src in shell:
        assert any("shell string" in f for f in python_findings(src)), src
    for name in ("pids.max", "memory.max", "memory.high", "cpu.max", "cpu.weight", "cgroup.kill", "cgroup.procs",
                 "cgroup.subtree_control", "cgroup.freeze"):
        assert _mentions(f"echo 1 > /x/{name}") == [name], name
    assert text_findings("command: ['sh', '-c', 'echo 1 > /host/cgroup/x/cgroup.freeze']", ".yaml")
    assert text_findings("echo 100 > /sys/fs/cgroup/kubepods/foo", ".sh")                  # redirect to a cgroup path
    assert text_findings("echo 1 | tee /sys/fs/cgroup/x/y", ".sh")
    assert text_findings("# the Security Agent writes cgroup.freeze\nmountPath: /host/cgroup", ".yaml") == []
    assert python_findings("p = 'cgroup.events'\nx = 'populated'\n") == []
    assert python_findings("limits = {'memory': '1Gi'}\nprint(cgroup_root + '/io.stat')") == []


def test_the_detector_catches_violations(tmp_path):
    assert _mentions("open('/sys/fs/cgroup/x/cgroup.freeze', 'w')") == ["cgroup.freeze"]
    assert _mentions("p / 'cgroup.kill'") == ["cgroup.kill"]
    assert _mentions("cgroup.events and /proc/1/cgroup") == []
    src = ("def a(p):\n    open(p, 'w').write('1')\n    open(p, mode='ab')\n    open(p)\n"
           "    os.open(p, 1)\n    p.write_text('1')\n    p.open('w')\n")
    kinds = [w for _l, w, _f in write_calls(src)]
    assert kinds == [".write()", "open(write mode)", "open(write mode)", "os.open", ".write_text()", ".open(write mode)"]
    assert write_calls("def a(p):\n    return open(p).read()\n") == []
