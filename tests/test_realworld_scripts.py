"""Offline checks of deploy/scripts/realworld/*: they parse, honour the cluster guard, touch only khe-rw-* namespaces,
clean up on exit, and a --dry-run never calls kubectl/helm/docker/k3d/git (a fake of each on PATH records any call)."""

import py_compile
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RW = ROOT / "deploy/scripts/realworld"
SH = ["soak.sh", "chaos.sh", "multinode.sh", "upgrade.sh"]
PY = ["rwlib.py", "soak.py", "scale.py"]
TOOLS = ("kubectl", "helm", "docker", "k3d", "git", "minikube")


@pytest.mark.parametrize("name", SH + ["lib.sh"])
def test_bash_syntax(name):
    assert subprocess.run(["bash", "-n", str(RW / name)], capture_output=True, text=True).returncode == 0


@pytest.mark.parametrize("name", PY)
def test_python_compiles(name, tmp_path):
    py_compile.compile(str(RW / name), cfile=str(tmp_path / "x.pyc"), doraise=True)


@pytest.mark.parametrize("name", SH)
def test_scripts_use_the_shared_guard_and_trap(name):
    assert 'source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"' in (RW / name).read_text()
    lib = (RW / "lib.sh").read_text()
    assert 'source "$ROOT/deploy/scripts/lib/guard.sh"' in lib and "kh_guard" in lib
    assert "trap rw_cleanup EXIT" in lib and "trap 'exit 130' INT TERM" in lib


def test_python_entry_points_run_the_guard():
    assert "guard.sh" in (RW / "rwlib.py").read_text() and "pin(" in (RW / "scale.py").read_text()
    assert "cleanup_all()" in (RW / "scale.py").read_text() and "finally:" in (RW / "scale.py").read_text()


@pytest.mark.parametrize("name", SH + PY + ["lib.sh"])
def test_only_khe_rw_namespaces_are_named(name):
    text = (RW / name).read_text()
    assert not re.findall(r"khe-(?!rw-)", text), "namespaces must start with khe-rw-"


def fake_path(tmp_path):
    bindir, log = tmp_path / "bin", tmp_path / "calls.log"
    bindir.mkdir()
    for t in TOOLS:
        (bindir / t).write_text(f'#!/bin/sh\necho "{t} $*" >> {log}\nexit 1\n')
        (bindir / t).chmod(0o755)
    return bindir, log


@pytest.mark.parametrize("cmd", [
    ["soak.sh", "--dry-run", "--hours", "0.01"],
    ["chaos.sh", "--dry-run"],
    ["multinode.sh", "--dry-run"],
    ["upgrade.sh", "--dry-run", "--from-ref", "HEAD~1", "--path", "both", "--wipe"],
    ["scale.py", "--dry-run"],
])
def test_dry_run_succeeds_without_touching_a_cluster(cmd, tmp_path, monkeypatch):
    bindir, log = fake_path(tmp_path)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.delenv("KH_CTX", raising=False)
    exe = ["python3", str(RW / cmd[0])] if cmd[0].endswith(".py") else ["bash", str(RW / cmd[0])]
    r = subprocess.run([*exe, *cmd[1:]], capture_output=True, text=True, timeout=120, cwd=tmp_path)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-800:]
    assert not log.exists(), log.read_text()   # no real kubectl/helm/docker/k3d/git call


def test_refusals_are_loud(tmp_path):
    r = subprocess.run(["bash", str(RW / "upgrade.sh"), "--dry-run"], capture_output=True, text=True)
    assert r.returncode != 0 and "--from-ref" in r.stderr
    r = subprocess.run(["bash", str(RW / "upgrade.sh"), "--dry-run", "--from-ref", "HEAD", "--path", "both"], capture_output=True, text=True)
    assert r.returncode != 0 and "--wipe" in r.stderr
    r = subprocess.run(["python3", str(RW / "scale.py"), "--dry-run", "--deployments", "5000"], capture_output=True, text=True)
    assert r.returncode != 0


@pytest.mark.parametrize("cmd", [["soak.sh"], ["chaos.sh"], ["multinode.sh"], ["upgrade.sh", "--from-ref", "HEAD"]])
def test_guard_refuses_a_non_lab_context_before_doing_anything(cmd, tmp_path, monkeypatch):
    bindir, log = fake_path(tmp_path)
    script = ("#!/bin/sh\n" f'echo "kubectl $*" >> {log}\n'
              '[ "$1 $2" = "config current-context" ] && { echo prod-eu-1; exit 0; }\nexit 1\n')
    (bindir / "kubectl").write_text(script)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    r = subprocess.run(["bash", str(RW / cmd[0]), *cmd[1:]], capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert r.returncode == 2 and "refusing" in r.stderr, r.stderr[-400:]
    assert set(log.read_text().splitlines()) == {"kubectl config current-context"}
