"""deploy/scripts/lib/guard.sh pins the verified context: later kubectl/helm calls cannot follow a context switch."""

import subprocess
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "deploy/scripts/lib/guard.sh"


def test_guard_pins_context_for_kubectl_and_helm_in_this_shell_and_children(tmp_path):
    log = tmp_path / "calls"
    # fake kubectl/helm: the current context is "minikube" on the first look and "prod" afterwards (someone ran use-context)
    (tmp_path / "kubectl").write_text(f"#!/bin/sh\necho \"kubectl $*\" >> {log}\n"
                                      f"[ \"$1 $2\" = 'config current-context' ] && {{ [ -e {tmp_path}/switched ] && echo prod || echo minikube; }}\nexit 0\n")
    (tmp_path / "helm").write_text(f"#!/bin/sh\necho \"helm $*\" >> {log}\n")
    for f in ("kubectl", "helm"):
        (tmp_path / f).chmod(0o755)
    child = tmp_path / "child.sh"
    child.write_text("kubectl get pods\n")
    script = f"source {GUARD}; kh_guard; touch {tmp_path}/switched; kubectl get ns; helm list; bash {child}"
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={"PATH": f"{tmp_path}:/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    calls = log.read_text().splitlines()
    assert "kubectl --context minikube get ns" in calls
    assert "helm --kube-context minikube list" in calls
    assert "kubectl --context minikube get pods" in calls   # the child bash script inherits the pin


def test_guard_script_prints_the_context_on_stdout(tmp_path):
    (tmp_path / "kubectl").write_text("#!/bin/sh\necho k3d-kubeheal\n")
    (tmp_path / "kubectl").chmod(0o755)
    r = subprocess.run(["bash", str(GUARD)], capture_output=True, text=True, env={"PATH": f"{tmp_path}:/usr/bin:/bin"})
    assert r.returncode == 0 and r.stdout.strip() == "k3d-kubeheal"
