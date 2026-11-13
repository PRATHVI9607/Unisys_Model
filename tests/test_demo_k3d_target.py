"""Guard the k3d setup entrypoint against implicit or cross-cluster targeting."""
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / "demo" / "k3d" / "up.ps1"


def test_up_requires_a_cluster_name_and_threads_that_name_to_every_cluster_target():
    source = UP.read_text(encoding="utf-8")
    assert "[Parameter(Mandatory = $true)]" in source
    assert "[string]$TargetCluster," in source
    assert '[string]$TargetCluster = "kubeheal"' not in source
    assert "TargetCluster is required; refusing to select a k3d cluster implicitly." in source
    assert '$script:ClusterName = $TargetCluster' in source
    assert '$script:Context = "k3d-$TargetCluster"' in source
    assert "cluster create $TargetCluster" in source
    assert "cluster start $TargetCluster" in source
    assert 'K label node "k3d-$TargetCluster-agent-0"' in source
    assert "cluster create kubeheal" not in source
    assert "cluster start kubeheal" not in source


def test_up_without_target_fails_during_parameter_binding_before_script_body():
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is unavailable; static target-routing assertions still run")
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(UP), "-Stage", "cluster"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "TargetCluster" in output
    assert "creating cluster" not in output
    assert "cluster start" not in output
