import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.security_agent.proc_scanner import parse_cgroup_line

def test_cgroups_v1():
    r=parse_cgroup_line('10:memory:/kubepods/burstable/pod1234abcd-5678/abcdef1234567890')
    assert r==('1234abcd-5678','abcdef123456')

def test_cgroups_v2_containerd():
    r=parse_cgroup_line('0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234abcd_5678.slice/cri-containerd-fedcba0987654321.scope')
    assert r==('1234abcd-5678','fedcba098765')

def test_cgroups_v2_docker():
    r=parse_cgroup_line('0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaa11bb22.slice/docker-1122334455667788.scope')
    assert r==('aa11bb22','112233445566')

def test_non_kube_line():
    assert parse_cgroup_line('0::/system.slice/sshd.service') is None
