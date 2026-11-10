"""F6: the Security Agent maps PIDs to pods with proc_scanner (cgroups v1 and v2, any namespace)."""
import sys
from pathlib import Path
from types import SimpleNamespace as NS

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.security_agent import proc_scanner as ps
from agents.security_agent import agent as sec_agent

UID1 = "5f2c1a9e-1111-4222-8333-444455556666"
UID2 = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
CID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def make_pod(ns, name, uid, owner_kind=None, owner_name=None):
    owners = [NS(kind=owner_kind, name=owner_name)] if owner_kind else []
    return NS(metadata=NS(namespace=ns, name=name, uid=uid, owner_references=owners),
              spec=NS(containers=[NS(name="app")]))


def fixture_proc(tmp_path):
    (tmp_path / "101").mkdir()
    (tmp_path / "101" / "cgroup").write_text(f"0::/kubepods/burstable/pod{UID1}/{CID}\n")
    (tmp_path / "202").mkdir()   # systemd driver, uid with underscores
    (tmp_path / "202" / "cgroup").write_text(
        f"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID2.replace('-', '_')}.slice/"
        f"cri-containerd-{CID}.scope\n")
    (tmp_path / "303").mkdir()   # host process, not a pod
    (tmp_path / "303" / "cgroup").write_text("0::/system.slice/sshd.service\n")
    (tmp_path / "self").mkdir()  # non-numeric entries are ignored
    return str(tmp_path)


def build_index():
    idx = ps.PodIndex()
    idx.update_from(
        [make_pod("prod", "web-6d8f-abcde", UID1, "ReplicaSet", "web-6d8f"),
         make_pod("payments", "db-0", UID2, "StatefulSet", "db")],
        {("prod", "web-6d8f"): "web"})
    return idx


def test_cgroup_v1_and_v2_lines():
    assert ps.parse_cgroup_line(f"0::/kubepods/burstable/pod{UID1}/{CID}") == (UID1, CID[:12])
    v2 = (f"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"
          f"{UID2.replace('-', '_')}.slice/cri-containerd-{CID}.scope")
    assert ps.parse_cgroup_line(v2) == (UID2, CID[:12])
    assert ps.parse_cgroup_line("0::/system.slice/sshd.service") is None


def test_scan_maps_pids_in_any_namespace(tmp_path):
    root = fixture_proc(tmp_path)
    out = ps.scan_pids(build_index(), root)
    assert set(out) == {101, 202}
    assert out[101]["namespace"] == "prod" and out[101]["workload"] == "web"
    assert out[101]["workload_kind"] == "Deployment" and out[101]["pod"] == "web-6d8f-abcde"
    assert out[202]["namespace"] == "payments" and out[202]["workload"] == "db"
    assert out[202]["workload_kind"] == "StatefulSet"


def test_security_agent_uses_proc_scanner_not_its_own():
    assert not hasattr(sec_agent, "ProcessScanner")
    assert sec_agent.scan_pids is ps.scan_pids
    assert sec_agent.PodIndex is ps.PodIndex


def test_security_agent_cannot_act_on_its_own():
    src = Path(sec_agent.__file__).read_text(encoding="utf-8")
    for forbidden in ("_direct_kill", "os.kill", "create_namespaced_network_policy",
                      "_apply_network_isolation"):
        assert forbidden not in src
