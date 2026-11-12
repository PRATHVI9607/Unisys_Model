"""V5-S5a: the Security Agent half of cgroup-freeze containment (agents/security_agent/containment.py).

No real cgroup anywhere: /proc and the cgroup root are temp directory trees, and a cgroup.events file is flipped
by a fake that stands in for the kernel. Redis is the in-memory fake of the P6 tests.
"""
import asyncio
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fake_redis import FakeRedis
from agents.security_agent import containment as ct
from agents.security_agent.proc_scanner import PodIndex
from redis.exceptions import ResponseError

NODE, OTHER_NODE = "node-a", "node-b"
UID = "5f2c1a9e-1111-4222-8333-444455556666"
OTHER_UID = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
AGENT_UID = "99999999-8888-4777-8666-555544443333"
CID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
REQ_ID = "0123456789abcdef0123456789abcdef"
NOW = 1_700_000_000.0
NL = chr(10)
POD_REL = f"kubepods/burstable/pod{UID}"
RESULT_FIELDS = {"status", "reason", "request_id", "incident_id", "namespace", "pod", "pod_uid", "node", "action",
                 "frozen", "mode_seen", "cgroup", "ts_ms"}


def run(coro):
    return asyncio.run(coro)


def make_pod(ns, name, uid, node):
    return NS(metadata=NS(namespace=ns, name=name, uid=uid, owner_references=[]),
              spec=NS(containers=[NS(name="app")], node_name=node))


class Scene:
    """A fake host: /proc, a cgroup root, a pod index, a mode and a writer spy that flips cgroup.events."""

    def __init__(self, tmp_path, proc_line=None, mode="enforce", pod_node=NODE, flip_after_polls=0, flips=True,
                 make_dir=True, protected=False, jumps=None, **cfg_over):
        self.proc, self.root = tmp_path / "proc", tmp_path / "cgroup"
        self.proc.mkdir()
        self.root.mkdir()
        line = proc_line if proc_line is not None else f"0::/{POD_REL}/{CID}\n"
        (self.proc / "101").mkdir()
        (self.proc / "101" / "cgroup").write_text(line)
        (self.proc / "999").mkdir()                       # a host process
        (self.proc / "999" / "cgroup").write_text("0::/system.slice/sshd.service\n")
        (self.proc / "self").mkdir()                      # the agent's own cgroup (another pod, besteffort)
        (self.proc / "self" / "cgroup").write_text(f"0::/kubepods/besteffort/pod{AGENT_UID}/{CID}\n")
        self.pod_dir = self.root / POD_REL
        if make_dir:
            (self.pod_dir / CID).mkdir(parents=True)
            (self.pod_dir / "cgroup.freeze").write_text("0")
            (self.pod_dir / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        self.index = PodIndex()
        self.index.update_from([make_pod("prod", "web-1", UID, pod_node)], {})
        self.mode = mode
        self.mode_calls = []
        self.writes = []
        self.polls = 0
        self.flips, self.flip_after_polls = flips, flip_after_polls
        self.t = 0.0
        self.now = NOW
        self.jumps = jumps or {}                          # mode call number -> seconds the clock moves forward
        self.protected = protected
        cfg_over.setdefault("own_pod_uid", AGENT_UID)
        self.cfg = ct.ContainmentConfig(node=NODE, proc_root=str(self.proc), cgroup_root=str(self.root),
                                        consumer="c1", **cfg_over)
        self.handler = ct.ContainmentHandler(self.cfg, self.index, self._mode_for, writer=self._writer,
                                             protected_for=self._protected_for,
                                             clock=lambda: self.now, monotonic=lambda: self.t, sleep=self._sleep)

    def _protected_for(self, namespace):
        if isinstance(self.protected, Exception):
            raise self.protected
        return self.protected

    def _mode_for(self, namespace):
        self.mode_calls.append(namespace)
        self.now += self.jumps.get(len(self.mode_calls), 0)
        m = self.mode
        if isinstance(m, Exception):
            raise m
        if callable(m):
            return m(len(self.mode_calls))
        return m

    def _set_frozen(self, value):
        (self.pod_dir / "cgroup.events").write_text(f"populated 1\nfrozen {value}\n")

    def _writer(self, directory, value, root):
        ct.write_cgroup_freeze(directory, value, root)      # the real writer, on the temp tree
        self.writes.append(value)
        if self.flips and self.flip_after_polls == 0:
            self._set_frozen(value)

    async def _sleep(self, seconds):
        self.polls += 1
        self.t += seconds
        if self.flips and self.writes and self.polls >= self.flip_after_polls:
            self._set_frozen(self.writes[-1])

    def freeze_file(self):
        return (self.pod_dir / "cgroup.freeze").read_text()

    def handle(self, **over):
        return run(self.handler.handle(req(**over)))


def req(**over):
    f = {"request_id": REQ_ID, "incident_id": "inc-1", "namespace": "prod", "pod": "web-1", "pod_uid": UID,
         "node": NODE, "action": "freeze", "label": "ransomware", "requested_by": "executor",
         "timestamp_ms": str(int(NOW * 1000))}
    f.update(over)
    return f


@pytest.fixture(autouse=True)
def _namespaces(monkeypatch):
    monkeypatch.setenv("EXEC_NAMESPACES", "prod,staging,dev")


def assert_untouched(s, result):
    assert s.writes == [] and s.freeze_file() == "0"
    assert result["frozen"] == "0"


# ---------------------------------------------------------------------------------------------------------
# validation matrix
# ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("over,reason", [
    ({"label": "suspicious"}, "label_not_allowed"),
    ({"label": "benign"}, "label_not_allowed"),
    ({"label": ""}, "label_not_allowed"),
    ({"label": "Ransomware "}, "label_not_allowed"),
    ({"action": "unfreeze"}, "bad_action"),
    ({"action": ""}, "bad_action"),
    ({"action": "thaw", "label": "ransomware"}, "label_not_allowed"),
    ({"requested_by": "fusion"}, "bad_requested_by"),
    ({"request_id": "xyz"}, "bad_request_id"),
    ({"request_id": REQ_ID.upper()}, "bad_request_id"),
    ({"request_id": REQ_ID[:-1]}, "bad_request_id"),
    ({"request_id": REQ_ID + chr(10)}, "bad_request_id"),
    ({"incident_id": "inc-1" + chr(10)}, "bad_incident_id"),
    ({"namespace": "prod" + chr(10)}, "bad_namespace"),
    ({"pod_uid": UID + chr(10)}, "bad_pod_uid"),
    ({"incident_id": ""}, "bad_incident_id"),
    ({"incident_id": "Inc_1"}, "bad_incident_id"),
    ({"incident_id": "a" * 64}, "bad_incident_id"),
    ({"namespace": "Prod"}, "bad_namespace"),
    ({"namespace": ""}, "bad_namespace"),
    ({"pod": "Web_1"}, "bad_pod"),
    ({"pod": ""}, "bad_pod"),
    ({"pod_uid": "not-a-uid"}, "bad_pod_uid"),
    ({"pod_uid": OTHER_UID}, "pod_uid_mismatch"),
    ({"node": OTHER_NODE}, "wrong_node"),
    ({"namespace": "kube-system"}, "namespace_not_allowed"),
    ({"namespace": "kubeheal"}, "namespace_not_allowed"),
    ({"namespace": "payments"}, "namespace_not_allowed"),
    ({"pod": "web-2"}, "pod_unknown"),
    ({"timestamp_ms": str(int((NOW - 31) * 1000))}, "expired"),
    ({"timestamp_ms": str(int((NOW + 3600) * 1000))}, "bad_timestamp"),
    ({"timestamp_ms": "soon"}, "bad_timestamp"),
    ({"timestamp_ms": ""}, "bad_timestamp"),
])
def test_validation_matrix_refuses_and_touches_nothing(tmp_path, over, reason):
    s = Scene(tmp_path)
    result = s.handle(**over)
    assert result["status"] == "refused", result
    assert result["reason"].startswith(reason), result
    assert_untouched(s, result)
    assert RESULT_FIELDS <= set(result)


def test_pod_on_another_node_is_refused(tmp_path):
    s = Scene(tmp_path, pod_node=OTHER_NODE)
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "wrong_node")
    assert_untouched(s, result)


def test_pod_without_node_information_is_refused(tmp_path):
    s = Scene(tmp_path, pod_node="")
    assert s.handle()["reason"] == "pod_node_unknown"


def test_request_exactly_at_the_ttl_is_still_served(tmp_path):
    s = Scene(tmp_path)
    assert s.handle(timestamp_ms=str(int((NOW - 30) * 1000)))["status"] == "frozen"


def test_ttl_comes_from_the_environment():
    cfg = ct.ContainmentConfig.from_env({"NODE_NAME": NODE, "CONTAIN_REQUEST_TTL_S": "5",
                                         "CONTAIN_FREEZE_VERIFY_S": "bad", "CGROUP_ROOT": "/x"})
    assert cfg.request_ttl_s == 5.0 and cfg.verify_s == ct.DEFAULT_VERIFY_S and cfg.cgroup_root == "/x"
    assert cfg.stream == f"kubeheal.contain.req:{NODE}"


def test_pod_index_carries_the_node_name():
    idx = PodIndex()
    idx.update_from([make_pod("prod", "web-1", UID, NODE), NS(metadata=NS(namespace="prod", name="x", uid="u2",
                                                              owner_references=[]), spec=None)], {})
    assert idx.lookup_pod("prod", "web-1").node == NODE
    assert idx.lookup_pod("prod", "x").node == ""


# ---------------------------------------------------------------------------------------------------------
# mode
# ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["test", "TEST", "", None, "garbage", RuntimeError("watcher down")])
def test_mode_test_or_unreadable_is_dry_run_and_writes_nothing(tmp_path, mode):
    s = Scene(tmp_path, mode=mode)
    result = s.handle()
    assert result["status"] == "dry_run" and result["mode_seen"] == "test"
    assert_untouched(s, result)


def test_thaw_works_in_test_mode_and_records_the_mode(tmp_path):
    s = Scene(tmp_path, mode="test")
    s._set_frozen(1)
    (s.pod_dir / "cgroup.freeze").write_text("1")
    result = s.handle(action="thaw", label="", requested_by="operator")
    assert result["status"] == "thawed" and result["frozen"] == "0" and result["mode_seen"] == "test"
    assert s.writes == ["0"] and s.freeze_file() == "0"


@pytest.mark.parametrize("mode", ["test", RuntimeError("watcher down"), None, ""])
def test_thaw_works_when_the_mode_is_test_or_unreadable(tmp_path, mode):
    s = Scene(tmp_path, mode=mode)
    s._set_frozen(1)
    result = s.handle(action="thaw", label="", requested_by="operator")
    assert result["status"] == "thawed" and result["mode_seen"] == "test", result


@pytest.mark.parametrize("mode", ["enforce", "test"])
def test_thaw_by_the_executor_is_refused(tmp_path, mode):
    s = Scene(tmp_path, mode=mode)
    s._set_frozen(1)
    result = s.handle(action="thaw", label="", requested_by="executor")
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "bad_requested_by")
    assert s.writes == []


def test_a_thaw_in_test_mode_still_passes_every_other_check(tmp_path):
    s = Scene(tmp_path, mode="test")
    for over, reason in (({"namespace": "kube-system"}, "namespace_not_allowed"), ({"pod_uid": OTHER_UID}, "pod_uid_mismatch"),
                         ({"node": OTHER_NODE}, "wrong_node"), ({"timestamp_ms": str(int((NOW - 31) * 1000))}, "expired")):
        result = s.handle(action="thaw", label="", requested_by="operator", **over)
        assert result["status"] == "refused" and result["reason"].startswith(reason), result
    assert s.writes == []


def test_freeze_in_test_mode_is_still_a_dry_run(tmp_path):
    s = Scene(tmp_path, mode="test")
    assert s.handle()["status"] == "dry_run" and s.writes == []


def test_mode_flipping_to_test_between_validation_and_write_writes_nothing(tmp_path):
    s = Scene(tmp_path, mode=lambda n: "enforce" if n == 1 else "test")
    result = s.handle()
    assert result["status"] == "dry_run" and result["mode_seen"] == "test"
    assert "before the write" in result["reason"]
    assert result["cgroup"] == POD_REL                  # the path was resolved, the write never happened
    assert_untouched(s, result)
    assert len(s.mode_calls) >= 2


def test_the_real_mode_watcher_is_used_global_absolute_label_only_stricter():
    from agents.common.killswitch import ModeWatcher
    w = ModeWatcher()
    assert w.mode_for("prod") == "test"                  # never read: fail safe
    w.apply_configmap(NS(data={"mode": "enforce"}))
    w.ns_readable = True
    assert w.mode_for("prod") == "enforce"
    w.apply_namespace(NS(metadata=NS(name="prod", labels={"kubeheal/mode": "test"})))
    assert w.mode_for("prod") == "test"


# ---------------------------------------------------------------------------------------------------------
# path safety
# ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("line,status,reason", [
    # a `.` or `..` after the first normal component is refused (only a LEADING run of `..` is allowed)
    (f"0::/x/../kubepods/burstable/pod{UID}/{CID}" + NL, "refused", "cgroup_path_mismatch"),
    (f"0::/../a/../pod{UID}/{CID}" + NL, "failed", "pod_pids_not_found"),          # anchored scan: not mapped
    (f"0::/./kubepods/burstable/pod{UID}/{CID}" + NL, "refused", "cgroup_path_mismatch"),
    (f"0::/kubepods/../../../etc/pod{UID}/{CID}" + NL, "failed", "pod_pids_not_found"),
    (f"12:memory:/kubepods/burstable/pod{UID}/{CID}" + NL, "failed", "cgroup_v1_not_supported"),
    (f"12:memory:/kubepods/burstable/pod{UID}/{CID}" + NL + f"11:cpu:/kubepods/burstable/pod{UID}/{CID}" + NL,
     "failed", "cgroup_v1_not_supported"),
    # the PID scan does not map another pod's uid to this pod: no process, no write
    (f"0::/kubepods/burstable/pod{OTHER_UID}/{CID}" + NL, "failed", "pod_pids_not_found"),
    (f"0::/../../pod{UID}/../x/{CID}" + NL, "failed", "pod_pids_not_found"),     # the scan does not map it
])
def test_path_safety(tmp_path, line, status, reason):
    s = Scene(tmp_path, proc_line=line)
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == (status, reason), result
    assert_untouched(s, result)


def test_pod_dir_name_takes_the_pod_component_never_its_parent_or_a_scope():
    us = UID.replace("-", "_")
    assert ct.pod_dir_name(f"/kubepods/burstable/pod{UID}/{CID}", UID) == f"pod{UID}"
    assert ct.pod_dir_name(f"/kubepods/burstable/pod{UID}/{CID}/sub", UID) == f"pod{UID}"
    assert ct.pod_dir_name(f"/../../pod{UID}/{CID}", UID) == f"pod{UID}"
    assert ct.pod_dir_name(f"/../../../burstable/pod{UID}/{CID}", UID) == f"pod{UID}"
    assert ct.pod_dir_name(f"/../../kubepods-pod{us}.slice/cri-containerd-{CID}.scope", UID) == f"kubepods-pod{us}.slice"
    assert ct.pod_dir_name(f"/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{us}.slice/x.scope", UID) \
        == f"kubepods-besteffort-pod{us}.slice"
    for path in (f"/kubepods/../x/pod{UID}", f"/a/./pod{UID}", f"/../a/../pod{UID}", "/", "", "/../..",
                 "/kubepods/burstable/podother/c", f"/kubepods/burstable/x{UID}/c", f"/kubepods/burstable/pod{UID}x/c"):
        with pytest.raises(ct._Refuse) as e:
            ct.pod_dir_name(path, UID)
        assert e.value.status == "refused" and e.value.reason.startswith("cgroup_path_mismatch"), path


def test_find_pod_dir_looks_only_at_the_six_known_places(tmp_path):
    root = str(tmp_path)
    name = f"pod{UID}"
    for rel in (("a", "kubepods", name), ("kubepods", "guaranteed", name), ("kubepods", "burstable", "x", name),
                ("kubepods.slice", "kubepods-guaranteed.slice", name), ("system.slice", name)):
        (tmp_path.joinpath(*rel)).mkdir(parents=True)
    with pytest.raises(ct._Refuse) as e:                  # no recursive walk: none of these places is one of the six
        ct.find_pod_dir(root, name)
    assert e.value.reason.startswith("cgroup_dir_missing")
    for rel in (("kubepods", name), ("kubepods", "burstable", name), ("kubepods", "besteffort", name),
                ("kubepods.slice", name), ("kubepods.slice", "kubepods-burstable.slice", name),
                ("kubepods.slice", "kubepods-besteffort.slice", name)):
        base = tmp_path / ("c_" + "_".join(rel[:-1]))
        base.joinpath(*rel).mkdir(parents=True)
        assert ct.find_pod_dir(str(base), name) == str(base.joinpath(*rel))


def test_hybrid_hierarchy_with_an_unrelated_v2_line_is_v1_not_supported(tmp_path):
    line = f"12:memory:/kubepods/burstable/pod{UID}/{CID}\n0::/\n"
    s = Scene(tmp_path, proc_line=line)
    result = s.handle()
    assert result["status"] == "failed" and result["reason"].startswith("cgroup_v1_not_supported")


def test_no_process_of_the_pod_is_failed_not_guessed(tmp_path):
    s = Scene(tmp_path)
    s.index.update_from([make_pod("prod", "web-1", OTHER_UID, NODE)], {})   # the pod's pids carry another uid
    result = s.handle(pod_uid=OTHER_UID)
    assert (result["status"], result["reason"].split(":")[0]) == ("failed", "pod_pids_not_found")
    assert s.writes == []


def test_missing_directory_is_refused(tmp_path):
    s = Scene(tmp_path, make_dir=False)
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_dir_missing")


def test_a_symlink_that_leaves_the_cgroup_root_is_refused(tmp_path):
    s = Scene(tmp_path, make_dir=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "cgroup.freeze").write_text("0")
    (s.root / "kubepods" / "burstable").mkdir(parents=True)
    try:
        os.symlink(outside, s.pod_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_path_mismatch")
    assert (outside / "cgroup.freeze").read_text() == "0"


def test_the_writer_itself_refuses_a_directory_outside_the_root(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "cgroup.freeze").write_text("0")
    with pytest.raises(ValueError):
        ct.write_cgroup_freeze(str(outside), "1", str(root))
    with pytest.raises(ValueError):
        ct.write_cgroup_freeze(str(root), "1", str(root))             # the root itself
    with pytest.raises(ValueError):
        ct.write_cgroup_freeze(str(root / ".." / "outside"), "1", str(root))
    pod = root / "kubepods" / "burstable" / f"pod{UID}"
    pod.mkdir(parents=True)
    with pytest.raises(ValueError):
        ct.write_cgroup_freeze(str(pod), "2", str(root))              # not 0 or 1
    with pytest.raises(FileNotFoundError):                            # opened without create: never makes a file
        ct.write_cgroup_freeze(str(pod), "1", str(root))
    assert not (pod / "cgroup.freeze").exists()
    assert (outside / "cgroup.freeze").read_text() == "0"


def test_the_pods_processes_naming_two_different_pod_directories_are_refused(tmp_path):
    s = Scene(tmp_path)
    us = UID.replace("-", "_")
    (s.proc / "102").mkdir()
    (s.proc / "102" / "cgroup").write_text(
        f"0::/../../kubepods-burstable-pod{us}.slice/cri-containerd-{CID}.scope" + NL)
    result = s.handle()
    assert result["status"] == "refused" and "different pod cgroups" in result["reason"]
    assert s.writes == []


def test_two_directories_with_the_pod_name_are_ambiguous(tmp_path):
    s = Scene(tmp_path)
    (s.root / "kubepods" / "besteffort" / f"pod{UID}").mkdir(parents=True)
    (s.root / "kubepods" / "besteffort" / f"pod{UID}" / "cgroup.freeze").write_text("0")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_path_ambiguous")
    assert s.writes == [] and s.freeze_file() == "0"


# ---------------------------------------------------------------------------------------------------------
# freeze and thaw against the fake tree
# ---------------------------------------------------------------------------------------------------------
def test_happy_path_cgroupfs_layout(tmp_path):
    s = Scene(tmp_path)
    result = s.handle()
    assert result["status"] == "frozen" and result["frozen"] == "1" and result["reason"] == ""
    assert result["mode_seen"] == "enforce" and result["cgroup"] == POD_REL
    assert (result["namespace"], result["pod"], result["pod_uid"], result["node"]) == ("prod", "web-1", UID, NODE)
    assert (result["request_id"], result["incident_id"], result["action"]) == (REQ_ID, "inc-1", "freeze")
    assert set(result) == RESULT_FIELDS and result["ts_ms"].isdigit()
    assert s.writes == ["1"] and s.freeze_file() == "1"


def test_happy_path_systemd_layout_with_underscore_uid(tmp_path):
    slice_path = (f"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID.replace('-', '_')}.slice")
    line = f"0::/{slice_path}/cri-containerd-{CID}.scope\n"
    s = Scene(tmp_path, proc_line=line, make_dir=False)
    pod_dir = s.root / slice_path
    (pod_dir / f"cri-containerd-{CID}.scope").mkdir(parents=True)
    (pod_dir / "cgroup.freeze").write_text("0")
    (pod_dir / "cgroup.events").write_text("frozen 0\n")
    s.pod_dir = pod_dir
    result = s.handle()
    assert result["status"] == "frozen" and result["cgroup"] == slice_path
    assert s.freeze_file() == "1"


def test_freeze_is_confirmed_by_polling_until_events_flip(tmp_path):
    s = Scene(tmp_path, flip_after_polls=3)
    result = s.handle()
    assert result["status"] == "frozen" and result["frozen"] == "1" and s.polls == 3


def test_freeze_not_confirmed_is_failed_and_never_thawed(tmp_path):
    s = Scene(tmp_path, flips=False, verify_s=5.0)
    result = s.handle()
    assert result["status"] == "failed" and result["reason"].startswith("freeze_not_confirmed")
    assert "not thawed" in result["reason"] and result["frozen"] == "0"
    assert s.writes == ["1"]                              # one write: no automatic thaw
    assert s.freeze_file() == "1"                         # the cgroup is left as it is
    assert s.t >= 5.0 and s.polls <= 60                   # bounded by CONTAIN_FREEZE_VERIFY_S


def test_write_error_is_failed_with_the_state_read_back(tmp_path):
    s = Scene(tmp_path)
    (s.pod_dir / "cgroup.freeze").unlink()               # a kernel without the control file
    result = s.handle()
    assert result["status"] == "failed" and result["reason"].startswith("cgroup_write_failed")
    assert result["frozen"] == "0" and s.writes == []


def test_thaw(tmp_path):
    s = Scene(tmp_path)
    s._set_frozen(1)
    (s.pod_dir / "cgroup.freeze").write_text("1")
    result = s.handle(action="thaw", label="", requested_by="operator")
    assert result["status"] == "thawed" and result["frozen"] == "0" and result["action"] == "thaw"
    assert s.writes == ["0"] and s.freeze_file() == "0"


def test_thaw_goes_through_the_same_validation(tmp_path):
    s = Scene(tmp_path)
    result = s.handle(action="thaw", label="", pod_uid=OTHER_UID, requested_by="operator")
    assert result["status"] == "refused" and s.writes == []
    result = s.handle(action="thaw", label="", namespace="kube-system", requested_by="operator")
    assert result["reason"].startswith("namespace_not_allowed") and s.writes == []


def test_thaw_not_confirmed_is_failed(tmp_path):
    s = Scene(tmp_path, flips=False)
    s._set_frozen(1)
    result = s.handle(action="thaw", label="", requested_by="operator")
    assert result["status"] == "failed" and result["reason"].startswith("thaw_not_confirmed")
    assert result["frozen"] == "1"


def test_exfiltration_also_freezes(tmp_path):
    s = Scene(tmp_path)
    assert s.handle(label="exfiltration")["status"] == "frozen"


# ---------------------------------------------------------------------------------------------------------
# review fixes: protected namespace, own pod, writer rules, surviving mutations, expired read-back, threads
# ---------------------------------------------------------------------------------------------------------
def test_a_freeze_in_a_protected_namespace_is_refused_but_a_thaw_is_not_blocked(tmp_path):
    s = Scene(tmp_path, protected=True)
    result = s.handle()
    assert result["status"] == "refused" and result["reason"].startswith("namespace_protected")
    assert s.writes == []
    s._set_frozen(1)
    assert s.handle(action="thaw", label="", requested_by="operator")["status"] == "thawed"


def test_an_unreadable_protected_label_fails_closed_for_a_freeze(tmp_path):
    s = Scene(tmp_path, protected=RuntimeError("labels unknown"))
    assert s.handle()["reason"].startswith("namespace_protected") and s.writes == []


def test_the_real_mode_watcher_protects_unknown_namespaces_and_labelled_ones():
    from agents.common.killswitch import ModeWatcher
    w = ModeWatcher()
    assert w.protected_for("prod") is True                # never loaded: fail closed
    w.ns_readable = True
    w.apply_namespace(NS(metadata=NS(name="prod", labels={})))
    w.apply_namespace(NS(metadata=NS(name="dev", labels={"kubeheal/protected": "true"})))
    assert (w.protected_for("prod"), w.protected_for("dev"), w.protected_for("nope")) == (False, True, True)


def test_the_service_hands_the_watchers_protected_check_to_the_handler():
    svc = ct.ContainmentService.from_env(FakeRedis(), PodIndex(), env={"NODE_NAME": NODE})
    assert svc.consumer.handler._protected_for == svc.mode.protected_for
    assert svc.consumer.handler._protected("prod") is True          # no data yet: protected


def test_a_freeze_of_the_agents_own_pod_is_refused(tmp_path):
    s = Scene(tmp_path)
    (s.proc / "self" / "cgroup").write_text(f"0::/{POD_REL}/{CID}\n")      # the agent runs in the target pod
    result = s.handle()
    assert result["status"] == "refused" and result["reason"].startswith("self_pod")
    assert s.writes == []


def test_refuse_own_pod_by_path_applies_only_to_a_normal_absolute_path_with_a_pod_uid(tmp_path):
    s = Scene(tmp_path)
    root = str(s.root)
    target = os.path.realpath(s.root / "kubepods" / "burstable" / f"pod{UID}")
    own = lambda path: (s.proc / "self" / "cgroup").write_text(path + chr(10))    # noqa: E731
    own(f"0::/kubepods/burstable/pod{UID}")                                       # equal
    with pytest.raises(ct._Refuse) as e:
        ct.refuse_own_pod(target, "x" * 36, str(s.proc), root)
    assert e.value.reason.startswith("self_pod")
    own(f"0::/kubepods/burstable/pod{UID}/{CID}/agent")                           # the target contains the agent
    with pytest.raises(ct._Refuse):
        ct.refuse_own_pod(target, "x" * 36, str(s.proc), root)
    ancestor = os.path.realpath(s.root / "kubepods" / "burstable")                # an ancestor of the agent
    own(f"0::/kubepods/burstable/pod{OTHER_UID}/{CID}")
    with pytest.raises(ct._Refuse):
        ct.refuse_own_pod(ancestor, OTHER_UID.replace("a", "b"), str(s.proc), root)
    own(f"0::/kubepods/besteffort/pod{AGENT_UID}/{CID}")                          # a sibling pod is fine
    ct.refuse_own_pod(target, UID, str(s.proc), root)
    own(f"0::/kubepods/besteffort/pod{AGENT_UID}/{CID}".replace("0::/", "0::/../../"))   # not placeable: skipped
    ct.refuse_own_pod(target, UID, str(s.proc), root)
    own("0::/")                                                                    # the real private namespace
    ct.refuse_own_pod(target, UID, str(s.proc), root)
    own("12:memory:/kubepods/besteffort/podx")                                    # no cgroup v2 line
    ct.refuse_own_pod(target, UID, str(s.proc), root)
    (s.proc / "self" / "cgroup").unlink()                                         # unreadable: POD_UID is the guard
    ct.refuse_own_pod(target, UID, str(s.proc), root)


def test_a_thaw_does_not_need_the_own_pod_check(tmp_path):
    s = Scene(tmp_path, own_pod_uid="")
    s._set_frozen(1)
    assert s.handle(action="thaw", label="", requested_by="operator")["status"] == "thawed"


def _tree(root, *parts):
    d = root.joinpath(*parts)
    d.mkdir(parents=True)
    (d / "cgroup.freeze").write_text("0")
    return d


def test_the_writer_refuses_qos_slices_kubepods_itself_and_paths_without_a_pod_uid(tmp_path):
    root = tmp_path / "root"
    uid_us = UID.replace("-", "_")
    bad = [
        _tree(root, "kubepods.slice", "kubepods-burstable.slice"),           # a QoS slice
        _tree(root, "kubepods", "burstable"),                                # a QoS directory
        _tree(root, "kubepods", "besteffort"),
        _tree(root, "kubepods", "guaranteed"),
        root / "kubepods.slice",                                             # kubepods itself
        root / "kubepods",
        _tree(root, f"pod{UID}"),                                            # a pod uid but no kubepods above it
        _tree(root, "system.slice", f"pod{UID}"),
        _tree(root, "kubepods", "burstable", "not-a-pod"),                   # below kubepods but no uid
        _tree(root, f"kubepods.slice-pod{UID}"),                             # looks similar, is not kubepods
    ]
    (root / "kubepods.slice" / "cgroup.freeze").write_text("0")
    (root / "kubepods" / "cgroup.freeze").write_text("0")
    for d in bad:
        with pytest.raises(ValueError):
            ct.write_cgroup_freeze(str(d), "1", str(root))
        assert (d / "cgroup.freeze").read_text() == "0", d
    outside = _tree(tmp_path, "elsewhere", "kubepods", f"pod{UID}")
    with pytest.raises(ValueError):
        ct.write_cgroup_freeze(str(outside), "1", str(root))                 # a pod path, but outside the root
    assert (outside / "cgroup.freeze").read_text() == "0"
    for good in (_tree(root, "kubepods", "burstable", f"pod{UID}"),
                 _tree(root, "kubepods.slice", "kubepods-burstable.slice", f"kubepods-burstable-pod{uid_us}.slice")):
        ct.write_cgroup_freeze(str(good), "1", str(root))
        assert (good / "cgroup.freeze").read_text() == "1"


def test_the_handler_turns_a_writer_refusal_into_a_refused_result(tmp_path):
    s = Scene(tmp_path)

    def refusing(directory, value, root):
        raise ValueError("not a pod directory")
    s.handler._writer = refusing
    result = s.handle()
    assert result["status"] == "refused" and result["reason"].startswith("cgroup_path_mismatch: writer refused")


def test_the_ttl_is_checked_again_right_before_the_write(tmp_path):
    s = Scene(tmp_path, jumps={2: 31})                    # the clock passes the 30 s TTL while the pod is looked up
    result = s.handle()
    assert result["status"] == "refused" and result["reason"] == "expired"
    assert result["cgroup"] == POD_REL and s.writes == [] and s.freeze_file() == "0"


def test_only_the_pids_of_the_requested_pod_are_used(tmp_path):
    s = Scene(tmp_path)
    (s.proc / "101" / "cgroup").write_text("0::/system.slice/sshd.service" + chr(10))       # web-1 has no pid now
    (s.proc / "102").mkdir()
    (s.proc / "102" / "cgroup").write_text(f"0::/kubepods/besteffort/pod{OTHER_UID}/{CID}" + chr(10))
    s.index.update_from([make_pod("prod", "web-1", UID, NODE), make_pod("prod", "web-2", OTHER_UID, NODE)], {})
    result = s.handle()                                   # web-2's pid must not be taken for web-1's
    assert (result["status"], result["reason"].split(":")[0]) == ("failed", "pod_pids_not_found")
    assert s.writes == []
    other = s.handle(pod="web-2", pod_uid=OTHER_UID)
    assert other["reason"].startswith("cgroup_dir_missing")           # its own pid was found, its directory is not


def test_resolve_refuses_a_directory_that_is_outside_the_root_or_the_root_itself(tmp_path, monkeypatch):
    s = Scene(tmp_path)
    outside = tmp_path / "outside" / f"pod{UID}"
    outside.mkdir(parents=True)
    monkeypatch.setattr(ct, "find_pod_dir", lambda root, name: os.path.realpath(str(outside)))
    with pytest.raises(ct._Refuse) as e:
        ct.resolve_pod_cgroup(s.index, "prod", "web-1", UID, str(s.proc), str(s.root))
    assert e.value.status == "refused" and "outside the cgroup root" in e.value.reason
    monkeypatch.setattr(ct, "find_pod_dir", lambda root, name: root)                       # the root itself
    with pytest.raises(ct._Refuse) as e:
        ct.resolve_pod_cgroup(s.index, "prod", "web-1", UID, str(s.proc), str(s.root))
    assert e.value.status == "refused"                       # the root itself is not the directory that was found


def test_an_expired_freeze_of_a_frozen_cgroup_is_failed_expired_but_frozen(tmp_path):
    s = Scene(tmp_path)
    s._set_frozen(1)                                      # an earlier attempt wrote the freeze, then the agent died
    result = s.handle(timestamp_ms=str(int((NOW - 31) * 1000)))
    assert (result["status"], result["reason"], result["frozen"]) == ("failed", "expired_but_frozen", "1")
    assert result["cgroup"] == POD_REL and s.writes == []


def test_an_expired_freeze_of_a_cgroup_that_is_not_frozen_stays_refused_expired(tmp_path):
    s = Scene(tmp_path)
    result = s.handle(timestamp_ms=str(int((NOW - 31) * 1000)))
    assert (result["status"], result["reason"], result["frozen"]) == ("refused", "expired", "0")


@pytest.mark.parametrize("over", [{"namespace": "kube-system"}, {"pod_uid": OTHER_UID}, {"label": "suspicious"},
                                  {"action": "thaw", "label": "", "requested_by": "operator"}])
def test_the_expired_read_back_only_happens_for_an_otherwise_valid_freeze(tmp_path, over):
    s = Scene(tmp_path)
    s._set_frozen(1)
    result = s.handle(timestamp_ms=str(int((NOW - 31) * 1000)), **over)
    assert result["status"] == "refused" and result["reason"] != "expired_but_frozen"
    assert result["frozen"] == "0"


def test_an_expired_freeze_with_an_unresolvable_cgroup_is_refused_expired(tmp_path):
    s = Scene(tmp_path, make_dir=False)
    result = s.handle(timestamp_ms=str(int((NOW - 31) * 1000)))
    assert (result["status"], result["reason"]) == ("refused", "expired")


def test_the_proc_scan_runs_in_a_worker_thread(tmp_path, monkeypatch):
    import threading
    s = Scene(tmp_path)
    seen = []
    real = ct.resolve_pod_cgroup
    monkeypatch.setattr(ct, "resolve_pod_cgroup", lambda *a, **k: (seen.append(threading.get_ident()), real(*a, **k))[1])
    main = []

    async def go():
        main.append(threading.get_ident())
        return await s.handler.handle(req())
    assert run(go())["status"] == "frozen"
    assert seen and seen[0] != main[0]


# ---------------------------------------------------------------------------------------------------------
# V5-S5c: the layouts a real k3d run showed (private cgroup namespace, relative paths with leading `..`)
# ---------------------------------------------------------------------------------------------------------
US = UID.replace("-", "_")


def real_scene(tmp_path, proc_line, rel_dir, **kw):
    """The agent sees itself as `0::/`; the target pod's pid shows the given relative path; the mount shows the node
    cgroup root with the pod directory at `rel_dir` (a tuple of components)."""
    s = Scene(tmp_path, proc_line=proc_line + NL, make_dir=False, **kw)
    (s.proc / "self" / "cgroup").write_text("0::/" + NL)
    (s.proc / "999" / "cgroup").write_text("0::/../../../../init" + NL)             # a node process
    s.pod_dir = s.root.joinpath(*rel_dir)
    s.ctr = s.pod_dir / (f"cri-containerd-{CID}.scope" if rel_dir[-1].endswith(".slice") else CID)
    s.ctr.mkdir(parents=True)
    (s.pod_dir / "cgroup.freeze").write_text("0")
    (s.pod_dir / "cgroup.events").write_text("populated 1" + NL + "frozen 0" + NL)
    return s


REAL = {
    "guaranteed": (f"0::/../../pod{UID}/{CID}", ("kubepods", f"pod{UID}")),
    "burstable": (f"0::/../../../burstable/pod{UID}/{CID}", ("kubepods", "burstable", f"pod{UID}")),
    "besteffort": (f"0::/../../../besteffort/pod{UID}/{CID}", ("kubepods", "besteffort", f"pod{UID}")),
    "systemd_guaranteed": (f"0::/../../kubepods-pod{US}.slice/cri-containerd-{CID}.scope",
                           ("kubepods.slice", f"kubepods-pod{US}.slice")),
    "systemd_burstable": (f"0::/../../../kubepods-burstable.slice/kubepods-burstable-pod{US}.slice/"
                          f"cri-containerd-{CID}.scope",
                          ("kubepods.slice", "kubepods-burstable.slice", f"kubepods-burstable-pod{US}.slice")),
    "systemd_besteffort": (f"0::/../../../kubepods-besteffort.slice/kubepods-besteffort-pod{US}.slice/"
                           f"cri-containerd-{CID}.scope",
                           ("kubepods.slice", "kubepods-besteffort.slice", f"kubepods-besteffort-pod{US}.slice")),
}


@pytest.mark.parametrize("kind", sorted(REAL))
def test_real_k3d_layouts_freeze_the_pod_directory_and_never_a_scope_or_a_qos_dir(tmp_path, kind):
    line, rel = REAL[kind]
    s = real_scene(tmp_path, line, rel)
    result = s.handle()
    assert result["status"] == "frozen" and result["frozen"] == "1", result
    assert result["cgroup"] == "/".join(rel)
    assert s.writes == ["1"] and s.freeze_file() == "1"
    assert not (s.ctr / "cgroup.freeze").exists()                    # the container scope was not touched
    for parent in s.pod_dir.parents:
        if parent == s.root:
            break
        assert not (parent / "cgroup.freeze").exists()                          # neither was a QoS dir or kubepods


@pytest.mark.parametrize("kind", sorted(REAL))
def test_real_k3d_layouts_thaw(tmp_path, kind):
    line, rel = REAL[kind]
    s = real_scene(tmp_path, line, rel)
    s._set_frozen(1)
    result = s.handle(action="thaw", label="", requested_by="operator")
    assert result["status"] == "thawed" and s.writes == ["0"]


def test_the_proc_scanner_maps_the_relative_forms_and_nothing_else():
    from agents.security_agent.proc_scanner import parse_cgroup_line
    cid12 = CID[:12]
    assert parse_cgroup_line(f"0::/../../pod{UID}/{CID}") == (UID, cid12)
    assert parse_cgroup_line(f"0::/../../../burstable/pod{UID}/{CID}") == (UID, cid12)
    assert parse_cgroup_line(f"0::/../../kubepods-pod{US}.slice/cri-containerd-{CID}.scope") == (UID, cid12)
    assert parse_cgroup_line(f"0::/../../../kubepods-burstable.slice/kubepods-burstable-pod{US}.slice/"
                             f"cri-containerd-{CID}.scope") == (UID, cid12)
    assert parse_cgroup_line(f"0::/kubepods/burstable/pod{UID}/{CID}") == (UID, cid12)       # the old forms still work
    for line in ("0::/", "0::/../../../../init", "0::/../../../../k3s", "0::/system.slice/sshd.service",
                 f"0::/../../podnot-a-uuid/{CID}", f"0::/../../xpod{UID}/{CID}"):
        assert parse_cgroup_line(line) is None, line


def test_a_crafted_dot_dot_in_the_middle_of_a_real_layout_is_never_frozen(tmp_path):
    line, rel = REAL["burstable"]
    s = real_scene(tmp_path, f"0::/../../../burstable/../pod{UID}/{CID}", rel)
    result = s.handle()
    assert result["status"] in ("refused", "failed") and s.writes == [] and s.freeze_file() == "0"
    for path in (f"/../../../burstable/../pod{UID}/{CID}", f"/../a/./pod{UID}/{CID}"):     # the second line of defence
        with pytest.raises(ct._Refuse) as e:
            ct.pod_dir_name(path, UID)
        assert e.value.reason.startswith("cgroup_path_mismatch: path has a dot component")


def test_the_name_comes_from_the_pod_uid_not_from_where_the_path_says_the_pod_is(tmp_path):
    # the only thing taken from /proc is the pod directory NAME; the place is found in the mounted tree
    s = real_scene(tmp_path, f"0::/../../../besteffort/pod{UID}/{CID}", ("kubepods", "burstable", f"pod{UID}"))
    assert s.handle()["status"] == "frozen"


def test_a_path_outside_the_kubelet_layout_is_not_mapped_to_the_pod(tmp_path):
    # the anchored relative forms: `/system.slice/pod<uid>/<cid>` (with or without leading `..`) is not a pod
    from agents.security_agent.proc_scanner import parse_cgroup_line
    for line in (f"0::/system.slice/pod{UID}/{CID}", f"0::/../../../system.slice/pod{UID}/{CID}",
                 f"0::/../../x/burstable/pod{UID}/{CID}"):
        assert parse_cgroup_line(line) is None, line
    s = real_scene(tmp_path, f"0::/system.slice/pod{UID}/{CID}", ("kubepods", f"pod{UID}"))
    result = s.handle()
    assert result["status"] == "failed" and result["reason"].startswith("pod_pids_not_found")
    assert s.writes == []


def test_the_pod_directory_must_hold_a_container_of_the_pod(tmp_path):
    line, rel = REAL["guaranteed"]
    s = real_scene(tmp_path, line, rel)
    s.ctr.rename(s.pod_dir / ("f" * 64))                                         # a container id nobody saw in /proc
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_container_missing")
    assert s.writes == [] and s.freeze_file() == "0"


def test_a_file_or_a_symlink_named_like_the_container_does_not_count(tmp_path):
    line, rel = REAL["guaranteed"]
    s = real_scene(tmp_path, line, rel)
    s.ctr.rmdir()
    s.ctr.write_text("not a directory")
    result = s.handle()
    assert result["reason"].startswith("cgroup_container_missing") and s.writes == []


def test_the_systemd_container_scope_is_matched_by_its_id(tmp_path):
    line, rel = REAL["systemd_guaranteed"]
    s = real_scene(tmp_path, line, rel)
    assert s.handle()["status"] == "frozen"
    (tmp_path / "bad").mkdir()
    s2 = real_scene(tmp_path / "bad", line, rel)
    s2.ctr.rename(s2.pod_dir / ("cri-containerd-" + "e" * 64 + ".scope"))
    assert s2.handle()["reason"].startswith("cgroup_container_missing")


def test_a_uid_inside_another_component_name_is_refused_as_an_unknown_form():
    with pytest.raises(ct._Refuse) as e:
        ct.pod_dir_name(f"/../../x-pod{UID}-y/{CID}", UID)
    assert "unknown form" in e.value.reason
    with pytest.raises(ct._Refuse) as e:
        ct.pod_dir_name(f"/../../pod{UID}x/{CID}", UID)
    assert "unknown form" in e.value.reason


def test_only_a_strict_lowercase_uuid_is_mapped_by_the_relative_form():
    from agents.security_agent.proc_scanner import parse_cgroup_line
    for bad in ("5F2C1A9E-1111-4222-8333-444455556666", "5f2c1a9e-1111-4222-8333-4444555566", "5f2c1a9e1111422283334444555566",
                "5f2c1a9e-1111-4222-8333-444455556666-1"):
        assert parse_cgroup_line(f"0::/../../pod{bad}/{CID}") is None, bad


def _fake_symlinks(monkeypatch, *names):
    """Report a symlink for any path whose last component is in `names` (real symlinks need rights on Windows)."""
    real = ct._kind
    monkeypatch.setattr(ct, "_kind", lambda path: "link" if os.path.basename(path) in names else real(path))


def test_a_symlink_named_like_the_pod_directory_is_refused_even_where_symlinks_cannot_be_made(tmp_path, monkeypatch):
    line, rel = REAL["guaranteed"]
    s = real_scene(tmp_path, line, rel)
    _fake_symlinks(monkeypatch, f"pod{UID}")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_path_mismatch")
    assert "symlink" in result["reason"] and s.writes == [] and s.freeze_file() == "0"


def test_an_intermediate_symlink_is_not_walked_even_where_symlinks_cannot_be_made(tmp_path, monkeypatch):
    line, rel = REAL["burstable"]
    s = real_scene(tmp_path, line, rel)
    _fake_symlinks(monkeypatch, "kubepods", "burstable")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_dir_missing")
    assert s.writes == [] and s.freeze_file() == "0"


def test_two_places_with_the_pod_name_are_ambiguous(tmp_path):
    line, rel = REAL["guaranteed"]
    s = real_scene(tmp_path, line, rel)
    (s.root / "kubepods.slice" / f"pod{UID}").mkdir(parents=True)
    (s.root / "kubepods.slice" / f"pod{UID}" / "cgroup.freeze").write_text("0")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_path_ambiguous")
    assert s.writes == []


def test_a_real_layout_pod_without_a_directory_in_the_mount_is_refused_cgroup_dir_missing(tmp_path):
    line, rel = REAL["burstable"]
    s = real_scene(tmp_path, line, rel)
    (s.pod_dir / "cgroup.freeze").unlink()
    import shutil as _sh
    _sh.rmtree(s.pod_dir)
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_dir_missing")


def test_a_symlink_named_like_the_pod_directory_is_refused_and_never_followed(tmp_path):
    line, rel = REAL["guaranteed"]
    s = real_scene(tmp_path, line, rel)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "cgroup.freeze").write_text("0")
    import shutil as _sh
    _sh.rmtree(s.pod_dir)
    try:
        os.symlink(outside, s.pod_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_path_mismatch")
    assert "symlink" in result["reason"] and (outside / "cgroup.freeze").read_text() == "0"


def test_a_symlinked_kubepods_directory_is_not_walked(tmp_path):
    line, rel = REAL["guaranteed"]
    s = real_scene(tmp_path, line, rel)
    elsewhere = tmp_path / "elsewhere"
    s.root.joinpath("kubepods").rename(elsewhere)
    try:
        os.symlink(elsewhere, s.root / "kubepods", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("refused", "cgroup_dir_missing")
    assert (elsewhere / f"pod{UID}" / "cgroup.freeze").read_text() == "0"


def test_the_agents_own_pod_uid_refuses_a_freeze(tmp_path):
    s = Scene(tmp_path, own_pod_uid=UID)
    result = s.handle()
    assert result["status"] == "refused" and result["reason"].startswith("self_pod")
    assert not result["reason"].startswith("self_pod_unknown") and s.writes == []


def test_the_agents_own_pod_name_in_its_namespace_refuses_a_freeze(tmp_path):
    s = Scene(tmp_path, own_pod_name="web-1", own_namespace="prod")
    assert s.handle()["reason"].startswith("self_pod")
    (tmp_path / "b").mkdir()
    s2 = Scene(tmp_path / "b", own_pod_name="web-1", own_namespace="dev")           # same name, other namespace
    assert s2.handle()["status"] == "frozen"


def test_without_pod_uid_the_consumer_starts_but_refuses_every_freeze(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        cfg = ct.ContainmentConfig.from_env({"NODE_NAME": NODE})
    assert cfg is not None and cfg.own_pod_uid == "" and "POD_UID" in caplog.text
    s = Scene(tmp_path, own_pod_uid="")
    for label in ("ransomware", "exfiltration"):
        result = s.handle(label=label)
        assert result["status"] == "refused" and result["reason"].startswith("self_pod_unknown"), result
    assert s.writes == []
    s.mode = "test"
    assert s.handle()["reason"].startswith("self_pod_unknown")                      # even in test mode: fail closed
    s._set_frozen(1)
    assert s.handle(action="thaw", label="", requested_by="operator")["status"] == "thawed"   # a thaw is unaffected


def test_pod_uid_and_pod_name_come_from_the_environment():
    cfg = ct.ContainmentConfig.from_env({"NODE_NAME": NODE, "POD_UID": AGENT_UID.upper(), "POD_NAME": "sa-1",
                                         "NAMESPACE": "kubeheal"})
    assert (cfg.own_pod_uid, cfg.own_pod_name, cfg.own_namespace) == (AGENT_UID, "sa-1", "kubeheal")
    assert ct.ContainmentConfig.from_env({"NODE_NAME": NODE, "POD_UID": "not-a-uid"}).own_pod_uid == ""


# ---------------------------------------------------------------------------------------------------------
# the Redis consumer
# ---------------------------------------------------------------------------------------------------------
class Redis(FakeRedis):
    """FakeRedis with a read log, an optional stop-after-ack hook and hash failure injection."""

    def __init__(self):
        super().__init__()
        self.read_streams, self.consumer, self.stop_after_acks, self.hset_fail = [], None, 1, None
        self.reads = 0
        self.hget_fail, self.hset_fail_keys, self.xack_fail_ids = {}, {}, set()   # key or id -> exception or flag

    async def hget(self, key, field):
        if key in self.hget_fail:
            raise self.hget_fail[key]
        return await super().hget(key, field)

    async def xreadgroup(self, group, consumer, streams, count=None, block=None):
        self.reads += 1
        assert self.reads < 500, "consumer loop did not stop"
        self.read_streams.extend(streams)
        return await super().xreadgroup(group, consumer, streams, count=count, block=block)

    async def hset(self, key, field=None, value=None, mapping=None):
        if key in self.hset_fail_keys:
            raise self.hset_fail_keys[key]
        if self.hset_fail is not None:
            exc, self.hset_fail = self.hset_fail, None
            raise exc
        return await super().hset(key, field, value, mapping)

    async def xack(self, stream, group, *ids):
        if self.xack_fail_ids & set(ids):
            raise ResponseError("NOGROUP injected")
        n = await super().xack(stream, group, *ids)
        if len(self.acked) >= self.stop_after_acks and self.consumer is not None:
            self.consumer.running = False
        return n


def make_consumer(s, metrics=None, redis=None):
    r = redis or Redis()
    r.sleeps = []

    async def sleeper(seconds):                       # the consumer's back-off: record it and let Redis recover
        r.sleeps.append(seconds)
        r.fail.clear()
    c = ct.ContainmentConsumer(r, s.handler, s.cfg, metrics, monotonic=lambda: s.t, sleep=sleeper)
    r.consumer = c
    return r, c


async def publish(r, **over):
    return await r.xadd(f"kubeheal.contain.req:{NODE}", req(**over))


def drain(r, c):
    async def go():
        c.running = True
        await c.run()
    run(go())


def test_consumer_answers_acks_and_expires_the_result(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    run(publish(r))
    drain(r, c)
    key = ct.RESULT_KEY_PREFIX + REQ_ID
    assert r.hashes[key]["status"] == "frozen" and r.hashes[key]["frozen"] == "1"
    assert set(r.hashes[key]) == RESULT_FIELDS
    assert r.expiry[key] == r.now + 300
    assert r.pending_ids(f"kubeheal.contain.req:{NODE}", "security-agent") == []
    assert len(r.acked) == 1 and s.freeze_file() == "1"


def test_consumer_counts_results_by_status(tmp_path):
    seen = []
    s = Scene(tmp_path)
    r, c = make_consumer(s, metrics=NS(record_action=lambda a, o: seen.append((a, o))))
    run(publish(r))
    drain(r, c)
    assert seen == [("cgroup_freeze", "frozen")]


def test_a_request_id_that_was_answered_is_acked_and_ignored(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    key = ct.RESULT_KEY_PREFIX + REQ_ID
    r.hashes[key] = {"status": "frozen", "frozen": "1", "request_id": REQ_ID}
    run(publish(r))
    drain(r, c)
    assert s.writes == [] and s.mode_calls == []
    assert r.hashes[key] == {"status": "frozen", "frozen": "1", "request_id": REQ_ID}
    assert len(r.acked) == 1


def test_an_expired_request_is_refused_by_the_consumer_and_acked(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    run(publish(r, timestamp_ms=str(int((NOW - 120) * 1000))))
    drain(r, c)
    res = r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]
    assert (res["status"], res["reason"]) == ("refused", "expired") and s.writes == []
    assert len(r.acked) == 1


def test_a_bad_but_safe_request_id_gets_a_refused_result_and_an_unsafe_one_is_dropped(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.stop_after_acks = 2
    run(publish(r, request_id="short-id"))
    run(publish(r, request_id="bad:key*id"))
    drain(r, c)
    assert r.hashes[ct.RESULT_KEY_PREFIX + "short-id"]["reason"] == "bad_request_id"
    assert not any("bad:key" in k for k in r.hashes) and len(r.acked) == 2


def test_a_handler_exception_becomes_a_failed_result(tmp_path):
    s = Scene(tmp_path)

    async def boom(f):
        raise RuntimeError("secret detail")
    s.handler.handle = boom
    r, c = make_consumer(s)
    run(publish(r))
    drain(r, c)
    res = r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]
    assert res["status"] == "failed" and res["reason"] == "internal_error: RuntimeError"
    assert RESULT_FIELDS <= set(res)


def test_a_node_never_reads_another_nodes_stream(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.stop_after_acks = 1
    run(r.xadd(f"kubeheal.contain.req:{OTHER_NODE}", req(node=OTHER_NODE, request_id="f" * 32)))
    run(publish(r))
    drain(r, c)
    assert set(r.read_streams) == {f"kubeheal.contain.req:{NODE}"}
    assert (f"kubeheal.contain.req:{OTHER_NODE}", "security-agent") not in r.groups
    assert ct.RESULT_KEY_PREFIX + "f" * 32 not in r.hashes
    assert ct.RESULT_KEY_PREFIX + REQ_ID in r.hashes


def test_the_consumer_survives_a_redis_error_and_backs_off(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.fail["xreadgroup"] = ConnectionError("redis went away")
    run(publish(r))
    drain(r, c)
    assert r.sleeps == [ct.BACKOFF_INITIAL_S]
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen"


def test_backoff_grows_and_is_capped(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    sleeps = r.sleeps

    async def sleeper(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 8:
            r.fail.clear()
    c._sleep = sleeper
    r.fail["xreadgroup"] = ConnectionError("down")
    run(publish(r))
    drain(r, c)
    assert sleeps[:5] == [1.0, 2.0, 4.0, 8.0, 16.0] and max(sleeps) == ct.BACKOFF_MAX_S


def test_no_ack_before_the_result_is_written_and_the_message_is_retried(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.hset_fail = ConnectionError("result write failed")
    run(publish(r))
    drain(r, c)
    # the first attempt froze and failed to write the result, nothing was acked; the retry answered from the
    # pending list, froze again (idempotent) and only then acked
    assert s.writes == ["1", "1"] and len(r.acked) == 1
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen"


def test_a_message_left_pending_by_a_dead_consumer_is_reclaimed_and_answered_expired(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    run(r.xgroup_create(s.cfg.stream, s.cfg.group, id="0", mkstream=True))
    run(publish(r, timestamp_ms=str(int((NOW - 120) * 1000))))
    run(r.xreadgroup(s.cfg.group, "dead-consumer", {s.cfg.stream: ">"}, count=10))
    assert len(r.pending_ids(s.cfg.stream, s.cfg.group)) == 1
    r.advance(120)                                        # idle for longer than the request TTL
    drain(r, c)
    res = r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]
    assert (res["status"], res["reason"]) == ("refused", "expired") and s.writes == []
    assert r.pending_ids(s.cfg.stream, s.cfg.group) == [] and len(r.acked) == 1


POISON_ID = "b" * 32


def poison_key():
    return ct.RESULT_KEY_PREFIX + POISON_ID


def test_a_wrongtype_poison_message_does_not_block_the_request_behind_it(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.stop_after_acks = 2
    r.hget_fail[poison_key()] = ResponseError("WRONGTYPE Operation against a key holding the wrong kind of value")
    run(publish(r, request_id=POISON_ID))
    run(publish(r))
    drain(r, c)
    res = r.hashes[poison_key()]
    assert (res["status"], res["reason"]) == ("failed", "poison") and RESULT_FIELDS <= set(res)
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen" and len(r.acked) == 2
    assert r.pending_ids(s.cfg.stream, s.cfg.group) == [] and s.writes == ["1"]     # the poison one never froze


def test_a_poison_message_whose_result_key_cannot_be_written_is_still_acked(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.stop_after_acks = 2
    r.hget_fail[poison_key()] = ResponseError("WRONGTYPE")
    r.hset_fail_keys[poison_key()] = ResponseError("WRONGTYPE")
    run(publish(r, request_id=POISON_ID))
    run(publish(r))
    drain(r, c)
    assert poison_key() not in r.hashes and len(r.acked) == 2
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen"


def test_a_message_that_keeps_raising_becomes_poison_after_the_chosen_number_of_attempts(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.stop_after_acks = 2
    calls = []

    real_hget = r.hget

    async def hget(key, field):
        if key == poison_key() and field == "status":
            calls.append(key)
            if len(calls) <= ct.MAX_DELIVERIES:                  # the three attempts of `process` all raise
                raise ConnectionError("always the same failure")
        return await real_hget(key, field)
    r.hget = hget
    run(publish(r, request_id=POISON_ID))
    run(publish(r))
    drain(r, c)
    assert r.hashes[poison_key()]["reason"] == "poison"
    assert len(r.sleeps) == ct.MAX_DELIVERIES                      # one back-off per failed attempt
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen" and len(r.acked) == 2


def test_a_message_delivered_too_often_is_poison_without_being_handled(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    run(r.xgroup_create(s.cfg.stream, s.cfg.group, id="0", mkstream=True))
    run(publish(r))
    run(r.xreadgroup(s.cfg.group, s.cfg.consumer, {s.cfg.stream: ">"}, count=10))
    for meta in r.groups[(s.cfg.stream, s.cfg.group)]["pending"].values():
        meta["times"] = ct.MAX_DELIVERIES + 1
    drain(r, c)
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["reason"] == "poison"
    assert s.writes == [] and len(r.acked) == 1


def test_a_failing_reclaim_never_blocks_new_requests(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    r.fail["xautoclaim"] = RuntimeError("xautoclaim not supported here")
    run(publish(r))
    drain(r, c)
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen" and r.sleeps == []


def test_an_entry_that_cannot_be_acked_is_not_read_again_and_again(tmp_path):
    s = Scene(tmp_path)
    r, c = make_consumer(s)
    run(r.xgroup_create(s.cfg.stream, s.cfg.group, id="0", mkstream=True))
    entry_id = run(publish(r, request_id=POISON_ID))
    run(r.xreadgroup(s.cfg.group, s.cfg.consumer, {s.cfg.stream: ">"}, count=10))   # ours, pending, never acked
    r.hget_fail[poison_key()] = ResponseError("WRONGTYPE")
    r.xack_fail_ids.add(entry_id)
    run(publish(r))                                                                 # new, behind the stuck one
    drain(r, c)                                                                     # (the read guard in Redis stops a loop)
    assert r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]["status"] == "frozen"
    assert r.pending_ids(s.cfg.stream, s.cfg.group) == [entry_id]


def test_a_reclaimed_expired_freeze_of_a_frozen_pod_is_failed_expired_but_frozen(tmp_path):
    s = Scene(tmp_path)
    s._set_frozen(1)
    r, c = make_consumer(s)
    run(r.xgroup_create(s.cfg.stream, s.cfg.group, id="0", mkstream=True))
    run(publish(r, timestamp_ms=str(int((NOW - 120) * 1000))))
    run(r.xreadgroup(s.cfg.group, "dead-consumer", {s.cfg.stream: ">"}, count=10))
    r.advance(120)
    drain(r, c)
    res = r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]
    assert (res["status"], res["reason"], res["frozen"]) == ("failed", "expired_but_frozen", "1")
    assert s.writes == [] and len(r.acked) == 1


def test_the_default_ttl_is_30_seconds_and_the_docstring_explains_why():
    assert ct.DEFAULT_REQUEST_TTL_S == 30.0
    cfg = ct.ContainmentConfig.from_env({"NODE_NAME": NODE})
    assert cfg.request_ttl_s == 30.0
    assert "CONTAIN_FREEZE_TIMEOUT_S" in ct.__doc__ and "expired_but_frozen" in ct.__doc__


# ---------------------------------------------------------------------------------------------------------
# start-up
# ---------------------------------------------------------------------------------------------------------
def test_without_node_name_the_consumer_does_not_start_and_says_so(caplog):
    with caplog.at_level(logging.WARNING):
        assert ct.ContainmentService.from_env(FakeRedis(), PodIndex(), env={}) is None
        assert ct.ContainmentService.from_env(FakeRedis(), PodIndex(), env={"NODE_NAME": "  "}) is None
        assert ct.ContainmentService.from_env(FakeRedis(), PodIndex(), env={"NODE_NAME": "Bad_Node"}) is None
    assert "NODE_NAME" in caplog.text


def test_service_with_node_name_reads_only_its_stream():
    svc = ct.ContainmentService.from_env(FakeRedis(), PodIndex(), env={"NODE_NAME": NODE, "HOSTNAME": "h1"})
    assert svc.consumer.cfg.stream == f"kubeheal.contain.req:{NODE}" and svc.consumer.cfg.consumer == "h1"
    assert svc.mode.mode_for("prod") == "test"            # no watcher data yet: fail safe


def test_the_security_agent_hook_is_wired_and_idle_without_node_name(monkeypatch):
    from agents.security_agent import agent as sec_agent
    assert "ContainmentService" in vars(sec_agent)
    monkeypatch.delenv("NODE_NAME", raising=False)
    a = sec_agent.SecurityAgent(redis_url="redis://localhost:1")
    assert a.containment is None                          # created only in start(), and only with NODE_NAME


def test_service_start_runs_the_consumer_and_stop_cancels_it(tmp_path):
    s = Scene(tmp_path)

    class Yielding(FakeRedis):                            # a real Redis read suspends the task; the fake does not
        async def xreadgroup(self, *a, **k):
            await asyncio.sleep(0)
            return await super().xreadgroup(*a, **k)
    r, c = make_consumer(s, redis=Yielding())
    svc = ct.ContainmentService(c, __import__("agents.common.killswitch", fromlist=["ModeWatcher"]).ModeWatcher())

    async def go():
        await svc.start(core_api=None)                    # the watcher fails on a missing API and stays in test
        run_task = svc._task
        await asyncio.sleep(0)
        await svc.stop()
        return run_task
    task = run(go())
    assert task.done() and c.running is False
    assert svc.mode.mode_for("prod") == "test"
