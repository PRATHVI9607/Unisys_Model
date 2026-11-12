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

NODE, OTHER_NODE = "node-a", "node-b"
UID = "5f2c1a9e-1111-4222-8333-444455556666"
OTHER_UID = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
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
                 make_dir=True, **cfg_over):
        self.proc, self.root = tmp_path / "proc", tmp_path / "cgroup"
        self.proc.mkdir()
        self.root.mkdir()
        line = proc_line if proc_line is not None else f"0::/{POD_REL}/{CID}\n"
        (self.proc / "101").mkdir()
        (self.proc / "101" / "cgroup").write_text(line)
        (self.proc / "999").mkdir()                       # a host process
        (self.proc / "999" / "cgroup").write_text("0::/system.slice/sshd.service\n")
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
        self.cfg = ct.ContainmentConfig(node=NODE, proc_root=str(self.proc), cgroup_root=str(self.root),
                                        consumer="c1", **cfg_over)
        self.handler = ct.ContainmentHandler(self.cfg, self.index, self._mode_for, writer=self._writer,
                                             clock=lambda: NOW, monotonic=lambda: self.t, sleep=self._sleep)

    def _mode_for(self, namespace):
        self.mode_calls.append(namespace)
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
    ({"timestamp_ms": str(int((NOW - 61) * 1000))}, "expired"),
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
    assert s.handle(timestamp_ms=str(int((NOW - 60) * 1000)))["status"] == "frozen"


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


def test_dry_run_also_covers_a_thaw(tmp_path):
    s = Scene(tmp_path, mode="test")
    assert s.handle(action="thaw", label="")["status"] == "dry_run"
    assert s.writes == []


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
    # the PID scan matches the tail of these lines, so they reach the path check, which refuses them
    (f"0::/x/../kubepods/burstable/pod{UID}/{CID}" + NL, "refused", "cgroup_path_mismatch"),
    (f"0::/../../kubepods/burstable/pod{UID}/{CID}" + NL, "refused", "cgroup_path_mismatch"),
    (f"0::/./kubepods/burstable/pod{UID}/{CID}" + NL, "refused", "cgroup_path_mismatch"),
    (f"0::/pod{UID}/kubepods/burstable/pod{UID}/{CID}" + NL, "refused", "cgroup_path_mismatch"),  # uid before kubepods
    (f"12:memory:/kubepods/burstable/pod{UID}/{CID}" + NL, "failed", "cgroup_v1_not_supported"),
    (f"12:memory:/kubepods/burstable/pod{UID}/{CID}" + NL + f"11:cpu:/kubepods/burstable/pod{UID}/{CID}" + NL,
     "failed", "cgroup_v1_not_supported"),
    # the PID scan itself does not map these lines to the pod: no process, no write
    (f"0::/kubepods/../../../etc/pod{UID}/{CID}" + NL, "failed", "pod_pids_not_found"),
    (f"0::/system.slice/pod{UID}/{CID}" + NL, "failed", "pod_pids_not_found"),                  # not under kubepods
    (f"0::/kubepods/burstable/pod{OTHER_UID}/{CID}" + NL, "failed", "pod_pids_not_found"),      # another pod's uid
])
def test_path_safety(tmp_path, line, status, reason):
    s = Scene(tmp_path, proc_line=line)
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == (status, reason), result
    assert_untouched(s, result)


def test_path_check_directly_refuses_dots_outside_kubepods_and_uid_mismatch():
    for path in (f"/kubepods/../x/pod{UID}", f"/etc/pod{UID}/c", "/kubepods/burstable/podother/c",
                 f"/pod{UID}/kubepods", "/", ""):
        with pytest.raises(ct._Refuse) as e:
            ct.pod_cgroup_components(path, UID)
        assert e.value.status == "refused" and e.value.reason.startswith("cgroup_path_mismatch")
    assert ct.pod_cgroup_components(f"/kubepods/burstable/pod{UID}/{CID}", UID) == ["kubepods", "burstable", f"pod{UID}"]
    assert ct.pod_cgroup_components(f"/kubepods/burstable/pod{UID}/{CID}/sub", UID)[-1] == f"pod{UID}"


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


def test_missing_directory_is_failed(tmp_path):
    s = Scene(tmp_path, make_dir=False)
    result = s.handle()
    assert (result["status"], result["reason"].split(":")[0]) == ("failed", "cgroup_dir_missing")


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
    (root / "pod").mkdir()
    with pytest.raises(ValueError):
        ct.write_cgroup_freeze(str(root / "pod"), "2", str(root))     # not 0 or 1
    with pytest.raises(FileNotFoundError):                            # opened without create: never makes a file
        ct.write_cgroup_freeze(str(root / "pod"), "1", str(root))
    assert not (root / "pod" / "cgroup.freeze").exists()
    assert (outside / "cgroup.freeze").read_text() == "0"


def test_two_pods_cgroups_for_one_pod_are_ambiguous(tmp_path):
    s = Scene(tmp_path)
    (s.proc / "102").mkdir()
    (s.proc / "102" / "cgroup").write_text(f"0::/kubepods/besteffort/pod{UID}/{CID}\n")
    result = s.handle()
    assert result["status"] == "refused" and "different pod cgroups" in result["reason"]
    assert s.writes == []


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
    result = s.handle(action="thaw", label="", pod_uid=OTHER_UID)
    assert result["status"] == "refused" and s.writes == []
    result = s.handle(action="thaw", label="", namespace="kube-system")
    assert result["reason"].startswith("namespace_not_allowed") and s.writes == []


def test_thaw_not_confirmed_is_failed(tmp_path):
    s = Scene(tmp_path, flips=False)
    s._set_frozen(1)
    result = s.handle(action="thaw", label="")
    assert result["status"] == "failed" and result["reason"].startswith("thaw_not_confirmed")
    assert result["frozen"] == "1"


def test_exfiltration_also_freezes(tmp_path):
    s = Scene(tmp_path)
    assert s.handle(label="exfiltration")["status"] == "frozen"


# ---------------------------------------------------------------------------------------------------------
# the Redis consumer
# ---------------------------------------------------------------------------------------------------------
class Redis(FakeRedis):
    """FakeRedis with a read log, an optional stop-after-ack hook and hash failure injection."""

    def __init__(self):
        super().__init__()
        self.read_streams, self.consumer, self.stop_after_acks, self.hset_fail = [], None, 1, None
        self.reads = 0

    async def xreadgroup(self, group, consumer, streams, count=None, block=None):
        self.reads += 1
        assert self.reads < 500, "consumer loop did not stop"
        self.read_streams.extend(streams)
        return await super().xreadgroup(group, consumer, streams, count=count, block=block)

    async def hset(self, key, field=None, value=None, mapping=None):
        if self.hset_fail is not None:
            exc, self.hset_fail = self.hset_fail, None
            raise exc
        return await super().hset(key, field, value, mapping)

    async def xack(self, stream, group, *ids):
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
    run(publish(r))
    run(r.xreadgroup(s.cfg.group, "dead-consumer", {s.cfg.stream: ">"}, count=10))
    r.advance(120)                                        # idle for longer than the request TTL
    drain(r, c)
    res = r.hashes[ct.RESULT_KEY_PREFIX + REQ_ID]
    assert res["status"] == "frozen" or res["reason"] == "expired"
    assert r.pending_ids(s.cfg.stream, s.cfg.group) == []


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


def test_the_security_agent_hook_starts_and_stops_the_service(monkeypatch):
    from agents.security_agent import agent as sec_agent
    assert "ContainmentService" in vars(sec_agent)
    monkeypatch.delenv("NODE_NAME", raising=False)
    a = sec_agent.SecurityAgent(redis_url="redis://localhost:1")
    assert a.containment is None                          # created only in start(), and only with NODE_NAME
