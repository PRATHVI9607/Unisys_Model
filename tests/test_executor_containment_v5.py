"""V5-S5 (Executor half): containment order, the cgroup freeze request and its verified answer, the gap when the
freeze is not confirmed, and the scale to zero for an exfiltration containment.

The node-local Security Agent is simulated by a Redis whose `xadd` on the node stream answers like the agent would."""
import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import remediation_fakes as fk
from agents.executor import freeze as fz
from agents.executor import quarantine, snapshots
from agents.executor.config import ExecConfig
from agents.executor.ledger_guard import PROTECTIVE_STEPS
from agents.executor.support import ESCALATE_PREFIXES, Recorder
from agents.executor.validation import Request

INC = "inc-20261110-101500-ab12cd"
ENV = {"SNAPSHOT_CLASS": "csi-snap", "ROLLOUT_TIMEOUT_S": "50", "ROLLOUT_POLL_S": "5",
       "CONTAIN_FREEZE_TIMEOUT_S": "10"}
NODE, UID = "k3d-agent-0", "11111111-2222-3333-4444-555555555555"


def run(c):
    return asyncio.run(c)


class AgentRedis(fk.Redis):
    """Fake Redis with hashes, answering a freeze request the way the Security Agent does."""

    def __init__(self, answer="frozen", **overrides):
        super().__init__()
        self.hashes = {}
        self.answer, self.overrides = answer, overrides

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def xadd(self, s, f):
        await super().xadd(s, f)
        if s.startswith(fz.STREAM_PREFIX) and self.answer is not None:
            result = {"status": self.answer, "reason": "", "request_id": f["request_id"],
                      "incident_id": f["incident_id"], "namespace": f["namespace"], "pod": f["pod"],
                      "pod_uid": f["pod_uid"], "node": f["node"], "action": "freeze",
                      "frozen": "1" if self.answer == "frozen" else "0", "mode_seen": "enforce",
                      "cgroup": "kubepods.slice/pod-x", "ts_ms": "1"}
            result.update(self.overrides)
            self.hashes[fz.result_key(f["request_id"])] = result


class Scene:
    def __init__(self, label="ransomware", restore_after=True, answer="frozen", node=NODE, uid=UID, gate=None,
                 replicas=2, overrides=None, **more):
        self.c, self.clock = fk.Cluster(), fk.Clock()
        self.pod = fk.add_db_workload(self.c, replicas=replicas)
        pod = self.c.pods[self.pod]
        if node:
            pod["spec"]["nodeName"] = node
        if uid:
            pod["metadata"]["uid"] = uid
        self.redis = AgentRedis(answer, **{**(overrides or {}), **more})
        self.steps = []
        self.rec = Recorder(lambda i, s, p: self.steps.append(s), INC)
        self.gate = gate or fk.Gate()
        self.req = Request(action="contain", namespace="prod", incident_id=INC, deployment="db", pod=self.pod,
                           containment_label=label, restore_after=restore_after)

    def go(self):
        return run(quarantine.contain(self.gate, self.c.core, self.c.net, self.c.apps, self.c.custom, self.req,
                                      self.rec, ExecConfig(ENV), snapshots.SnapshotFreeze(self.redis),
                                      redis=self.redis, sleep=self.clock.sleep, clock=self.clock))

    def writes(self):
        return [e[1] for e in self.c.log]


# ---- the request and its verification ------------------------------------------------------------------
def test_the_request_goes_to_the_stream_of_the_pods_own_node():
    s = Scene()
    assert s.go() == "contained"
    (stream, fields), = [x for x in s.redis.added if x[0].startswith(fz.STREAM_PREFIX)]
    assert stream == f"kubeheal.contain.req:{NODE}"
    assert fields["pod_uid"] == UID and fields["node"] == NODE and fields["incident_id"] == INC
    assert fields["action"] == "freeze" and fields["label"] == "ransomware" and fields["requested_by"] == "executor"
    assert len(fields["request_id"]) == 32


def test_a_confirmed_freeze_comes_first_then_snapshot_then_quarantine_and_ransomware_does_not_scale():
    s = Scene(label="ransomware", restore_after=True)
    assert s.go() == "contained"
    assert s.steps.index("freeze_confirmed") < s.steps.index("forensic_snapshot_created") \
        < s.steps.index("quarantine_policy_created") < s.steps.index("pod_labelled")
    assert s.writes() == ["create_snapshot", "create_policy", "patch_pod"]      # no scale: the restore request does it


def test_an_exfiltration_containment_scales_the_owner_to_zero_and_remembers_the_replicas():
    s = Scene(label="exfiltration", restore_after=False, replicas=3)
    assert s.go() == "contained"
    dep = s.c.workloads[("Deployment", "db")]
    assert dep["metadata"]["annotations"]["kubeheal/original-replicas"] == "3"
    assert dep["spec"]["replicas"] == 0
    assert s.steps.index("pod_labelled") < s.steps.index("replicas_remembered") < s.steps.index("scaled_to_zero")


def test_an_existing_replica_annotation_is_not_overwritten():
    s = Scene(label="exfiltration", restore_after=False, replicas=3)
    s.c.workloads[("Deployment", "db")]["metadata"]["annotations"]["kubeheal/original-replicas"] = "5"
    assert s.go() == "contained"
    assert s.c.workloads[("Deployment", "db")]["metadata"]["annotations"]["kubeheal/original-replicas"] == "5"


# ---- freeze not confirmed: the chain goes on, the gap is reported, Fusion does not restore -------------------
@pytest.mark.parametrize("scene_kw,reason", [
    ({"answer": None}, "no_result_in_time"),
    ({"answer": "dry_run"}, "status_dry_run"),
    ({"answer": "refused", "reason": "cgroup_path_mismatch"}, "status_refused: cgroup_path_mismatch"),
    ({"answer": "failed", "reason": "freeze_not_confirmed"}, "status_failed: freeze_not_confirmed"),
    ({"answer": "frozen", "pod_uid": "someone-else"}, "result_mismatch:pod_uid"),
    ({"answer": "frozen", "overrides": {"node": "other-node"}}, "result_mismatch:node"),
    ({"answer": "frozen", "incident_id": "inc-other"}, "result_mismatch:incident_id"),
    ({"answer": "frozen", "frozen": "0"}, "status_frozen"),
])
def test_an_unconfirmed_freeze_is_a_gap_and_never_a_contained_outcome(scene_kw, reason):
    s = Scene(**scene_kw)
    out = s.go()
    assert out.startswith("contained_with_gaps:freeze_unconfirmed:" + reason), out
    assert out != "contained" and out.startswith(ESCALATE_PREFIXES)            # Fusion ignores it, a human is told
    assert s.writes() == ["create_snapshot", "create_policy", "patch_pod"]      # the other protective steps still ran
    assert "freeze_confirmed" not in s.steps and "freeze_unconfirmed" in s.steps


def test_a_pod_without_node_or_uid_cannot_be_frozen_and_is_a_gap():
    s = Scene(node="", uid="")
    assert s.go().startswith("contained_with_gaps:freeze_unconfirmed:pod_node_or_uid_unknown")
    assert not [x for x in s.redis.added if x[0].startswith(fz.STREAM_PREFIX)]


def test_the_wait_is_bounded_by_the_configured_timeout():
    s = Scene(answer=None)
    s.go()
    assert 9.0 <= sum(s.clock.sleeps) <= 12.0       # 10 s chosen default, polled every second


# ---- the kill switch and the other labels ------------------------------------------------------------------
def test_in_mode_test_no_freeze_request_is_sent_and_nothing_is_written():
    s = Scene(gate=fk.Gate(allow=0))
    out = s.go()
    assert out.startswith("DRY RUN: would have CONTAIN prod/db-abc-1")
    assert s.c.log == [] and s.redis.added == [] and s.redis.store == {}


def test_a_dry_run_blocks_first_even_when_the_pod_has_no_node():
    s = Scene(node="", uid="", gate=fk.Gate(allow=0))
    assert s.go().startswith("DRY RUN: would have CONTAIN")
    assert s.c.log == [] and s.redis.added == []


@pytest.mark.parametrize("label", ["", "suspicious", "benign", "weird"])
def test_only_the_two_automatic_labels_freeze_everything_else_keeps_the_old_behaviour(label):
    s = Scene(label=label, restore_after=False)
    assert s.go() == "contained"
    assert not [x for x in s.redis.added if x[0].startswith(fz.STREAM_PREFIX)]
    assert "freeze_skipped" in s.steps
    assert s.c.workloads[("Deployment", "db")]["spec"]["replicas"] == 2        # no scale either


def test_the_mode_flipping_after_the_freeze_stops_before_the_next_step():
    s = Scene(gate=fk.Gate(allow=1))          # the freeze request is write 1, the snapshot is refused
    out = s.go()
    assert out.startswith("stopped_mode_test") and s.c.log == []


# ---- units ---------------------------------------------------------------------------------------------
def test_request_freeze_is_a_protective_step_and_the_stream_name_is_per_node():
    assert "request_freeze" in PROTECTIVE_STEPS
    assert fz.request_stream("n1") == "kubeheal.contain.req:n1"
    assert fz.result_key("abc") == "kubeheal:contain:result:abc"
    assert fz.FREEZE_LABELS == {"ransomware", "exfiltration"}


def test_verify_result_accepts_only_a_frozen_one_with_matching_identity():
    good = {"status": "frozen", "frozen": "1", "request_id": "r", "pod_uid": "u"}
    assert fz.verify_result(good, {"request_id": "r", "pod_uid": "u"}) == ""
    assert fz.verify_result({}, {}) == "no_result"
    assert fz.verify_result({**good, "request_id": "x"}, {"request_id": "r"}) == "result_mismatch:request_id"
    assert fz.verify_result({"status": "frozen"}, {}).startswith("status_frozen")
    assert fz.verify_result({b"status".decode(): "refused", "reason": "expired"}, {}) == "status_refused: expired"


def test_the_executor_config_has_the_freeze_timeout_default_and_rejects_nonsense():
    assert ExecConfig({}, use_defaults=True).freeze_timeout_s == 10.0
    with pytest.raises(Exception):
        ExecConfig({"CONTAIN_FREEZE_TIMEOUT_S": "0"}).freeze_timeout_s


# ---- review fixes ---------------------------------------------------------------------------------------
class BrokenRedis(AgentRedis):
    def __init__(self, fail="xadd"):
        super().__init__()
        self.fail = fail

    async def xadd(self, s, f):
        if self.fail == "xadd" and s.startswith(fz.STREAM_PREFIX):
            raise ConnectionError("redis down")
        await super().xadd(s, f)

    async def hgetall(self, key):
        if self.fail == "hgetall":
            raise ConnectionError("redis down")
        return await super().hgetall(key)


@pytest.mark.parametrize("fail", ["xadd", "hgetall"])
def test_a_redis_error_on_the_freeze_is_a_gap_and_the_other_protective_steps_still_run(fail):
    s = Scene(answer=None)
    s.redis = BrokenRedis(fail)
    out = s.go()
    assert out.startswith("contained_with_gaps:freeze_unconfirmed:redis_error"), out
    assert s.writes() == ["create_snapshot", "create_policy", "patch_pod"]


def test_the_rolling_snapshots_are_frozen_right_after_the_freeze_not_only_at_the_end():
    s = Scene()
    s.go()
    assert s.steps.index("freeze_confirmed") < s.steps.index("rolling_snapshots_frozen") \
        < s.steps.index("forensic_snapshot_created")


def test_the_result_must_also_say_the_action_was_a_freeze():
    s = Scene(answer="frozen", overrides={"action": "thaw"})
    assert s.go().startswith("contained_with_gaps:freeze_unconfirmed:result_mismatch:action")

