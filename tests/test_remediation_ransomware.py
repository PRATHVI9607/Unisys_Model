"""P7-RR-3 to RR-6: snapshots, quarantine, restore, entropy re-check (fake clients, no cluster)."""
import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import remediation_fakes as fk
from agents.executor import quarantine, restore, snapshots
from agents.executor.config import ExecConfig
from agents.executor.main import ACTIONS_STREAM, ESCALATIONS_STREAM, ExecutorService
from agents.executor.support import Recorder
from agents.executor.validation import Request

ENV = {"CANARY_WINDOW_S": "7", "ROLLOUT_TIMEOUT_S": "50", "ROLLOUT_POLL_S": "5", "SNAPSHOT_CLASS": "csi-snap"}
T0 = 2_000_000          # seconds; requests carry milliseconds
INC = "inc-20261110-101500-ab12cd"


def run(c):
    return asyncio.run(c)


def req(action="contain", pod="db-abc-1", deployment="db", **kw):
    return Request(action=action, namespace="prod", incident_id=INC, deployment=deployment, pod=pod,
                   t0_ms=kw.pop("t0_ms", T0 * 1000), **kw)


# ---- snapshot selection and the scheduler ---------------------------------------------------------------
def test_select_snapshot_is_newest_ready_rolling_strictly_before_t0():
    items = [
        fk.snapshot_obj("old", "db-data", T0 - 900),
        fk.snapshot_obj("best", "db-data", T0 - 300),
        fk.snapshot_obj("not-ready", "db-data", T0 - 100, ready=False),
        fk.snapshot_obj("forensic", "db-data", T0 - 50, kind="forensic"),
        fk.snapshot_obj("other-pvc", "other", T0 - 10),
        fk.snapshot_obj("at-t0", "db-data", T0),
        fk.snapshot_obj("after", "db-data", T0 + 300),
    ]
    assert snapshots.select_snapshot(items, "db-data", T0)["metadata"]["name"] == "best"
    assert snapshots.select_snapshot(items, "db-data", T0 - 1000) is None


def test_select_snapshot_uses_capture_time_not_object_creation_time():
    s = fk.snapshot_obj("late-object", "db-data", T0 - 300)
    s["metadata"]["creationTimestamp"] = fk.snapshot_obj("x", "p", T0 + 500)["metadata"]["creationTimestamp"]
    assert snapshots.select_snapshot([s], "db-data", T0) is not None
    s["status"].pop("creationTime")
    assert snapshots.select_snapshot([s], "db-data", T0) is None      # no capture time: never guessed


class Sched:
    def __init__(self, gate=None, frozen=(), namespaces=None, env=ENV):
        self.c, self.clock = fk.Cluster(), fk.Clock(start=5000.0)
        self.c.snapshot_clock = self.clock
        self.records = []
        self.c.pvcs["data"] = {"metadata": {"name": "data", "namespace": "prod"}, "status": {"phase": "Bound"}}
        self.c.pvcs["pending"] = {"metadata": {"name": "pending", "namespace": "prod"},
                                  "status": {"phase": "Pending"}}

        async def is_frozen(ns, pvc):
            return (ns, pvc) in frozen
        self.s = snapshots.SnapshotScheduler(
            self.c.core, self.c.custom, gate or fk.Gate(), namespaces=namespaces or ["prod"],
            cfg=ExecConfig(env), clock=self.clock, sleep=self.clock.sleep, is_frozen=is_frozen,
            record_step=lambda i, st, p: self.records.append(st))

    def seed(self, n, pvc="data", base=1000):
        for i in range(n):
            self.c.snapshots[f"seed-{pvc}-{i}"] = fk.snapshot_obj(f"seed-{pvc}-{i}", pvc, base + i * 300)


def test_plan_constants_are_the_documented_ones():
    assert snapshots.INTERVAL_S == 300 and snapshots.KEEP == 12


def test_scheduler_snapshots_bound_pvcs_and_keeps_the_newest_twelve():
    t = Sched()
    t.seed(12)
    t.c.snapshots["forensic-1"] = fk.snapshot_obj("forensic-1", "data", 10, kind="forensic")
    out = run(t.s.run_once())
    assert out["created"] == ["prod/kubeheal-roll-data-5000"]              # Pending PVC skipped
    assert out["deleted"] == ["prod/seed-data-0"]                          # the oldest rolling one
    rolling = [s for s in t.c.snapshots.values() if s["metadata"]["labels"]["kubeheal/snapshot-kind"] == "rolling"]
    assert len(rolling) == 12
    assert "forensic-1" in t.c.snapshots                                   # forensic is never pruned
    body = t.c.writes("create_snapshot")[0][3]
    assert body["spec"] == {"volumeSnapshotClassName": "csi-snap", "source": {"persistentVolumeClaimName": "data"}}


def test_scheduler_does_not_prune_below_twelve():
    t = Sched()
    t.seed(5)
    out = run(t.s.run_once())
    assert out["deleted"] == [] and len(t.c.snapshots) == 6


def test_scheduler_loop_uses_the_injected_clock_every_300_seconds():
    t = Sched()
    runs = []

    async def sleep(s):
        runs.append(s)
        t.clock.now += s
        if len(runs) == 3:
            t.s.stop()
    t.s.sleep = sleep
    run(t.s.run_forever())
    assert runs == [300.0, 300.0, 300.0]
    assert sorted(t.c.snapshots) == ["kubeheal-roll-data-5000", "kubeheal-roll-data-5300", "kubeheal-roll-data-5600"]


def test_scheduler_in_test_mode_writes_nothing():
    t = Sched(gate=fk.Gate(allow=0))
    t.seed(12)
    out = run(t.s.run_once())
    assert out["created"] == [] and t.c.writes() == [] and "dry_run" in " ".join(t.records)
    assert out["skipped"][0].split(":", 1)[1].startswith("DRY RUN: would have created snapshot")


def test_scheduler_skips_frozen_pvcs_and_never_prunes_them():
    t = Sched(frozen={("prod", "data")})
    t.seed(14)
    out = run(t.s.run_once())
    assert out["created"] == [] and out["deleted"] == [] and out["skipped"] == ["prod/data:frozen"]


def test_scheduler_needs_the_snapshot_class_and_stays_in_protected_namespaces():
    t = Sched(env={})
    out = run(t.s.run_once())
    assert out["created"] == [] and out["skipped"] == ["config:SNAPSHOT_CLASS"] and t.c.writes() == []
    from agents.executor.guard import allowed_namespaces
    assert "kube-system" not in allowed_namespaces() and "kubeheal" not in allowed_namespaces()
    assert snapshots.SnapshotScheduler(None, None, None)._namespaces() == sorted(allowed_namespaces())


# ---- quarantine -----------------------------------------------------------------------------------------
def contain_env(**kw):
    c = fk.Cluster()
    pod = fk.add_db_workload(c)
    rec_list = []
    rec = Recorder(lambda i, s, p: rec_list.append(s), INC)
    redis = fk.Redis()
    return c, pod, rec, rec_list, redis


def do_contain(c, rec, redis, gate=None, env=ENV, **kw):
    return run(quarantine.contain(gate or fk.Gate(), c.core, c.net, c.apps, c.custom, req(**kw), rec,
                                  ExecConfig(env), snapshots.SnapshotFreeze(redis)))


def test_quarantine_policy_selects_only_the_labelled_pod_and_denies_both_directions():
    p = quarantine.quarantine_policy(INC)
    assert p["spec"]["podSelector"] == {"matchLabels": {"kubeheal/quarantine": "true", "kubeheal/incident": INC}}
    assert p["spec"]["podSelector"] != {}
    assert set(p["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    assert "ingress" not in p["spec"] and "egress" not in p["spec"]


def test_contain_quarantines_labels_snapshots_and_freezes_in_order():
    c, pod, rec, steps, redis = contain_env()
    assert do_contain(c, rec, redis) == "contained"
    assert [e[1] for e in c.log] == ["create_policy", "patch_pod", "create_snapshot"]
    assert c.pods[pod]["metadata"]["labels"]["kubeheal/quarantine"] == "true"
    assert c.pods[pod]["metadata"]["labels"]["kubeheal/incident"] == INC
    snap = c.log[2][3]
    assert snap["metadata"]["labels"]["kubeheal/snapshot-kind"] == "forensic"
    assert snap["spec"]["source"]["persistentVolumeClaimName"] == "db-data"
    assert redis.store["kubeheal:snapfreeze:prod:db-data"] == INC            # rolling snapshots frozen
    assert not [e for e in c.log if "delete" in e[1]]                        # the pod is NOT deleted
    assert steps[:3] == ["quarantine_policy_created", "pod_labelled", "rolling_snapshots_frozen"]


def test_contain_dry_run_writes_nothing():
    c, pod, rec, steps, redis = contain_env()
    out = do_contain(c, rec, redis, gate=fk.Gate(allow=0))
    assert out.startswith("DRY RUN: would have CONTAIN prod/db-abc-1") and c.log == [] and redis.store == {}


@pytest.mark.parametrize("allow,written", [(1, ["create_policy"]), (2, ["create_policy", "patch_pod"])])
def test_contain_stops_when_the_mode_flips_mid_action(allow, written):
    c, pod, rec, steps, redis = contain_env()
    out = do_contain(c, rec, redis, gate=fk.Gate(allow=allow))
    assert out.startswith("stopped_mode_test")
    assert [e[1] for e in c.log] == written


def test_contain_refuses_a_pod_the_workload_does_not_own():
    c, pod, rec, steps, redis = contain_env()
    fk.add_db_workload(c, name="other", claim="other-data", pod="other-xyz-1")
    out = do_contain(c, rec, redis, deployment="other", pod="db-abc-1")
    assert out.startswith("contain_failed:pod db-abc-1 is not owned")
    assert "kubeheal/quarantine" not in c.pods["db-abc-1"]["metadata"]["labels"]
    assert "patch_pod" not in [e[1] for e in c.log]


def test_contain_without_snapshot_class_still_isolates_and_reports_the_gap():
    c, pod, rec, steps, redis = contain_env()
    out = do_contain(c, rec, redis, env={})
    assert out.startswith("contained_with_gaps:forensic snapshot: SNAPSHOT_CLASS not set")
    assert [e[1] for e in c.log] == ["create_policy", "patch_pod"]


def test_contain_tolerates_an_existing_policy():
    c, pod, rec, steps, redis = contain_env()
    assert do_contain(c, rec, redis) == "contained"
    assert do_contain(c, rec, redis) == "contained"          # second request: policy and snapshot exist


# ---- restore ----------------------------------------------------------------------------------------------
class R:
    def __init__(self, kind="Deployment", env=ENV, vct=False, digest=fk.DIGEST, entropy=True, gate=None,
                 replicas=1, seed_snapshots=True, freeze_old=True):
        self.c, self.clock, self.redis = fk.Cluster(), fk.Clock(), fk.Redis()
        self.pod = fk.add_db_workload(self.c, kind=kind, vct=vct, digest=digest, replicas=replicas)
        self.kind, self.env, self.gate = kind, env, gate or fk.Gate()
        self.steps = []
        self.rec = Recorder(lambda i, s, p: self.steps.append(s), INC)
        if seed_snapshots:
            for n, off, kw in [("s-900", 900, {}), ("s-300", 300, {}), ("s-100-notready", 100, {"ready": False}),
                               ("s-forensic", 50, {"kind": "forensic"})]:
                self.c.snapshots[n] = fk.snapshot_obj(n, "db-data", T0 - off, **kw)
            self.c.snapshots["s-after"] = fk.snapshot_obj("s-after", "db-data", T0 + 300)
        if freeze_old:
            self.redis.store["kubeheal:snapfreeze:prod:db-data"] = INC
        self.entropy_calls = []
        self._verdict = entropy

        async def check(ns, wl, pvcs):
            self.entropy_calls.append((ns, wl, pvcs))
            if isinstance(self._verdict, Exception):
                raise self._verdict
            return self._verdict
        self.entropy = None if entropy == "no-callable" else check

    def go(self, **kw):
        r = req("restore", kind=self.kind, **kw)
        return run(restore.restore(self.gate, self.c.core, self.c.apps, self.c.net, self.c.custom, r, self.rec,
                                   ExecConfig(self.env), snapshots.SnapshotFreeze(self.redis), self.entropy,
                                   self.clock.sleep, self.clock))

    def methods(self):
        return [e[1] for e in self.c.log]

    def wl(self):
        return self.c.workloads[(self.kind, "db")]


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet"])
def test_restore_full_path_in_order(kind):
    r = R(kind=kind)
    assert r.go() == "restored"
    assert r.methods() == ["create_policy", f"patch_{kind}", f"scale_{kind}", "create_pvc", f"patch_{kind}",
                           f"scale_{kind}", f"patch_{kind}", "delete_policy"]
    # remembered the replica count, then scaled to zero, then back to it
    assert r.c.log[1][3] == {"metadata": {"annotations": {"kubeheal/original-replicas": "1"}}}
    assert (r.c.log[2][3], r.c.log[5][3]) == (0, 1)
    # new PVC from the newest ready rolling snapshot before T0 (not forensic, not after, not unready)
    pvc = r.c.log[3][3]
    assert pvc["metadata"]["name"] == f"db-data-restore-{INC}"
    assert pvc["spec"]["dataSource"] == {"name": "s-300", "kind": "VolumeSnapshot",
                                         "apiGroup": "snapshot.storage.k8s.io"}
    assert pvc["spec"]["storageClassName"] == "local-path" and pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert pvc["spec"]["resources"]["requests"]["storage"] == "1Gi"
    # workload repointed, image pinned by digest, pods start quarantined
    pod_spec = r.wl()["spec"]["template"]["spec"]
    assert pod_spec["volumes"][0]["persistentVolumeClaim"]["claimName"] == f"db-data-restore-{INC}"
    assert pod_spec["containers"][0]["image"] == "reg:5000/db@" + fk.DIGEST
    repoint = r.c.log[4][3]["spec"]["template"]["metadata"]["labels"]
    assert repoint == {"kubeheal/quarantine": "true", "kubeheal/incident": INC}
    # clean entropy: quarantine lifted, policy removed, replicas restored, evidence untouched
    assert "kubeheal/quarantine" not in r.wl()["spec"]["template"]["metadata"]["labels"]
    assert r.c.policies == {} and r.wl()["spec"]["replicas"] == 1
    assert r.entropy_calls == [("prod", "db", [f"db-data-restore-{INC}"])]
    assert "db-data" in r.c.pvcs and r.redis.store.get("kubeheal:snapfreeze:prod:db-data") == INC
    assert f"kubeheal:snapfreeze:prod:db-data-restore-{INC}" not in r.redis.store


@pytest.mark.parametrize("verdict,reason", [(False, "entropy still high"), (None, "unknown"),
                                            (RuntimeError("boom"), "unknown"), ("no-callable", "unknown")])
def test_restore_keeps_isolation_unless_entropy_is_clean(verdict, reason):
    r = R(entropy=verdict)
    out = r.go()
    assert out.startswith("restored_kept_isolated:") and reason in out
    assert "delete_policy" not in r.methods()
    assert r.c.policies                                                        # still isolated
    assert r.wl()["spec"]["template"]["metadata"]["labels"]["kubeheal/quarantine"] == "true"
    assert r.redis.store[f"kubeheal:snapfreeze:prod:db-data-restore-{INC}"] == INC   # new PVC stays frozen


def test_restore_restored_pods_not_ready_keeps_isolation():
    r = R()
    orig = r.c.apps._scale

    def stuck_scale(kind, name, body):
        orig(kind, name, body)
        if body["spec"]["replicas"] > 0:
            r.wl()["status"]["readyReplicas"] = 0
    r.c.apps._scale = stuck_scale
    assert r.go().startswith("restored_kept_isolated:restored pods not ready")
    assert r.entropy_calls == []


def test_restore_without_t0_escalates_and_never_guesses():
    ex = ExecutorService(redis=fk.Redis(), core_api=fk.Cluster().core, mode=fk.Mode())
    out = run(ex.execute({"action": "restore", "namespace": "prod", "deployment": "db", "pod": "db-abc-1",
                          "incident_id": INC}))
    assert out.startswith("escalated:t0_missing")


def test_restore_with_no_snapshot_before_t0_escalates_without_any_write():
    r = R()
    out = r.go(t0_ms=(T0 - 1000) * 1000)
    assert out.startswith("escalated:no_snapshot_before_t0") and r.c.log == []


def test_restore_in_test_mode_has_taken_no_rolling_snapshots_so_it_escalates():
    r = R(seed_snapshots=False)
    assert r.go().startswith("escalated:no_snapshot_before_t0") and r.c.log == []


def test_restore_statefulset_volume_claim_template_escalates_before_writing():
    r = R(kind="StatefulSet", vct=True)
    out = r.go()
    assert out.startswith("escalated:restore_unsupported_volume_claim_template") and r.c.log == []


def test_restore_without_image_digest_escalates_before_writing():
    r = R(digest="")
    assert r.go().startswith("escalated:image_digest_unavailable") and r.c.log == []


@pytest.mark.parametrize("env,name", [({k: v for k, v in ENV.items() if k != "ROLLOUT_TIMEOUT_S"}, "ROLLOUT_TIMEOUT_S"),
                                      ({k: v for k, v in ENV.items() if k != "ROLLOUT_POLL_S"}, "ROLLOUT_POLL_S")])
def test_restore_needs_rollout_config_before_writing(env, name):
    r = R(env=env)
    assert r.go() == f"escalated:config_missing:{name}" and r.c.log == []


def test_restore_dry_run_reads_but_writes_nothing():
    r = R(gate=fk.Gate(allow=0))
    out = r.go()
    assert out.startswith("DRY RUN: would have RESTORE prod/db") and r.c.log == []
    assert r.wl()["spec"]["replicas"] == 1


@pytest.mark.parametrize("allow,last", [(2, "patch_Deployment"), (3, "scale_Deployment"), (4, "create_pvc"),
                                        (5, "patch_Deployment"), (6, "scale_Deployment")])
def test_restore_stops_before_the_next_step_when_the_mode_flips(allow, last):
    r = R(gate=fk.Gate(allow=allow))
    out = r.go()
    assert out.startswith("stopped_mode_test")
    assert r.methods()[-1] == last and len(r.c.log) == allow


def test_restore_scale_down_that_never_settles_is_not_followed_by_more_writes():
    r = R()
    r.c.stuck_scale_down = True
    out = r.go()
    assert out.startswith("restore_failed:scale to zero did not settle") and "create_pvc" not in r.methods()


def test_restore_failure_leaves_workload_isolated_and_remembers_replicas():
    r = R()

    async def boom(ns, body):
        raise RuntimeError("quota exceeded")
    r.c.core.create_namespaced_persistent_volume_claim = boom
    out = r.go()
    assert out.startswith("restore_failed:create PVC") and "replicas 1 in annotation" in out
    assert r.wl()["metadata"]["annotations"]["kubeheal/original-replicas"] == "1"
    assert "scale_Deployment" in r.methods() and r.methods().count("scale_Deployment") == 1


def test_restore_resumes_from_the_remembered_replica_count():
    r = R(replicas=0)
    r.wl()["metadata"]["annotations"]["kubeheal/original-replicas"] = "3"
    assert r.go() == "restored"
    assert r.wl()["spec"]["replicas"] == 3


def test_restore_at_zero_replicas_without_a_remembered_count_escalates():
    r = R(replicas=0)
    assert r.go().startswith("escalated:replicas_unknown") and r.c.log == []


def test_restore_never_deletes_the_original_pvc_or_any_snapshot():
    r = R()
    r.go()
    assert not [e for e in r.c.log if e[1] in ("delete_snapshot",)] and "db-data" in r.c.pvcs


# ---- through the ExecutorService ---------------------------------------------------------------------------
def make_executor(r, entropy):
    return ExecutorService(redis=r.redis, core_api=r.c.core, apps_api=r.c.apps, networking_api=r.c.net,
                           custom_api=r.c.custom, mode=fk.Mode(), cfg=ExecConfig(ENV), entropy_check=entropy,
                           sleep=r.clock.sleep, clock=r.clock)


def test_executor_contain_then_restore_end_to_end():
    r = R(freeze_old=False)
    ex = make_executor(r, r.entropy)
    base = {"namespace": "prod", "deployment": "db", "pod": "db-abc-1", "incident_id": INC}
    assert run(ex.handle_entry("kubeheal.exec", "1-0", dict(base, action="contain")))
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"
    assert r.redis.stream(ESCALATIONS_STREAM) == []
    assert run(ex.handle_entry("kubeheal.exec", "2-0", dict(base, action="restore", t0_ms=str(T0 * 1000))))
    assert r.redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "restored"
    assert r.redis.acked == ["1-0", "2-0"] and r.redis.stream(ESCALATIONS_STREAM) == []


def test_executor_escalates_when_the_restore_stays_isolated():
    r = R(entropy=False)
    ex = make_executor(r, r.entropy)
    run(ex.handle_entry("kubeheal.exec", "1-0", {"action": "restore", "namespace": "prod", "deployment": "db",
                                                 "pod": "db-abc-1", "incident_id": INC, "t0_ms": str(T0 * 1000)}))
    esc = r.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human" and esc[0]["reason"].startswith("restored_kept_isolated")


# ---- review findings: retention, digest form, StatefulSet containment ----------------------------------------
def test_prune_never_deletes_the_newest_ready_snapshot_even_when_the_newest_twelve_are_unready():
    t = Sched()
    for i in range(3):                                   # older, ready
        t.c.snapshots[f"ready-{i}"] = fk.snapshot_obj(f"ready-{i}", "data", 1000 + i * 300)
    for i in range(12):                                  # newer, all stuck unready
        t.c.snapshots[f"stuck-{i}"] = fk.snapshot_obj(f"stuck-{i}", "data", 4000 + i * 300, ready=False)
    run(t.s.run_once())
    assert "ready-2" in t.c.snapshots                    # the newest ready one survives
    assert "ready-0" not in t.c.snapshots and "ready-1" not in t.c.snapshots


def test_digest_is_only_taken_from_the_pullable_repo_at_sha256_form():
    good = "sha256:" + "ab" * 32
    assert restore.image_digest(f"docker.io/reg/db@{good}") == good
    assert restore.image_digest(f"docker-pullable://reg/db@{good}") == good
    assert restore.image_digest(good) is None            # bare config id (k3d image import)
    assert restore.image_digest("") is None


def test_restore_escalates_on_a_bare_image_id_without_writing():
    r = R()
    r.c.pods[r.pod]["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "cd" * 32
    assert r.go().startswith("escalated:image_digest_unavailable") and r.c.log == []


def test_contain_isolates_a_statefulset_pod_when_the_kind_was_not_given():
    c = fk.Cluster()
    pod = fk.add_db_workload(c, kind="StatefulSet")
    rec_list = []
    redis = fk.Redis()
    out = do_contain(c, Recorder(lambda i, s, p: rec_list.append(s), INC), redis)     # Fusion sends no kind
    assert out == "contained" and c.pods[pod]["metadata"]["labels"]["kubeheal/quarantine"] == "true"


def test_contain_with_an_explicit_wrong_kind_does_not_label_the_pod():
    c = fk.Cluster()
    pod = fk.add_db_workload(c, kind="StatefulSet")
    redis = fk.Redis()
    out = do_contain(c, Recorder(None, INC), redis, kind="Deployment", kind_given=True)
    assert out.startswith("contain_failed:pod") and "patch_pod" not in [e[1] for e in c.log]


def test_missing_snapshot_class_is_recorded_once_not_every_cycle():
    t = Sched(env={})
    for _ in range(4):
        run(t.s.run_once())
    assert t.records.count("snapshot_run_skipped") == 1
