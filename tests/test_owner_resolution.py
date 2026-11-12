"""F3 fix: the containment request must name the Deployment or StatefulSet that owns the pod, never the pod name.

Cause found in the 2026-11-12 D-5 run: the Security Agent's pod index did not know the pod when the event was
published, so `deployment` was the pod name and the Executor refused the request as a pod/workload mismatch.
Now the Security Agent resolves pod -> ReplicaSet -> Deployment (or StatefulSet) through ownerReferences before it
publishes, an unresolved owner is published as an empty `deployment`, and Fusion refuses to queue a containment
for such an event (fail closed)."""
from types import SimpleNamespace as NS

import pytest

from fusion_helpers import make_agent, ledger_steps, run as frun, sec_event, stream
from test_security_v5 import burst_window, check, make_agent_sec, published, run
from agents.fusion_agent import agent as fusion
from agents.security_agent.proc_scanner import PodIndex, PodInfo

POD = "victim-app-7d9f8b6c5-x2k4q"
NS_NAME = "demo"
UID = "uid-9"


def ref(kind, name):
    return NS(kind=kind, name=name)


def pod_obj(owners, uid=UID, name=POD):
    return NS(metadata=NS(name=name, namespace=NS_NAME, uid=uid, owner_references=owners),
              spec=NS(containers=[NS(name="app")], node_name="node-1"))


class FakeCore:
    def __init__(self, pod=None, error=None):
        self.pod, self.error, self.reads = pod, error, 0

    async def read_namespaced_pod(self, name, namespace):
        self.reads += 1
        if self.error:
            raise self.error
        return self.pod


class FakeApps:
    def __init__(self, rs_owners=None, error=None):
        self.rs_owners, self.error, self.reads = rs_owners, error, 0

    async def read_namespaced_replica_set(self, name, namespace):
        self.reads += 1
        if self.error:
            raise self.error
        return NS(metadata=NS(name=name, namespace=namespace, owner_references=self.rs_owners))


def resolve(core, apps, uid=UID):
    idx = PodIndex()
    return idx, run(idx.resolve_live(core, apps, NS_NAME, POD, uid))


# ---- PodIndex.resolve_live ------------------------------------------------------------------------------
def test_replicaset_owner_resolves_to_the_deployment_and_is_cached_in_the_index():
    idx, info = resolve(FakeCore(pod_obj([ref("ReplicaSet", "victim-app-7d9f8b6c5")])),
                        FakeApps([ref("Deployment", "victim-app")]))
    assert (info.workload_kind, info.workload, info.uid, info.container) == ("Deployment", "victim-app", UID, "app")
    assert idx.lookup_pod(NS_NAME, POD) is info


def test_statefulset_owner_resolves_directly_without_reading_a_replicaset():
    apps = FakeApps()
    _, info = resolve(FakeCore(pod_obj([ref("StatefulSet", "db")])), apps)
    assert (info.workload_kind, info.workload) == ("StatefulSet", "db") and apps.reads == 0


@pytest.mark.parametrize("core,apps", [
    pytest.param(FakeCore(pod_obj(None)), FakeApps(), id="bare pod"),
    pytest.param(FakeCore(pod_obj([ref("ReplicaSet", "rs")])), FakeApps(None), id="orphan replicaset"),
    pytest.param(FakeCore(pod_obj([ref("ReplicaSet", "rs")])), FakeApps([ref("Rollout", "r")]),
                 id="replicaset owned by something else"),
    pytest.param(FakeCore(pod_obj([ref("DaemonSet", "ds")])), FakeApps(), id="other controller kind"),
    pytest.param(FakeCore(pod_obj([ref("StatefulSet", "a"), ref("StatefulSet", "b")])), FakeApps(),
                 id="two owners"),
    pytest.param(FakeCore(error=RuntimeError("403")), FakeApps(), id="pod read fails"),
    pytest.param(FakeCore(pod_obj([ref("ReplicaSet", "rs")])), FakeApps(error=RuntimeError("500")),
                 id="replicaset read fails"),
])
def test_no_owner_means_none_and_the_index_is_left_alone(core, apps):
    idx, info = resolve(core, apps)
    assert info is None and idx.lookup_pod(NS_NAME, POD) is None


def test_a_live_uid_that_differs_from_the_event_uid_is_unresolved():
    # a recreated StatefulSet pod keeps its name; the event was about the old one
    _, info = resolve(FakeCore(pod_obj([ref("StatefulSet", "db")], uid="new-uid")), FakeApps(), uid="old-uid")
    assert info is None


def test_a_missing_event_uid_does_not_block_resolution():
    _, info = resolve(FakeCore(pod_obj([ref("StatefulSet", "db")])), FakeApps(), uid="")
    assert info.workload == "db"


# ---- the Security Agent ---------------------------------------------------------------------------------
def agent_with(core, apps):
    ag = make_agent_sec()
    ag.core_api, ag.apps_api = core, apps
    return ag


def test_empty_index_at_publish_time_publishes_the_deployment_not_the_pod_name():
    """The D-5 reproduction: the index does not know the pod, the event used to carry deployment == pod name."""
    ag = agent_with(FakeCore(pod_obj([ref("ReplicaSet", "victim-app-7d9f8b6c5")])),
                    FakeApps([ref("Deployment", "victim-app")]))
    assert ag.pod_index.lookup_pod(NS_NAME, POD) is None
    check(ag, burst_window())
    [ev] = published(ag)
    assert ev["deployment"] == "victim-app" and ev["pod_name"] == POD and ev["deployment"] != ev["pod_name"]
    assert ev["workload_kind"] == "Deployment" and ev["owner_resolved"] == "true" and ev["pod_uid"] == UID
    assert ag.redis.hashes.get("kubeheal:security:score:demo:victim-app") is not None


def test_no_owner_publishes_an_empty_deployment_and_says_so():
    ag = agent_with(FakeCore(pod_obj(None)), FakeApps())
    check(ag, burst_window())
    [ev] = published(ag)
    assert ev["deployment"] == "" and ev["pod_name"] == POD
    assert ev["workload_kind"] == "Pod" and ev["owner_resolved"] == "false"


def test_api_error_fails_closed_the_same_way():
    ag = agent_with(FakeCore(error=RuntimeError("apiserver down")), FakeApps())
    check(ag, burst_window())
    [ev] = published(ag)
    assert ev["deployment"] == "" and ev["owner_resolved"] == "false"


def test_a_pod_the_index_knows_needs_no_live_read():
    core = FakeCore(pod_obj([ref("StatefulSet", "other")]))
    ag = agent_with(core, FakeApps())
    ag.pod_index.by_pod[(NS_NAME, POD)] = PodInfo(NS_NAME, POD, "app", "Deployment", "victim-app", UID)
    check(ag, burst_window())
    [ev] = published(ag)
    assert ev["deployment"] == "victim-app" and core.reads == 0


def test_the_index_entry_of_a_bare_pod_is_re_resolved_live():
    core = FakeCore(pod_obj([ref("ReplicaSet", "victim-app-7d9f8b6c5")]))
    ag = agent_with(core, FakeApps([ref("Deployment", "victim-app")]))
    ag.pod_index.by_pod[(NS_NAME, POD)] = PodInfo(NS_NAME, POD, "app", "Pod", POD, UID)   # stale fallback
    check(ag, burst_window())
    assert published(ag)[0]["deployment"] == "victim-app" and core.reads == 1


# ---- Fusion: fail closed --------------------------------------------------------------------------------
def exec_requests(a):
    return stream(a.redis, fusion.EXEC_STREAM)


def escalations(a):
    return stream(a.redis, fusion.ESCALATIONS_STREAM)


def actions(a):
    return stream(a.redis, fusion.ACTIONS_STREAM)


def test_fusion_queues_the_containment_for_a_resolved_owner():
    a = make_agent()
    assert frun(a._handle_entry(fusion.SEC_STREAM, "1-0", sec_event(owner_resolved="true"))) is True
    [req] = exec_requests(a)
    assert req["action"] == "contain" and req["deployment"] == "payments" and req["pod"] == "payments-abc-1"


@pytest.mark.parametrize("extra", [
    {"deployment": "", "workload_kind": "Pod", "owner_resolved": "false"},
    {"deployment": "", "workload_kind": "ReplicaSet"},
    {"deployment": "payments-abc-1", "workload_kind": "Pod"},               # the old pod-name-as-deployment shape
    {"owner_resolved": "false"},
])
def test_fusion_queues_no_containment_and_escalates_when_the_owner_is_unresolved(extra):
    a = make_agent()
    assert frun(a._handle_entry(fusion.SEC_STREAM, "1-0", sec_event(**extra))) is True
    assert exec_requests(a) == []
    [esc] = escalations(a)
    assert esc["required"] == "human" and "contain_not_requested" in esc["reason"]
    assert [r["step"] for r in ledger_steps(a)].count("fusion_escalation") == 1
    assert [x["outcome"] for x in actions(a) if x["action_type"] == "auto_contain"] == ["not_queued_owner_unresolved"]


def test_an_event_from_an_older_agent_without_kind_or_flag_is_left_to_the_executor():
    a = make_agent()
    ev = sec_event()
    del ev["workload_kind"]
    assert frun(a._handle_entry(fusion.SEC_STREAM, "1-0", ev)) is True
    assert len(exec_requests(a)) == 1
