"""V5-D1: pure failure_reasons functions (ported from v5's Health Agent tests, plus our own cases)."""
from datetime import UTC, datetime

import pytest

from agents.health_agent import failure_reasons as fr

T0 = datetime.fromisoformat("2026-10-17T10:00:00Z").timestamp()
NOW = T0 + 1000
OWNED = {"labels": {"app": "web", "pod-template-hash": "5d4f9c"},
         "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d4f9c", "controller": True}]}


def iso(epoch):
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def deployment(replicas=2, generation=2, name="web"):
    return {"metadata": {"name": name, "namespace": "shop", "generation": generation},
            "spec": {"replicas": replicas}, "status": {}}


def rolled_out(dep):
    r = dep["spec"].get("replicas", 1)
    dep["status"] = {"observedGeneration": dep["metadata"]["generation"], "replicas": r, "updatedReplicas": r,
                     "availableReplicas": r}
    return dep


def pod(created, waiting=None, last_terminated=None, init=False, owned=True, deleting=False):
    cs = {"name": "app", "state": {"waiting": {"reason": waiting}} if waiting else {"running": {}},
          "lastState": {"terminated": {"reason": last_terminated}} if last_terminated else {}}
    meta = {"creationTimestamp": created, **(OWNED if owned else {})}
    if deleting:
        meta["deletionTimestamp"] = "2026-10-17T10:05:00Z"
    return {"metadata": meta, "status": {("initContainerStatuses" if init else "containerStatuses"): [cs]}}


def rpod(age_s, probe=None, ready=False, deleting=False, created_off=1, extra=None, startup=None):
    """Pod whose app container started `age_s` before NOW; probe None = no readiness probe."""
    c = {"name": "app", **({"readinessProbe": probe} if probe is not None else {}),
         **({"startupProbe": startup} if startup is not None else {})}
    meta = {"creationTimestamp": iso(T0 + created_off), **OWNED}
    if deleting:
        meta["deletionTimestamp"] = "2026-10-17T10:05:00Z"
    return {"metadata": meta, "spec": {"containers": [c]}, "status": {
        "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        "containerStatuses": [{"name": "app", "ready": ready, "state": {"running": {"startedAt": iso(NOW - age_s)}}}]
        + (extra or [])}}


# ---- rollout_complete ---------------------------------------------------------------------------------
def test_rollout_complete():
    assert fr.rollout_complete(rolled_out(deployment()))
    assert not fr.rollout_complete(deployment())                       # no rollout status yet


def test_rollout_incomplete_when_available_below_updated():
    stuck = rolled_out(deployment())
    stuck["status"]["availableReplicas"] = 1                           # e.g. ImagePullBackOff
    assert not fr.rollout_complete(stuck)


def test_rollout_incomplete_when_observed_generation_is_stale():
    stale = rolled_out(deployment())
    stale["metadata"]["generation"] = 3                                # controller not caught up
    assert not fr.rollout_complete(stale)


def test_rollout_incomplete_when_updated_below_desired():
    partial = rolled_out(deployment(replicas=3))
    partial["status"] |= {"updatedReplicas": 2}
    assert not fr.rollout_complete(partial)


def test_rollout_incomplete_while_old_replicas_are_left():
    # replicas 1, maxSurge 1 / maxUnavailable 0: the available pod is still the OLD one
    surging = rolled_out(deployment(replicas=1))
    surging["status"] |= {"replicas": 2, "updatedReplicas": 1, "availableReplicas": 1}
    assert not fr.rollout_complete(surging)
    surging["status"] |= {"replicas": 1}                               # old pod gone, new one available
    assert fr.rollout_complete(surging)
    surging["status"] |= {"availableReplicas": 0}
    assert not fr.rollout_complete(surging)


def test_rollout_never_complete_at_zero_replicas():
    zero = rolled_out(deployment(replicas=0))
    zero["status"] = {"observedGeneration": 2}                         # API omits zero counts
    assert not fr.rollout_complete(zero)


# ---- progress_deadline_exceeded ----------------------------------------------------------------------
def test_progress_deadline_exceeded_only_for_the_current_generation():
    dep = rolled_out(deployment())
    dep["status"]["conditions"] = [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]
    assert fr.progress_deadline_exceeded(dep)
    dep["metadata"]["generation"] = 3                                  # condition is about the old spec
    assert not fr.progress_deadline_exceeded(dep)
    assert not fr.progress_deadline_exceeded(rolled_out(deployment()))


def test_progress_deadline_needs_status_false_and_the_right_reason():
    dep = rolled_out(deployment())
    dep["status"]["conditions"] = [{"type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable"}]
    assert not fr.progress_deadline_exceeded(dep)
    dep["status"]["conditions"] = [{"type": "Progressing", "status": "False", "reason": "SomethingElse"}]
    assert not fr.progress_deadline_exceeded(dep)


# ---- owned_by ----------------------------------------------------------------------------------------
def test_owned_by_matches_replicaset_name_with_template_hash():
    assert fr.owned_by(pod("2026-10-17T10:00:30Z"), "web")
    assert fr.owned_by(pod("2026-10-17T10:00:30Z"), deployment())      # Deployment dict or name


def test_owned_by_rejects_overlapping_deployment_and_unowned_pods():
    canary = pod("2026-10-17T10:00:30Z")
    canary["metadata"] = {**canary["metadata"], "labels": {"app": "web", "track": "canary", "pod-template-hash": "6c8"},
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "web-canary-6c8"}]}
    assert not fr.owned_by(canary, "web")
    assert not fr.owned_by(pod("2026-10-17T10:00:30Z", owned=False), "web")
    assert not fr.owned_by({"metadata": {}}, "web")
    assert not fr.owned_by(pod("2026-10-17T10:00:30Z"), "web-other")
    wrong_kind = pod("2026-10-17T10:00:30Z")
    wrong_kind["metadata"]["ownerReferences"] = [{"kind": "StatefulSet", "name": "web-5d4f9c"}]
    assert not fr.owned_by(wrong_kind, "web")


# ---- pod_failure_reasons -----------------------------------------------------------------------------
def test_pod_failure_reasons_only_counts_pods_created_after_the_change():
    pods = [pod("2026-10-17T09:00:00Z", waiting="CrashLoopBackOff"),                # old revision: ignored
            pod("2026-10-17T09:59:57Z", waiting="ImagePullBackOff"),                # within clock slack
            pod("2026-10-17T10:00:30Z", last_terminated="OOMKilled"),
            pod("2026-10-17T10:00:31Z", waiting="ContainerCreating"),               # normal start-up
            pod("2026-10-17T10:00:32Z", waiting="CreateContainerConfigError", init=True),
            pod("2026-10-17T10:00:33Z", last_terminated="Completed"),
            {"metadata": {}, "status": {}}]
    assert fr.pod_failure_reasons(pods, T0, now=NOW) == {"ImagePullBackOff", "OOMKilled",
                                                         "CreateContainerConfigError"}


@pytest.mark.parametrize("reason", sorted(fr.WAITING_FAILURES))
def test_each_waiting_reason_is_reported(reason):
    assert fr.pod_failure_reasons([pod("2026-10-17T10:00:30Z", waiting=reason)], T0, now=NOW) == {reason}


def test_waiting_reason_set_is_exactly_the_seven_documented():
    assert fr.WAITING_FAILURES == {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CrashLoopBackOff",
                                   "CreateContainerConfigError", "CreateContainerError", "RunContainerError"}


def test_oomkilled_last_state_is_reported():
    assert fr.pod_failure_reasons([pod("2026-10-17T10:00:30Z", last_terminated="OOMKilled")], T0, now=NOW) \
        == {"OOMKilled"}


def test_init_container_waiting_is_reported():
    p = pod("2026-10-17T10:00:30Z", waiting="ImagePullBackOff", init=True)
    assert fr.pod_failure_reasons([p], T0, now=NOW) == {"ImagePullBackOff"}


def test_created_exactly_at_the_slack_boundary_counts_and_one_second_earlier_does_not():
    assert fr.pod_failure_reasons([pod(iso(T0 - 5), waiting="ErrImagePull")], T0, now=NOW) == {"ErrImagePull"}
    assert fr.pod_failure_reasons([pod(iso(T0 - 6), waiting="ErrImagePull")], T0, now=NOW) == set()


def test_terminating_pods_are_ignored():
    p = pod("2026-10-17T10:00:30Z", waiting="CrashLoopBackOff", deleting=True)
    assert fr.pod_failure_reasons([p], T0, now=NOW) == set()


def test_pod_with_unparseable_creation_timestamp_is_ignored():
    assert fr.pod_failure_reasons([pod("not-a-time", waiting="CrashLoopBackOff")], T0, now=NOW) == set()


def test_api_serialised_offset_timestamps_are_understood():
    assert fr.pod_failure_reasons([pod("2026-10-17T10:00:30+00:00", waiting="CrashLoopBackOff")], T0, now=NOW) \
        == {"CrashLoopBackOff"}


# ---- readiness budget --------------------------------------------------------------------------------
def never_ready(pods):
    return "ReadinessNeverPassed" in fr.pod_failure_reasons(pods, T0, now=NOW)


@pytest.mark.parametrize("probe,age,expected", [
    ({}, 59, False), ({}, 61, True),                                   # defaults 0 + 10x3 + 30 margin = 60 s (= floor)
    ({"periodSeconds": 5, "failureThreshold": 2}, 61, True),           # 10 + 30 = 40 s, floored to 60 s
    ({"initialDelaySeconds": 120, "periodSeconds": 10, "failureThreshold": 3}, 100, False),   # 120+30+30 = 180 s
    ({"initialDelaySeconds": 120, "periodSeconds": 10, "failureThreshold": 3}, 181, True),
    (None, 500, False),                                                # no probe: never the culprit
])
def test_readiness_budget(probe, age, expected):
    assert never_ready([rpod(age, probe)]) is expected


def test_startup_probe_budget_is_added():
    startup = {"periodSeconds": 10, "failureThreshold": 30}            # 300 s
    assert not never_ready([rpod(300, {}, startup=startup)])           # 30 + 300 + 30 = 360 s
    assert never_ready([rpod(361, {}, startup=startup)])


def test_readiness_ignores_ready_terminating_old_and_not_running_pods():
    assert not never_ready([rpod(500, {}, ready=True)])
    assert not never_ready([rpod(500, {}, deleting=True)])
    assert not never_ready([rpod(500, {}, created_off=-100)])          # created before the change
    waiting = rpod(500, {})
    waiting["status"]["containerStatuses"][0]["state"] = {"waiting": {"reason": "ContainerCreating"}}
    assert not never_ready([waiting])


def test_readiness_needs_every_container_running():
    extra = [{"name": "sidecar", "ready": False, "state": {"waiting": {"reason": "PodInitializing"}}}]
    assert not never_ready([rpod(500, {}, extra=extra)])


def test_readiness_ignores_container_without_probe_even_if_not_ready():
    assert not fr.readiness_never_passed(rpod(500, None), NOW)


# ---- failure_reasons (the helper) --------------------------------------------------------------------
def test_deployment_with_no_pods_gives_an_empty_list():
    assert fr.failure_reasons(rolled_out(deployment()), [], T0, now=NOW) == []
    assert fr.failure_reasons(deployment(), [], T0, now=NOW) == []


def test_failure_reasons_sorted_and_includes_progress_deadline():
    dep = rolled_out(deployment())
    dep["status"]["conditions"] = [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]
    pods = [pod("2026-10-17T10:00:30Z", waiting="ImagePullBackOff"),
            pod("2026-10-17T10:00:31Z", last_terminated="OOMKilled")]
    assert fr.failure_reasons(dep, pods, T0, now=NOW) == ["ImagePullBackOff", "OOMKilled", "ProgressDeadlineExceeded"]


def test_progress_deadline_only_for_the_current_generation_in_the_helper():
    dep = rolled_out(deployment())
    dep["status"]["conditions"] = [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]
    dep["metadata"]["generation"] = 3
    assert fr.failure_reasons(dep, [], T0, now=NOW) == []


def test_failure_reasons_ignore_old_replicaset_terminating_unowned_and_unprobed_pods():
    other_rs = pod("2026-10-17T10:00:30Z", waiting="CrashLoopBackOff")      # new in time, another Deployment's RS
    other_rs["metadata"]["ownerReferences"] = [{"kind": "ReplicaSet", "name": "api-5d4f9c"}]
    pods = [pod("2026-10-17T09:00:00Z", waiting="CrashLoopBackOff"),                  # created before the change
            pod("2026-10-17T10:00:30Z", waiting="CrashLoopBackOff", deleting=True),   # terminating
            pod("2026-10-17T10:00:30Z", waiting="CrashLoopBackOff", owned=False),     # not owned
            other_rs,
            rpod(500, None)]                                                          # no readiness probe
    assert fr.failure_reasons(rolled_out(deployment()), pods, T0, now=NOW) == []


def test_failure_reasons_only_uses_pods_of_this_deployment():
    canary = pod("2999-01-01T00:00:00Z", waiting="CrashLoopBackOff")
    canary["metadata"] = {**canary["metadata"], "labels": {"app": "web", "track": "canary", "pod-template-hash": "6c8"},
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "web-canary-6c8"}]}
    dep = deployment()
    assert fr.failure_reasons(dep, [canary], 0.0) == []
    assert fr.failure_reasons(dep, [canary, pod("2999-01-01T00:00:00Z", waiting="ErrImagePull")], 0.0) \
        == ["ErrImagePull"]


def test_failure_reasons_reports_readiness_never_passed():
    assert fr.failure_reasons(deployment(), [rpod(500, {})], T0, now=NOW) == ["ReadinessNeverPassed"]


def test_module_has_no_kubernetes_client_or_http_import():
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(fr))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"__future__", "time", "datetime"}
