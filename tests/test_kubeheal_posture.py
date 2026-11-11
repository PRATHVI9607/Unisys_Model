"""kubeheal.posture: posture weakenings and the inclusive 10x resource-cut rule (owner decision D1)."""

from __future__ import annotations

import copy

import pytest

from kubeheal import posture
from kubeheal.contracts import POLICY_REASON_PREFIX
from kubeheal.features.health import canonical_spec
from kubeheal.posture import policy_violations, posture_violations_present, weakens_posture


def deployment(cpu="500m", memory="256Mi", replicas=2, name="web"):
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": "shop"},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "app", "image": "nginx:1.27",
                                         "resources": {"limits": {"cpu": cpu, "memory": memory}}}]},
            },
        },
    }


def with_resources(res, name="app"):
    d = deployment()
    d["spec"]["template"]["spec"]["containers"][0]["name"] = name
    d["spec"]["template"]["spec"]["containers"][0]["resources"] = res
    return canonical_spec(d)


def posture_change(dep, **pod):
    dep = copy.deepcopy(dep)
    tpl = dep["spec"]["template"]["spec"]
    sc = pod.pop("container_sc", None)
    if sc:
        tpl["containers"][0]["securityContext"] = sc
    tpl.update(pod)
    return dep


P = POLICY_REASON_PREFIX


def test_prefix_is_policy():
    assert P == "policy:"


# posture flags -----------------------------------------------------------------------------------
@pytest.mark.parametrize("change,expected", [
    ({}, []),
    ({"container_sc": {"privileged": True}}, [P + "privileged_added"]),
    ({"container_sc": {"runAsUser": 0}}, [P + "root_user_added"]),
    ({"container_sc": {"runAsNonRoot": False}}, [P + "root_user_added"]),
    ({"container_sc": {"capabilities": {"add": ["SYS_ADMIN"]}}}, [P + "capabilities_added"]),
    ({"hostNetwork": True}, [P + "host_namespace_added"]),
    ({"hostPID": True}, [P + "host_namespace_added"]),
    ({"hostIPC": True}, [P + "host_namespace_added"]),
    ({"volumes": [{"name": "h", "hostPath": {"path": "/"}}]}, [P + "host_path_added"]),
    ({"hostNetwork": True, "container_sc": {"privileged": True}},
     [P + "privileged_added", P + "host_namespace_added"]),
])
def test_each_posture_flag_in_isolation(change, expected):
    base = canonical_spec(deployment())
    assert policy_violations(base, canonical_spec(posture_change(deployment(), **change))) == expected


def test_unchanged_posture_is_empty():
    base = canonical_spec(deployment())
    assert policy_violations(base, base) == []
    assert not posture_violations_present(base, base)


def test_violation_already_in_baseline_is_not_reported():
    priv = canonical_spec(posture_change(deployment(), container_sc={"privileged": True}, hostPID=True,
                                         volumes=[{"name": "h", "hostPath": {"path": "/"}}]))
    assert policy_violations(priv, priv) == []


def test_adding_a_privileged_container():
    new = deployment()
    new["spec"]["template"]["spec"]["containers"].append(
        {"name": "side", "image": "busybox:1.36", "securityContext": {"privileged": True}})
    assert policy_violations(deployment(), new) == [P + "privileged_added"]


def test_init_containers_are_covered():
    new = deployment()
    new["spec"]["template"]["spec"]["initContainers"] = [
        {"name": "init", "image": "busybox:1.36", "securityContext": {"privileged": True}}]
    assert policy_violations(deployment(), new) == [P + "privileged_added"]
    new["spec"]["template"]["spec"]["initContainers"][0]["securityContext"] = {"runAsUser": 0}
    assert policy_violations(deployment(), new) == [P + "root_user_added"]


# 10x cut rule (inclusive, D1) --------------------------------------------------------------------
@pytest.mark.parametrize("old,new,expected", [
    ("500m", "50m", [P + "cpu_cut_10x"]),    # D1: inclusive, v5 did not fire here
    ("500m", "5m", [P + "cpu_cut_10x"]),
    ("500m", "49m", [P + "cpu_cut_10x"]),
    ("500m", "51m", []),                     # above the floor
    ("400m", "50m", []),                     # factor 8
    ("1", "100m", []),                       # 10x but 100m is above the floor
    ("500m", "100m", []),                    # 5x
    ("500m", "125m", []),                    # 4x
    ("2", "100m", []),
    ("300m", "30m", [P + "cpu_cut_10x"]),    # float rounding must not hide an exact 10x
    ("500m", "500m", []),
])
def test_cpu_cut_limits(old, new, expected):
    assert policy_violations(canonical_spec(deployment(cpu=old)), canonical_spec(deployment(cpu=new))) == expected


def test_cpu_cut_on_request():
    base = with_resources({"requests": {"cpu": "100m"}})
    assert policy_violations(base, with_resources({"requests": {"cpu": "10m"}})) == [P + "cpu_cut_10x"]
    base = with_resources({"requests": {"cpu": "500m"}, "limits": {"cpu": "1"}})
    assert policy_violations(base, with_resources({"requests": {"cpu": "50m"}})) == [P + "cpu_cut_10x"]
    assert policy_violations(base, with_resources({"limits": {"cpu": "50m"}})) == [P + "cpu_cut_10x"]   # 1 -> 50m: 20x
    assert policy_violations(base, with_resources({"limits": {"cpu": "100m"}})) == []   # above the floor


@pytest.mark.parametrize("old,new,expected", [
    ("320Mi", "32Mi", [P + "memory_cut_10x"]),   # exactly 10x, at the floor
    ("512Mi", "10Mi", [P + "memory_cut_10x"]),
    ("128Mi", "32Mi", []),                       # factor 4
    ("128Mi", "33Mi", []),                       # factor 3.9
    ("1Gi", "33Mi", []),                         # 31x but above the floor
    ("1Gi", "32Mi", [P + "memory_cut_10x"]),
])
def test_memory_cut_limits(old, new, expected):
    assert policy_violations(canonical_spec(deployment(memory=old)), canonical_spec(deployment(memory=new))) == expected


def test_memory_cut_on_request_and_removal_is_not_a_cut():
    base = with_resources({"requests": {"cpu": "500m", "memory": "512Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}})
    assert policy_violations(base, with_resources({"requests": {"memory": "16Mi"}})) == [P + "memory_cut_10x"]
    assert policy_violations(base, with_resources({"limits": {"memory": "128Mi"}})) == []
    assert policy_violations(base, with_resources({})) == []           # removed, not cut


def test_missing_baseline_resources_never_trigger():
    assert policy_violations(with_resources({}), with_resources({"limits": {"cpu": "5m", "memory": "1Mi"}})) == []
    # limit in baseline, only a request in the new spec: different kinds are never compared
    base = with_resources({"limits": {"cpu": "1"}})
    assert policy_violations(base, with_resources({"requests": {"cpu": "5m"}})) == []


def test_new_container_without_baseline_never_triggers_cut():
    new = deployment(cpu="5m")
    new["spec"]["template"]["spec"]["containers"][0]["name"] = "other"
    assert policy_violations(deployment(cpu="500m"), new) == []


def test_unparsable_quantities_never_trigger():
    assert policy_violations(canonical_spec(deployment(cpu="500m")), canonical_spec(deployment(cpu="lots"))) == []
    assert policy_violations(canonical_spec(deployment(cpu="lots")), canonical_spec(deployment(cpu="5m"))) == []


def test_constants_are_the_documented_ones():
    assert posture.CUT_FACTOR == 10
    assert posture.CUT_FLOORS["cpu"][0] == 0.05
    assert posture.CUT_FLOORS["memory"][0] == 32 * 2**20


# order, forms ------------------------------------------------------------------------------------
def test_result_order_is_deterministic():
    new = posture_change(deployment(cpu="5m", memory="1Mi"), hostNetwork=True,
                         volumes=[{"name": "h", "hostPath": {"path": "/"}}],
                         container_sc={"privileged": True, "runAsUser": 0, "capabilities": {"add": ["NET_ADMIN"]}})
    new["spec"]["template"]["spec"]["containers"][0]["resources"] = {"limits": {"cpu": "5m", "memory": "1Mi"}}
    expected = [P + "privileged_added", P + "root_user_added", P + "capabilities_added",
                P + "host_namespace_added", P + "host_path_added", P + "cpu_cut_10x", P + "memory_cut_10x"]
    for _ in range(3):
        assert policy_violations(deployment(), new) == expected


def test_accepts_deployment_canonical_and_spec_forms():
    base_dep = deployment()
    new_dep = posture_change(deployment(cpu="5m"), container_sc={"privileged": True})
    expected = [P + "privileged_added", P + "cpu_cut_10x"]
    assert policy_violations(base_dep, new_dep) == expected                                   # Deployment
    assert policy_violations(canonical_spec(base_dep), canonical_spec(new_dep)) == expected   # canonical
    assert policy_violations(base_dep["spec"], new_dep["spec"]) == expected                   # spec only
    assert policy_violations(base_dep, canonical_spec(new_dep)) == expected                   # mixed
    assert policy_violations(base_dep["spec"]["template"], new_dep["spec"]["template"]) == expected   # pod template
    assert policy_violations(base_dep["spec"]["template"]["spec"],
                             new_dep["spec"]["template"]["spec"]) == expected                 # pod spec


def test_accepts_api_shaped_camelcase_and_snake_case_models():
    api = {"spec": {"template": {"spec": {
        "hostNetwork": True,
        "containers": [{"name": "app", "image": "nginx:1.27",
                        "securityContext": {"runAsNonRoot": False, "privileged": True},
                        "resources": {"limits": {"cpu": "5m", "memory": "256Mi"}}}]}}}}
    assert policy_violations(deployment(), api) == [
        P + "privileged_added", P + "root_user_added", P + "host_namespace_added", P + "cpu_cut_10x"]
    snake = {"template": {"spec": {"host_network": True, "containers": [
        {"name": "app", "image": "nginx:1.27", "security_context": {"run_as_user": 0}}]}}}
    assert policy_violations(deployment(), snake) == [P + "root_user_added", P + "host_namespace_added"]


def test_inputs_are_not_mutated():
    base, new = deployment(), posture_change(deployment(cpu="5m"), hostPID=True)
    b0, n0 = copy.deepcopy(base), copy.deepcopy(new)
    policy_violations(base, new)
    assert base == b0 and new == n0


# convenience wrappers ----------------------------------------------------------------------------
def test_posture_violations_present():
    assert posture_violations_present(deployment(), posture_change(deployment(), hostIPC=True))
    assert posture_violations_present(deployment(cpu="500m"), deployment(cpu="50m"))
    assert not posture_violations_present(deployment(), deployment(replicas=5))


def test_weakens_posture_is_candidate_first_reference_second():
    live = deployment()
    candidate = posture_change(deployment(), container_sc={"privileged": True})
    assert weakens_posture(candidate, live) == [P + "privileged_added"]
    assert weakens_posture(live, candidate) == []          # tightening is not a weakening
    assert weakens_posture(candidate, live) == policy_violations(live, candidate)
