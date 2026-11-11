import copy
import json

import pytest

from kubeheal.features.health import (
    HEALTH_FEATURES,
    METRIC_FEATURES,
    SPEC_FEATURES,
    canonical_spec,
    changed_paths,
    health_features,
    metric_features,
    spec_diff_features,
    spec_hash,
)

SPEC = {
    "replicas": 3,
    "selector": {"matchLabels": {"app": "web"}},
    "template": {
        "metadata": {"labels": {"app": "web", "my_label": "x"}},
        "spec": {
            "containers": [{
                "name": "web",
                "image": "nginx:1.27",
                "env": [{"name": "MODE", "value": "a"}],
                "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "250m"}},
                "readinessProbe": {"httpGet": {"path": "/health", "port": 80}},
                "volumeMounts": [{"name": "data", "mountPath": "/data"}],
            }],
            "volumes": [{"name": "data", "emptyDir": {}}],
        },
    },
}






def test_canonical_spec_forms_and_user_keys():
    deployment = {"metadata": {"name": "web"}, "spec": SPEC}
    snake = copy.deepcopy(SPEC)
    snake["template"]["spec"]["containers"][0]["readiness_probe"] = snake["template"]["spec"]["containers"][0].pop("readinessProbe")
    snake["template"]["spec"]["containers"][0]["volume_mounts"] = snake["template"]["spec"]["containers"][0].pop("volumeMounts")
    snake["template"]["spec"]["node_selector"] = None
    snake["min_ready_seconds"] = None
    snake["match_labels_noise"] = []
    assert canonical_spec(deployment) == canonical_spec(SPEC) == canonical_spec(snake)
    # label keys are user data and must survive (they are restored by AUTO-PATCH)
    assert canonical_spec(SPEC)["template"]["metadata"]["labels"]["my_label"] == "x"
    assert "volumes" in canonical_spec(SPEC)["template"]["spec"]   # emptyDir {} dropped, volume kept by name


def test_no_change_gives_zero_diff():
    f = spec_diff_features(canonical_spec(SPEC), canonical_spec(copy.deepcopy(SPEC)))
    assert list(f) == SPEC_FEATURES
    assert f["spec_changed"] == 0.0 and f["n_changed_fields"] == 0.0
    assert f["cpu_limit_ratio"] == 1.0 and f["replicas_ratio"] == 1.0


def test_risky_change_features():
    new = copy.deepcopy(SPEC)
    new["replicas"] = 0
    c = new["template"]["spec"]["containers"][0]
    c["image"] = "nginx"
    c["resources"]["limits"] = {"cpu": "100m"}
    c["securityContext"] = {"privileged": True, "runAsUser": 0, "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]}}
    c["env"] = [{"name": "MODE", "value": "b"}, {"name": "DEBUG", "value": "1"}]
    del c["readinessProbe"]
    c["volumeMounts"] = []
    new["template"]["spec"]["hostPID"] = True
    new["template"]["spec"]["volumes"].append({"name": "root", "hostPath": {"path": "/"}})

    f = spec_diff_features(canonical_spec(SPEC), canonical_spec(new))
    assert f["cpu_limit_ratio"] == pytest.approx(0.2)
    assert f["mem_limit_ratio"] is None          # new side has no memory limit: ratio unknown, not 0
    assert f["mem_limit_removed"] == 1.0 and f["cpu_limit_removed"] == 0.0
    assert f["replicas_to_zero"] == 1.0 and f["replicas_ratio"] == 0.0
    assert f["image_changed"] == 1.0 and f["image_unpinned"] == 1.0
    assert f["privileged_added"] == 1.0 and f["root_user_added"] == 1.0
    assert f["capabilities_added"] == 2.0
    assert f["host_namespace_added"] == 1.0 and f["host_path_added"] == 1.0
    assert f["probe_changed"] == 1.0 and f["probe_removed"] == 1.0
    assert f["env_count_delta"] == 1.0 and f["env_values_changed"] == 1.0
    assert f["volume_mounts_removed"] == 1.0


def test_changed_paths():
    new = copy.deepcopy(SPEC)
    new["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "1"
    new["replicas"] = 5
    assert changed_paths(SPEC, new) == ["replicas", "template.spec.containers[0].resources.limits.cpu"]
    assert changed_paths(SPEC, new, limit=1) == ["replicas"]


def test_metric_features_units_and_missing():
    window = {
        "cpu_usage_cores": [0.25, 0.5], "cpu_limit_cores": [0.5],
        "memory_working_set_bytes": [128 * 2**20], "memory_limit_bytes": [256 * 2**20],
        "request_rate_rps": [10.0, 10.0], "error_rate_rps": [1.0, 0.0],
        "latency_p99_s": [0.1, 0.2, float("nan")], "restarts_total": [1, 3],
        "replicas_desired": [4], "replicas_ready": [2],
    }
    f = metric_features(window)
    assert list(f) == METRIC_FEATURES
    assert f["cpu_util_mean"] == pytest.approx(0.75) and f["cpu_util_max"] == pytest.approx(1.0)
    assert f["mem_util_max"] == pytest.approx(0.5)
    assert f["latency_p99_max_s"] == pytest.approx(0.2)
    assert f["latency_trend"] == pytest.approx(0.4)        # +0.1 s per 15 s sample = 0.4 s/min
    assert f["error_ratio"] == pytest.approx(0.05)
    assert f["restarts_delta"] == 2.0 and f["ready_ratio"] == 0.5
    assert f["cpu_throttle_mean"] is None

    assert all(v is None for v in metric_features({}).values())


def test_health_features_order_and_canonicalisation():
    f = health_features({"spec": SPEC}, SPEC, {})
    assert list(f) == HEALTH_FEATURES
    assert f["spec_changed"] == 0.0


def _spec(**kw):
    pod = {"containers": [{"name": "app", "image": "a:1"}], **kw.pop("pod", {})}
    return {"replicas": 1, "template": {"spec": pod}}


def test_init_container_posture_and_runasuser_precedence():
    base = _spec()
    priv_init = _spec(pod={"initContainers": [{"name": "i", "image": "a:1", "securityContext": {"privileged": True}}]})
    assert spec_diff_features(base, priv_init)["privileged_added"] == 1.0
    root_pod = {"securityContext": {"runAsUser": 0}}
    overridden = _spec(pod={**root_pod, "containers": [{"name": "app", "image": "a:1",
                                                         "securityContext": {"runAsUser": 1000, "runAsNonRoot": True}}]})
    assert spec_diff_features(base, overridden)["root_user_added"] == 0.0
    assert spec_diff_features(base, _spec(pod=root_pod))["root_user_added"] == 1.0


def test_restarts_delta_ignores_pod_replacement_resets():
    assert metric_features({"restarts_total": [5, 5, 0, 2]})["restarts_delta"] == 2.0
