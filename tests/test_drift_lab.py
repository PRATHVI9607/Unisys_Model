"""drift_lab: labels from observed impact (agent's window features + pod observations), pure spec ops."""

from agents.health_agent import agent as ha
from training.collect import drift_lab

OK = {"waiting": [], "oom": False, "restarts": 0, "stuck": False, "desired": 2}


def test_lab_uses_the_agents_window_and_delay():
    assert drift_lab.ASSESS_DELAY_S is ha.ASSESS_DELAY_S
    assert drift_lab.fetch_window is ha.fetch_window


def test_impact_label_from_observed_impact():
    calm = {"latency_p99_mean_s": 0.012, "ready_ratio": 1.0, "error_ratio": 0.0}
    assert drift_lab.impact_label(calm, OK, 0.010, []) == ("benign", [])
    # p99 doubled but by < 10 ms: podinfo histogram bucket noise, not degradation
    assert drift_lab.impact_label({**calm, "latency_p99_mean_s": 0.009}, OK, 0.004, [])[0] == "benign"
    assert drift_lab.impact_label({**calm, "latency_p99_mean_s": 0.05}, OK, 0.01, []) == ("degradation", ["p99>=2x_pre"])
    assert drift_lab.impact_label({**calm, "cpu_throttle_mean": 0.4}, OK, None, [])[0] == "degradation"
    assert drift_lab.impact_label({**calm, "ready_ratio": 0.0}, OK, 0.01, [])[0] == "critical"
    assert drift_lab.impact_label(calm, OK | {"desired": 0}, 0.01, []) == ("critical", ["scaled_to_zero"])
    assert drift_lab.impact_label(calm, OK | {"waiting": ["ImagePullBackOff"]}, 0.01, [])[1] == [
        "pod_waiting:ImagePullBackOff"]
    assert drift_lab.impact_label(calm, OK, 0.01, [{"op": "privileged"}]) == (
        "critical", ["policy:security_posture:privileged"])
    # missing metrics are unknown, never a reason
    assert drift_lab.impact_label({}, OK, None, []) == ("benign", [])


def test_observe_pods_counts_restarts_since_t0_and_bad_waits():
    obs = {"waiting": set(), "oom": False, "restarts": 0}
    pods = [{"metadata": {"uid": "a"}, "status": {"containerStatuses": [
        {"restartCount": 3, "state": {"waiting": {"reason": "CrashLoopBackOff"}},
         "lastState": {"terminated": {"reason": "OOMKilled"}}}]}}]
    drift_lab.observe_pods(pods, {"a": 1}, obs)
    assert obs == {"waiting": {"CrashLoopBackOff"}, "oom": True, "restarts": 2}


def test_pick_ops_always_changes_the_base():
    import random
    base = drift_lab.canonical_spec(drift_lab.deployment("lab-00", drift_lab.variant(random.Random(1))))
    r = random.Random(0)
    for _ in range(300):
        fam, ops = drift_lab.pick_ops(r, base)
        assert drift_lab.apply_ops(base, ops) != base and all(drift_lab.op_name(o) for o in ops), fam


def test_settle_wait_until_the_last_rollout_left_the_pre_window():
    def dep(reason, ts="2026-10-17T10:00:00Z"):
        return {"status": {"conditions": [{"type": "Available", "status": "True", "lastUpdateTime": ts},
                                          {"type": "Progressing", "reason": reason, "lastUpdateTime": ts}]}}
    done = drift_lab.datetime.fromisoformat("2026-10-17T10:00:00Z").timestamp()
    assert drift_lab.settle_wait_s(dep("NewReplicaSetAvailable"), done + 30) == drift_lab.PRE_SETTLE_S - 30
    assert drift_lab.settle_wait_s(dep("NewReplicaSetAvailable"), done + 999) == 0.0    # long settled
    assert drift_lab.settle_wait_s(dep("ReplicaSetUpdated"), done) == 0.0              # stuck/rolling: no completion
    assert drift_lab.settle_wait_s({}, done) == 0.0


def test_weights_table_covers_every_family_and_favours_subtle_slowdowns():
    assert drift_lab.WEIGHTS.keys() == drift_lab.FAMILIES.keys() and all(w > 0 for w in drift_lab.WEIGHTS.values())
    assert max(drift_lab.WEIGHTS, key=drift_lab.WEIGHTS.get) == "cpu_throttle"


def test_absolute_limit_targets_and_requests_clamped():
    import random
    base = drift_lab.canonical_spec(drift_lab.deployment("lab-00", drift_lab.variant(random.Random(1))))
    c = drift_lab.apply_ops(base, [{"op": "cpu_limit", "m": 8}, {"op": "mem_limit", "mi": 12}])[
        "template"]["spec"]["containers"][0]["resources"]
    assert c["limits"] == {"cpu": "8m", "memory": "12Mi"}
    assert drift_lab.parse_cpu(c["requests"]["cpu"]) <= 0.008 and c["requests"]["memory"] == "12Mi"
    r = random.Random(0)
    assert {drift_lab.FAMILIES["cpu_throttle"](r)["m"] for _ in range(200)} <= {5, 8, 10, 12, 15, 18, 22}
    assert {drift_lab.FAMILIES["mem_pressure"](r)["mi"] for _ in range(200)} <= {30, 32, 34}
