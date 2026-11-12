"""P7-RR-1 and P7-RR-2: drift canary path with fake Kubernetes clients and an injected metric source."""
import asyncio
import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import remediation_fakes as fk
from agents.executor import drift
from agents.executor.config import ExecConfig
from agents.executor.main import ACTIONS_STREAM, ESCALATIONS_STREAM, ExecutorService
from agents.executor.metrics_source import PrometheusMetricSource, queries
from agents.executor.support import Recorder
from agents.executor.validation import Request
from agents.health_agent.baseline import drift_view

CPU = "template.spec.containers[0].resources.limits.cpu"
ENV = {"CANARY_WINDOW_S": "7", "ROLLOUT_TIMEOUT_S": "50", "ROLLOUT_POLL_S": "5"}


def run(c):
    return asyncio.run(c)


class Scenario:
    """Golden = cpu 500m / memory 256Mi. Live = cpu 50m (the drift) and memory 64Mi (an unrelated change)."""

    def __init__(self, metrics_before=None, metrics_after=None, env=ENV, gate=None, **dep_kw):
        self.c, self.clock, self.redis = fk.Cluster(), fk.Clock(), fk.Redis()
        golden_dep = fk.deployment_obj("web", cpu="500m", memory="256Mi", **dep_kw)
        self.golden = fk.golden_record(golden_dep)
        live = fk.deployment_obj("web", cpu="50m", memory="64Mi", **dep_kw)
        self.c.workloads[("Deployment", "web")] = live
        self.live_before = copy.deepcopy(drift_view(live["spec"]))
        self.records = []
        self.rec = Recorder(lambda i, s, p: self.records.append((s, p)), "inc-1")
        self.before = metrics_before if metrics_before is not None else {
            "http_p99_latency_ms": 200.0, "cpu_throttle_percent": 40.0}
        self.after = metrics_after if metrics_after is not None else [
            {"http_p99_latency_ms": 90.0, "cpu_throttle_percent": 0.0}] * 3
        self.calls = []
        self.gate = gate if gate is not None else fk.Gate()
        self.env = env

        async def source(ns, dep, window_s):
            self.calls.append((ns, dep, window_s))
            if len(self.calls) == 1:
                return self.before
            return self.after[min(len(self.calls) - 2, len(self.after) - 1)]
        self.source = source

    def go(self, field=CPU, source="default", **req_kw):
        req = Request(action="patch", namespace="prod", incident_id="inc-1", deployment="web",
                      patch_field=field, **req_kw)
        src = self.source if source == "default" else source
        return run(drift.canary_patch(self.gate, self.c.apps, req, self.golden, self.rec, src,
                                      drift.RollbackStore(self.redis), ExecConfig(self.env),
                                      self.clock.sleep, self.clock))

    def live_spec(self):
        return drift_view(self.c.workloads[("Deployment", "web")]["spec"])

    def steps(self):
        return [s for s, _ in self.records]


# ---- pure patch building ------------------------------------------------------------------------
def test_patch_touches_only_the_requested_field_and_forces_max_unavailable_zero():
    s = Scenario()
    plan = drift.build_patch(s.golden["spec"], s.live_before, CPU)
    paths = [o["path"] for o in plan.forward if o["op"] != "test"]
    assert "/spec/template/spec/containers/0/resources/limits/cpu" in paths
    assert not any("memory" in p for p in paths)                     # unrelated drift is left alone
    assert "/spec/strategy/rollingUpdate/maxUnavailable" in paths
    assert {"op": "test", "path": "/spec/template/spec/containers/0/resources/limits/cpu",
            "value": "50m"} in plan.forward                           # guarded by the live value
    assert plan.drifted == [CPU]


def test_structural_field_restores_the_whole_subtree_below_it():
    s = Scenario()
    plan = drift.build_patch(s.golden["spec"], s.live_before, "template.spec.containers[0].resources.limits")
    paths = [o["path"] for o in plan.forward if o["op"] == "replace"]
    assert any(p.endswith("/limits/cpu") for p in paths) and any(p.endswith("/limits/memory") for p in paths)


def test_dotted_label_keys_are_escaped_in_the_pointer():
    golden = {"template": {"metadata": {"labels": {"app.kubernetes.io/name": "web"}}}, "strategy": {}}
    live = {"template": {"metadata": {"labels": {"app.kubernetes.io/name": "evil"}}}, "strategy": {}}
    plan = drift.build_patch(golden, live, "template.metadata.labels")
    assert "/spec/template/metadata/labels/app.kubernetes.io~1name" in [o["path"] for o in plan.forward]


def test_rollback_patch_restores_the_original_spec_exactly():
    s = Scenario()
    plan = drift.build_patch(s.golden["spec"], s.live_before, CPU)
    doc = {"spec": copy.deepcopy(s.live_before)}
    patched = fk.json_patch(doc, plan.forward)
    assert patched["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"
    assert patched["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0
    assert fk.json_patch(patched, plan.rollback)["spec"] == s.live_before
    restored = fk.json_patch(patched, plan.restore_strategy)["spec"]
    assert restored["strategy"] == s.live_before["strategy"]
    assert restored["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"


def test_recreate_strategy_becomes_rolling_update_with_zero_unavailable():
    s = Scenario()
    live = copy.deepcopy(s.live_before)
    live["strategy"] = {"type": "Recreate"}
    plan = drift.build_patch(s.golden["spec"], live, CPU)
    out = fk.json_patch({"spec": live}, plan.forward)["spec"]["strategy"]
    assert out == {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 0}}


@pytest.mark.parametrize("field", ["", "unknown", "template.spec.containers[0].image"])
def test_plan_errors_when_no_field_or_nothing_drifted_there(field):
    s = Scenario()
    with pytest.raises(drift.PlanError):
        drift.build_patch(s.golden["spec"], s.live_before, field)


def test_improved_rule_is_relative_and_missing_means_not_improved():
    b = {"http_p99_latency_ms": 200.0, "cpu_throttle_percent": 40.0}
    assert drift.improved(b, {"http_p99_latency_ms": 100.0, "cpu_throttle_percent": 40.0})[0]
    assert not drift.improved(b, {"http_p99_latency_ms": 100.0, "cpu_throttle_percent": 41.0})[0]
    assert not drift.improved(b, {"http_p99_latency_ms": 200.0, "cpu_throttle_percent": 40.0})[0]   # equal
    assert not drift.improved(b, {"http_p99_latency_ms": None, "cpu_throttle_percent": 0.0})[0]
    assert drift.improved({"http_p99_latency_ms": None, "cpu_throttle_percent": 40.0},
                          {"http_p99_latency_ms": None, "cpu_throttle_percent": 1.0})[0]
    assert not drift.improved({}, {"http_p99_latency_ms": 1.0})[0]


# ---- the path -----------------------------------------------------------------------------------------
def test_canary_keeps_when_improved_in_three_windows():
    s = Scenario()
    assert s.go() == "patched_kept"
    live = s.live_spec()
    assert live["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"
    assert live["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] == "64Mi"
    assert live["strategy"] == s.live_before["strategy"]            # maxUnavailable 0 was only for the rollout
    assert len(s.c.writes()) == 2                                    # patch + strategy restore
    assert len(s.calls) == 4                                         # 1 before + 3 windows
    assert s.clock.sleeps.count(7) == 3                              # three windows of CANARY_WINDOW_S
    assert s.steps().index("rollback_point_saved") < s.steps().index("patched")
    saved = run(drift.RollbackStore(s.redis).load("prod", "web"))
    assert saved["live_spec"] == s.live_before and saved["rollback"]


def test_pending_canary_after_restart_applies_saved_rollback_and_waits():
    s = Scenario()
    plan = drift.build_patch(s.golden["spec"], s.live_before, CPU)
    obj = s.c.workloads[("Deployment", "web")]
    patched = fk.json_patch(obj, plan.forward)
    obj.clear()
    obj.update(patched)
    obj["metadata"]["generation"] += 1
    obj["status"].update({"observedGeneration": obj["metadata"]["generation"]})
    run(drift.RollbackStore(s.redis).save("prod", "web", {
        "incident_id": "inc-1", "live_spec": s.live_before,
        "rollback": plan.rollback, "restore_strategy": plan.restore_strategy,
        "saved_at": s.clock(), "state": "pending"}))

    assert s.go() == "rolled_back:executor_restart_recovery"
    assert s.live_spec() == s.live_before
    assert s.calls == []
    assert s.steps()[-1] == "rollback_recovered_after_restart"
    assert run(drift.RollbackStore(s.redis).load("prod", "web"))["state"] == "recovered"


def test_pending_rollback_from_another_incident_blocks_new_canary():
    s = Scenario()
    run(drift.RollbackStore(s.redis).save("prod", "web", {
        "incident_id": "inc-old", "rollback": [{"op": "replace", "path": "/spec/x", "value": 1}],
        "state": "pending"}))
    assert s.go().startswith("escalated:rollback_recovery_required")
    assert s.c.writes() == [] and s.calls == []


def test_canary_rolls_back_on_a_worse_window_and_restores_the_exact_spec():
    worse = {"http_p99_latency_ms": 300.0, "cpu_throttle_percent": 0.0}
    good = {"http_p99_latency_ms": 90.0, "cpu_throttle_percent": 0.0}
    s = Scenario(metrics_after=[good, worse])
    out = s.go()
    assert out.startswith("rolled_back:window 2")
    assert s.live_spec() == s.live_before
    bad_window = [payload for step, payload in s.records if step == "canary_window" and payload["window"] == 2][0]
    assert bad_window["why"] == "http_p99_latency_ms worse: 300.0 > 200.0"
    saved = run(drift.RollbackStore(s.redis).load("prod", "web"))
    assert saved["state"] == "rolled_back" and saved["live_spec"] == s.live_before
    assert s.steps()[-1] == "rolled_back"


def test_canary_rolls_back_when_a_metric_is_missing_after_the_patch():
    s = Scenario(metrics_after=[{"http_p99_latency_ms": None, "cpu_throttle_percent": 0.0}])
    assert s.go().startswith("rolled_back:window 1")
    assert s.live_spec() == s.live_before


def test_canary_rolls_back_when_the_rollout_never_settles():
    s = Scenario()
    s.c.stuck_rollout = True
    out = s.go()
    assert out.startswith("patch_failed:rollback rollout did not settle")
    assert s.live_spec() == s.live_before
    assert len(s.calls) == 1                                         # no canary windows were observed


@pytest.mark.parametrize("kwargs,prefix", [
    (dict(source=None), "escalated:no_metric_source"),
    (dict(env={}), "escalated:config_missing:CANARY_WINDOW_S"),
    (dict(env={"CANARY_WINDOW_S": "7", "ROLLOUT_POLL_S": "5"}), "escalated:config_missing:ROLLOUT_TIMEOUT_S"),
])
def test_missing_prerequisites_escalate_before_any_write(kwargs, prefix):
    src = kwargs.pop("source", "default")
    s = Scenario(**kwargs)
    assert s.go(source=src).startswith(prefix)
    assert s.c.writes() == [] and run(drift.RollbackStore(s.redis).load("prod", "web")) is None


def test_no_pre_patch_reading_escalates_without_writing():
    s = Scenario(metrics_before={"http_p99_latency_ms": None, "cpu_throttle_percent": None})
    assert s.go().startswith("escalated:no_pre_patch_metrics")
    assert s.c.writes() == []


def test_nothing_drifted_at_the_field_escalates_without_writing():
    s = Scenario()
    assert s.go(field="template.spec.containers[0].image").startswith("escalated:no_drift_at_field")
    assert s.c.writes() == []


def test_max_surge_zero_escalates_without_writing():
    s = Scenario(max_surge="0")
    assert s.go().startswith("escalated:max_surge_zero")
    assert s.c.writes() == []


def test_rollback_point_that_cannot_be_saved_blocks_the_patch():
    s = Scenario()
    s.redis = None                       # no store
    assert s.go().startswith("escalated:rollback_point_not_saved")
    assert s.c.writes() == []


def test_dry_run_writes_nothing_and_says_would_have():
    s = Scenario(gate=fk.Gate(allow=0))
    out = s.go()
    assert out.startswith("DRY RUN: would have PATCH prod/web (patch_deployment)")
    assert s.c.writes() == [] and s.live_spec() == s.live_before


def test_mode_flip_after_the_patch_stops_the_watch_and_escalates():
    gate = fk.ToggleGate()
    s = Scenario(gate=gate)
    orig = s.source

    async def flipping(ns, dep, w):
        res = await orig(ns, dep, w)
        if len(s.calls) == 2:
            gate.on = False              # test mode arrives during window 1
        return res
    out = s.go(source=flipping)
    assert out.startswith("stopped_mode_test") and "window 2" in out
    assert len(s.c.writes()) == 1        # only the patch; no strategy restore, no rollback


def test_mode_flip_while_canary_fails_reports_that_the_rollback_was_not_applied():
    gate = fk.ToggleGate()
    s = Scenario(gate=gate, metrics_after=[{"http_p99_latency_ms": 999.0, "cpu_throttle_percent": 99.0}])
    orig = s.source

    async def flipping(ns, dep, w):
        res = await orig(ns, dep, w)
        if len(s.calls) == 2:
            gate.on = False
        return res
    out = s.go(source=flipping)
    assert out.startswith("stopped_mode_test") and "rollback was not applied" in out
    assert len(s.c.writes()) == 1


def test_executor_escalates_on_rollback_and_records_every_step():
    s = Scenario(metrics_after=[{"http_p99_latency_ms": 999.0, "cpu_throttle_percent": 99.0}])
    s.redis.store["kubeheal:baseline:prod:web"] = __import__("json").dumps(s.golden)
    steps = []
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(), metric_source=s.source,
                         cfg=ExecConfig(ENV), sleep=s.clock.sleep, clock=s.clock,
                         record_step=lambda i, st, p: steps.append((i, st)))
    ok = run(ex.handle_entry("kubeheal.exec", "1-0", {
        "action": "patch", "namespace": "prod", "deployment": "web", "pod": "", "patch_field": CPU,
        "incident_id": "inc-77"}))
    assert ok
    esc = s.redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human" and esc[0]["reason"].startswith("rolled_back")
    assert s.redis.stream(ACTIONS_STREAM)[-1]["outcome"].startswith("rolled_back")
    names = [st for i, st in steps if i == "inc-77"]
    for needed in ("request_accepted", "plan", "metrics_before", "rollback_point_saved", "patched",
                   "canary_window", "rolled_back", "result"):
        assert needed in names, needed


def test_executor_dry_run_in_test_mode():
    s = Scenario()
    s.redis.store["kubeheal:baseline:prod:web"] = __import__("json").dumps(s.golden)
    ex = ExecutorService(redis=s.redis, apps_api=s.c.apps, mode=fk.Mode(dry=True), metric_source=s.source,
                         cfg=ExecConfig(ENV), sleep=s.clock.sleep, clock=s.clock)
    out = run(ex.execute({"action": "patch", "namespace": "prod", "deployment": "web",
                          "patch_field": CPU, "incident_id": "inc-5"}))
    assert out.startswith("DRY RUN: would have PATCH prod/web") and s.c.writes() == []


# ---- default metric source (Prometheus) -----------------------------------------------------------------
def test_prometheus_source_builds_range_queries_and_never_turns_missing_into_zero():
    seen = []

    async def http(url, params):
        seen.append((url, params["query"]))
        if "histogram_quantile" in params["query"]:
            return {"data": {"result": [{"value": [0, "123.5"]}]}}
        return {"data": {"result": []}}
    out = run(PrometheusMetricSource("http://prom:9090/", http)("prod", "web", 60))
    assert out == {"http_p99_latency_ms": 123.5, "cpu_throttle_percent": None}
    assert all(u == "http://prom:9090/api/v1/query" for u, _ in seen)
    q = queries("prod", "web", 60)
    assert "[60s]" in q["http_p99_latency_ms"] and 'pod=~"web-.*"' in q["cpu_throttle_percent"]


def test_a_metric_source_that_raises_during_a_canary_window_rolls_back():
    s = Scenario()
    state = {"n": 0}

    async def flaky(ns, dep, w):
        state["n"] += 1
        if state["n"] == 1:
            return s.before
        raise RuntimeError("prometheus down")
    out = s.go(source=flaky)
    assert out.startswith("rolled_back:window 1")
    assert "canary_metric_error" in s.steps() and s.steps()[-1] == "rolled_back"
    assert s.live_spec() == s.live_before            # the rollback restored the live spec


# ---- review findings: no pending rollback point when nothing was patched --------------------------------
def _stored(s):
    return run(drift.RollbackStore(s.redis).load("prod", "web"))


def test_dry_run_leaves_no_pending_rollback_point_and_a_later_live_request_patches():
    gate = fk.ToggleGate()
    s = Scenario(gate=gate)
    gate.on = False
    assert s.go().startswith("DRY RUN: would have PATCH prod/web")
    assert (_stored(s) or {}).get("state") != "pending"
    assert s.c.writes() == [] and "rollback_point_saved" not in s.steps()
    gate.on = True
    s.calls.clear()                                      # the metric fake counts calls: next one is "before"
    assert s.go() == "patched_kept"                      # SAME incident id inc-1
    assert "rollback_recovered_after_restart" not in s.steps()
    assert s.live_spec()["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "500m"
    assert _stored(s)["state"] == "kept"


def test_dry_run_does_not_block_a_later_different_incident():
    gate = fk.ToggleGate()
    s = Scenario(gate=gate)
    gate.on = False
    assert s.go().startswith("DRY RUN:")
    gate.on = True
    s.calls.clear()
    req = Request(action="patch", namespace="prod", incident_id="inc-2", deployment="web", patch_field=CPU)
    out = run(drift.canary_patch(s.gate, s.c.apps, req, s.golden, s.rec, s.source,
                                 drift.RollbackStore(s.redis), ExecConfig(s.env), s.clock.sleep, s.clock))
    assert out == "patched_kept"
    assert "rollback_recovery_blocked" not in s.steps()


def test_gate_closing_between_the_save_and_the_patch_closes_the_pending_record():
    s = Scenario(gate=fk.Gate(allow=1))      # first query (before the save) opens, the write gate refuses
    out = s.go()
    assert out.startswith("DRY RUN: would have PATCH")
    assert s.c.writes() == []
    assert _stored(s)["state"] == "failed"
    assert "rollback_point_discarded" in s.steps()


class _ApiError(Exception):
    def __init__(self, status):
        super().__init__(f"api {status}")
        self.status = status


def test_patch_rejected_by_the_api_closes_the_pending_record():
    s = Scenario()

    async def reject(*a, **k):
        raise _ApiError(422)
    s.c.apps.patch_namespaced_deployment = reject
    assert s.go().startswith("patch_failed:")
    assert _stored(s)["state"] == "failed"


def test_ambiguous_patch_failure_keeps_the_pending_record_for_recovery():
    s = Scenario()

    async def timeout(*a, **k):
        raise TimeoutError("connection lost")        # the patch may have been applied
    s.c.apps.patch_namespaced_deployment = timeout
    assert s.go().startswith("patch_failed:")
    assert _stored(s)["state"] == "pending"


def test_rollback_record_without_a_state_is_terminal_not_pending():
    s = Scenario()
    run(drift.RollbackStore(s.redis).save("prod", "web", {
        "incident_id": "inc-old", "rollback": [{"op": "replace", "path": "/spec/x", "value": 1}]}))
    assert s.go() == "patched_kept"
    assert "rollback_recovery_blocked" not in s.steps()
    # the same incident id with a missing state must not trigger the recovery rollback either
    s2 = Scenario()
    run(drift.RollbackStore(s2.redis).save("prod", "web", {
        "incident_id": "inc-1", "rollback": [{"op": "replace", "path": "/spec/x", "value": 1}]}))
    assert s2.go() == "patched_kept" and "rollback_recovered_after_restart" not in s2.steps()
