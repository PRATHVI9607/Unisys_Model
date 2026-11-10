"""P7-RR-8: the Executor validates stream fields, records every step through record_step and escalates."""
import asyncio
import json
import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import remediation_fakes as fk
from agents.executor.main import ACTIONS_STREAM, ESCALATIONS_STREAM, ExecutorService
from agents.executor.support import Recorder, needs_escalation
from agents.executor.validation import parse_request

INC = "inc-20261110-101500-ab12cd"


def run(c):
    return asyncio.run(c)


def ok_fields(**kw):
    f = {"action": "contain", "namespace": "prod", "deployment": "db", "pod": "db-abc-1", "incident_id": INC}
    f.update(kw)
    return f


@pytest.mark.parametrize("changes,reason", [
    ({"action": "delete"}, "unknown action"),
    ({"action": ""}, "unknown action"),
    ({"namespace": "Prod_1"}, "invalid namespace"),
    ({"incident_id": ""}, "incident_id"),
    ({"incident_id": "Bad ID"}, "incident_id"),
    ({"deployment": "Web!"}, "invalid deployment"),
    ({"pod": "-x"}, "invalid pod"),
    ({"pod": "web-abc-1", "deployment": "db"}, "does not belong"),
    ({"pod": "database-1"}, "does not belong"),          # same prefix text, not the workload's pods
    ({"pod": ""}, "needs a pod"),
    ({"workload_kind": "DaemonSet"}, "workload_kind"),
    ({"t0_ms": "yesterday"}, "t0_ms"),
    ({"t0_ms": "-5"}, "t0_ms"),
])
def test_malformed_requests_are_refused(changes, reason):
    status, why, _ = parse_request(ok_fields(**changes))
    assert status == "refused" and reason in why


def test_patch_rules_pod_may_be_empty_but_must_belong_and_deployment_is_required():
    base = {"action": "patch", "namespace": "prod", "deployment": "web", "pod": "", "patch_field": "a.b",
            "incident_id": INC}
    assert parse_request(base)[0] == "ok"
    assert parse_request(dict(base, pod="web-abc-1"))[0] == "ok"
    assert parse_request(dict(base, pod="api-abc-1"))[0] == "refused"
    assert parse_request(dict(base, deployment=""))[0] == "refused"
    assert parse_request(dict(base, workload_kind="StatefulSet"))[0] == "refused"
    for empty in ("", "unknown", "UNKNOWN"):
        status, why, _ = parse_request(dict(base, patch_field=empty))
        assert status == "escalate" and why.startswith("no_patch_field")


def test_restore_needs_t0_and_never_guesses_it():
    f = ok_fields(action="restore")
    status, why, _ = parse_request(f)
    assert status == "escalate" and why.startswith("t0_missing")
    status, _, req = parse_request(dict(f, t0_ms="1700000000000"))
    assert status == "ok" and req.t0_ms == 1700000000000


def test_dry_run_flag_is_parsed():
    assert parse_request(ok_fields(dry_run="true"))[2].dry_run is True
    assert parse_request(ok_fields())[2].dry_run is False


def make_ex(cluster=None, **kw):
    c = cluster or fk.Cluster()
    redis = fk.Redis()
    steps = []
    ex = ExecutorService(redis=redis, core_api=c.core, apps_api=c.apps, networking_api=c.net,
                         custom_api=c.custom, mode=fk.Mode(), record_step=lambda i, s, p: steps.append((i, s, p)),
                         **kw)
    return ex, c, redis, steps


def test_refusals_touch_nothing_and_are_recorded_with_an_outcome():
    ex, c, redis, steps = make_ex()
    for bad in (ok_fields(action="drop"), ok_fields(pod="web-1"), ok_fields(namespace="kube-system"),
                ok_fields(namespace="default")):
        assert run(ex.handle_entry("kubeheal.exec", "1-0", bad))
    assert c.log == []
    outcomes = [f["outcome"] for f in redis.stream(ACTIONS_STREAM)]
    assert len(outcomes) == 4 and all(o.startswith("refused:") for o in outcomes)
    assert redis.stream(ESCALATIONS_STREAM) == []                       # refusals are not escalations
    assert [s for _, s, _ in steps].count("refused") == 4


def test_t0_missing_is_recorded_and_sent_to_a_human():
    ex, c, redis, steps = make_ex()
    run(ex.handle_entry("kubeheal.exec", "1-0", ok_fields(action="restore")))
    assert c.log == []
    assert redis.stream(ACTIONS_STREAM)[-1]["outcome"].startswith("escalated:t0_missing")
    esc = redis.stream(ESCALATIONS_STREAM)
    assert len(esc) == 1 and esc[0]["required"] == "human" and esc[0]["incident_id"] == INC


def test_record_step_accepts_async_callbacks_and_survives_a_failing_one():
    got = []

    async def async_cb(i, s, p):
        got.append(s)
    run(Recorder(async_cb, INC)("x", {}))
    assert got == ["x"]

    def broken(i, s, p):
        raise RuntimeError("ledger down")
    run(Recorder(broken, INC)("x", {}))                                  # must not raise

    ex, c, redis, steps = make_ex()
    ex.record_step = broken
    out = run(ex.execute(ok_fields(action="bogus")))
    assert out.startswith("refused:")


def test_default_record_step_uses_the_shared_ledger():
    from agents.common.ledger import InMemoryLedgerStore, Ledger

    store = InMemoryLedgerStore()
    ex = ExecutorService(redis=fk.Redis(), mode=fk.Mode(), ledger=Ledger(store))
    assert callable(ex.record_step)
    assert run(ex.execute(ok_fields(action="bogus"))).startswith("refused:")
    assert [json.loads(value)["step"] for value in store.objects.values()] == ["refused"]


def test_every_step_and_the_result_are_recorded_for_a_dry_run_contain():
    c = fk.Cluster()
    fk.add_db_workload(c)
    ex, c, redis, steps = make_ex(c)
    ex.mode = fk.Mode(dry=True)
    out = run(ex.execute(ok_fields()))
    assert out.startswith("DRY RUN: would have CONTAIN prod/db-abc-1") and c.log == []
    names = [s for _, s, _ in steps]
    assert names[0] == "request_accepted" and "blocked" in names and names[-1] == "result"
    assert steps[-1][2]["outcome"] == out and all(i == INC for i, _, _ in steps)


def test_escalation_outcome_classifier():
    for o in ("stopped_mode_test: x", "escalated:y", "rolled_back:z", "contain_failed:q", "restore_failed:r",
              "restored_kept_isolated:s", "contained_with_gaps:g", "patch_failed:p", "no_baseline_escalated"):
        assert needs_escalation(o), o
    for o in ("contained", "restored", "patched_kept", "refused:x", "DRY RUN: would have PATCH x"):
        assert not needs_escalation(o), o


def test_the_consume_loop_does_not_serialise_requests():
    """A canary watch lasts several windows: entries must run as separate tasks so a containment
    request queued behind it is not delayed."""
    src = inspect.getsource(ExecutorService._consume)
    assert "create_task(self.handle_entry" in src


def test_concurrent_patch_and_restore_on_one_workload_are_serialised():
    ex, *_ = make_ex()
    assert ex._lock("prod", "web") is ex._lock("prod", "web") and ex._lock("prod", "web") is not ex._lock("prod", "db")


def test_to_dict_reuses_one_serializer_instead_of_opening_a_session_per_call():
    from agents.executor import support
    from kubernetes_asyncio import client

    built = []

    class Spy(client.ApiClient):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            built.append(self)

    async def go():
        support._serializer = None
        orig, client.ApiClient = client.ApiClient, Spy
        try:
            pod = client.V1Pod(metadata=client.V1ObjectMeta(name="x", labels={"a": "b"}))
            for _ in range(3):
                assert support.to_dict(pod)["metadata"]["name"] == "x"
        finally:
            client.ApiClient = orig
            await support._serializer.close()
            support._serializer = None
    run(go())
    assert len(built) == 1


def test_kind_given_is_tracked():
    assert parse_request(ok_fields())[2].kind_given is False
    assert parse_request(ok_fields(workload_kind="StatefulSet"))[2].kind_given is True


def test_refused_requests_are_counted_as_refused_not_success():
    import agents.executor.main as m
    from agents.common.metrics import KubeHealMetrics
    seen = []

    class M(KubeHealMetrics):
        def record_action(self, action, outcome):
            seen.append((action, outcome))
    old = m.METRICS
    m.METRICS = M()
    try:
        class R:
            async def get(self, *a): return None          # P6-R1: result marker lookup
            async def set(self, *a, **k): return True
            async def xack(self, *a): return 1
            async def xadd(self, *a, **k): return "1-0"
        ex = m.ExecutorService(redis=R(), ledger=type("L", (), {"append": lambda *a, **k: None})())
        ok = asyncio.run(ex.handle_entry("kubeheal.exec", "1-0",
                                          {"action": "patch", "namespace": "kube-system", "deployment": "x"}))
    finally:
        m.METRICS = old
    assert ok is True and seen == [("patch", "refused")]


# ---- owner-chosen Executor defaults (2026-11-11): chosen, not measured; fail closed if set empty ----
def test_process_environment_gets_the_chosen_defaults(monkeypatch):
    from agents.executor.config import ExecConfig
    for name in ("CANARY_WINDOW_S", "ROLLOUT_TIMEOUT_S", "ROLLOUT_POLL_S", "SNAPSHOT_CLASS", "PROMETHEUS_URL"):
        monkeypatch.delenv(name, raising=False)
    c = ExecConfig()
    assert (c.canary_window_s, c.rollout_timeout_s, c.rollout_poll_s) == (30.0, 180.0, 5.0)
    assert c.snapshot_class == "csi-hostpath-snapclass"
    assert c.prometheus_url == "http://prometheus-operated.monitoring.svc.cluster.local:9090"


def test_defaults_are_tunable_and_an_empty_value_still_fails_closed(monkeypatch):
    from agents.executor.config import ConfigMissing, ExecConfig
    monkeypatch.setenv("CANARY_WINDOW_S", "12")
    monkeypatch.setenv("SNAPSHOT_CLASS", "")          # set but empty: not replaced by the default
    c = ExecConfig()
    assert c.canary_window_s == 12.0
    with pytest.raises(ConfigMissing):
        c.snapshot_class
    monkeypatch.setenv("ROLLOUT_POLL_S", "0")
    with pytest.raises(ConfigMissing):
        c.rollout_poll_s


def test_an_explicit_mapping_has_no_defaults():
    from agents.executor.config import ConfigMissing, ExecConfig
    with pytest.raises(ConfigMissing):
        ExecConfig({}).canary_window_s
    assert ExecConfig({}, use_defaults=True).canary_window_s == 30.0
