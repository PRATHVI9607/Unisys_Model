"""P3 kill switch: pure rules, watcher state, policy input, Executor gate, mid-action stop,
and a live Watch-API check on the k3d cluster (skipped when the cluster is unreachable)."""
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from agents.common import killswitch as ks
from agents.executor import actions
from agents.executor.main import ExecutorService, ESCALATIONS_STREAM, ACTIONS_STREAM
from agents.fusion_agent import decision_policy as dp
from agents.common.ledger import InMemoryLedgerStore, Ledger


def run(c):
    return asyncio.run(c)


# ---- pure rules -------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("enforce", "enforce"), (" Enforce ", "enforce"), ("ENFORCE", "enforce"),
    ("test", "test"), ("", "test"), ("yes", "test"), ("true", "test"), (None, "test"), (1, "test"),
])
def test_normalize_only_exact_enforce_enforces(value, expected):
    assert ks.normalize(value) == expected


def test_effective_mode_truth_table():
    assert ks.effective_mode("enforce", None, True) == "enforce"
    assert ks.effective_mode("enforce", "enforce", True) == "enforce"
    assert ks.effective_mode("enforce", "test", True) == "test"        # namespace can be stricter
    assert ks.effective_mode("enforce", "garbage", True) == "test"
    assert ks.effective_mode("test", "enforce", True) == "test"        # label cannot override global test
    assert ks.effective_mode("test", None, True) == "test"
    assert ks.effective_mode("enforce", None, False) == "test"         # unreadable
    assert ks.effective_mode(None, None, True) == "test"               # never read


# ---- watcher state -----------------------------------------------------------
def cm(mode):
    return NS(data={"mode": mode} if mode is not None else {})


def ns_obj(name, label=None):
    return NS(metadata=NS(name=name, labels={ks.NAMESPACE_LABEL: label} if label else {}))


def ready_watcher():
    w = ks.ModeWatcher()
    w.ns_readable = True
    return w


def test_fresh_watcher_is_test():
    w = ks.ModeWatcher()
    assert w.mode_for("prod") == "test" and w.dry_run_for("prod") is True


def test_configmap_enforce_then_test_and_history():
    changes = []
    w = ks.ModeWatcher(on_change=lambda o, n, s: changes.append((o, n)))
    w.ns_readable = True
    w.apply_configmap(cm("enforce"))
    assert w.mode_for("prod") == "enforce"
    w.apply_configmap(cm("test"))
    assert w.mode_for("prod") == "test"
    assert changes == [(None, "enforce"), ("enforce", "test")]
    assert [h["to"] for h in w.history] == ["enforce", "test"]


def test_namespace_label_can_make_one_namespace_test():
    w = ready_watcher()
    w.apply_configmap(cm("enforce"))
    w.apply_namespace(ns_obj("prod", "test"))
    assert w.mode_for("prod") == "test" and w.mode_for("staging") == "enforce"
    w.apply_namespace(ns_obj("prod"))                     # label removed
    assert w.mode_for("prod") == "enforce"


def test_namespace_label_cannot_enable_enforce_when_global_is_test():
    w = ready_watcher()
    w.apply_configmap(cm("test"))
    w.apply_namespace(ns_obj("prod", "enforce"))
    assert w.mode_for("prod") == "test"


@pytest.mark.parametrize("event", ["deleted", "missing_key", "garbage", "unreadable"])
def test_unreadable_or_invalid_means_test(event):
    w = ready_watcher()
    w.apply_configmap(cm("enforce"))
    assert w.mode_for("prod") == "enforce"
    if event == "deleted":
        w.apply_configmap_deleted()
    elif event == "missing_key":
        w.apply_configmap(cm(None))
    elif event == "garbage":
        w.apply_configmap(cm("on"))
    else:
        w.mark_unreadable("api down")
    assert w.mode_for("prod") == "test"


def test_namespace_labels_unknown_means_test():
    w = ks.ModeWatcher()
    w.apply_configmap(cm("enforce"))      # namespaces never loaded (ns_readable False)
    assert w.mode_for("prod") == "test"


# ---- policy ---------------------------------------------------------------------
def test_policy_default_is_dry_run_and_mode_is_an_input():
    base = dict(health_risk=0.79, sec_risk=0.1, namespace_tier="prod", health_field_top="cpu")
    out = dp.make_decision(dp.DecisionInput(**base))
    assert out.dry_run is True
    assert dp.make_decision(dp.DecisionInput(mode="enforce", **base)).dry_run is False
    assert dp.make_decision(dp.DecisionInput(mode="whatever", **base)).dry_run is True
    # Sense, Score and Decide are unaffected by the mode
    assert out.decision == dp.make_decision(dp.DecisionInput(mode="enforce", **base)).decision \
        == dp.Decision.AUTO_PATCH


# ---- actions and gate ---------------------------------------------------------------
class Net:
    def __init__(self):
        self.created = []

    async def create_namespaced_network_policy(self, ns, body):
        self.created.append(ns)


class Core:
    def __init__(self):
        self.deleted = []
        self.patched = []

    async def read_namespaced_pod(self, name, ns):
        return {"metadata": {"ownerReferences": []}, "spec": {"volumes": []}}

    async def patch_namespaced_pod(self, name, ns, body):
        self.patched.append((name, body))

    async def delete_namespaced_pod(self, name, ns, grace_period_seconds=None):
        self.deleted.append(name)


class Apps:
    def __init__(self):
        self.patched = []

    async def patch_namespaced_deployment(self, name, ns, body):
        self.patched.append(name)


class Gate:
    def __init__(self, allow_calls):
        self.calls, self.allow_calls = 0, allow_calls

    def allow_write(self, ns):
        self.calls += 1
        return self.calls <= self.allow_calls


async def _noop_write(log, name):
    log.append(name)
    return name


def test_write_gate_blocks_in_test_mode_and_never_calls_the_api():
    calls = []
    gate = Gate(0)
    with pytest.raises(actions.ModeBlocked) as e:
        run(actions._write(gate, "prod", "patch_deployment", _noop_write, calls, "x"))
    assert e.value.step == "patch_deployment" and calls == []


def test_missing_gate_blocks():
    calls = []
    with pytest.raises(actions.ModeBlocked):
        run(actions._write(None, "prod", "step", _noop_write, calls, "x"))
    assert calls == []


def test_gate_is_checked_before_every_write_and_a_mid_sequence_switch_stops_the_next_one():
    calls = []
    gate = Gate(allow_calls=1)          # first write allowed, mode flips to test before the second
    assert run(actions._write(gate, "prod", "one", _noop_write, calls, "a")) == "a"
    with pytest.raises(actions.ModeBlocked) as e:
        run(actions._write(gate, "prod", "two", _noop_write, calls, "b"))
    assert e.value.step == "two" and calls == ["a"] and gate.calls == 2


def test_blocked_outcome_text_dry_run_vs_mid_action():
    b = actions.ModeBlocked("create_networkpolicy")
    assert actions._blocked_outcome("CONTAIN prod/web-1", ["a", "b"], [], b).startswith(
        "DRY RUN: would have CONTAIN prod/web-1")
    assert actions._blocked_outcome("CONTAIN prod/web-1", ["a", "b"], ["a"], b).startswith(
        "stopped_mode_test")


# Dry run, mid-action stop and fail-safe for the dispatched paths are tested next to them:
# tests/test_remediation_drift.py (canary patch) and tests/test_remediation_ransomware.py
# (contain, restore, snapshot scheduler).


# ---- Executor integration ---------------------------------------------------------------
class Redis:
    def __init__(self):
        self.added, self.acked, self.store = [], [], {}

    async def xadd(self, s, f):
        self.added.append((s, f))

    async def xack(self, s, g, i):
        self.acked.append(i)

    async def get(self, k):
        return self.store.get(k)


class FlippingMode:
    """enforce for the first N checks, then test."""

    def __init__(self, n):
        self.n, self.calls = n, 0

    def dry_run_for(self, ns):
        self.calls += 1
        return self.calls > self.n


def test_executor_dry_run_request_from_fusion_wins_even_in_enforce():
    r, core, net = Redis(), Core(), Net()
    ex = ExecutorService(redis=r, core_api=core, networking_api=net, mode=FlippingMode(99))
    ok = run(ex.handle_entry("kubeheal.exec", "1-0", {"action": "contain", "namespace": "prod", "pod": "p",
                                                      "dry_run": "true", "incident_id": "inc-9"}))
    assert ok and core.deleted == [] and net.created == []
    rec = [f for s, f in r.added if s == ACTIONS_STREAM][0]
    assert rec["outcome"].startswith("DRY RUN: would have CONTAIN prod/p")


def test_executor_mid_action_switch_escalates_to_human():
    r, core, net = Redis(), Core(), Net()
    ex = ExecutorService(redis=r, core_api=core, networking_api=net, mode=FlippingMode(1))
    run(ex.handle_entry("kubeheal.exec", "2-0", {"action": "contain", "namespace": "prod", "pod": "p",
                                                 "incident_id": "inc-10"}))
    assert core.deleted == [] and net.created == ["prod"]
    esc = [f for s, f in r.added if s == ESCALATIONS_STREAM]
    assert len(esc) == 1 and esc[0]["required"] == "human" and esc[0]["incident_id"] == "inc-10"


def test_executor_reads_the_mode_itself():
    """An executor with no mode information (fresh watcher) never writes."""
    r, core, net = Redis(), Core(), Net()
    ex = ExecutorService(redis=r, core_api=core, networking_api=net)      # real, unread ModeWatcher
    run(ex.handle_entry("kubeheal.exec", "3-0", {"action": "contain", "namespace": "prod", "pod": "p"}))
    assert core.deleted == [] and net.created == []


def test_executor_records_dry_run_step_and_result():
    store = InMemoryLedgerStore()
    ex = ExecutorService(redis=Redis(), core_api=Core(), networking_api=Net(),
                         mode=FlippingMode(99), ledger=Ledger(store))
    run(ex.handle_entry("kubeheal.exec", "4-0", {
        "action": "contain", "namespace": "prod", "pod": "p",
        "dry_run": "true", "incident_id": "inc-dry",
    }))

    records = [json.loads(store.objects[key]) for key in sorted(store.objects)]
    assert [record["step"] for record in records] == [
        "request_accepted", "blocked", "result", "executor_result"
    ]
    assert records[1]["payload"]["step"] == "create_quarantine_policy"
    assert records[2]["payload"]["outcome"].startswith("DRY RUN: would have CONTAIN")


def test_executor_records_mid_action_steps_and_escalation():
    store = InMemoryLedgerStore()
    core = Core()
    ex = ExecutorService(redis=Redis(), core_api=core, networking_api=Net(),
                         mode=FlippingMode(1), ledger=Ledger(store))
    run(ex.handle_entry("kubeheal.exec", "5-0", {
        "action": "contain", "namespace": "prod", "pod": "p", "incident_id": "inc-stop",
    }))

    records = [json.loads(store.objects[key]) for key in sorted(store.objects)]
    assert [record["step"] for record in records] == [
        "request_accepted", "quarantine_policy_created", "blocked",
        "result", "executor_escalation", "executor_result",
    ]
    assert records[2]["payload"]["step"] == "label_pod"
    assert records[4]["payload"]["required"] == "human"
    assert core.patched == [] and core.deleted == []


def test_executor_mode_watcher_change_is_written_to_ledger():
    store = InMemoryLedgerStore()
    ex = ExecutorService(redis=Redis(), ledger=Ledger(store))
    ex.mode.apply_configmap(NS(data={"mode": "enforce"}))

    records = [json.loads(value) for value in store.objects.values()]
    assert len(records) == 1
    assert records[0]["step"] == "mode_change"
    assert records[0]["payload"] == {"from": None, "to": "enforce", "source": "configmap"}


# ---- static: every write method inside the executor only goes through _write -----------------------
def test_executor_write_methods_only_passed_to_write_gate():
    import ast
    import re
    pat = re.compile(r"^(create|patch|delete|replace)_(namespaced_\w+|namespace|node)$")
    for f in (ROOT / "agents" / "executor").glob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and pat.match(node.attr):
                parent = parents[node]
                ok = (isinstance(parent, ast.Call) and node in parent.args and
                      isinstance(parent.func, ast.Name) and parent.func.id == "_write")
                assert ok, f"{f.name}:{node.lineno} {node.attr} is not routed through _write"


# ---- live: Watch API on k3d ----------------------------------------------------------------------
def _kubectl(*args):
    return subprocess.run(["kubectl", "--context", "k3d-kubeheal", *args], capture_output=True,
                          text=True, timeout=30)


def _cluster_ok():
    try:
        return _kubectl("get", "--raw", "/readyz").returncode == 0
    except Exception:
        return False


def _patch_mode(value):
    r = _kubectl("-n", "kubeheal", "patch", "cm", "kubeheal-mode", "--type", "merge", "-p",
                 json.dumps({"data": {"mode": value}}))
    assert r.returncode == 0, r.stderr


def _ns_label(ns):
    r = _kubectl("get", "ns", ns, "-o", "json")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["metadata"].get("labels", {}).get("kubeheal/mode")


@pytest.mark.skipif(not _cluster_ok(), reason="k3d-kubeheal cluster not reachable")
def test_live_watch_follows_configmap_without_polling():
    from kubernetes_asyncio import client, config

    async def go():
        await config.load_kube_config(context="k3d-kubeheal")
        api = client.ApiClient()
        w = ks.ModeWatcher()
        await w.start(client.CoreV1Api(api))

        async def wait_for(expect, secs=20):
            t0 = time.time()
            while time.time() - t0 < secs:
                if w.mode_for("prod") == expect:
                    return time.time() - t0
                await asyncio.sleep(0.1)
            return None

        original = json.loads(_kubectl("-n", "kubeheal", "get", "cm", "kubeheal-mode",
                                       "-o", "json").stdout)["data"]["mode"]
        original_label = _ns_label("prod")      # restored exactly as found
        try:
            _patch_mode("test")
            assert await wait_for("test") is not None
            _patch_mode("enforce")
            assert await wait_for("enforce") is not None
            _patch_mode("test")
            assert await wait_for("test") is not None
            r = _kubectl("label", "ns", "prod", "kubeheal/mode=test", "--overwrite")
            assert r.returncode == 0, r.stderr
            _patch_mode("enforce")
            await asyncio.sleep(2)
            assert w.mode_for("prod") == "test" and w.mode_for("staging") == "enforce"
        finally:
            if original_label is None:
                _kubectl("label", "ns", "prod", "kubeheal/mode-")
            else:
                _kubectl("label", "ns", "prod", f"kubeheal/mode={original_label}", "--overwrite")
            _patch_mode(original)
            await w.stop()
            await api.close()

    run(go())
