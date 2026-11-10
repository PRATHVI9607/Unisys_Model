"""P2: the Executor refuses unsafe targets, acts only on queued requests, acks only on success,
and the Fusion Agent never calls the Kubernetes API."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.executor import guard
from agents.executor.main import ExecutorService, EXEC_STREAM, ACTIONS_STREAM
from agents.fusion_agent import agent as fusion
from agents.fusion_agent import decision_policy as dp


def run(c):
    return asyncio.run(c)


class Mode:
    # stand-in for ModeWatcher: enforce unless dry=True
    def __init__(self, dry=False):
        self.dry = dry

    def dry_run_for(self, namespace):
        return self.dry


class FakeRedis:
    def __init__(self, store=None):
        self.store = store or {}
        self.added, self.acked = [], []

    async def get(self, k):
        return self.store.get(k)

    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.store:
            return None
        self.store[k] = v
        return True

    async def incr(self, k):
        self.store[k] = int(self.store.get(k, 0)) + 1
        return self.store[k]

    async def expire(self, k, t):
        return True

    async def xadd(self, stream, fields):
        self.added.append((stream, fields))

    async def xack(self, stream, group, msg_id):
        self.acked.append(msg_id)

    async def eval(self, *a):
        return 1


class FakeApps:
    def __init__(self):
        self.patched = []

    async def patch_namespaced_deployment(self, name, ns, body):
        self.patched.append((name, ns, body))


class FakeCore:
    def __init__(self):
        self.deleted = []

    async def delete_namespaced_pod(self, name, ns, grace_period_seconds=None):
        self.deleted.append((name, ns))


class FakeNet:
    def __init__(self):
        self.created = []

    async def create_namespaced_network_policy(self, ns, body):
        self.created.append(ns)


def test_guard_never_acts_on_system_or_kubeheal_namespaces():
    for ns in ("kubeheal", "kube-system", "kube-public", "kube-node-lease"):
        ok, reason = guard.check_target(ns)
        assert not ok and "never" in reason
    assert guard.check_target("prod")[0] is True
    assert guard.check_target("default")[0] is False         # not in the protected set
    assert guard.check_target("")[0] is False


def test_executor_refuses_forbidden_namespace_without_calling_kubernetes():
    apps, core, net = FakeApps(), FakeCore(), FakeNet()
    ex = ExecutorService(redis=FakeRedis(), core_api=core, apps_api=apps, networking_api=net, mode=Mode())
    out = run(ex.execute({"action": "contain", "namespace": "kube-system", "pod": "coredns-1"}))
    assert out.startswith("refused:")
    assert core.deleted == [] and net.created == []
    out = run(ex.execute({"action": "patch", "namespace": "kubeheal", "deployment": "fusion-agent"}))
    assert out.startswith("refused:") and apps.patched == []


def test_executor_patch_never_overwrites_the_whole_template():
    # P7-RR-8: the P2 interim behaviour (whole golden template) is gone. A patch request needs a
    # patch_field; the field-level canary path is tested in tests/test_remediation_drift.py.
    baseline = {"template": {"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "500m"}}}]}}}
    r = FakeRedis({"kubeheal:baseline:prod:web": json.dumps(baseline)})
    apps = FakeApps()
    ex = ExecutorService(redis=r, apps_api=apps, mode=Mode())
    out = run(ex.execute({"action": "patch", "namespace": "prod", "deployment": "web"}))
    assert out.startswith("escalated:no_patch_field") and apps.patched == []


def test_executor_patch_without_baseline_escalates_and_does_not_write():
    apps = FakeApps()
    ex = ExecutorService(redis=FakeRedis(), apps_api=apps, mode=Mode())
    out = run(ex.execute({"action": "patch", "namespace": "prod", "deployment": "web"}))
    assert out == "no_baseline_escalated" and apps.patched == []


def test_executor_acks_only_after_success_and_records_outcome():
    r = FakeRedis()
    ex = ExecutorService(redis=r, core_api=FakeCore(), networking_api=FakeNet(), mode=Mode())
    ok = run(ex.handle_entry(EXEC_STREAM, "9-0", {"action": "contain", "namespace": "prod", "pod": "p1",
                                                 "incident_id": "inc-1"}))
    assert ok and r.acked == ["9-0"]
    assert r.added[-1][0] == ACTIONS_STREAM and r.added[-1][1]["incident_id"] == "inc-1"

    async def boom(_):
        raise RuntimeError("x")
    ex.execute = boom
    r2 = FakeRedis()
    ex.redis = r2
    assert run(ex.handle_entry(EXEC_STREAM, "10-0", {})) is False and r2.acked == []


def test_fusion_enqueues_for_executor_and_has_no_kubernetes_client():
    a = fusion.FusionAgentV4()
    a.redis = FakeRedis()
    assert not hasattr(a, "core_api") and not hasattr(a, "apps_api")
    out = dp.make_decision(dp.DecisionInput(health_risk=0.79, sec_risk=0.1, namespace_tier="prod",
                                            health_field_top="cpu", models_ok=True,
                                            namespace_protected=False,
                                            metric_samples_seen=dp.BURN_IN_SAMPLES))
    assert out.decision == dp.Decision.AUTO_PATCH
    inp = dp.DecisionInput(health_field_top="cpu", namespace_tier="prod")
    run(a._execute("prod", "web", "web-abc-1", out, inp, []))
    streams = [s for s, _ in a.redis.added]
    assert fusion.EXEC_STREAM in streams
    req = dict(a.redis.added)[fusion.EXEC_STREAM]
    assert req["action"] == "patch" and req["deployment"] == "web" and req["namespace"] == "prod"
    assert req["incident_id"].startswith("inc-")
    rec = dict(a.redis.added)[fusion.ACTIONS_STREAM]
    assert rec["outcome"] == "queued_for_executor" and rec["incident_id"] == req["incident_id"]
