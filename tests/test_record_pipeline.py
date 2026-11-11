import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_redis import FakeRedis  # noqa: E402

from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.executor.main import ExecutorService
from agents.fusion_agent import agent as fusion


class _Redis:
    def __init__(self):
        self.added = []
        self.acked = []
        self.values = {}

    async def xadd(self, stream, fields):
        self.added.append((stream, fields))

    async def xack(self, stream, group, message_id):
        self.acked.append((stream, group, message_id))

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True

    async def eval(self, script, count, key, value, *args):
        if self.values.get(key) != value:
            return 0
        if "expire" in script:
            return 1
        self.values.pop(key, None)
        return 1


class _Mode:
    def dry_run_for(self, namespace):
        return False


class _KubeApi:
    def __init__(self):
        self.calls = []

    async def read_namespaced_pod(self, name, namespace):
        # containment verifies pod -> ReplicaSet -> Deployment ownership before creating anything
        return {"metadata": {"name": name, "ownerReferences": [{"kind": "ReplicaSet", "name": "payments-rs"}]},
                "spec": {"volumes": []}}

    async def read_namespaced_replica_set(self, name, namespace):
        return {"metadata": {"name": name, "ownerReferences": [{"kind": "Deployment", "name": "payments"}]}}

    async def create_namespaced_network_policy(self, namespace, body):
        self.calls.append(("quarantine", namespace))

    async def delete_namespaced_pod(self, pod, namespace, grace_period_seconds):
        self.calls.append(("delete", namespace, pod))


def _run(coro):
    return asyncio.run(coro)


def test_fusion_and_executor_records_share_one_incident_ledger():
    store = InMemoryLedgerStore()
    ledger = Ledger(store)
    fusion_redis = FakeRedis()
    agent = fusion.FusionAgentV4(ledger=ledger)
    agent.redis = fusion_redis
    # P6 fail-closed inputs: the namespace labels were read and prod is not protected
    agent.mode.ns_readable = True
    agent.mode.ns_protect = {"prod": None}

    _run(agent._decide("prod:payments", None, {
        "event_id": "sec-test",
        "namespace": "prod",
        "deployment": "payments",
        "pod_name": "payments-abc",
        "sec_risk": "0.95",
        "sec_label": "ransomware_active",
        "sec_ci_width": "0.01",
        "top_syscall": "write",
        "model_scored": "true",
    }))

    exec_request = next(fields for stream, fields in fusion_redis.added if stream == fusion.EXEC_STREAM)
    incident_id = exec_request["incident_id"]
    assert exec_request["dry_run"] == "true"

    executor_redis = _Redis()
    core = _KubeApi()
    network = _KubeApi()
    executor = ExecutorService(
        redis=executor_redis,
        core_api=core,
        apps_api=_KubeApi(),
        networking_api=network,
        mode=_Mode(),
        ledger=ledger,
    )
    handled = _run(executor.handle_entry(fusion.EXEC_STREAM, "1-0", exec_request))

    records = [json.loads(store.objects[key]) for key in sorted(store.objects)]
    assert handled is True
    assert {record["incident_id"] for record in records} == {incident_id}
    assert [record["step"] for record in records] == [
        "detection",
        "scores",
        "decision",
        "request_accepted",
        "blocked",
        "result",
        "executor_result",
    ]
    assert records[2]["payload"]["decision"] == "auto_contain"
    assert records[-1]["payload"]["outcome"].startswith("DRY RUN:")
    assert core.calls == [] and network.calls == []
    assert executor_redis.acked == [(fusion.EXEC_STREAM, "executor", "1-0")]
