"""Offline acceptance of the Fusion-to-Executor kill-switch path using fakes only."""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import remediation_fakes as fk
from fusion_helpers import ledger_steps, make_agent, sec_event, stream
from agents.common.ledger import Ledger
from agents.executor.config import ExecConfig
from agents.executor.main import ACTIONS_STREAM, ExecutorService
from agents.common.containment_auth import sign_fields
from agents.fusion_agent import agent as fusion


EXEC_CONFIG = {"SNAPSHOT_CLASS": "csi-snap", "CONTAIN_FREEZE_TIMEOUT_S": "1"}
FAKE_HMAC_KEY = "offline-test-key-not-a-deployment-secret"


def run(coro):
    return asyncio.run(coro)


class FreezeReplyRedis(fk.Redis):
    """Fake Redis that returns an authenticated Security Agent freeze acknowledgment."""

    def __init__(self):
        super().__init__()
        self.hashes = {}

    async def xadd(self, stream_name, fields):
        await super().xadd(stream_name, fields)
        if stream_name.startswith("kubeheal.contain.req:"):
            answer = {key: fields[key] for key in
                      ("request_id", "incident_id", "namespace", "pod", "pod_uid", "node", "action")}
            answer.update(status="frozen", frozen="1", mode_seen="enforce", cgroup="/fake/cgroup")
            self.hashes[f"kubeheal:contain:result:{fields['request_id']}"] = sign_fields(answer, FAKE_HMAC_KEY)

    async def hgetall(self, key):
        return self.hashes.get(key, {})


def run_security_to_executor(mode, monkeypatch):
    """Feed one scored Security event through fake Fusion, Redis stream, and fake Executor."""
    fusion_agent = make_agent(enforce=(mode == "enforce"))
    ledger = Ledger(fusion_agent.store)
    fusion_agent.ledger = ledger
    if mode == "test":
        fusion_agent.mode.apply_configmap(type("ConfigMap", (), {"data": {"mode": "test"}})())

    event = sec_event(event_id=f"sec-{mode}")
    assert run(fusion_agent._handle_entry(fusion.SEC_STREAM, "1-0", event)) is True
    [request] = stream(fusion_agent.redis, fusion.EXEC_STREAM)

    cluster = fk.Cluster()
    fk.add_db_workload(cluster, name="payments", pod="payments-abc-1")
    cluster.pods["payments-abc-1"]["metadata"]["uid"] = "fake-pod-uid"
    cluster.pods["payments-abc-1"]["spec"]["nodeName"] = "fake-node"
    executor_redis = FreezeReplyRedis()
    monkeypatch.setenv("CONTAIN_HMAC_KEY", FAKE_HMAC_KEY)
    executor = ExecutorService(
        redis=executor_redis,
        core_api=cluster.core,
        apps_api=cluster.apps,
        networking_api=cluster.net,
        custom_api=cluster.custom,
        mode=fk.Mode(dry=(mode == "test")),
        ledger=ledger,
        cfg=ExecConfig(EXEC_CONFIG),
        entropy_check=lambda *_: True,
    )
    assert run(executor.handle_entry("kubeheal.exec", "2-0", request)) is True
    return event, request, ledger_steps(fusion_agent), executor_redis, cluster


def test_test_mode_runs_sense_score_decide_record_without_kubernetes_writes(monkeypatch):
    event, request, records, executor_redis, cluster = run_security_to_executor("test", monkeypatch)

    assert event["model_scored"] == "true" and event["sec_prediction_set"] == '["ransomware"]'
    assert request["action"] == "contain" and request["dry_run"] == "true"
    steps = [record["step"] for record in records]
    assert steps[:3] == ["detection", "scores", "decision"]
    assert "request_accepted" in steps and "blocked" in steps and "executor_result" in steps
    assert any(record["payload"].get("outcome", "").startswith("DRY RUN: would have CONTAIN")
               for record in records)
    assert executor_redis.stream(ACTIONS_STREAM)[-1]["outcome"].startswith("DRY RUN: would have CONTAIN")
    assert cluster.log == []


def test_enforce_mode_runs_the_same_pipeline_and_fake_kubernetes_actions(monkeypatch):
    event, request, records, executor_redis, cluster = run_security_to_executor("enforce", monkeypatch)

    assert event["model_scored"] == "true"
    assert request["action"] == "contain" and request["dry_run"] == "false"
    assert [record["step"] for record in records][:3] == ["detection", "scores", "decision"]
    assert executor_redis.stream(ACTIONS_STREAM)[-1]["outcome"] == "contained"
    assert {entry[1] for entry in cluster.log} >= {"create_snapshot", "create_policy", "patch_pod"}
    assert any(name.startswith("kubeheal.contain.req:") for name, _ in executor_redis.added)
