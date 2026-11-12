"""Shared builders for the P6 Fusion tests: an agent on the in-memory Redis, a stubbed DCM, event factories."""
import asyncio
import base64
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.fusion_agent import agent as fusion
from agents.fusion_agent.breakers import BURN_IN_SEEN_KEY
from agents.fusion_agent.config import FusionConfig
from agents.fusion_agent.decision_policy import BURN_IN_SAMPLES
from agents.fusion_agent.interpretation_client import CorrelateResult, InterpretationClient
from fake_redis import FakeRedis

NOW_MS = 1_760_000_000_000


def run(coro):
    return asyncio.run(coro)


def emb(n=4, seed=0):
    rng = np.random.default_rng(seed)
    return base64.b64encode(rng.random(n).astype(np.float32).tobytes()).decode()


def sec_event(**kw):
    ev = {"event_id": "sec-1", "namespace": "prod", "deployment": "payments", "pod_name": "payments-abc-1",
          "pid_target": "42", "workload_kind": "Deployment", "namespace_tier": "prod",
          "sec_risk": "0.95", "sec_label": "ransomware", "sec_prediction_set": '["ransomware"]',
          "sec_uncertain": "false",
          "top_syscall": "write", "model_scored": "true", "syscall_source": "falco",
          "entropy_phase": "initial", "entropy_valid_samples": "1", "timestamp_ms": str(NOW_MS)}
    ev.update(kw)
    return ev


def health_event(**kw):
    ev = {"event_id": "health-1", "namespace": "prod", "deployment": "payments", "pod_name": "payments",
          "namespace_tier": "prod", "health_risk": "0.95", "health_label": "degradation",
          "health_prediction_set": '["degradation"]', "health_uncertain": "false", "changed_fields_json": '["template.spec.containers[0].resources.limits.cpu"]', "model_scored": "true",
          "timestamp_ms": str(NOW_MS + 1000)}
    ev.update(kw)
    return ev


class StubInterp(InterpretationClient):
    """The DCM answer is configured; `explain` is the real one."""

    def __init__(self, result=None, explainer=None):
        super().__init__("http://dcm.invalid", explainer=explainer)
        self.result = result or CorrelateResult(True, {"correlation_score": 0.2, "compound_flag": False,
                                                       "causal_chain": ["DCM line"], "nl_summary": "summary"})
        self.calls = 0

    async def correlate(self, health, sec, h_emb, s_emb, deadline_s):
        self.calls += 1
        return self.result


def rule_health_event(**kw):
    """A health event that carries rule evidence (V5-D2 failure_reasons), a baseline and a changed spec. The
    Health Model did not answer: the rule path does not need it (Q1)."""
    ev = health_event(health_risk="0", health_label="benign", health_prediction_set="[]",
                      model_scored="false", model_unavailable="true", spec_changed="true", has_baseline="true",
                      failure_reasons_json=json.dumps(["ImagePullBackOff"]),
                      changed_fields_json=json.dumps(["containers[0].image"]))
    ev.update(kw)
    return ev


def security_score_key(namespace="prod", workload="payments"):
    return f"{fusion.SECURITY_SCORE_PREFIX}:{namespace}:{workload}"


def set_security_score(agent, namespace="prod", workload="payments", sec_risk="0.05", model_scored="true",
                       ts_ms=None):
    """What the Security Agent (V5-S2) will write: a hash per workload. The agent clock is 1_000_000.0 s."""
    agent.redis.hashes[security_score_key(namespace, workload)] = {
        "sec_risk": str(sec_risk), "model_scored": model_scored,
        "ts_ms": str(int(agent.clock() * 1000) if ts_ms is None else ts_ms)}


def make_agent(enforce=True, protected=False, burn_in_over=True, interp=None, cfg=None, redis=None, clock=None,
               namespaces=("prod", "dev", "staging"), legacy_dcm=False):
    store = InMemoryLedgerStore()
    a = fusion.FusionAgentV4(ledger=Ledger(store), cfg=cfg or FusionConfig(), interp=interp or StubInterp(),
                             clock=clock or (lambda: 1_000_000.0))
    # V5-D3: no DCM by default (independent of the DCM_URL of the test machine); legacy_dcm=True is the old path
    a.dcm_url = "http://dcm.invalid" if legacy_dcm else ""
    a.redis = redis or FakeRedis()
    a.mode.ns_readable = True
    a.mode.ns_protect = {n: ("true" if protected else None) for n in namespaces}
    if enforce:
        a.mode.apply_configmap(SimpleNamespace(data={"mode": "enforce"}))
        a.mode.ns_readable = True
    if burn_in_over:
        a.redis.sets[BURN_IN_SEEN_KEY] = {f"s{i}" for i in range(BURN_IN_SAMPLES)}
    a.store = store
    return a


def ledger_steps(agent, incident_id=None):
    recs = [json.loads(v) for k, v in agent.store.objects.items()]
    if incident_id:
        recs = [r for r in recs if r["incident_id"] == incident_id]
    return recs


def stream(redis, name):
    return [f for s, f in redis.added if s == name]
