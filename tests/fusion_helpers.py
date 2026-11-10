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
          "sec_risk": "0.95", "sec_label": "ransomware_active", "sec_ci_width": "0.05",
          "top_syscall": "write", "model_scored": "true", "syscall_source": "falco",
          "entropy_phase": "initial", "entropy_valid_samples": "1", "timestamp_ms": str(NOW_MS)}
    ev.update(kw)
    return ev


def health_event(**kw):
    ev = {"event_id": "health-1", "namespace": "prod", "deployment": "payments", "pod_name": "payments",
          "namespace_tier": "prod", "health_risk": "0.95", "health_label": "drift",
          "health_ci_width": "0.05", "top_field": "spec.cpu", "timestamp_ms": str(NOW_MS + 1000)}
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


def make_agent(enforce=True, protected=False, burn_in_over=True, interp=None, cfg=None, redis=None, clock=None,
               namespaces=("prod", "dev", "staging")):
    store = InMemoryLedgerStore()
    a = fusion.FusionAgentV4(ledger=Ledger(store), cfg=cfg or FusionConfig(), interp=interp or StubInterp(),
                             clock=clock or (lambda: 1_000_000.0))
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
