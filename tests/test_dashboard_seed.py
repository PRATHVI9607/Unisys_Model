"""Shared fixtures for the dashboard tests: a seed helper for ledger incidents and fake services.

The numbers below are arbitrary test fixtures, not measurements of any model.
"""
import json

import pytest
from fastapi.testclient import TestClient

from agents.common.ledger import Ledger
from fake_redis import FakeRedis
from dashboard.admin_routes import DashboardServices
from dashboard.fastapi_app import app

TOKEN = "unit-test-admin-token"
INC = "inc-20260101-000000-abc123"
HEALTH_EVENT = "hev-1"
SECURITY_EVENT = "sev-1"


class FakeModeStore:
    """Stands in for the kubeheal-mode ConfigMap. Records every write."""

    def __init__(self, mode="test", fail_read=False, fail_write=False):
        self.mode, self.fail_read, self.fail_write = mode, fail_read, fail_write
        self.namespace_modes = {}
        self.fail_namespace_read = False
        self.writes = []

    async def read_mode(self):
        if self.fail_read:
            raise RuntimeError("no access")
        return self.mode

    async def read_namespace_mode(self, namespace):
        if self.fail_namespace_read:
            raise RuntimeError("namespace labels unavailable")
        return self.namespace_modes.get(namespace)

    async def write_mode(self, mode):
        if self.fail_write:
            raise RuntimeError("api down")
        self.writes.append(mode)
        self.mode = mode


class DashRedis(FakeRedis):
    """FakeRedis plus SCAN and the compare-and-set overwrite of the golden baseline (a Python mirror of
    PROMOTE_BASELINE_LUA in agents/health_agent/baseline.py)."""

    async def eval(self, script, n, key, token, *extra):
        if "kubeheal:promote_baseline" in script:
            if await self.get(key) != token:
                return 0
            self.store[key] = extra[0]
            return 1
        return await super().eval(script, n, key, token, *extra)

    async def scan_iter(self, match=None):
        prefix = (match or "").rstrip("*")
        for k in list(self.store) + list(self.hashes):
            if k.startswith(prefix):
                yield k


class BytesRedis:
    """What the dashboard's client (decode_responses=False) returns: bytes keys and values. Writes pass through."""

    def __init__(self, inner):
        self.inner = inner

    @staticmethod
    def _b(v):
        return v.encode() if isinstance(v, str) else v

    @staticmethod
    def _s(k):
        return k.decode() if isinstance(k, bytes) else k

    async def get(self, k):
        return self._b(await self.inner.get(self._s(k)))

    async def hgetall(self, k):
        return {self._b(a): self._b(b) for a, b in (await self.inner.hgetall(self._s(k))).items()}

    async def scan_iter(self, match=None):
        async for k in self.inner.scan_iter(match=match):
            yield self._b(k)

    async def set(self, *a, **kw):
        return await self.inner.set(*a, **kw)

    async def delete(self, *a):
        return await self.inner.delete(*a)

    async def eval(self, *a):
        return await self.inner.eval(*a)


class Harness:
    def __init__(self, mode="test", **mode_kwargs):
        self.ledger = Ledger()
        self.mode_store = FakeModeStore(mode, **mode_kwargs)
        self.exec_requests = []
        self.claims = {}            # incident_id -> claim value
        self.events = {}            # (kind, event_id) -> hash-like dict of strings
        self.enqueue_error = None
        self.claim_denied = False
        self.claim_set_error = None
        self.redis_inner = DashRedis()                    # inspect `.store` here
        self.redis = BytesRedis(self.redis_inner)         # what the dashboard sees

    def services(self) -> DashboardServices:
        async def enqueue(fields):
            if self.enqueue_error:
                raise self.enqueue_error
            self.exec_requests.append(dict(fields))
            return f"{len(self.exec_requests)}-0"

        async def claim(incident_id):
            if self.claim_denied or incident_id in self.claims:
                return False
            self.claims[incident_id] = "claimed"
            return True

        async def release(incident_id):
            self.claims.pop(incident_id, None)

        async def claim_set(incident_id, value):
            if self.claim_set_error:
                raise self.claim_set_error
            if incident_id in self.claims:
                self.claims[incident_id] = value

        async def claim_get(incident_id):
            return self.claims.get(incident_id)

        async def list_claims():
            return list(self.claims.items())

        async def exec_entry_exists(stream_id):
            return any(f"{i}-0" == stream_id for i in range(1, len(self.exec_requests) + 1))

        async def fetch(kind, event_id):
            return self.events.get((kind, event_id))

        return DashboardServices(self.ledger, self.mode_store, enqueue, claim, release, claim_set, claim_get,
                                 list_claims, exec_entry_exists, fetch, get_redis=lambda: self.redis)

    def steps(self, incident_id=INC):
        prefix = f"incidents/{incident_id}/"
        return [k[len(prefix):].split("-", 1)[1][:-5] for k in sorted(self.ledger.store.keys(prefix))]

    def records(self, incident_id=INC):
        prefix = f"incidents/{incident_id}/"
        return [json.loads(self.ledger.store.objects[k]) for k in sorted(self.ledger.store.keys(prefix))]


def seed_incident(h: Harness, incident_id=INC, decision="human_patch", *, namespace="staging",
                  deployment="web", pod="", top_field="resources.limits.cpu", approval=True,
                  t0_ms=None, rationale="fixture rationale", chain=None, with_events=True,
                  field_weights=None, syscall_weights=None, patch_fields=None, containment=None):
    """Write detection, scores, decision (and approval_requested) the way the Fusion Agent does."""
    led = h.ledger
    detection = {"namespace": namespace, "deployment": deployment, "pod": pod,
                 "health_event_id": HEALTH_EVENT, "security_event_id": SECURITY_EVENT,
                 "signals": ["health", "security"]}
    scores = {"health": {"health_risk": "0.7000", "health_label": "high",
                         "health_ci_width": "0.2000", "top_field": top_field},
              "security": {"sec_risk": "0.6000", "sec_label": "suspicious",
                           "sec_ci_width": "0.1000", "top_syscall": "rename"},
              "correlation_score": 0.5, "compound": True}
    dec = {"decision": decision, "adjusted_score": 0.66, "rationale": rationale, "dry_run": True,
           "namespace_tier": "staging", "compound": True,
           "causal_chain": chain if chain is not None else ["T+0.0s: Config field changed", "DCM: compound"]}
    if t0_ms is not None:
        dec["t0_ms"] = t0_ms
    if patch_fields is not None:                 # what Fusion records since V5-D9 (the spec-diff candidates)
        dec["patch_fields"] = patch_fields
    if containment is not None:                  # what Fusion records for a contain decision since V5-S5
        dec.update(containment)
    led.append(incident_id, "detection", detection)
    led.append(incident_id, "scores", scores)
    led.append(incident_id, "decision", dec)
    if approval:
        led.append(incident_id, "approval_requested",
                   {"decision": decision, "status": "pending", "rationale": rationale})
    if with_events:
        h.events[("health", HEALTH_EVENT)] = {
            "health_risk": "0.7000", "health_ci_width": "0.2000", "top_field": top_field,
            "top_metric": "cpu_throttling",
            "field_attribution_json": json.dumps(field_weights or {top_field: 0.8, "replicas": 0.1}),
        }
        h.events[("security", SECURITY_EVENT)] = {
            "sec_risk": "0.6000", "sec_ci_width": "0.1000", "top_syscall": "rename",
            "syscall_attribution_json": json.dumps(syscall_weights or {"rename": 0.5, "write": 0.2}),
            "early_signals_json": json.dumps({"rename_burst": True}),
            "entropy_spike_json": json.dumps({}),
        }
    return incident_id


def seed_v5_incident(h: Harness, incident_id=INC, decision="human_contain", *, namespace="staging",
                     deployment="web", pod="web-abc-1", approval=True, health_set='["degradation"]',
                     health_uncertain="false", sec_set='["ransomware"]', sec_uncertain="false",
                     n_factors=10, rule_path=False, rule_reasons=None, patch_fields=None, containment="default",
                     with_events=True, events_have_legacy=False):
    """An incident as the V5 agents write it: prediction sets and TreeSHAP factors, NO ci width, no embeddings,
    no field attribution. The numbers are arbitrary fixtures."""
    def factors(prefix):
        return json.dumps([{"feature": f"{prefix}_f{i}", "value": float(i), "contribution": ((-1) ** i) * (i + 1) / 100}
                           for i in range(n_factors)])

    health = {"health_risk": "0.7100", "health_label": "degradation", "health_prediction_set": health_set,
              "health_uncertain": health_uncertain, "top_factors_json": factors("h"), "model_scored": "true",
              "model_version": "health-fixture-1"}
    security = {"sec_risk": "0.9100", "sec_label": "ransomware", "sec_prediction_set": sec_set,
                "sec_uncertain": sec_uncertain, "top_factors_json": factors("s"), "model_scored": "true",
                "model_version": "security-fixture-1"}
    led = h.ledger
    led.append(incident_id, "detection", {"namespace": namespace, "deployment": deployment, "pod": pod,
                                          "health_event_id": HEALTH_EVENT, "security_event_id": SECURITY_EVENT,
                                          "signals": ["health", "security"]})
    led.append(incident_id, "scores", {"health": health, "security": security, "correlation_score": 0.5,
                                       "compound": True})
    dec = {"decision": decision, "adjusted_score": 0.8, "rationale": "fixture", "dry_run": True,
           "namespace_tier": "staging", "compound": True, "causal_chain": ["step one"], "models_ok": True,
           "health_prediction_set": json.loads(health_set), "sec_prediction_set": json.loads(sec_set),
           "rule_path": rule_path, "rule_reasons": rule_reasons if rule_reasons is not None else [],
           "patch_fields": patch_fields if patch_fields is not None else [], "security_fresh": True,
           "top_factors_json": {"health": health["top_factors_json"], "security": security["top_factors_json"]}}
    if containment == "default":
        containment = {"containment_label": "ransomware", "restore_after": True, "human_followup": False}
    if containment:
        dec.update(containment)
    led.append(incident_id, "decision", dec)
    if approval:
        led.append(incident_id, "approval_requested", {"decision": decision, "status": "pending", "rationale": "fixture"})
    if with_events:
        hev = {**health, "top_metric": "unused"} if events_have_legacy else dict(health)
        if events_have_legacy:
            hev["field_attribution_json"] = json.dumps({"resources.limits.cpu": 0.8})
        h.events[("health", HEALTH_EVENT)] = hev
        h.events[("security", SECURITY_EVENT)] = {**security, "syscall_attribution_json": "{}",
                                                  "early_signals_json": json.dumps({"rename_burst": True}),
                                                  "entropy_spike_json": "{}"}
    return incident_id


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setenv("KUBEHEAL_ADMIN_TOKEN", TOKEN)
    monkeypatch.delenv("KUBEHEAL_ADMIN_IDENTITY", raising=False)
    h = Harness()
    previous = getattr(app.state, "services", None)
    app.state.services = h.services()
    yield h
    app.state.services = previous


@pytest.fixture
def client(harness):
    # No `with`: the lifespan (Redis, Kubernetes) must not run in tests.
    return TestClient(app)


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_seed_helper_writes_what_fusion_writes(harness):
    seed_incident(harness)
    assert harness.steps() == ["detection", "scores", "decision", "approval_requested"]
    seed_incident(harness, "inc-2", approval=False)
    assert harness.steps("inc-2") == ["detection", "scores", "decision"]
