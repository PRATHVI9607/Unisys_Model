"""Shared fixtures for the dashboard tests: a seed helper for ledger incidents and fake services.

The numbers below are arbitrary test fixtures, not measurements of any model.
"""
import json

import pytest
from fastapi.testclient import TestClient

from agents.common.ledger import Ledger
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
        self.writes = []

    async def read_mode(self):
        if self.fail_read:
            raise RuntimeError("no access")
        return self.mode

    async def write_mode(self, mode):
        if self.fail_write:
            raise RuntimeError("api down")
        self.writes.append(mode)
        self.mode = mode


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

        async def fetch(kind, event_id):
            return self.events.get((kind, event_id))

        return DashboardServices(self.ledger, self.mode_store, enqueue, claim, release, claim_set, claim_get, fetch)

    def steps(self, incident_id=INC):
        prefix = f"incidents/{incident_id}/"
        return [k[len(prefix):].split("-", 1)[1][:-5] for k in sorted(self.ledger.store.keys(prefix))]

    def records(self, incident_id=INC):
        prefix = f"incidents/{incident_id}/"
        return [json.loads(self.ledger.store.objects[k]) for k in sorted(self.ledger.store.keys(prefix))]


def seed_incident(h: Harness, incident_id=INC, decision="human_patch", *, namespace="staging",
                  deployment="web", pod="", top_field="resources.limits.cpu", approval=True,
                  t0_ms=None, rationale="fixture rationale", chain=None, with_events=True,
                  field_weights=None, syscall_weights=None):
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
