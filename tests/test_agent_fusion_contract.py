"""Fusion agent: join, observe/enforce actions, publishing and stream handling.

Kube APIs are a fake that records every call; Redis is fakeredis. The incident
lock (Lua) is replaced by a stub here and tested in test_incident_lock.py.
"""

import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import fakeredis
import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from agents.fusion_agent import agent as fa
from kubeheal.contracts import (
    PROTECTED_NAMESPACES,
    STREAM_ACTIONS,
    STREAM_DEADLETTER,
    STREAM_HEALTH,
    STREAM_SECURITY,
    ActionEvent,
    Decision,
    Factor,
    HealthEvent,
    SecurityEvent,
    key_baseline,
    key_event,
    now_ms,
)

MUTATING = {"patch_namespaced_pod", "create_namespaced_network_policy", "delete_namespaced_pod",
            "patch_namespaced_deployment"}
TEMPLATE = {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "web:1.2"}]}}


class FakeKube:
    """Stands in for CoreV1Api, AppsV1Api and NetworkingV1Api at once."""

    def __init__(self, pod_labels=None, dep_labels=None, errors=None, ns_labels=None):
        self.calls, self.pod_labels, self.dep_labels, self.ns_labels = [], pod_labels, dep_labels, ns_labels
        self.errors = errors or {}     # method name -> HTTP status to raise

    def _rec(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if name in self.errors:
            raise ApiException(status=self.errors[name], reason="Fake")

    async def read_namespace(self, name):     # read-only tier lookup; not recorded in calls
        if "read_namespace" in self.errors:
            raise ApiException(status=self.errors["read_namespace"], reason="Fake")
        return SimpleNamespace(metadata=SimpleNamespace(name=name, labels=self.ns_labels))

    async def read_namespaced_pod(self, name, ns):
        self._rec("read_namespaced_pod", name, ns)
        return SimpleNamespace(metadata=SimpleNamespace(name=name, uid="uid-123", labels=self.pod_labels))

    async def read_namespaced_deployment(self, name, ns):
        self._rec("read_namespaced_deployment", name, ns)
        return SimpleNamespace(metadata=SimpleNamespace(name=name, uid="uid-dep", labels=self.dep_labels))

    async def patch_namespaced_pod(self, name, ns, body):
        self._rec("patch_namespaced_pod", name, ns, body)

    async def create_namespaced_network_policy(self, ns, body):
        self._rec("create_namespaced_network_policy", ns, body)

    async def delete_namespaced_pod(self, name, ns, **kwargs):
        self._rec("delete_namespaced_pod", name, ns, **kwargs)

    async def patch_namespaced_deployment(self, name, ns, body, **kwargs):
        self._rec("patch_namespaced_deployment", name, ns, body, **kwargs)

    @property
    def names(self):
        return [c[0] for c in self.calls]


def lock_stub(held=True):
    @asynccontextmanager
    async def _lock(redis, key):
        yield held
    return _lock


@pytest.fixture
def redis():
    return fakeredis.FakeAsyncRedis(decode_responses=True)


@pytest.fixture(autouse=True)
def _no_lua(monkeypatch):
    monkeypatch.setattr(fa, "incident_lock", lock_stub(True))


def make(redis, kube=None, **kw):
    kube = kube or FakeKube()
    return fa.FusionAgent(redis, kube, kube, kube, **kw), kube


def ransomware(ns="prod-shop", pod="web-7d9f-abcde", ts=None, eid="s1", risk=0.9):
    return SecurityEvent(event_id=eid, namespace=ns, workload="web", pod=pod, label="ransomware", risk=risk,
                         timestamp_ms=ts or now_ms(),
                         top_factors=[Factor(feature="entropy_mean", value=7.9, contribution=1.2),
                                      Factor(feature="frac_rename", value=0.4, contribution=0.8)])


def drift(ns="prod-shop", ts=None, eid="h1", risk=0.9, label="critical"):
    return HealthEvent(event_id=eid, namespace=ns, workload="web", label=label, risk=risk, has_baseline=True,
                       timestamp_ms=ts or now_ms(), changed_fields=["template.spec.containers[0].image"])


async def set_baseline(redis, ns="prod-shop"):
    await redis.set(key_baseline(ns, "web"), json.dumps({"replicas": 2, "template": TEMPLATE}))


# ── observe mode ─────────────────────────────────────────────────────────────
async def test_observe_never_mutates(redis):
    kube = FakeKube()
    await set_baseline(redis)
    kill = await make(redis, kube)[0].handle(ransomware())     # mode defaults to observe
    patch = await make(redis, kube)[0].handle(drift())         # fresh agent: no pairing with the kill
    assert (kill.decision, kill.outcome, kill.mode) == (Decision.AUTO_KILL, "would_kill", "observe")
    assert (patch.decision, patch.outcome) == (Decision.AUTO_PATCH, "would_patch")
    assert kube.calls and not MUTATING & set(kube.names)


# ── enforce: kill ───────────────────────────────────────────────────────────
async def test_enforce_kill_sequence(redis):
    agent, kube = make(redis, mode="enforce")
    a = await agent.handle(ransomware())
    assert (a.decision, a.outcome) == (Decision.AUTO_KILL, "pod_killed")
    assert kube.names == ["read_namespaced_pod", "read_namespaced_deployment", "patch_namespaced_pod",
                          "create_namespaced_network_policy", "delete_namespaced_pod"]
    label_body = kube.calls[2][1][2]
    assert label_body == {"metadata": {"labels": {"kubeheal.io/quarantined": "true"}}}
    ns, policy = kube.calls[3][1]
    assert ns == "prod-shop"
    assert policy["metadata"]["ownerReferences"][0] == {"apiVersion": "v1", "kind": "Pod",
                                                        "name": "web-7d9f-abcde", "uid": "uid-123"}
    assert policy["spec"] == {"podSelector": {"matchLabels": {"kubeheal.io/quarantined": "true"}},
                              "policyTypes": ["Ingress", "Egress"]}       # no rules = deny all
    assert kube.calls[4][2] == {"grace_period_seconds": 0}


@pytest.mark.parametrize("errors,outcome", [
    ({"read_namespaced_pod": 404}, "pod_already_gone"),
    ({"delete_namespaced_pod": 404}, "pod_already_gone"),
    ({"create_namespaced_network_policy": 409}, "pod_killed"),     # retry after partial run
    ({"read_namespaced_deployment": 404}, "pod_killed"),          # bare pod / deployment gone
    ({"delete_namespaced_pod": 500}, "failed:api_500_Fake"),
])
async def test_enforce_kill_idempotency(redis, errors, outcome):
    agent, kube = make(redis, FakeKube(errors=errors), mode="enforce")
    assert (await agent.handle(ransomware())).outcome == outcome


async def test_kill_circuit_breaker(redis):
    agent, kube = make(redis, mode="enforce", max_kills=1)
    assert (await agent.handle(ransomware(eid="s1"))).outcome == "pod_killed"
    assert (await agent.handle(ransomware(eid="s2"))).outcome == "skipped_circuit_open"
    assert kube.names.count("delete_namespaced_pod") == 1


async def test_lock_held_skips(redis, monkeypatch):
    monkeypatch.setattr(fa, "incident_lock", lock_stub(False))
    agent, kube = make(redis, mode="enforce")
    assert (await agent.handle(ransomware())).outcome == "skipped_locked"
    assert not MUTATING & set(kube.names)


# ── protection ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ns,protected,pod_labels,dep_labels", [
    ("kube-system", PROTECTED_NAMESPACES, None, None),
    ("payments-prod", PROTECTED_NAMESPACES | {"payments-prod"}, None, None),     # EXTRA_PROTECTED_NAMESPACES
    ("prod-shop", PROTECTED_NAMESPACES, {"kubeheal.io/protected": "true"}, None),   # pod label: kill only
    ("prod-shop", PROTECTED_NAMESPACES, None, {"kubeheal.io/protected": "true"}),
])
async def test_protected_never_acted_on(redis, ns, protected, pod_labels, dep_labels):
    agent, kube = make(redis, FakeKube(pod_labels=pod_labels, dep_labels=dep_labels), mode="enforce",
                       protected=protected)
    await set_baseline(redis, ns)
    # call act() directly: protected namespaces are dev-tier, so the policy alone rarely reaches AUTO_*
    assert await agent.act(Decision.AUTO_KILL, None, ransomware(ns=ns)) == (Decision.AUTO_KILL, "skipped_protected")
    if not pod_labels:
        assert await agent.act(Decision.AUTO_PATCH, drift(ns=ns), None) == (Decision.AUTO_PATCH, "skipped_protected")
    assert not MUTATING & set(kube.names)


# ── enforce: patch ──────────────────────────────────────────────────────────
async def test_enforce_patch_json_patch(redis):
    agent, kube = make(redis, mode="enforce")
    await set_baseline(redis)
    a = await agent.handle(drift())
    assert (a.decision, a.outcome) == (Decision.AUTO_PATCH, "patched")
    name, args, kwargs = kube.calls[-1]
    assert name == "patch_namespaced_deployment"
    assert args == ("web", "prod-shop", [{"op": "replace", "path": "/spec/template", "value": TEMPLATE}])
    assert kwargs == {"_content_type": "application/json-patch+json"}


async def test_replicas_drift_restores_replicas_too(redis):
    agent, kube = make(redis, mode="enforce")
    await set_baseline(redis)
    ev = drift()
    ev.changed_fields = ["replicas"]
    assert (await agent.handle(ev)).outcome == "patched"
    assert kube.calls[-1][1][2] == [{"op": "replace", "path": "/spec/template", "value": TEMPLATE},
                                    {"op": "replace", "path": "/spec/replicas", "value": 2}]


@pytest.mark.parametrize("ns_labels,errors,decision", [
    ({"kubeheal.io/namespace-tier": "prod"}, None, Decision.AUTO_KILL),   # label beats the dev-looking name
    ({"kubeheal.io/namespace-tier": "bogus"}, None, Decision.HUMAN),       # invalid → name heuristic (dev)
    (None, {"read_namespace": 403}, Decision.HUMAN),                       # lookup fails → name heuristic
])
async def test_namespace_tier_label(redis, ns_labels, errors, decision):
    agent, _ = make(redis, FakeKube(ns_labels=ns_labels, errors=errors), mode="enforce")
    assert (await agent.handle(ransomware(ns="demo", risk=0.95))).decision is decision


async def test_patch_without_baseline_goes_to_human(redis):
    agent, kube = make(redis, mode="enforce")
    a = await agent.handle(drift())
    assert (a.decision, a.outcome) == (Decision.HUMAN, "escalated_no_baseline")
    assert kube.calls == []


async def test_patch_deployment_gone(redis):
    agent, _ = make(redis, FakeKube(errors={"read_namespaced_deployment": 404}), mode="enforce")
    await set_baseline(redis)
    assert (await agent.handle(drift())).outcome == "workload_gone"


# ── publishing ──────────────────────────────────────────────────────────────
async def test_every_decision_published(redis):
    agent, _ = make(redis)
    a = await agent.handle(drift(ns="dev", risk=0.05, label="benign"))
    assert a.decision is Decision.BENIGN and a.outcome == "none"
    (_, fields), = await redis.xrange(STREAM_ACTIONS)
    assert ActionEvent.from_fields(fields) == a
    key = key_event("action", a.event_id)
    assert await redis.hgetall(key) == fields
    assert 0 < await redis.ttl(key) <= 24 * 3600


async def test_stale_event_skipped(redis):
    agent, _ = make(redis)
    assert await agent.handle(ransomware(ts=now_ms() - 301_000)) is None
    assert await redis.xlen(STREAM_ACTIONS) == 0


# ── join ────────────────────────────────────────────────────────────────────
async def test_join_pairs_once_by_event_time(redis, monkeypatch):
    seen = []
    monkeypatch.setattr(fa, "compound_score", lambda h, s: seen.append((h.event_id, s.event_id)) or
                        (0.8, ["security onset precedes degradation"]))
    agent, _ = make(redis)
    t = now_ms()
    first = await agent.handle(drift(ns="staging", eid="h1", risk=0.5, label="degradation", ts=t - 60_000))
    assert first.security_event_id == "" and first.compound_score == 0.0
    paired = await agent.handle(ransomware(ns="staging", eid="s1", risk=0.5, ts=t))
    assert (paired.health_event_id, paired.security_event_id) == ("h1", "s1")
    assert paired.compound_score == 0.8 and "Correlated as one incident" in paired.summary
    assert "x1.15" in paired.rationale
    again = await agent.handle(ransomware(ns="staging", eid="s2", risk=0.5, ts=t + 1000))
    assert again.health_event_id == ""                       # h1 was consumed by the pair
    assert seen == [("h1", "s1")]


async def test_join_window_and_workload(redis, monkeypatch):
    monkeypatch.setattr(fa, "compound_score", lambda h, s: (0.9, ["x"]))
    agent, _ = make(redis)
    t = now_ms()
    await agent.handle(drift(ns="staging", eid="h1", risk=0.5, ts=t - 121_000))
    assert (await agent.handle(ransomware(ns="staging", eid="s1", risk=0.5, ts=t))).health_event_id == ""
    other = SecurityEvent(event_id="s2", namespace="staging", workload="api", pod="api-1", label="suspicious",
                          risk=0.5, timestamp_ms=t)
    await agent.handle(drift(ns="staging", eid="h2", risk=0.5, ts=t))
    assert (await agent.handle(other)).health_event_id == ""   # different workload never pairs


async def test_partner_does_not_repeat_an_automatic_action(redis):
    agent, kube = make(redis, mode="enforce", max_kills=5)
    t = now_ms()
    assert (await agent.handle(ransomware(eid="s1", ts=t))).outcome == "pod_killed"
    paired = await agent.handle(drift(eid="h1", ts=t + 1000))      # pairs with s1, decides AUTO_KILL again
    assert (paired.decision, paired.outcome) == (Decision.AUTO_KILL, "already_handled")
    assert paired.security_event_id == "s1"
    assert kube.names.count("delete_namespaced_pod") == 1
    assert await redis.get(fa.key_circuit("kill", "prod-shop", "web")) == "1"


def test_summary_is_short_and_factual():
    text = fa.summarize(drift(), ransomware(), 0.75, ["security high", "no config cause"])
    assert "entropy_mean, frac_rename" in text and "security high; no config cause" in text
    assert text.count(". ") <= 2


# ── stream handling ─────────────────────────────────────────────────────────
async def test_group_starts_at_new_events_and_acks_after_success(redis):
    agent, _ = make(redis)
    await redis.xadd(STREAM_SECURITY, ransomware(eid="old").to_fields())   # history before deploy
    await agent.ensure_groups()
    await redis.xadd(STREAM_SECURITY, ransomware(eid="new").to_fields())
    await agent.poll_once(block_ms=1)
    actions = [ActionEvent.from_fields(f) for _, f in await redis.xrange(STREAM_ACTIONS)]
    assert [a.security_event_id for a in actions] == ["new"]
    assert (await redis.xpending(STREAM_SECURITY, fa.GROUP))["pending"] == 0


async def test_failure_not_acked_then_deadlettered_after_3(redis, monkeypatch):
    monkeypatch.setattr(fa, "CLAIM_MIN_IDLE_MS", 0)
    agent, _ = make(redis)

    async def boom(ev):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(agent, "handle", boom)
    await agent.ensure_groups()
    await redis.xadd(STREAM_HEALTH, drift().to_fields())
    for delivery in (1, 2):
        await agent.poll_once(block_ms=1)
        assert (await redis.xpending(STREAM_HEALTH, fa.GROUP))["pending"] == 1, delivery
        assert await redis.xlen(STREAM_DEADLETTER) == 0
    await agent.poll_once(block_ms=1)                        # 3rd delivery fails → dead-letter + ack
    assert (await redis.xpending(STREAM_HEALTH, fa.GROUP))["pending"] == 0
    (_, dl), = await redis.xrange(STREAM_DEADLETTER)
    assert dl["_stream"] == STREAM_HEALTH and "kaboom" in dl["_error"] and dl["event_id"] == "h1"


async def test_malformed_event_deadlettered_immediately(redis):
    agent, _ = make(redis)
    await agent.ensure_groups()
    await redis.xadd(STREAM_SECURITY, {"event_id": "x", "risk": "not-a-number"})
    await agent.poll_once(block_ms=1)
    assert await redis.xlen(STREAM_DEADLETTER) == 1
    assert (await redis.xpending(STREAM_SECURITY, fa.GROUP))["pending"] == 0


async def test_restart_prunes_idle_consumers_keeps_ones_with_pending(redis):
    from kubeheal.contracts import STREAM_SECURITY as S
    old, _ = make(redis, consumer="pod-old")
    await old.ensure_groups()
    await redis.xadd(S, ransomware().to_fields())
    await redis.xreadgroup(fa.GROUP, "pod-crashed", {S: ">"})          # read, never acked
    await redis.xreadgroup(fa.GROUP, "pod-old", {S: ">"})               # nothing left: idle consumer
    new, _ = make(redis, consumer="pod-new")
    await new.ensure_groups()
    names = {c["name"] for c in await redis.xinfo_consumers(S, fa.GROUP)}
    assert names == {"pod-crashed"}                                     # its pending entry survives



async def test_lost_consumer_group_is_recreated(redis, monkeypatch):
    """Redis restart / reset.sh deletes the streams and with them the group: fusion must not spin on NOGROUP."""
    import asyncio

    import redis.asyncio as aioredis
    agent, _ = make(redis, mode="enforce")
    await agent.ensure_groups()
    await redis.delete(STREAM_HEALTH, STREAM_SECURITY)
    script = [aioredis.ResponseError("NOGROUP No such key or consumer group"), asyncio.CancelledError()]

    async def poll():
        raise script.pop(0)
    monkeypatch.setattr(agent, "poll_once", poll)
    with pytest.raises(asyncio.CancelledError):
        await agent.run()
    for stream in (STREAM_HEALTH, STREAM_SECURITY):
        assert [g["name"] for g in await redis.xinfo_groups(stream)] == [fa.GROUP]
