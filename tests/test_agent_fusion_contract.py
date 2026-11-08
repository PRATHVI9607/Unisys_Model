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
    """Stands in for CoreV1Api, AppsV1Api, NetworkingV1Api and BatchV1Api at once."""

    def __init__(self, pod_labels=None, dep_labels=None, errors=None, ns_labels=None, owners="web", pod_uid="uid-123",
                 pod_owner=None, ctrl_labels=None):
        self.calls, self.pod_labels, self.dep_labels, self.ns_labels = [], pod_labels, dep_labels, ns_labels
        self.owners, self.pod_uid = owners, pod_uid     # owners: Deployment name the pod's ReplicaSet belongs to
        self.pod_owner, self.ctrl_labels = pod_owner, ctrl_labels   # (kind, name) of a non-RS controller
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
        kind, owner = self.pod_owner or (("ReplicaSet", "web-7d9f") if self.owners else (None, None))
        refs = [SimpleNamespace(kind=kind, name=owner, controller=True)] if kind else []
        return SimpleNamespace(metadata=SimpleNamespace(name=name, uid=self.pod_uid, labels=self.pod_labels,
                                                        owner_references=refs))

    async def read_namespaced_replica_set(self, name, ns):
        self._rec("read_namespaced_replica_set", name, ns)
        return SimpleNamespace(metadata=SimpleNamespace(
            owner_references=[SimpleNamespace(kind="Deployment", name=self.owners, controller=True)]))

    async def read_namespaced_deployment(self, name, ns):
        self._rec("read_namespaced_deployment", name, ns)
        spec = {"replicas": 2, "selector": {"matchLabels": {"app": "web"}}, "template": TEMPLATE}
        return SimpleNamespace(metadata=SimpleNamespace(name=name, uid="uid-dep", labels=self.dep_labels),
                               to_dict=lambda serialize=False: {"spec": spec})

    async def _ctrl(self, method, name, ns):
        self._rec(method, name, ns)
        return SimpleNamespace(metadata=SimpleNamespace(name=name, labels=self.ctrl_labels))

    async def read_namespaced_stateful_set(self, name, ns):
        return await self._ctrl("read_namespaced_stateful_set", name, ns)

    async def read_namespaced_daemon_set(self, name, ns):
        return await self._ctrl("read_namespaced_daemon_set", name, ns)

    async def read_namespaced_job(self, name, ns):
        return await self._ctrl("read_namespaced_job", name, ns)

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
    return fa.FusionAgent(redis, kube, kube, kube, kube, **kw), kube


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
    assert kube.names == ["read_namespaced_pod", "read_namespaced_deployment", "read_namespaced_replica_set",
                          "patch_namespaced_pod", "create_namespaced_network_policy",
                          "delete_namespaced_pod"]   # quarantine before delete
    label_body = kube.calls[3][1][2]
    assert label_body == {"metadata": {"uid": "uid-123", "labels": {"kubeheal.io/quarantined": "true"}}}
    ns, policy = kube.calls[4][1]
    assert ns == "prod-shop"
    assert policy["metadata"]["ownerReferences"][0] == {"apiVersion": "v1", "kind": "Pod",
                                                        "name": "web-7d9f-abcde", "uid": "uid-123"}
    assert policy["spec"] == {"podSelector": {"matchLabels": {"kubeheal.io/quarantined": "true"}},
                              "policyTypes": ["Ingress", "Egress"]}       # no rules = deny all
    opts = kube.calls[5][2]
    assert opts["grace_period_seconds"] == 0 and opts["body"].preconditions.uid == "uid-123"   # read UID, always


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
    assert await redis.get(fa.key_circuit("kill", "prod-shop", "Deployment/web")) == "1"


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

    async def boom(ev, ack=None):
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


# ── review fixes ────────────────────────────────────────────────────────────
class OwnerKube(FakeKube):
    """Only the real Deployment exists; a Deployment named after the pod is a 404."""

    async def read_namespaced_deployment(self, name, ns):
        if name != "web":
            self._rec("read_namespaced_deployment", name, ns)
            raise ApiException(status=404, reason="NotFound")
        return await super().read_namespaced_deployment(name, ns)


async def test_protected_deployment_found_via_owner_when_event_workload_is_the_pod_name(redis):
    kube = OwnerKube(dep_labels={"kubeheal.io/protected": "true"}, owners="web")
    agent, _ = make(redis, kube, mode="enforce")
    ev = ransomware()
    ev.workload = ev.pod                        # security agent's owner lookup failed
    assert (await agent.handle(ev)).outcome == "skipped_protected"
    assert not MUTATING & set(kube.names)


async def test_lock_and_circuit_keyed_on_resolved_deployment(redis):
    agent, kube = make(redis, OwnerKube(owners="web"), mode="enforce")
    ev = ransomware()
    ev.workload = ev.pod
    assert (await agent.handle(ev)).outcome == "pod_killed"
    assert await redis.get(fa.key_circuit("kill", "prod-shop", "Deployment/web")) == "1"


async def test_stale_pod_uid_is_not_deleted(redis):
    agent, kube = make(redis, FakeKube(pod_uid="new-uid"), mode="enforce")
    ev = ransomware()
    ev.pod_uid = "old-uid"
    assert (await agent.handle(ev)).outcome == "skipped_stale_pod"
    assert not MUTATING & set(kube.names)


async def test_delete_carries_uid_precondition_when_known(redis):
    agent, kube = make(redis, mode="enforce")
    ev = ransomware()
    ev.pod_uid = "uid-123"
    assert (await agent.handle(ev)).outcome == "pod_killed"
    opts = kube.calls[-1][2]["body"]
    assert opts.preconditions.uid == "uid-123"


async def test_partner_not_handled_after_a_failed_or_skipped_outcome(redis, monkeypatch):
    agent, kube = make(redis, mode="enforce", max_kills=5)
    t = now_ms()
    monkeypatch.setattr(fa, "incident_lock", lock_stub(False))
    assert (await agent.handle(ransomware(eid="s1", ts=t))).outcome == "skipped_locked"
    monkeypatch.setattr(fa, "incident_lock", lock_stub(True))
    paired = await agent.handle(drift(eid="h1", ts=t + 1000))      # same AUTO_KILL, but nothing was killed yet
    assert paired.outcome == "pod_killed"


async def test_failed_tier_lookup_is_cached(redis):
    kube = FakeKube(errors={"read_namespace": 500})
    agent, _ = make(redis, kube)
    reads = []
    orig = kube.read_namespace
    kube.read_namespace = lambda n: reads.append(n) or orig(n)
    assert await agent.tier("demo") is None and await agent.tier("demo") is None
    assert len(reads) == 1


async def test_connection_error_becomes_failed_outcome(redis):
    import aiohttp
    kube = FakeKube()

    async def boom(*a, **k):
        raise aiohttp.ClientConnectionError("down")
    kube.read_namespaced_pod = boom
    agent, _ = make(redis, kube, mode="enforce")
    assert (await agent.handle(ransomware())).outcome == "failed:kube_ClientConnectionError"


async def test_recreated_group_replays_events_published_during_the_loss(redis, monkeypatch):
    agent, kube = make(redis, mode="enforce")
    await agent.ensure_groups()
    await redis.delete(STREAM_HEALTH, STREAM_SECURITY)
    await redis.xadd(STREAM_SECURITY, ransomware().to_fields())   # published before fusion noticed
    await agent.ensure_groups("0")
    await agent.poll_once(block_ms=1)
    assert kube.names.count("delete_namespaced_pod") == 1


# ── controller resolution, idempotency, containment ─────────────────────────
PROTECTED = {"kubeheal.io/protected": "true"}


async def test_breaker_and_lock_keyed_on_the_daemonset_not_the_pod(redis):
    agent, kube = make(redis, FakeKube(pod_owner=("DaemonSet", "node-agent")), mode="enforce", max_kills=1)
    assert (await agent.handle(ransomware(eid="s1", pod="node-agent-aaaaa"))).outcome == "pod_killed"
    # the replacement pod has a new name but the same controller: the budget is spent
    assert (await agent.handle(ransomware(eid="s2", pod="node-agent-bbbbb"))).outcome == "skipped_circuit_open"
    assert await redis.get(fa.key_circuit("kill", "prod-shop", "DaemonSet/node-agent")) == "1"
    assert "read_namespaced_daemon_set" in kube.names


@pytest.mark.parametrize("kind", ["StatefulSet", "DaemonSet", "Job"])
async def test_protected_controller_label_is_honoured(redis, kind):
    kube = FakeKube(pod_owner=(kind, "db"), ctrl_labels=PROTECTED)
    agent, _ = make(redis, kube, mode="enforce")
    assert (await agent.handle(ransomware())).outcome == "skipped_protected"
    assert not MUTATING & set(kube.names)


async def test_unreadable_controller_kind_escalates(redis):
    agent, kube = make(redis, FakeKube(pod_owner=("Rollout", "web")), mode="enforce")
    a = await agent.handle(ransomware())
    assert (a.decision, a.outcome) == (Decision.HUMAN, "escalated_unknown_owner")
    assert not MUTATING & set(kube.names)


async def test_bare_pod_is_its_own_target(redis):
    agent, _ = make(redis, FakeKube(owners=None), mode="enforce")
    assert (await agent.handle(ransomware())).outcome == "pod_killed"
    assert await redis.get(fa.key_circuit("kill", "prod-shop", "Pod/web-7d9f-abcde")) == "1"


async def test_quarantine_label_uid_conflict_is_a_stale_pod(redis):
    agent, kube = make(redis, FakeKube(errors={"patch_namespaced_pod": 409}), mode="enforce")
    assert (await agent.handle(ransomware())).outcome == "skipped_stale_pod"
    assert "delete_namespaced_pod" not in kube.names


async def test_breaker_counts_only_successful_kills(redis):
    kube = FakeKube(errors={"delete_namespaced_pod": 500})
    agent, _ = make(redis, kube, mode="enforce", max_kills=1)
    for i in range(3):
        assert (await agent.handle(ransomware(eid=f"s{i}"))).outcome == "failed:api_500_Fake"
    kube.errors = {}
    assert (await agent.handle(ransomware(eid="s9"))).outcome == "pod_killed"


async def test_failed_publish_is_retried_without_acting_twice(redis, monkeypatch):
    agent, kube = make(redis, mode="enforce")
    real, calls = fa.publish_event, []

    async def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionError("redis blip")
        await real(*a, **k)
    monkeypatch.setattr(fa, "publish_event", flaky)
    ev = ransomware()
    with pytest.raises(ConnectionError):
        await agent.handle(ev)
    again = await agent.handle(ev)                                    # redelivery
    assert again.outcome == "pod_killed" and kube.names.count("delete_namespaced_pod") == 1
    assert await redis.xlen(STREAM_ACTIONS) == 1
    assert await redis.get(fa.key_circuit("kill", "prod-shop", "Deployment/web")) == "1"


async def test_publish_and_ack_in_one_transaction(redis):
    agent, _ = make(redis)
    await agent.ensure_groups()
    await redis.xadd(STREAM_SECURITY, ransomware().to_fields())
    await agent.poll_once(block_ms=1)
    assert await redis.xlen(STREAM_ACTIONS) == 1
    assert (await redis.xpending(STREAM_SECURITY, fa.GROUP))["pending"] == 0


async def test_progress_counts_per_kube_call(redis):
    agent, _ = make(redis)
    agent.last_progress -= 100
    assert not agent.alive()
    await agent._kube(agent.core.read_namespace("x"))
    assert agent.alive()


async def test_non_nogroup_redis_error_backs_off_instead_of_crashing(redis, monkeypatch):
    import asyncio

    import redis.asyncio as aioredis
    monkeypatch.setattr(fa, "RETRY_S", 0)
    agent, _ = make(redis)
    script = [aioredis.ResponseError("OOM command not allowed when used memory > 'maxmemory'"),
              asyncio.CancelledError()]

    async def poll():
        raise script.pop(0)
    monkeypatch.setattr(agent, "poll_once", poll)
    with pytest.raises(asyncio.CancelledError):
        await agent.run()
    assert script == []


async def test_deadletter_failure_leaves_entry_pending(redis, monkeypatch):
    import redis.asyncio as aioredis
    agent, _ = make(redis)
    await agent.ensure_groups()
    await redis.xadd(STREAM_SECURITY, {"event_id": "x", "risk": "not-a-number"})

    async def oom(*a, **k):
        raise aioredis.ResponseError("OOM command not allowed")
    monkeypatch.setattr(redis, "xadd", oom)
    await agent.poll_once(block_ms=1)                                 # does not raise
    assert (await redis.xpending(STREAM_SECURITY, fa.GROUP))["pending"] == 1


async def test_namespace_gone_is_observed_not_escalated(redis):
    kube = FakeKube(errors={"read_namespace": 404})
    agent, _ = make(redis, kube, mode="enforce")
    a = await agent.handle(ransomware(ns="demo", risk=0.95))
    assert (a.decision, a.outcome) == (Decision.OBSERVE, "namespace_gone")
    assert "namespace gone" in a.rationale and kube.calls == []


async def test_containment_requested_before_the_delete(redis):
    agent, _ = make(redis, mode="enforce")
    a = await agent.handle(ransomware(eid="s7"))
    assert (a.outcome, a.containment) == ("pod_killed", "requested")
    (_, entry), = await redis.xrange(fa.STREAM_CONTAIN)
    assert {k: entry[k] for k in ("pod_uid", "namespace", "pod", "event_id")} == {
        "pod_uid": "uid-123", "namespace": "prod-shop", "pod": "web-7d9f-abcde", "event_id": "s7"}
    assert int(entry["ts_ms"]) > 0


@pytest.mark.parametrize("kw", [{"mode": "observe"}, {"mode": "enforce", "protected": PROTECTED_NAMESPACES | {"prod-shop"}}])
async def test_no_containment_when_not_killing(redis, kw):
    agent, _ = make(redis, **kw)
    a = await agent.handle(ransomware())
    assert a.containment == "" and await redis.xlen(fa.STREAM_CONTAIN) == 0


async def test_protected_pod_gets_no_containment(redis):
    agent, _ = make(redis, FakeKube(pod_labels=PROTECTED), mode="enforce")
    assert (await agent.handle(ransomware())).outcome == "skipped_protected"
    assert await redis.xlen(fa.STREAM_CONTAIN) == 0


async def test_containment_failure_never_blocks_the_kill(redis, monkeypatch):
    real = redis.xadd

    async def xadd(name, *a, **k):
        if name == fa.STREAM_CONTAIN:
            raise ConnectionError("redis down")
        return await real(name, *a, **k)
    monkeypatch.setattr(redis, "xadd", xadd)
    agent, kube = make(redis, mode="enforce")
    a = await agent.handle(ransomware())
    assert (a.outcome, a.containment) == ("pod_killed", "failed")


async def test_owner_chain_is_cached(redis):
    agent, kube = make(redis, mode="enforce", max_kills=5)
    await agent.handle(ransomware(eid="s1"))
    assert len(kube.calls) == 6
    kube.calls.clear()
    await agent.handle(ransomware(eid="s2", pod="web-7d9f-fghij"))       # same ReplicaSet
    assert kube.names == ["read_namespaced_pod", "read_namespaced_deployment", "patch_namespaced_pod",
                          "create_namespaced_network_policy", "delete_namespaced_pod"]


def _unsafe(t):
    t["spec"]["containers"][0]["securityContext"] = {"privileged": True}


def _relabel(t):
    t["metadata"]["labels"] = {"app": "evil"}


def _hostpath(t):
    t["spec"]["volumes"] = [{"name": "root", "hostPath": {"path": "/"}}]


@pytest.mark.parametrize("tamper", [_unsafe, _relabel, _hostpath, lambda t: t.update(spec="x")])
async def test_unsafe_baseline_is_never_restored(redis, tamper):
    agent, kube = make(redis, mode="enforce")
    template = json.loads(json.dumps(TEMPLATE))
    tamper(template)
    await redis.set(fa.key_baseline("prod-shop", "web"), json.dumps({"replicas": 2, "template": template}))
    a = await agent.handle(drift())
    assert (a.decision, a.outcome) == (Decision.HUMAN, "escalated_unsafe_baseline")
    assert "patch_namespaced_deployment" not in kube.names
