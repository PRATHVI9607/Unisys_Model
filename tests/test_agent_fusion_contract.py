"""Fusion agent: join, observe/enforce actions, publishing and stream handling.

Kube APIs are a fake that records every call; Redis is fakeredis. The incident
lock (Lua) is replaced by a stub here and tested in test_incident_lock.py.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import fakeredis
import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from agents.fusion_agent import agent as fa
from kubeheal.contracts import (
    KEY_MODE,
    LEDGER_RETENTION_DAYS,
    PROTECTED_NAMESPACES,
    STREAM_ACTIONS,
    STREAM_APPROVALS,
    STREAM_DEADLETTER,
    STREAM_HEALTH,
    STREAM_LEDGER,
    STREAM_SECURITY,
    ActionEvent,
    Decision,
    Factor,
    HealthEvent,
    SecurityEvent,
    key_approval,
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

    async def poll(streams=fa.STREAMS):
        if streams != fa.STREAMS:      # the approvals task idles; the script is for the event loop
            await asyncio.sleep(3600)
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

    async def poll(streams=fa.STREAMS):
        if streams != fa.STREAMS:      # the approvals task idles; the script is for the event loop
            await asyncio.sleep(3600)
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


# ── runtime kill switch ─────────────────────────────────────────────────────
@pytest.mark.parametrize("env, key, expected", [
    ("observe", "enforce", "observe"),     # the key can never raise the manifest's mode
    ("enforce", "observe", "observe"),     # the kill switch
    ("enforce", "enforce", "enforce"),
    ("enforce", None, "enforce"),
    ("enforce", "bogus", "enforce"),       # invalid key → env mode
    ("enforce", " OBSERVE ", "observe"),
    ("observe", None, "observe"),
])
async def test_effective_mode(redis, env, key, expected):
    agent, _ = make(redis, mode=env)
    if key is not None:
        await redis.set(KEY_MODE, key)
    await agent.refresh_mode()
    assert agent.mode == expected


async def test_switch_back_to_enforce_when_key_removed(redis):
    agent, kube = make(redis, mode="enforce")
    await redis.set(KEY_MODE, "observe")
    await agent.refresh_mode()
    assert (await agent.handle(ransomware(eid="a"))).outcome == "would_kill"
    await redis.delete(KEY_MODE)
    await agent.refresh_mode()
    assert (await agent.handle(ransomware(eid="b"))).outcome == "pod_killed"
    assert kube.names.count("delete_namespaced_pod") == 1


async def test_mode_is_refreshed_in_background_never_on_the_kill_path(redis, monkeypatch):
    assert fa.MODE_REFRESH_S <= 1.0
    monkeypatch.setattr(fa, "MODE_REFRESH_S", 0.01)
    agent, _ = make(redis, mode="enforce")
    reads = []
    real = redis.get

    async def get(name, *a, **k):
        reads.append(name)
        return await real(name, *a, **k)
    monkeypatch.setattr(redis, "get", get)
    await agent.handle(ransomware(eid="x"))
    assert KEY_MODE not in reads                      # the kill path never reads the switch
    task = asyncio.create_task(agent.mode_loop())
    try:
        await real(KEY_MODE)
        await redis.set(KEY_MODE, "observe")
        for _ in range(100):
            if agent.mode == "observe":
                break
            await asyncio.sleep(0.01)
        assert agent.mode == "observe"
    finally:
        task.cancel()


async def test_mode_read_error_keeps_last_mode(redis, monkeypatch):
    import redis.asyncio as aioredis
    agent, _ = make(redis, mode="enforce")

    async def boom(*a, **k):
        raise aioredis.ConnectionError("down")
    monkeypatch.setattr(redis, "get", boom)
    await agent.refresh_mode()
    assert agent.mode == "enforce"


# ── pending approvals, ledger ───────────────────────────────────────────────
def uncertain(ev):
    return ev.model_copy(update={"uncertain": True})   # policy: HUMAN (score high, not certain)


async def ledger_entries(redis):
    return [f for _, f in await redis.xrange(STREAM_LEDGER)]


async def human(agent, redis, ev=None):
    """Publish a HUMAN decision (an uncertain ransomware verdict with a pod) and return its ActionEvent."""
    a = await agent.handle(ev or uncertain(ransomware(eid="s-h")))
    assert a.decision is Decision.HUMAN
    return a


async def approve(agent, redis, action_id, decision="approve", aid="ap1", actor="alice", reason="looks bad"):
    await agent.ensure_groups(streams=(STREAM_APPROVALS,))
    await redis.xadd(STREAM_APPROVALS, {"approval_id": aid, "action_event_id": action_id, "decision": decision,
                                        "actor": actor, "reason": reason, "ts_ms": str(now_ms())})
    await agent.poll_once(block_ms=1, streams=(STREAM_APPROVALS,))


async def record(redis, action_id):
    return json.loads(await redis.get(key_approval(action_id)))


async def test_human_with_executable_candidate_writes_pending_approval_and_ledger(redis):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    rec = await record(redis, a.event_id)
    assert rec["state"] == "pending" and rec["candidate"] == "AUTO_KILL"
    assert (rec["namespace"], rec["workload"], rec["pod"], rec["pod_uid"]) == ("prod-shop", "web", "web-7d9f-abcde", "")
    assert rec["security_event_id"] == "s-h" and rec["score"] == a.score and rec["rationale"] == a.rationale
    assert 0 < await redis.ttl(key_approval(a.event_id)) <= 24 * 3600
    (entry,) = await ledger_entries(redis)
    assert (entry["kind"], entry["actor"], entry["outcome"], entry["decision"], entry["action_event_id"]) == (
        "approval_pending", "fusion", "pending", "AUTO_KILL", a.event_id)
    assert not [n for n in kube.names if n in MUTATING]


async def test_health_candidate_is_a_patch_and_no_candidate_means_no_record(redis):
    agent, _ = make(redis, mode="enforce")
    h = await agent.handle(uncertain(drift()))
    assert (await record(redis, h.event_id))["candidate"] == "AUTO_PATCH"
    # no baseline for the health event, no pod for the security event: nothing executable
    nb = await agent.handle(uncertain(drift(eid="h2").model_copy(update={"has_baseline": False})))
    np_ = await agent.handle(uncertain(ransomware(eid="s2", pod="")))
    for a in (nb, np_):
        assert a.decision is Decision.HUMAN and not await redis.exists(key_approval(a.event_id))
    assert [e["kind"] for e in await ledger_entries(redis)] == ["approval_pending"]


async def test_automatic_actions_are_ledgered_in_every_outcome(redis):
    agent, _ = make(redis, mode="enforce", protected=PROTECTED_NAMESPACES | {"prod-shop"})
    await agent.handle(ransomware())                                           # skipped_protected
    agent2, _ = make(redis)                                                    # observe: would_kill
    await agent2.handle(ransomware(eid="s2", ns="prod-x"))
    e1, e2 = await ledger_entries(redis)
    assert (e1["kind"], e1["decision"], e1["outcome"], e1["actor"], e1["mode"]) == (
        "action", "AUTO_KILL", "skipped_protected", "fusion", "enforce")
    assert (e2["outcome"], e2["mode"], e2["pod"], e2["security_event_id"]) == ("would_kill", "observe", "web-7d9f-abcde", "s2")
    assert int(e1["ts_ms"]) > 0 and e1["namespace"] == "prod-shop" and e1["workload"] == "web"


async def test_benign_and_observe_decisions_are_not_ledgered(redis):
    agent, _ = make(redis)
    await agent.handle(drift(risk=0.05, label="benign", eid="b1"))
    assert await redis.xlen(STREAM_LEDGER) == 0


async def test_ledger_xadd_trims_by_age(redis):
    """XADD MINID ~ now - retention (approximate trimming only drops whole nodes, so check the command)."""
    async with redis.pipeline(transaction=True) as p:
        fa.ledger("action", "fusion", "enforce", outcome="x")(p)
        (args, _), = p.command_stack
    args = [a.decode() if isinstance(a, bytes) else a for a in args]
    assert args[:5] == ["XADD", STREAM_LEDGER, "MINID", "~", args[4]]
    assert abs(int(args[4]) - (now_ms() - LEDGER_RETENTION_DAYS * 86_400_000)) < 5000


async def test_ledger_xadd_shares_the_transaction_of_the_publish(redis):
    """A failing publish leaves neither the ActionEvent nor a ledger entry (one MULTI)."""
    agent, _ = make(redis)
    real = redis.pipeline

    def pipeline(*a, **k):
        p = real(*a, **k)
        async def execute(*a, **k):
            raise ConnectionError("down")
        p.execute = execute
        return p
    redis.pipeline = pipeline
    with pytest.raises(ConnectionError):
        await agent.handle(ransomware())
    assert await redis.xlen(STREAM_ACTIONS) == 0 and await redis.xlen(STREAM_LEDGER) == 0


# ── approvals consumer ──────────────────────────────────────────────────────
async def test_approve_executes_through_every_rail_once(redis):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    await approve(agent, redis, a.event_id)
    assert kube.names.count("delete_namespaced_pod") == 1
    out = [ActionEvent.from_fields(f) for _, f in await redis.xrange(STREAM_ACTIONS)][-1]
    assert (out.decision, out.outcome, out.mode, out.security_event_id) == (Decision.AUTO_KILL, "pod_killed", "enforce", "s-h")
    assert out.event_id != a.event_id and out.pod == "web-7d9f-abcde"
    assert out.rationale == f"approved by alice: looks bad; original: {a.rationale}"
    rec = await record(redis, a.event_id)
    assert (rec["state"], rec["outcome"], rec["actor"]) == ("executed", "pod_killed", "alice")
    kinds = await ledger_entries(redis)
    assert [(e["kind"], e["actor"], e["outcome"]) for e in kinds] == [
        ("approval_pending", "fusion", "pending"), ("approval", "alice", "pod_killed")]
    assert kinds[1]["approval_id"] == "ap1" and kinds[1]["action_event_id"] == a.event_id
    assert (await redis.xpending(STREAM_APPROVALS, fa.GROUP))["pending"] == 0
    # a second approval of the same action never executes again
    await approve(agent, redis, a.event_id, aid="ap2", actor="bob")
    assert kube.names.count("delete_namespaced_pod") == 1
    last = (await ledger_entries(redis))[-1]
    assert (last["kind"], last["actor"], last["outcome"]) == ("approval", "bob", "refused:not_pending:executed")


async def test_concurrent_approvals_have_one_winner(redis):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    reqs = [{"approval_id": f"c{i}", "action_event_id": a.event_id, "decision": "approve", "actor": "x"}
            for i in range(3)]
    await asyncio.gather(*(agent.handle_approval(r) for r in reqs))
    assert kube.names.count("delete_namespaced_pod") == 1


async def test_approve_in_observe_is_a_dry_run(redis):
    agent, kube = make(redis)
    a = await human(agent, redis)
    await approve(agent, redis, a.event_id)
    out = [ActionEvent.from_fields(f) for _, f in await redis.xrange(STREAM_ACTIONS)][-1]
    assert (out.outcome, out.mode) == ("would_kill", "observe")
    assert not [n for n in kube.names if n in MUTATING]


async def test_approve_after_kill_switch_flips_is_a_dry_run(redis):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    await redis.set(KEY_MODE, "observe")
    await agent.refresh_mode()
    await approve(agent, redis, a.event_id)
    assert not [n for n in kube.names if n in MUTATING]
    assert (await record(redis, a.event_id))["outcome"] == "would_kill"


async def test_approve_respects_protected_namespace_label_and_uid(redis):
    for kube, kw, outcome in [
        (FakeKube(), {"protected": PROTECTED_NAMESPACES | {"prod-shop"}}, "skipped_protected"),
        (FakeKube(pod_labels=PROTECTED), {}, "skipped_protected"),
        (FakeKube(), {}, "skipped_stale_pod"),
    ]:
        agent, kube = make(redis, kube, mode="enforce", **kw)
        ev = uncertain(ransomware(eid=f"s-{outcome}-{len(kw)}"))
        if outcome == "skipped_stale_pod":
            ev = ev.model_copy(update={"pod_uid": "other-uid"})
        a = await human(agent, redis, ev)
        await approve(agent, redis, a.event_id, aid=f"ap-{a.event_id}")
        assert not [n for n in kube.names if n in MUTATING]
        assert (await record(redis, a.event_id))["outcome"] == outcome
        assert (await record(redis, a.event_id))["state"] == "failed"


async def test_approve_patch_validates_the_baseline(redis):
    agent, kube = make(redis, mode="enforce")
    await set_baseline(redis)
    h = await agent.handle(uncertain(drift()))
    await approve(agent, redis, h.event_id)
    assert kube.names.count("patch_namespaced_deployment") == 1
    assert (await record(redis, h.event_id))["state"] == "executed"
    # a baseline that weakens posture is still refused by baseline_problem()
    agent2, kube2 = make(redis, mode="enforce")
    bad = {"metadata": {"labels": {"app": "other"}}, "spec": {"containers": [{"name": "w", "image": "w"}]}}
    await redis.set(key_baseline("prod-shop", "web"), json.dumps({"replicas": 2, "template": bad}))
    h2 = await agent2.handle(uncertain(drift(eid="h9")))
    await approve(agent2, redis, h2.event_id, aid="ap9")
    assert "patch_namespaced_deployment" not in kube2.names
    assert (await record(redis, h2.event_id))["outcome"] == "escalated_unsafe_baseline"


async def test_stale_approval_is_refused(redis):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    rec = await record(redis, a.event_id)
    await redis.set(key_approval(a.event_id), json.dumps({**rec, "created_ms": now_ms() - 2 * 3600 * 1000}), keepttl=True)
    n_actions = await redis.xlen(STREAM_ACTIONS)
    await approve(agent, redis, a.event_id)
    assert not [n for n in kube.names if n in MUTATING]
    assert await redis.xlen(STREAM_ACTIONS) == n_actions
    assert (await record(redis, a.event_id))["state"] == "pending"
    assert (await ledger_entries(redis))[-1]["outcome"] == "refused:stale"


async def test_reject_closes_the_approval(redis):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    await approve(agent, redis, a.event_id, decision="reject", reason="false alarm")
    assert (await record(redis, a.event_id))["state"] == "rejected"
    e = (await ledger_entries(redis))[-1]
    assert (e["kind"], e["outcome"], e["actor"], e["detail"]) == ("rejection", "rejected", "alice", "false alarm")
    await approve(agent, redis, a.event_id, aid="ap2")
    assert not [n for n in kube.names if n in MUTATING]
    assert (await ledger_entries(redis))[-1]["outcome"] == "refused:not_pending:rejected"


async def test_missing_record_and_bad_decision_are_refused(redis):
    agent, kube = make(redis, mode="enforce")
    await approve(agent, redis, "act-nope")
    a = await human(agent, redis)
    await approve(agent, redis, a.event_id, decision="maybe", aid="ap2")
    assert [e["outcome"] for e in (await ledger_entries(redis))[-3:]] == [
        "refused:no_such_approval", "pending", "refused:bad_decision"]
    assert (await record(redis, a.event_id))["state"] == "pending" and not kube.calls


async def test_malformed_approval_entry_is_dead_lettered(redis):
    agent, _ = make(redis)
    await agent.ensure_groups(streams=(STREAM_APPROVALS,))
    await redis.xadd(STREAM_APPROVALS, {"approval_id": "x"})
    await agent.poll_once(block_ms=1, streams=(STREAM_APPROVALS,))
    assert await redis.xlen(STREAM_DEADLETTER) == 1
    assert (await redis.xpending(STREAM_APPROVALS, fa.GROUP))["pending"] == 0


async def test_redelivered_approval_never_acts_twice(redis, monkeypatch):
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    real = fa.publish_event
    fails = [True]

    async def flaky(*args, **kw):
        if fails:
            fails.pop()
            raise ConnectionError("publish failed")
        return await real(*args, **kw)
    monkeypatch.setattr(fa, "publish_event", flaky)
    await approve(agent, redis, a.event_id)                       # executes, publish fails: entry stays pending
    assert (await redis.xpending(STREAM_APPROVALS, fa.GROUP))["pending"] == 1
    (msg_id, fields), = await redis.xrange(STREAM_APPROVALS)
    await agent.process(STREAM_APPROVALS, msg_id, fields, 2)      # redelivery
    assert kube.names.count("delete_namespaced_pod") == 1
    approvals = [e for e in await ledger_entries(redis) if e["kind"] == "approval"]
    assert [e["outcome"] for e in approvals] == ["pod_killed"]
    assert (await record(redis, a.event_id))["state"] == "executed"
    assert (await redis.xpending(STREAM_APPROVALS, fa.GROUP))["pending"] == 0


async def test_event_redelivery_keeps_one_pending_approval_and_one_ledger_entry(redis):
    agent, _ = make(redis)
    ev = uncertain(ransomware(eid="s-r"))
    a = await agent.handle(ev)
    rec = await redis.get(key_approval(a.event_id))
    await agent.handle(ev)                                        # done-marker path republishes the same action
    assert await redis.get(key_approval(a.event_id)) == rec


class SlowKube(FakeKube):
    """Blocks reading pod "slow-pod" until released."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.entered, self.release = asyncio.Event(), asyncio.Event()

    async def read_namespaced_pod(self, name, ns):
        if name == "slow-pod":
            self.entered.set()
            await self.release.wait()
        return await super().read_namespaced_pod(name, ns)


async def test_a_slow_approval_never_delays_event_handling(redis):
    kube = SlowKube()
    agent, _ = make(redis, kube, mode="enforce")
    slow = await human(agent, redis, uncertain(ransomware(eid="s-slow", pod="slow-pod")))
    await agent.ensure_groups(streams=(STREAM_APPROVALS,))
    await redis.xadd(STREAM_APPROVALS, {"approval_id": "ap-s", "action_event_id": slow.event_id,
                                        "decision": "approve", "actor": "alice"})
    approvals = asyncio.create_task(agent.poll_once(block_ms=1, streams=(STREAM_APPROVALS,)))
    await asyncio.wait_for(kube.entered.wait(), 2)               # the approval is stuck inside a kube call
    assert not approvals.done()
    fast = await asyncio.wait_for(agent.handle(ransomware(eid="s-fast", pod="fast-pod")), 1)
    assert fast.outcome == "pod_killed" and fast.containment == "requested"
    kube.release.set()
    await asyncio.wait_for(approvals, 2)
    assert (await record(redis, slow.event_id))["state"] == "executed"
    assert kube.names.count("delete_namespaced_pod") == 2


async def test_run_starts_mode_and_approval_tasks_beside_the_event_loop(redis, monkeypatch):
    monkeypatch.setattr(fa, "MODE_REFRESH_S", 0.01)
    agent, kube = make(redis, mode="enforce")
    a = await human(agent, redis)
    await agent.ensure_groups(streams=(STREAM_APPROVALS,))
    await redis.xadd(STREAM_APPROVALS, {"approval_id": "ap-r", "action_event_id": a.event_id,
                                        "decision": "approve", "actor": "alice"})
    await redis.set(KEY_MODE, "observe")
    real = agent.poll_once

    async def poll(streams=fa.STREAMS):
        if streams == fa.STREAMS:              # the event loop: done once both side tasks did their work
            while agent.mode != "observe" or (await record(redis, a.event_id))["state"] == "pending":  # noqa: ASYNC110
                await asyncio.sleep(0.01)
            raise asyncio.CancelledError
        await real(block_ms=1, streams=streams)   # fakeredis serialises blocking reads: keep this one short
        await asyncio.sleep(0.01)
    monkeypatch.setattr(agent, "poll_once", poll)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(agent.run(), 10)
    assert agent.mode == "observe" and (await record(redis, a.event_id))["outcome"] == "would_kill"


# ── alert webhook ───────────────────────────────────────────────────────────
async def test_alerts_for_actions_and_pending_approvals_only(redis):
    agent, _ = make(redis, alert_url="http://hook.invalid/x")
    await agent.handle(ransomware(eid="a1"))                                   # AUTO_KILL would_kill
    h = await agent.handle(uncertain(ransomware(eid="a2")))                    # HUMAN + candidate
    await agent.handle(uncertain(ransomware(eid="a3", pod="")))                # HUMAN, nothing to approve
    await agent.handle(drift(ns="dev-x", risk=0.05, label="benign", eid="b1"))   # BENIGN
    sent = [agent.alerter.queue.get_nowait() for _ in range(agent.alerter.queue.qsize())]
    assert [(b["decision"], b["outcome"]) for b in sent] == [("AUTO_KILL", "would_kill"), ("HUMAN", "none")]
    assert sent[1]["action_event_id"] == h.event_id and "needs approval" in sent[1]["text"]
    assert {"text", "namespace", "workload", "pod", "score", "mode", "console_path"} <= sent[0].keys()


async def test_no_alerter_without_url(redis):
    agent, _ = make(redis)
    assert agent.alerter is None
    await agent.handle(ransomware())


async def test_alert_queue_is_bounded_and_drops_oldest():
    from agents.fusion_agent.alerts import ALERTS, Alerter
    al = Alerter("http://hook.invalid/x", queue_max=3)
    before = ALERTS.labels("dropped")._value.get()
    for i in range(5):
        al.notify({"n": i})                                   # never blocks
    assert [al.queue.get_nowait()["n"] for _ in range(3)] == [2, 3, 4]
    assert ALERTS.labels("dropped")._value.get() - before == 2


async def test_alert_worker_posts_json_and_survives_a_dead_webhook():
    from aiohttp import web

    from agents.fusion_agent.alerts import Alerter
    got = []

    async def hook(request):
        got.append(await request.json())
        return web.Response(status=500 if len(got) == 1 else 200)
    app = web.Application()
    app.router.add_post("/x", hook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    al = Alerter(f"http://127.0.0.1:{port}/x")
    worker = asyncio.create_task(al.run())
    try:
        al.notify({"text": "one"})
        al.notify({"text": "two"})
        for _ in range(200):
            if len(got) == 2:
                break
            await asyncio.sleep(0.01)  # noqa: ASYNC110
        assert [g["text"] for g in got] == ["one", "two"]      # the 500 on the first did not stop the second
    finally:
        worker.cancel()
        await runner.cleanup()


async def test_slow_webhook_never_blocks_handling(redis):
    agent, _ = make(redis, alert_url="http://hook.invalid/x")  # no worker running: nothing drains the queue
    for i in range(150):
        await agent.handle(ransomware(eid=f"q{i}", pod=f"p{i}"))
    assert agent.alerter.queue.qsize() == 100


# ── containment HMAC ────────────────────────────────────────────────────────
async def test_containment_entries_are_signed_when_a_key_is_set(redis):
    from agents.common import contain_verify
    agent, _ = make(redis, mode="enforce", contain_key="s3cret")
    await agent.handle(ransomware(eid="sig1"))
    (_, entry), = await redis.xrange(fa.STREAM_CONTAIN)
    assert contain_verify("s3cret", entry) and not contain_verify("other", entry)
    assert not contain_verify("s3cret", {**entry, "pod": "evil"})
    assert not contain_verify("s3cret", {k: v for k, v in entry.items() if k != "sig"})


async def test_containment_is_unsigned_without_a_key(redis):
    agent, _ = make(redis, mode="enforce")
    await agent.handle(ransomware(eid="sig2"))
    (_, entry), = await redis.xrange(fa.STREAM_CONTAIN)
    assert "sig" not in entry
