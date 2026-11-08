"""Fusion agent: the single decision point of KubeHeal (docs/architecture.md, "Decision policy").

Consumes health + security events (Redis consumer group, single replica),
pairs them per workload by event time, scores the pair with
kubeheal.correlation, runs the pure decision policy, executes (enforce) or
records what it would do (observe, the default), and publishes every decision
to STREAM_ACTIONS.

Run: python -m agents.fusion_agent.agent
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time

import aiohttp
import redis.asyncio as aioredis
from kubernetes_asyncio import client
from kubernetes_asyncio.client.exceptions import ApiException
from prometheus_client import Counter

from agents.common import (
    connect_redis,
    load_kube_config,
    protected_namespaces,
    publish_event,
    run,
    setup_logging,
    start_http,
)
from agents.fusion_agent.decision_policy import decide
from agents.fusion_agent.incident_lock import circuit_count, circuit_open, incident_lock
from agents.health_agent.agent import policy_violations
from kubeheal.contracts import (
    CONTAIN_MAXLEN,
    PROTECTED_LABEL,
    PROTECTED_NAMESPACES,
    QUARANTINE_LABEL,
    STREAM_ACTIONS,
    STREAM_CONTAIN,
    STREAM_DEADLETTER,
    STREAM_HEALTH,
    STREAM_MAXLEN,
    STREAM_SECURITY,
    TIER_LABEL,
    TIERS,
    ActionEvent,
    Decision,
    HealthEvent,
    SecurityEvent,
    key_baseline,
    key_circuit,
    key_done,
    key_lock,
    new_event_id,
    now_ms,
    workload_key,
)
from kubeheal.correlation import COMPOUND_THRESHOLD, CORRELATION_WINDOW_S, compound_score
from kubeheal.features.health import canonical_spec

log = logging.getLogger("fusion")

GROUP = "fusion"
STREAMS = (STREAM_HEALTH, STREAM_SECURITY)
BATCH = 10
BLOCK_MS = 1000
CLAIM_MIN_IDLE_MS = 60_000
MAX_DELIVERIES = 3
MAX_EVENT_AGE_S = 300
KUBE_TIMEOUT_S = 10.0
LIVENESS_STALE_S = 30
TIER_TTL_S = 300
TIER_FAIL_TTL_S = 30
NAMESPACE_GONE = "<gone>"     # tier() result for a namespace that does not exist (404)
OWNER_TTL_S = 300             # ReplicaSet → Deployment cache (the mapping is fixed at RS creation)
OWNER_CACHE_MAX = 4096
CONTROLLERS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job"})   # pod controllers fusion can read
CONTAIN_TIMEOUT_S = 1.0       # the containment XADD never holds up the kill longer than this
DONE_TTL_S = 3600             # idempotency markers outlive every redelivery (stale after MAX_EVENT_AGE_S)
RETRY_S = 1.0                 # back-off after a Redis error in the consumer loop
# outcomes after which the same automatic decision on the partner event must not act again
HANDLED = frozenset({"pod_killed", "pod_already_gone", "patched", "would_kill", "would_patch"})

DECISIONS = Counter("kubeheal_fusion_decisions_total", "Decisions made", ["decision"])
OUTCOMES = Counter("kubeheal_fusion_outcomes_total", "Decision outcomes", ["outcome"])
DEADLETTERED = Counter("kubeheal_fusion_deadlettered_total", "Events moved to the dead-letter stream")
CONTAINMENT = Counter("kubeheal_fusion_containment_total", "Pod freeze requests on STREAM_CONTAIN",
                      ["result"])
SKIPPED_STALE = Counter("kubeheal_fusion_stale_events_total", "Events skipped as older than MAX_EVENT_AGE_S")

Event = HealthEvent | SecurityEvent
AUTOMATIC = (Decision.AUTO_KILL, Decision.AUTO_PATCH)


class PairBuffer:
    """Unpaired events per workload (with the decision and outcome taken on them alone), waiting for a partner.

    shortcut: in memory, so a restart forgets unpaired events (they were already
    decided alone); move to Redis if fusion ever runs more than one replica.
    """

    def __init__(self) -> None:
        self._pending: dict[tuple[str, type], tuple[Event, Decision, str]] = {}

    def partner(self, ev: Event) -> tuple[Event, Decision, str] | tuple[None, None, None]:
        other = SecurityEvent if isinstance(ev, HealthEvent) else HealthEvent
        hit = self._pending.get((workload_key(ev.namespace, ev.workload), other))
        if hit and abs(hit[0].timestamp_ms - ev.timestamp_ms) <= CORRELATION_WINDOW_S * 1000:
            return hit
        return None, None, None

    def commit(self, ev: Event, decision: Decision, outcome: str, partner: Event | None) -> None:
        """After a successful decision: a pair is consumed, a lone event waits for a partner."""
        key = workload_key(ev.namespace, ev.workload)
        if partner is not None:
            self._pending.pop((key, type(partner)), None)
        else:
            self._pending[(key, type(ev))] = (ev, decision, outcome)
        cutoff = now_ms() - (MAX_EVENT_AGE_S + CORRELATION_WINDOW_S) * 1000
        for k in [k for k, (e, _, _) in self._pending.items() if e.timestamp_ms < cutoff]:
            del self._pending[k]


def summarize(health: HealthEvent | None, security: SecurityEvent | None,
              cscore: float, reasons: list[str]) -> str:
    """1-3 plain sentences built only from the events (no LLM, nothing invented)."""
    def factors(ev: Event) -> str:
        names = [f.feature for f in ev.top_factors[:3]]
        return f"; top factors: {', '.join(names)}" if names else ""

    parts = []
    if security:
        parts.append(f"Security model rated pod {security.pod or '(unknown)'} of "
                     f"{security.namespace}/{security.workload} {security.label} "
                     f"(risk {security.risk:.2f}){factors(security)}.")
    if health:
        changed = f", changed {', '.join(health.changed_fields[:3])}" if health.changed_fields else ""
        parts.append(f"Health model rated the spec change of {health.namespace}/{health.workload} "
                     f"{health.label} (risk {health.risk:.2f}{changed}){factors(health)}.")
    if health and security:
        if cscore >= COMPOUND_THRESHOLD:
            parts.append(f"Correlated as one incident (score {cscore:.2f}): {'; '.join(reasons)}.")
        else:
            parts.append(f"Not treated as one incident (correlation {cscore:.2f} < {COMPOUND_THRESHOLD}).")
    return " ".join(parts)


def quarantine_policy(pod) -> dict:
    """Deny all ingress+egress for quarantined pods; GC'd together with the pod it is owned by."""
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"kubeheal-quarantine-{pod.metadata.name}"[:253],
            "labels": {"app.kubernetes.io/managed-by": "kubeheal"},
            "ownerReferences": [{"apiVersion": "v1", "kind": "Pod", "name": pod.metadata.name,
                                 "uid": pod.metadata.uid}],
        },
        "spec": {"podSelector": {"matchLabels": {QUARANTINE_LABEL: "true"}},
                 "policyTypes": ["Ingress", "Egress"]},
    }


def _labels(obj) -> dict:
    return (obj.metadata.labels or {}) if obj is not None else {}


def _controller_ref(obj):
    return next((r for r in obj.metadata.owner_references or [] if r.controller), None)


def baseline_problem(live: dict, template) -> str | None:
    """Why the stored baseline template must not replace the live Deployment's template; None if it may.

    Redis is reachable from other pods, so the restore target is checked, never trusted: it must be a pod
    template the Deployment's selector still matches, and no weaker in posture than what runs now.
    """
    try:
        if not (isinstance(template, dict) and isinstance(template.get("spec"), dict)
                and template["spec"].get("containers")):
            return "not a pod template"
        selector = live.get("selector") or {}
        labels = (template.get("metadata") or {}).get("labels") or {}
        # shortcut: matchExpressions selectors are not evaluated, so they always escalate.
        if selector.get("matchExpressions") or any(labels.get(k) != v for k, v in
                                                   (selector.get("matchLabels") or {}).items()):
            return "template labels do not match the selector"
        violations = policy_violations({"template": live.get("template") or {}}, {"template": template})
    except (AttributeError, TypeError, ValueError, KeyError) as e:   # malformed JSON shapes
        return f"unreadable template: {e!r}"
    return ", ".join(violations) or None


class FusionAgent:
    def __init__(self, redis, core, apps, net, batch, *, mode: str = "observe",
                 protected: frozenset = PROTECTED_NAMESPACES, max_kills: int = 3, max_patches: int = 5,
                 consumer: str = "fusion") -> None:
        self.redis, self.core, self.apps, self.net, self.batch = redis, core, apps, net, batch
        self.mode = mode
        self.protected = protected
        self.max_kills, self.max_patches = max_kills, max_patches
        self.consumer = consumer
        self.pairs = PairBuffer()
        self.last_progress = time.monotonic()
        self.tiers: dict[str, tuple[float, str | None]] = {}   # namespace → (expiry, TIER_LABEL value)
        self.owners: dict[tuple[str, str], tuple[float, tuple[str, str] | None]] = {}   # (ns, RS) → controller
        # Set by kill() during the current act(); read into the ActionEvent (also on a failed outcome).
        self.containment = ""

    # ── stream plumbing ─────────────────────────────────────────────────────
    async def ensure_groups(self, start: str = "$") -> None:
        for stream in STREAMS:
            try:   # "$": a fresh deploy starts at new events, never replays history; "0" after the group was lost
                await self.redis.xgroup_create(stream, GROUP, id=start, mkstream=True)
            except aioredis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise
            # Each pod is a new consumer (HOSTNAME); drop earlier ones with nothing pending so the group
            # does not grow per restart. Their unacked entries, if any, stay for XAUTOCLAIM.
            for c in await self.redis.xinfo_consumers(stream, GROUP):
                if c["name"] != self.consumer and c["pending"] == 0:
                    await self.redis.xgroup_delconsumer(stream, GROUP, c["name"])

    async def poll_once(self, block_ms: int = BLOCK_MS) -> None:
        self.last_progress = time.monotonic()
        for stream in STREAMS:   # retry entries another delivery left unacked
            _, claimed, _ = await self.redis.xautoclaim(stream, GROUP, self.consumer, CLAIM_MIN_IDLE_MS,
                                                        start_id="0-0", count=BATCH)
            for msg_id, fields in claimed:
                info = await self.redis.xpending_range(stream, GROUP, min=msg_id, max=msg_id, count=1)
                await self.process(stream, msg_id, fields, info[0]["times_delivered"] if info else MAX_DELIVERIES)
        resp = await self.redis.xreadgroup(GROUP, self.consumer, {s: ">" for s in STREAMS},
                                           count=BATCH, block=block_ms)
        for stream, entries in resp or []:
            for msg_id, fields in entries:
                await self.process(stream, msg_id, fields, 1)

    async def process(self, stream: str, msg_id: str, fields: dict, deliveries: int) -> None:
        """Ack only after successful handling; dead-letter malformed or repeatedly failing entries."""
        self.last_progress = time.monotonic()   # a batch of slow entries is progress, not a hang
        try:
            ev = (HealthEvent if stream == STREAM_HEALTH else SecurityEvent).from_fields(fields)
        except ValueError as e:   # pydantic ValidationError and bad JSON are ValueErrors
            log.error("malformed event %s on %s: %s", msg_id, stream, e)
            await self.deadletter(stream, msg_id, fields, f"malformed: {e}")
            return
        try:
            if await self.handle(ev, ack=(stream, GROUP, msg_id)) is not None:
                return                          # published and acked in one transaction
        except Exception as e:
            log.exception("handling %s on %s failed (delivery %d)", msg_id, stream, deliveries)
            if deliveries >= MAX_DELIVERIES:
                await self.deadletter(stream, msg_id, fields, repr(e))
            return
        await self.redis.xack(stream, GROUP, msg_id)   # stale: nothing published

    async def deadletter(self, stream: str, msg_id: str, fields: dict, error: str) -> None:
        try:
            await self.redis.xadd(STREAM_DEADLETTER,
                                  {**fields, "_stream": stream, "_id": msg_id, "_error": error[:500]},
                                  maxlen=STREAM_MAXLEN, approximate=True)
            await self.redis.xack(stream, GROUP, msg_id)
        except aioredis.RedisError:   # e.g. OOM: leave the entry pending, XAUTOCLAIM retries it later
            log.exception("could not dead-letter %s on %s", msg_id, stream)
            return
        DEADLETTERED.inc()

    # ── decision ────────────────────────────────────────────────────────────
    async def handle(self, ev: Event, ack: tuple[str, str, str] | None = None) -> ActionEvent | None:
        """Decide, act and publish one event; `ack` (stream, group, entry id) is XACKed with the publish."""
        if now_ms() - ev.timestamp_ms > MAX_EVENT_AGE_S * 1000:
            log.info("skipping stale %s (%.0f s old)", ev.event_id, (now_ms() - ev.timestamp_ms) / 1000)
            SKIPPED_STALE.inc()
            return None
        partner, partner_decision, partner_outcome = self.pairs.partner(ev)
        done = key_done(ev.event_id)
        if raw := await self.redis.get(done):   # acted on an earlier delivery whose publish or XACK failed
            action = ActionEvent.model_validate_json(raw)
        else:
            action = await self._decide(ev, partner, partner_decision, partner_outcome)
            # Recorded before publishing, so a redelivery after a failed publish/XACK never acts twice.
            await self.redis.set(done, action.model_dump_json(), nx=True, ex=DONE_TTL_S)
        await publish_event(self.redis, STREAM_ACTIONS, "action", action, ack)
        self.pairs.commit(ev, action.decision, action.outcome, partner)
        DECISIONS.labels(action.decision.value).inc()
        OUTCOMES.labels(action.outcome.split(":")[0]).inc()
        level = logging.WARNING if action.decision in AUTOMATIC else logging.INFO
        log.log(level, "%s %s/%s pod=%s outcome=%s :: %s", action.decision.value, ev.namespace, ev.workload,
                action.pod or "-", action.outcome, action.rationale)
        return action

    async def _decide(self, ev: Event, partner: Event | None, partner_decision: Decision | None,
                      partner_outcome: str | None) -> ActionEvent:
        health, security = (ev, partner) if isinstance(ev, HealthEvent) else (partner, ev)
        cscore, reasons = compound_score(health, security) if health and security else (0.0, [])
        label = await self.tier(ev.namespace)
        result = decide(health, security, compound=cscore >= COMPOUND_THRESHOLD,
                        tier=None if label == NAMESPACE_GONE else label)
        decision, rationale, self.containment = result.decision, result.rationale, ""
        if label == NAMESPACE_GONE and decision is not Decision.BENIGN:
            # Everything in it is deleted: nothing to act on or escalate, and the name-heuristic tier misleads.
            decision, outcome = Decision.OBSERVE, "namespace_gone"
            rationale = f"namespace gone, nothing to act on (policy alone: {result.decision.value}; {rationale})"
        elif decision is partner_decision and decision in AUTOMATIC and partner_outcome in HANDLED:
            # Same action on the same pod/workload was already taken when the partner was decided alone.
            outcome = "already_handled"
        else:
            decision, outcome = await self.act(decision, health, security)
        return ActionEvent(
            event_id=new_event_id("act"), namespace=ev.namespace, workload=ev.workload,
            pod=security.pod if security else "", decision=decision, mode=self.mode, outcome=outcome,
            score=result.score, compound_score=round(cscore, 4), rationale=rationale,
            summary=summarize(health, security, cscore, reasons),
            health_event_id=health.event_id if health else "",
            security_event_id=security.event_id if security else "",
            containment=self.containment,
        )

    # ── actions ─────────────────────────────────────────────────────────────
    async def act(self, decision: Decision, health: HealthEvent | None,
                  security: SecurityEvent | None) -> tuple[Decision, str]:
        if decision not in AUTOMATIC:
            return decision, "none"
        ev = security if decision is Decision.AUTO_KILL else health
        ns, wl = ev.namespace, ev.workload
        if ns in self.protected:
            return decision, "skipped_protected"
        try:
            if decision is Decision.AUTO_KILL:
                if not security.pod:
                    return Decision.HUMAN, "escalated_no_pod"
                outcome = await self.kill(ns, wl, security.pod, security.pod_uid, security.event_id)
            else:
                try:
                    baseline = json.loads(await self.redis.get(key_baseline(ns, wl)))
                    template = baseline["template"]
                except (TypeError, ValueError, KeyError):   # missing or unreadable baseline
                    template = None
                if not template:
                    return Decision.HUMAN, "escalated_no_baseline"
                ops = [{"op": "replace", "path": "/spec/template", "value": template}]
                if "replicas" in health.changed_fields:     # the drift scaled it (e.g. to 0): restore that too
                    ops.append({"op": "replace", "path": "/spec/replicas", "value": baseline.get("replicas", 1)})
                outcome = await self.patch(ns, wl, ops)
        except TimeoutError:
            return decision, "failed:kube_timeout"
        except aiohttp.ClientError as e:
            return decision, f"failed:kube_{type(e).__name__}"
        except ApiException as e:
            return decision, f"failed:api_{e.status}_{e.reason}"
        return (Decision.HUMAN if outcome.startswith("escalated_") else decision), outcome

    async def tier(self, ns: str) -> str | None:
        """The namespace's TIER_LABEL (cached); None → the policy falls back to the name heuristic;
        NAMESPACE_GONE when the namespace does not exist."""
        now = time.monotonic()
        if (hit := self.tiers.get(ns)) and hit[0] > now:
            return hit[1]
        try:
            label = _labels(await self._kube(self.core.read_namespace(ns))).get(TIER_LABEL)
        except (ApiException, TimeoutError, aiohttp.ClientError) as e:
            status = getattr(e, "status", None)
            if status == 404:
                self.tiers[ns] = (now + TIER_FAIL_TTL_S, NAMESPACE_GONE)   # short: the name may be re-created
                return NAMESPACE_GONE
            log.warning("tier lookup for namespace %s failed (%s); using its name", ns, status or e)
            self.tiers[ns] = (now + TIER_FAIL_TTL_S, None)   # do not hammer a failing API on every event
            return None
        if label is not None and label not in TIERS:
            log.warning("namespace %s has invalid %s=%r; using its name", ns, TIER_LABEL, label)
            label = None
        self.tiers[ns] = (now + TIER_TTL_S, label)
        return label

    async def _kube(self, coro):
        try:
            return await asyncio.wait_for(coro, KUBE_TIMEOUT_S)
        finally:
            self.last_progress = time.monotonic()   # every call ends within KUBE_TIMEOUT_S: progress

    async def _read(self, kind: str, ns: str, name: str):
        """GET a pod or workload object; None when it does not exist (404)."""
        api, method = {"Pod": (self.core, "read_namespaced_pod"),
                       "ReplicaSet": (self.apps, "read_namespaced_replica_set"),
                       "Deployment": (self.apps, "read_namespaced_deployment"),
                       "StatefulSet": (self.apps, "read_namespaced_stateful_set"),
                       "DaemonSet": (self.apps, "read_namespaced_daemon_set"),
                       "Job": (self.batch, "read_namespaced_job")}[kind]
        try:
            return await self._kube(getattr(api, method)(name, ns))
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    async def _controller(self, ns: str, pod) -> tuple[str, str] | None:
        """(kind, name) of the workload controlling the pod: a ReplicaSet's Deployment; a StatefulSet,
        DaemonSet or Job itself; the pod itself when bare. None: a controller kind fusion cannot read,
        so its kubeheal.io/protected label cannot be checked."""
        ref = _controller_ref(pod)
        if ref is None:
            return "Pod", pod.metadata.name
        if ref.kind != "ReplicaSet":
            return (ref.kind, ref.name) if ref.kind in CONTROLLERS else None
        now = time.monotonic()
        if (hit := self.owners.get((ns, ref.name))) and hit[0] > now:
            return hit[1]   # an RS's controller is fixed at creation; the controller itself is still read fresh
        rs = await self._read("ReplicaSet", ns, ref.name)
        up = _controller_ref(rs) if rs is not None else None
        if up is None:
            return "ReplicaSet", ref.name      # bare, orphaned or already deleted ReplicaSet
        owner = ("Deployment", up.name) if up.kind == "Deployment" else None   # e.g. an Argo Rollout
        if len(self.owners) >= OWNER_CACHE_MAX:
            self.owners.clear()
        self.owners[(ns, ref.name)] = (now + OWNER_TTL_S, owner)
        return owner

    async def kill(self, ns: str, wl: str, pod_name: str, pod_uid: str = "", event_id: str = "") -> str:
        # The event's workload is normally the controlling Deployment: read it alongside the pod (one
        # round trip instead of two). The pod's own controller is resolved and checked too.
        pod, wl_dep = await asyncio.gather(self._read("Pod", ns, pod_name), self._read("Deployment", ns, wl))
        if pod is None:
            return "pod_already_gone"
        if pod_uid and pod.metadata.uid != pod_uid:
            return "skipped_stale_pod"      # the name now belongs to a different pod
        owner = await self._controller(ns, pod)
        if owner is None:
            return "escalated_unknown_owner"
        kind, name = owner
        ctrl = (pod if kind == "Pod" else wl_dep if owner == ("Deployment", wl)
                else await self._read(kind, ns, name))
        if "true" in {_labels(o).get(PROTECTED_LABEL) for o in (pod, ctrl, wl_dep)}:
            return "skipped_protected"
        if self.mode != "enforce":
            return "would_kill"
        target, uid = f"{kind}/{name}", pod.metadata.uid
        async with incident_lock(self.redis, key_lock(ns, target)) as held:
            if not held:
                return "skipped_locked"
            breaker = key_circuit("kill", ns, target)
            if await circuit_open(self.redis, breaker, self.max_kills):
                return "skipped_circuit_open"
            contain = asyncio.create_task(self._contain(ns, pod_name, uid, event_id))   # freeze within ms
            try:
                # Quarantine (label + deny-all policy, concurrently) strictly before the delete, so the pod
                # is never alive and un-isolated. Both the patch and the delete carry the UID read above:
                # a successor that reuses the name (StatefulSet) is rejected with 409.
                await asyncio.gather(
                    self._kube(self.core.patch_namespaced_pod(
                        pod_name, ns, {"metadata": {"uid": uid, "labels": {QUARANTINE_LABEL: "true"}}})),
                    self._create_quarantine_policy(ns, pod))
                await self._kube(self.core.delete_namespaced_pod(
                    pod_name, ns, grace_period_seconds=0,
                    body=client.V1DeleteOptions(preconditions=client.V1Preconditions(uid=uid))))
            except ApiException as e:
                if e.status == 404:
                    return "pod_already_gone"
                if e.status == 409:
                    return "skipped_stale_pod"      # UID precondition failed
                raise
            finally:
                await contain                       # bounded by CONTAIN_TIMEOUT_S, never raises
            await circuit_count(self.redis, breaker)
        return "pod_killed"

    async def _contain(self, ns: str, pod: str, uid: str, event_id: str) -> None:
        """Ask every node's security agent to freeze the pod's cgroup now. Best effort: never delays the
        kill by more than CONTAIN_TIMEOUT_S and never fails it; the API delete follows regardless."""
        try:
            await asyncio.wait_for(self.redis.xadd(
                STREAM_CONTAIN, {"pod_uid": uid, "namespace": ns, "pod": pod, "event_id": event_id,
                                 "ts_ms": str(now_ms())},
                maxlen=CONTAIN_MAXLEN, approximate=True), CONTAIN_TIMEOUT_S)
        except Exception:   # any failure here must leave the kill path untouched
            log.warning("containment request for %s/%s failed; deleting via the API only", ns, pod, exc_info=True)
            self.containment = "failed"
        else:
            self.containment = "requested"
        CONTAINMENT.labels(self.containment).inc()

    async def _create_quarantine_policy(self, ns: str, pod) -> None:
        try:
            await self._kube(self.net.create_namespaced_network_policy(ns, quarantine_policy(pod)))
        except ApiException as e:
            if e.status != 409:   # 409: policy from an earlier attempt already exists
                raise

    async def patch(self, ns: str, wl: str, ops: list[dict]) -> str:
        dep = await self._read("Deployment", ns, wl)
        if dep is None:
            return "workload_gone"
        if _labels(dep).get(PROTECTED_LABEL) == "true":
            return "skipped_protected"
        if problem := baseline_problem(canonical_spec(dep), ops[0]["value"]):
            log.warning("baseline of %s/%s not restored: %s", ns, wl, problem)
            return "escalated_unsafe_baseline"
        if self.mode != "enforce":
            return "would_patch"
        target = f"Deployment/{wl}"
        async with incident_lock(self.redis, key_lock(ns, target)) as held:
            if not held:
                return "skipped_locked"
            breaker = key_circuit("patch", ns, target)
            if await circuit_open(self.redis, breaker, self.max_patches):
                return "skipped_circuit_open"
            try:
                await self._kube(self.apps.patch_namespaced_deployment(
                    wl, ns, ops, _content_type="application/json-patch+json"))
            except ApiException as e:
                if e.status == 404:
                    return "workload_gone"
                raise
            await circuit_count(self.redis, breaker)
        return "patched"

    # ── process ─────────────────────────────────────────────────────────────
    def alive(self) -> bool:
        return time.monotonic() - self.last_progress < LIVENESS_STALE_S

    async def run(self) -> None:
        log.info("fusion starting mode=%s consumer=%s protected=%s", self.mode, self.consumer, sorted(self.protected))
        start: str | None = "$"
        while True:
            try:
                if start:
                    await self.ensure_groups(start)
                    start = None
                await self.poll_once()
            except aioredis.RedisError as e:
                if "NOGROUP" in str(e):
                    # Redis restarted (no persistence) or the streams were deleted: recreate, keep consuming.
                    log.warning("consumer group missing (%s); recreating", e)
                    start = "0"   # "$" would drop what was published since the loss
                else:             # e.g. OOM or a timeout: back off and retry, never crash-loop
                    log.exception("redis error in consumer loop; retrying in %.0f s", RETRY_S)
                    await asyncio.sleep(RETRY_S)


async def main() -> None:
    setup_logging()
    mode = os.environ.get("KUBEHEAL_MODE", "observe").strip().lower()
    if mode not in ("observe", "enforce"):
        log.warning("unknown KUBEHEAL_MODE=%r; using observe", mode)
        mode = "observe"
    await load_kube_config()
    api = client.ApiClient()
    redis = await connect_redis()
    agent = FusionAgent(
        redis, client.CoreV1Api(api), client.AppsV1Api(api), client.NetworkingV1Api(api), client.BatchV1Api(api),
        mode=mode,
        protected=protected_namespaces(),
        max_kills=int(os.environ.get("MAX_KILLS_PER_HOUR", "3")),
        max_patches=int(os.environ.get("MAX_PATCHES_PER_HOUR", "5")),
        consumer=os.environ.get("HOSTNAME") or socket.gethostname(),
    )
    runner = await start_http(agent.alive)
    try:
        await agent.run()
    finally:
        await runner.cleanup()
        await redis.aclose()
        await api.close()


if __name__ == "__main__":
    run(main)
