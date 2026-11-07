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
from agents.fusion_agent.incident_lock import circuit_allows, incident_lock
from kubeheal.contracts import (
    PROTECTED_LABEL,
    PROTECTED_NAMESPACES,
    QUARANTINE_LABEL,
    STREAM_ACTIONS,
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
    key_lock,
    new_event_id,
    now_ms,
    workload_key,
)
from kubeheal.correlation import COMPOUND_THRESHOLD, CORRELATION_WINDOW_S, compound_score

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
# outcomes after which the same automatic decision on the partner event must not act again
HANDLED = frozenset({"pod_killed", "pod_already_gone", "patched", "would_kill", "would_patch"})

DECISIONS = Counter("kubeheal_fusion_decisions_total", "Decisions made", ["decision"])
OUTCOMES = Counter("kubeheal_fusion_outcomes_total", "Decision outcomes", ["outcome"])
DEADLETTERED = Counter("kubeheal_fusion_deadlettered_total", "Events moved to the dead-letter stream")
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


class FusionAgent:
    def __init__(self, redis, core, apps, net, *, mode: str = "observe", protected: frozenset = PROTECTED_NAMESPACES,
                 max_kills: int = 3, max_patches: int = 5, consumer: str = "fusion") -> None:
        self.redis, self.core, self.apps, self.net = redis, core, apps, net
        self.mode = mode
        self.protected = protected
        self.max_kills, self.max_patches = max_kills, max_patches
        self.consumer = consumer
        self.pairs = PairBuffer()
        self.last_poll = time.monotonic()
        self.tiers: dict[str, tuple[float, str | None]] = {}   # namespace → (expiry, TIER_LABEL value)

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
        self.last_poll = time.monotonic()
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
        try:
            ev = (HealthEvent if stream == STREAM_HEALTH else SecurityEvent).from_fields(fields)
        except ValueError as e:   # pydantic ValidationError and bad JSON are ValueErrors
            log.error("malformed event %s on %s: %s", msg_id, stream, e)
            await self.deadletter(stream, msg_id, fields, f"malformed: {e}")
            return
        try:
            await self.handle(ev)
        except Exception as e:
            log.exception("handling %s on %s failed (delivery %d)", msg_id, stream, deliveries)
            if deliveries >= MAX_DELIVERIES:
                await self.deadletter(stream, msg_id, fields, repr(e))
            return
        await self.redis.xack(stream, GROUP, msg_id)

    async def deadletter(self, stream: str, msg_id: str, fields: dict, error: str) -> None:
        await self.redis.xadd(STREAM_DEADLETTER,
                              {**fields, "_stream": stream, "_id": msg_id, "_error": error[:500]},
                              maxlen=STREAM_MAXLEN, approximate=True)
        await self.redis.xack(stream, GROUP, msg_id)
        DEADLETTERED.inc()

    # ── decision ────────────────────────────────────────────────────────────
    async def handle(self, ev: Event) -> ActionEvent | None:
        if now_ms() - ev.timestamp_ms > MAX_EVENT_AGE_S * 1000:
            log.info("skipping stale %s (%.0f s old)", ev.event_id, (now_ms() - ev.timestamp_ms) / 1000)
            SKIPPED_STALE.inc()
            return None
        partner, partner_decision, partner_outcome = self.pairs.partner(ev)
        health, security = (ev, partner) if isinstance(ev, HealthEvent) else (partner, ev)
        cscore, reasons = compound_score(health, security) if health and security else (0.0, [])
        result = decide(health, security, compound=cscore >= COMPOUND_THRESHOLD, tier=await self.tier(ev.namespace))
        if result.decision is partner_decision and partner_decision in AUTOMATIC and partner_outcome in HANDLED:
            # Same action on the same pod/workload was already taken when the partner was decided alone.
            decision, outcome = result.decision, "already_handled"
        else:
            decision, outcome = await self.act(result.decision, health, security)
        action = ActionEvent(
            event_id=new_event_id("act"), namespace=ev.namespace, workload=ev.workload,
            pod=security.pod if security else "", decision=decision, mode=self.mode, outcome=outcome,
            score=result.score, compound_score=round(cscore, 4), rationale=result.rationale,
            summary=summarize(health, security, cscore, reasons),
            health_event_id=health.event_id if health else "",
            security_event_id=security.event_id if security else "",
        )
        await publish_event(self.redis, STREAM_ACTIONS, "action", action)
        self.pairs.commit(ev, decision, outcome, partner)
        DECISIONS.labels(decision.value).inc()
        OUTCOMES.labels(outcome.split(":")[0]).inc()
        level = logging.WARNING if decision in AUTOMATIC else logging.INFO
        log.log(level, "%s %s/%s pod=%s outcome=%s :: %s", decision.value, ev.namespace, ev.workload,
                action.pod or "-", outcome, result.rationale)
        return action

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
                return decision, await self.kill(ns, wl, security.pod, security.pod_uid)
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
            return decision, await self.patch(ns, wl, ops)
        except TimeoutError:
            return decision, "failed:kube_timeout"
        except aiohttp.ClientError as e:
            return decision, f"failed:kube_{type(e).__name__}"
        except ApiException as e:
            return decision, f"failed:api_{e.status}_{e.reason}"

    async def tier(self, ns: str) -> str | None:
        """The namespace's TIER_LABEL (cached); None → the policy falls back to the name heuristic."""
        now = time.monotonic()
        if (hit := self.tiers.get(ns)) and hit[0] > now:
            return hit[1]
        try:
            label = _labels(await self._kube(self.core.read_namespace(ns))).get(TIER_LABEL)
        except (ApiException, TimeoutError, aiohttp.ClientError) as e:
            log.warning("tier lookup for namespace %s failed (%s); using its name", ns, getattr(e, "status", e))
            self.tiers[ns] = (now + TIER_FAIL_TTL_S, None)   # do not hammer a failing API on every event
            return None
        if label is not None and label not in TIERS:
            log.warning("namespace %s has invalid %s=%r; using its name", ns, TIER_LABEL, label)
            label = None
        self.tiers[ns] = (now + TIER_TTL_S, label)
        return label

    async def _kube(self, coro):
        return await asyncio.wait_for(coro, KUBE_TIMEOUT_S)

    async def _deployment(self, ns: str, wl: str):
        try:
            return await self._kube(self.apps.read_namespaced_deployment(wl, ns))
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    async def _owner_deployment(self, ns: str, pod, wl: str) -> str:
        """Deployment owning the pod (pod → ReplicaSet → Deployment); wl when the chain cannot be resolved."""
        rs = next((r for r in pod.metadata.owner_references or [] if r.kind == "ReplicaSet"), None)
        if rs is None:
            return wl
        try:
            owner = await self._kube(self.apps.read_namespaced_replica_set(rs.name, ns))
        except ApiException as e:
            if e.status == 404:
                return wl
            raise
        dep = next((r for r in owner.metadata.owner_references or [] if r.kind == "Deployment"), None)
        return dep.name if dep else wl

    async def kill(self, ns: str, wl: str, pod_name: str, pod_uid: str = "") -> str:
        try:
            pod = await self._kube(self.core.read_namespaced_pod(pod_name, ns))
        except ApiException as e:
            if e.status == 404:
                return "pod_already_gone"
            raise
        if pod_uid and pod.metadata.uid != pod_uid:
            return "skipped_stale_pod"      # the name now belongs to a different pod
        # The event's workload is the pod name when the owner lookup failed upstream: resolve the real
        # Deployment from the pod itself, check the protected label on it and on the event's workload.
        dep_name = await self._owner_deployment(ns, pod, wl)
        deps = await asyncio.gather(*(self._deployment(ns, n) for n in dict.fromkeys((dep_name, wl))))
        if "true" in (_labels(pod).get(PROTECTED_LABEL), *(_labels(d).get(PROTECTED_LABEL) for d in deps)):
            return "skipped_protected"
        if self.mode != "enforce":
            return "would_kill"
        async with incident_lock(self.redis, key_lock(ns, dep_name)) as held:
            if not held:
                return "skipped_locked"
            if not await circuit_allows(self.redis, key_circuit("kill", ns, dep_name), self.max_kills):
                return "skipped_circuit_open"
            try:   # quarantine (label + deny-all policy, concurrently) strictly before the delete
                await asyncio.gather(
                    self._kube(self.core.patch_namespaced_pod(
                        pod_name, ns, {"metadata": {"labels": {QUARANTINE_LABEL: "true"}}})),
                    self._create_quarantine_policy(ns, pod))
                opts = {"grace_period_seconds": 0}
                if pod_uid:                 # never delete a successor that reuses the name
                    opts["body"] = client.V1DeleteOptions(preconditions=client.V1Preconditions(uid=pod_uid))
                await self._kube(self.core.delete_namespaced_pod(pod_name, ns, **opts))
            except ApiException as e:
                if e.status == 404:
                    return "pod_already_gone"
                if e.status == 409 and pod_uid:
                    return "skipped_stale_pod"      # UID precondition failed
                raise
        return "pod_killed"

    async def _create_quarantine_policy(self, ns: str, pod) -> None:
        try:
            await self._kube(self.net.create_namespaced_network_policy(ns, quarantine_policy(pod)))
        except ApiException as e:
            if e.status != 409:   # 409: policy from an earlier attempt already exists
                raise

    async def patch(self, ns: str, wl: str, ops: list[dict]) -> str:
        dep = await self._deployment(ns, wl)
        if dep is None:
            return "workload_gone"
        if _labels(dep).get(PROTECTED_LABEL) == "true":
            return "skipped_protected"
        if self.mode != "enforce":
            return "would_patch"
        async with incident_lock(self.redis, key_lock(ns, wl)) as held:
            if not held:
                return "skipped_locked"
            if not await circuit_allows(self.redis, key_circuit("patch", ns, wl), self.max_patches):
                return "skipped_circuit_open"
            try:
                await self._kube(self.apps.patch_namespaced_deployment(
                    wl, ns, ops, _content_type="application/json-patch+json"))
            except ApiException as e:
                if e.status == 404:
                    return "workload_gone"
                raise
        return "patched"

    # ── process ─────────────────────────────────────────────────────────────
    def alive(self) -> bool:
        return time.monotonic() - self.last_poll < LIVENESS_STALE_S

    async def run(self) -> None:
        await self.ensure_groups()
        log.info("fusion started mode=%s consumer=%s protected=%s", self.mode, self.consumer, sorted(self.protected))
        while True:
            try:
                await self.poll_once()
            except aioredis.ResponseError as e:
                if "NOGROUP" not in str(e):
                    raise
                # Redis restarted (no persistence) or the streams were deleted: recreate, keep consuming.
                log.warning("consumer group missing (%s); recreating", e)
                await self.ensure_groups("0")   # "$" would drop what was published since the loss
            except aioredis.RedisError:
                log.exception("redis error in consumer loop; retrying in 1 s")
                await asyncio.sleep(1)


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
        redis, client.CoreV1Api(api), client.AppsV1Api(api), client.NetworkingV1Api(api), mode=mode,
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
