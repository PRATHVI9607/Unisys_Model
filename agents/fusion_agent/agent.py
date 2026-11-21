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
from collections.abc import Callable
from contextvars import ContextVar
from types import SimpleNamespace
from typing import Any

import aiohttp
import redis.asyncio as aioredis
from kubernetes_asyncio import client
from kubernetes_asyncio.client.exceptions import ApiException
from prometheus_client import Counter, Gauge, Histogram

from agents.common import (
    approval_sign,
    approval_verify,
    connect_redis,
    contain_sign,
    load_kube_config,
    protected_namespaces,
    publish_event,
    run,
    setup_logging,
    start_http,
)
from agents.fusion_agent.alerts import Alerter, payload
from agents.fusion_agent.decision_policy import decide
from agents.fusion_agent.incident_lock import circuit_count, circuit_open, incident_lock
from agents.health_agent.agent import policy_violations
from kubeheal.contracts import (
    CONTAIN_MAXLEN,
    KEY_APPROVALS_PENDING,
    KEY_MODE,
    KEY_MODE_EFFECTIVE,
    LEDGER_MAXLEN,
    LEDGER_RETENTION_DAYS,
    PROTECTED_LABEL,
    PROTECTED_NAMESPACES,
    QUARANTINE_LABEL,
    STREAM_ACTIONS,
    STREAM_APPROVALS,
    STREAM_CONTAIN,
    STREAM_DEADLETTER,
    STREAM_HEALTH,
    STREAM_LEDGER,
    STREAM_MAXLEN,
    STREAM_SECURITY,
    TIER_LABEL,
    TIERS,
    ActionEvent,
    Decision,
    HealthEvent,
    SecurityEvent,
    key_approval,
    key_approval_dedupe,
    key_baseline,
    key_circuit,
    key_done,
    key_lock,
    new_event_id,
    now_ms,
    workload_key,
)
from kubeheal.correlation import COMPOUND_THRESHOLD, CORRELATION_WINDOW_S, compound_score
from kubeheal.features.health import canonical_spec, spec_hash

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
DELETE_BACKOFF_S = (2.0, 5.0)  # waits before the 2nd and 3rd delete try (a frozen pod must not stay frozen on a blip)
RETRY_S = 1.0                 # back-off after a Redis error in the consumer loop
# outcomes after which the same automatic decision on the partner event must not act again
HANDLED = frozenset({"pod_killed", "pod_already_gone", "patched", "would_kill", "would_patch"})
MODE_REFRESH_S = 1.0          # runtime kill switch (KEY_MODE) is read at most this often, off the event path
APPROVAL_TTL_S = 3600         # pending-approval record lifetime; also the age past which an approval is refused
APPROVAL_MAX_AGE_S = APPROVAL_TTL_S   # the world has moved on: record expiry and refusal agree
HOUSEKEEP_S = 300             # ledger age trim and expired-approval index prune
LEDGER_REPEAT_S = 600         # an unchanged would_*/skipped_* outcome for a target is ledgered once per this
LEDGER_SEEN_MAX = 4096
APPROVE = frozenset({"approve", "auto_kill", "auto_patch"})   # `decision` values that mean approve
RELEASE = "release"           # thaw + un-quarantine a pod whose kill failed after the freeze (record `releasable`)

DECISIONS = Counter("kubeheal_fusion_decisions_total", "Decisions made", ["decision"])
OUTCOMES = Counter("kubeheal_fusion_outcomes_total", "Decision outcomes", ["outcome"])
DEADLETTERED = Counter("kubeheal_fusion_deadlettered_total", "Events moved to the dead-letter stream")
CONTAINMENT = Counter("kubeheal_fusion_containment_total", "Pod freeze requests on STREAM_CONTAIN",
                      ["result"])
SKIPPED_STALE = Counter("kubeheal_fusion_stale_events_total", "Events skipped as older than MAX_EVENT_AGE_S")
MODE = Gauge("kubeheal_fusion_mode", "Effective mode (1 for the active one)", ["mode"])
DETECT_TO_ACTION = Histogram("kubeheal_fusion_detection_to_action_seconds",
                             "Action publish time minus the deciding event's window end (automatic decisions only)",
                             ["decision"], buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300))
KILL_API = Histogram("kubeheal_fusion_kill_api_seconds", "Duration of kill() (reads, quarantine, delete)",
                     buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))
APPROVALS = Counter("kubeheal_fusion_approvals_total", "Operator approval requests handled", ["result"])

Event = HealthEvent | SecurityEvent
AUTOMATIC = (Decision.AUTO_KILL, Decision.AUTO_PATCH)


def ledger(kind: str, actor: str, mode: str, **f) -> Callable[[Any], None]:
    """Queue one audit-ledger XADD (count-capped; housekeeping trims by age) on a pipeline; pass it to
    publish_event(extra=...). MAXLEN and MINID cannot share one XADD, and Redis is noeviction: the cap is the one that
    must be on every write."""
    fields = {"ts_ms": str(now_ms()), "kind": kind, "actor": actor, "mode": mode}
    fields.update({k: str(v) for k, v in f.items()})
    return lambda p: p.xadd(STREAM_LEDGER, fields, maxlen=LEDGER_MAXLEN, approximate=True)


def parse_approval(fields: dict) -> dict:
    """The STREAM_APPROVALS entry as a dict; ValueError (→ dead letter) when a required field is missing."""
    missing = [k for k in ("approval_id", "action_event_id", "decision", "actor") if not fields.get(k)]
    if missing:
        raise ValueError(f"approval entry lacks {missing}")
    return fields


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
                 consumer: str = "fusion", alert_url: str = "", contain_key: str = "", approval_key: str = "") -> None:
        self.redis, self.core, self.apps, self.net, self.batch = redis, core, apps, net, batch
        self.env_mode = mode            # the manifest's KUBEHEAL_MODE: the ceiling the kill switch cannot raise
        self.mode = mode                # effective mode; refresh_mode() keeps it current, no I/O on the event path
        MODE.labels("observe").set(mode != "enforce")
        MODE.labels("enforce").set(mode == "enforce")
        self.protected = protected
        self.max_kills, self.max_patches = max_kills, max_patches
        self.consumer = consumer
        self.pairs = PairBuffer()
        self.contain_key = contain_key                    # signs STREAM_CONTAIN entries; empty: unsigned
        self.approval_key = approval_key                  # signs approval records; empty: unsigned accepted (dev)
        self.alerter = Alerter(alert_url) if alert_url else None
        self.ledger_seen: dict[tuple[str, str, str], tuple[str, float]] = {}   # (ns, workload, decision) → (outcome, t)
        self.side_failed = False                          # a side task died: alive() goes false, kubelet restarts us
        self.last_progress = time.monotonic()
        self.tiers: dict[str, tuple[float, str | None, bool]] = {}   # namespace → (expiry, TIER_LABEL value, protected label)
        self.owners: dict[tuple[str, str], tuple[float, tuple[str, str] | None]] = {}   # (ns, RS) → controller
        self._containment: ContextVar[str] = ContextVar("containment", default="")

    @property
    def containment(self) -> str:
        """Set by kill() during the current act(); read into the ActionEvent (also on a failed outcome).
        Per task, so an approval executing alongside an event never mixes the two up."""
        return self._containment.get()

    @containment.setter
    def containment(self, value: str) -> None:
        self._containment.set(value)

    async def refresh_mode(self) -> None:
        """effective = observe if the manifest says so or KEY_MODE is present and not "enforce" (fail safe: a
        typo or an unknown value is a kill switch); a missing key changes nothing. A Redis error keeps the last
        value. Publishes the result to KEY_MODE_EFFECTIVE (short TTL: missing = fusion not running)."""
        try:
            key = (await self.redis.get(KEY_MODE) or "").strip().lower()
        except aioredis.RedisError as e:
            log.warning("could not read %s (%s); keeping mode %s", KEY_MODE, e, self.mode)
            return
        new = "observe" if self.env_mode != "enforce" or (key and key != "enforce") else "enforce"
        if new != self.mode:
            log.warning("mode %s -> %s (manifest %s, %s=%r)", self.mode, new, self.env_mode, KEY_MODE, key)
            self.mode = new
            MODE.labels("observe").set(new == "observe")
            MODE.labels("enforce").set(new == "enforce")
        try:
            await self.redis.set(KEY_MODE_EFFECTIVE, self.mode, ex=5)
        except aioredis.RedisError as e:
            log.warning("could not write %s (%s)", KEY_MODE_EFFECTIVE, e)

    async def mode_loop(self) -> None:
        while True:
            try:
                await self.refresh_mode()
            except Exception:   # a bug here must not freeze the kill switch silently
                log.exception("mode refresh failed; keeping mode %s", self.mode)
            await asyncio.sleep(MODE_REFRESH_S)

    async def housekeep_once(self) -> None:
        """Age trim of the ledger (its XADDs only cap the count) and prune of expired pending approvals."""
        now = now_ms()
        await self.redis.xtrim(STREAM_LEDGER, minid=now - LEDGER_RETENTION_DAYS * 86_400_000, approximate=True)
        await self.redis.zremrangebyscore(KEY_APPROVALS_PENDING, "-inf", now - APPROVAL_TTL_S * 1000)

    async def housekeeping_loop(self) -> None:
        while True:
            try:
                await self.housekeep_once()
            except Exception:
                log.exception("housekeeping failed")
            await asyncio.sleep(HOUSEKEEP_S)

    # ── stream plumbing ─────────────────────────────────────────────────────
    async def ensure_groups(self, start: str = "$", streams: tuple[str, ...] = STREAMS) -> None:
        for stream in streams:
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

    async def poll_once(self, block_ms: int = BLOCK_MS, streams: tuple[str, ...] = STREAMS) -> None:
        self.last_progress = time.monotonic()
        for stream in streams:   # retry entries another delivery left unacked
            _, claimed, _ = await self.redis.xautoclaim(stream, GROUP, self.consumer, CLAIM_MIN_IDLE_MS,
                                                        start_id="0-0", count=BATCH)
            for msg_id, fields in claimed:
                info = await self.redis.xpending_range(stream, GROUP, min=msg_id, max=msg_id, count=1)
                await self.process(stream, msg_id, fields, info[0]["times_delivered"] if info else MAX_DELIVERIES)
        resp = await self.redis.xreadgroup(GROUP, self.consumer, {s: ">" for s in streams},
                                           count=BATCH, block=block_ms)
        for stream, entries in resp or []:
            for msg_id, fields in entries:
                await self.process(stream, msg_id, fields, 1)

    async def process(self, stream: str, msg_id: str, fields: dict, deliveries: int) -> None:
        """Ack only after successful handling; dead-letter malformed or repeatedly failing entries."""
        self.last_progress = time.monotonic()   # a batch of slow entries is progress, not a hang
        approvals = stream == STREAM_APPROVALS
        try:
            ev = (parse_approval(fields) if approvals else
                  (HealthEvent if stream == STREAM_HEALTH else SecurityEvent).from_fields(fields))
        except ValueError as e:   # pydantic ValidationError and bad JSON are ValueErrors
            log.error("malformed event %s on %s: %s", msg_id, stream, e)
            await self.deadletter(stream, msg_id, fields, f"malformed: {e}")
            return
        try:
            handler = self.handle_approval if approvals else self.handle
            if await handler(ev, ack=(stream, GROUP, msg_id)) is not None:
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
            fresh = False
        else:
            fresh = True
            action = await self._decide(ev, partner, partner_decision, partner_outcome)
            # Recorded before publishing, so a redelivery after a failed publish/XACK never acts twice.
            await self.redis.set(done, action.model_dump_json(), nx=True, ex=DONE_TTL_S)
        extra, notify = await self._extras(ev, partner, action)
        await publish_event(self.redis, STREAM_ACTIONS, "action", action, ack, extra)
        if fresh and action.outcome in ("pod_killed", "patched", "would_kill", "would_patch"):
            src = partner if (action.decision is Decision.AUTO_KILL) != isinstance(ev, SecurityEvent) else ev
            t0 = getattr(src, "window_end_ms", 0) or src.timestamp_ms
            DETECT_TO_ACTION.labels(action.decision.value).observe(max((now_ms() - t0) / 1000, 0.0))
        if extra and action.decision in AUTOMATIC:   # noted only once published: a retry must still ledger it
            self._ledger_note(action)
        if notify and self.alerter:
            self.alerter.notify(payload(action, action.decision is Decision.HUMAN))
        self.pairs.commit(ev, action.decision, action.outcome, partner)
        DECISIONS.labels(action.decision.value).inc()
        OUTCOMES.labels(action.outcome.split(":")[0]).inc()
        level = logging.WARNING if action.decision in AUTOMATIC else logging.INFO
        log.log(level, "%s %s/%s pod=%s outcome=%s :: %s", action.decision.value, ev.namespace, ev.workload,
                action.pod or "-", action.outcome, action.rationale)
        return action

    def _ledger_repeat(self, action: ActionEvent) -> bool:
        """An unchanged would_*/skipped_* outcome for the same target within LEDGER_REPEAT_S: not ledgered again."""
        if not action.outcome.startswith(("would_", "skipped_")):
            return False
        seen = self.ledger_seen.get((action.namespace, action.workload, action.decision.value))
        return bool(seen and seen[0] == action.outcome and time.monotonic() - seen[1] < LEDGER_REPEAT_S)

    def _ledger_note(self, action: ActionEvent) -> None:
        key = (action.namespace, action.workload, action.decision.value)
        if (seen := self.ledger_seen.get(key)) and seen[0] == action.outcome:
            return   # the 10 min window runs from the entry that was written
        if len(self.ledger_seen) >= LEDGER_SEEN_MAX:
            self.ledger_seen.clear()
        self.ledger_seen[key] = (action.outcome, time.monotonic())

    async def _extras(self, ev: Event, partner: Event | None,
                      action: ActionEvent) -> tuple[list[Callable[[Any], None]], bool]:
        """(commands queued in the ActionEvent's own transaction, whether to alert). An automatic action's ledger
        entry (alert: kills, patches, failures only), or a HUMAN decision's pending approval (when something
        executable exists and none is open for the target) plus its ledger entry. I/O only for HUMAN decisions:
        the AUTO_KILL path stays free of it."""
        ids = {"namespace": action.namespace, "workload": action.workload, "pod": action.pod,
               "action_event_id": action.event_id, "health_event_id": action.health_event_id,
               "security_event_id": action.security_event_id}
        if action.decision in AUTOMATIC:
            if action.outcome == "already_handled" or self._ledger_repeat(action):
                return [], False
            notify = action.outcome in ("pod_killed", "patched") or action.outcome.startswith("failed:")
            entries = [ledger("action", "fusion", action.mode, decision=action.decision.value,
                              outcome=action.outcome, detail=action.rationale, **ids)]
            sec = ev if isinstance(ev, SecurityEvent) else partner
            if (action.decision is Decision.AUTO_KILL and action.outcome.startswith("failed:")
                    and action.containment == "requested" and sec and sec.pod_uid):
                # The pod may be frozen but alive: the operator retries the kill or releases it.
                entries += await self._open_approval(action, Decision.AUTO_KILL, None, sec, ids, releasable=True)
            return entries, notify
        if action.decision is not Decision.HUMAN or action.outcome == "skipped_protected":
            return [], False
        health, security = (ev, partner) if isinstance(ev, HealthEvent) else (partner, ev)
        if security and security.pod:
            candidate = Decision.AUTO_KILL
        elif health and health.spec_changed and health.has_baseline:
            candidate = Decision.AUTO_PATCH
        else:
            return [], False
        queue = await self._open_approval(action, candidate, health, security, ids)
        return queue, bool(queue)

    async def _open_approval(self, action: ActionEvent, candidate: Decision, health: HealthEvent | None,
                             security: SecurityEvent | None, ids: dict, releasable: bool = False) -> list:
        """Commands that record a pending approval and its ledger entry; [] when one exists or none is possible."""
        if await self.redis.exists(key_approval(action.event_id)):   # redelivery: already recorded
            return []
        dedupe = key_approval_dedupe(action.namespace, action.workload, "RELEASE" if releasable else candidate.value)
        if prior := await self.redis.get(dedupe):   # one open approval per target: reuse it, never flood
            try:
                if json.loads(await self.redis.get(key_approval(prior)) or "{}").get("state") == "pending":
                    return []
            except ValueError:
                pass
        hsh = ""
        if candidate is Decision.AUTO_PATCH:   # precondition of the approved patch: the spec the operator was shown
            try:
                dep = await self._read("Deployment", action.namespace, action.workload)
            except (ApiException, TimeoutError, aiohttp.ClientError) as e:
                log.warning("no approval for %s/%s: cannot read the Deployment (%r)", action.namespace,
                            action.workload, e)
                return []
            if dep is None:
                return []
            hsh = spec_hash(dep)
        created = now_ms()
        record = {"state": "pending", "action_event_id": action.event_id, "candidate": candidate.value,
                  "namespace": action.namespace, "workload": action.workload, "pod": action.pod,
                  "pod_uid": security.pod_uid if security else "", "spec_hash": hsh,
                  "health_event_id": action.health_event_id, "security_event_id": action.security_event_id,
                  "rationale": action.rationale, "score": action.score, "created_ms": created,
                  "expires_ms": created + APPROVAL_TTL_S * 1000,
                  "changed_fields": health.changed_fields if health else [], "releasable": releasable}
        payload = self._seal(record)

        def queue(p) -> None:
            p.set(key_approval(action.event_id), payload, nx=True, ex=APPROVAL_TTL_S)
            p.set(dedupe, action.event_id, ex=APPROVAL_TTL_S)
            p.zadd(KEY_APPROVALS_PENDING, {action.event_id: created})
            p.zremrangebyscore(KEY_APPROVALS_PENDING, "-inf", created - APPROVAL_TTL_S * 1000)
        return [queue, ledger("approval_pending", "fusion", action.mode, decision=candidate.value,
                              outcome="pending", detail=action.rationale, **ids)]

    def _seal(self, rec: dict) -> str:
        """The record as JSON, signed over everything but `requested` (the dashboard's) when a key is set."""
        rec = {k: v for k, v in rec.items() if k != "sig"}
        if self.approval_key:
            rec["sig"] = approval_sign(self.approval_key, rec)
        return json.dumps(rec)

    # ── operator approvals (own task: never on the event path) ──────────────
    async def handle_approval(self, req: dict, ack: tuple[str, str, str] | None = None) -> bool:
        """Carry out or close one approval request. The result (action, ledger entry, record update) is
        stored under key_done(approval_id) before publishing, so a redelivery republishes it, never re-acts."""
        done = key_done(req["approval_id"])
        if raw := await self.redis.get(done):
            res = json.loads(raw)
        else:
            res = await self._decide_approval(req)
            await self.redis.set(done, json.dumps(res), nx=True, ex=DONE_TTL_S)
        kind, fields = res["ledger"]
        eid = req["action_event_id"]
        extra = [ledger(kind, req["actor"], self.mode, approval_id=req["approval_id"], action_event_id=eid, **fields)]
        if res["record"]:
            def close(p) -> None:   # xx: an expired record must not come back (keepttl would give it no expiry)
                p.set(key_approval(eid), res["record"], xx=True, keepttl=True)
                p.zrem(KEY_APPROVALS_PENDING, eid)
            extra.append(close)
        action = ActionEvent.model_validate_json(res["action"]) if res["action"] else None
        if action:
            await publish_event(self.redis, STREAM_ACTIONS, "action", action, ack, extra)
        else:
            async with self.redis.pipeline(transaction=True) as p:
                for queue in extra:
                    queue(p)
                if ack:
                    p.xack(*ack)
                await p.execute()
        if action and self.alerter and (action.outcome in ("pod_killed", "patched") or action.outcome.startswith("failed:")):
            self.alerter.notify(payload(action, False))
        APPROVALS.labels(res["result"]).inc()
        log.warning("approval %s by %s on %s: %s", req["decision"], req["actor"], eid,
                    res["ledger"][1].get("outcome"))
        return True

    @staticmethod
    def _plain(rec: dict) -> dict:
        """The record without what the dashboard or an earlier refusal attached (`requested`, `note`)."""
        return {k: v for k, v in rec.items() if k not in ("requested", "note")}

    async def _claim(self, eid: str, state: str | None, max_age_s: float | None,
                     hold: tuple[str, str] | None = None) -> tuple[dict | None, str]:
        """Atomically move a pending approval record to `state` (WATCH: one winner across replicas and
        concurrent requests), clearing the operator's `requested`. Returns (record, "") when claimed, else
        (record or None, why it was refused). A stale record becomes "expired"; a non-pending one only loses its
        `requested`; `hold`=(why, note) refuses but keeps it pending with the note. Records whose signature does
        not verify are never trusted. key_done(eid) marks the claim, so a replayed old snapshot cannot be claimed twice."""
        key, marker = key_approval(eid), key_done(eid)
        async with self.redis.pipeline() as p:
            try:
                await p.watch(key)
                try:
                    rec = json.loads(await p.get(key) or "")
                except ValueError:
                    return None, "no_such_approval"
                if not isinstance(rec, dict):
                    return None, "no_such_approval"
                if self.approval_key and not (rec.get("action_event_id") == eid
                                              and approval_verify(self.approval_key, rec)):
                    await self.redis.zrem(KEY_APPROVALS_PENDING, eid)
                    return None, "bad_sig"
                new, why = None, ""
                if rec.get("state") != "pending":
                    why = f"not_pending:{rec.get('state')}"
                    new = self._plain(rec) if "requested" in rec else None
                elif max_age_s is not None and now_ms() - int(rec.get("created_ms", 0)) > max_age_s * 1000:
                    why, new = "stale", {**self._plain(rec), "state": "expired"}
                elif hold:
                    why, new = hold[0], {**self._plain(rec), "note": hold[1]}
                elif await p.exists(marker):
                    why = "not_pending:claimed"
                else:
                    new = {**self._plain(rec), "state": state}
                if new is not None:
                    p.multi()
                    p.set(key, self._seal(new), xx=True, keepttl=True)
                    if new["state"] != "pending":
                        p.zrem(KEY_APPROVALS_PENDING, eid)
                    if not why:
                        p.set(marker, "1", ex=2 * APPROVAL_TTL_S)
                    await p.execute()
            except aioredis.WatchError:
                return None, "not_pending:claimed"
        return rec, why

    async def _decide_approval(self, req: dict) -> dict:
        eid, actor = req["action_event_id"], req["actor"]
        decision, reason = req["decision"].strip().lower(), req.get("reason", "")

        def result(kind, outcome, label, rec=None, action=None, record=None, **fields):
            rec = rec or {}
            f = {"namespace": rec.get("namespace", ""), "workload": rec.get("workload", ""),
                 "pod": rec.get("pod", ""), "decision": rec.get("candidate", ""), "outcome": outcome,
                 "health_event_id": rec.get("health_event_id", ""),
                 "security_event_id": rec.get("security_event_id", ""), "detail": reason, **fields}
            return {"ledger": [kind, f], "action": action, "record": record, "result": label}

        if decision == "reject":
            rec, why = await self._claim(eid, "rejected", None)
            if why:
                return result("approval", f"refused:{why}", "refused", rec)
            return result("rejection", "rejected", "rejected", rec, record=self._seal(
                {**self._plain(rec), "state": "rejected", "actor": actor, "reason": reason}))
        if decision not in APPROVE | {RELEASE}:
            rec, why = await self._claim(eid, None, None, hold=("bad_decision", "bad decision"))
            return result("approval", f"refused:{why}", "refused", rec)
        if self.mode != "enforce":   # nothing would run: stay pending for when enforcement is back
            rec, why = await self._claim(eid, None, APPROVAL_MAX_AGE_S, hold=("observe_mode", "mode is observe"))
            return result("approval", f"refused:{why}", "refused", rec)
        rec, why = await self._claim(eid, "executing", APPROVAL_MAX_AGE_S)
        if why:
            return result("approval", f"refused:{why}", "refused", rec)

        def failed(outcome):
            record = self._seal({**self._plain(rec), "state": "failed", "outcome": outcome, "actor": actor,
                                 "reason": reason})
            return result("approval", f"refused:{outcome}", "refused", rec, record=record)
        try:
            candidate = Decision(rec["candidate"])
            ns, wl = rec["namespace"], rec["workload"]
        except (KeyError, ValueError):
            return failed("bad_record")
        if decision == RELEASE and not rec.get("releasable"):
            return failed("not_releasable")
        if candidate is Decision.AUTO_KILL and not rec.get("pod_uid"):
            return failed("no_pod_uid")      # without the UID the delete could hit a successor of that name
        if candidate is Decision.AUTO_PATCH and not rec.get("spec_hash"):
            return failed("no_spec_hash")
        # The same act() path as an automatic decision: protected ns/label, lock, breaker, UID precondition,
        # baseline validation and the effective mode all apply (plus the spec the operator saw, for a patch).
        sec = SimpleNamespace(namespace=ns, workload=wl, pod=rec.get("pod", ""), pod_uid=rec.get("pod_uid", ""),
                              event_id=rec.get("security_event_id", ""))
        hlt = SimpleNamespace(namespace=ns, workload=wl, changed_fields=rec.get("changed_fields", []))
        self.containment = ""
        try:
            if decision == RELEASE:
                if ns in self.protected:
                    final, outcome = Decision.HUMAN, "skipped_protected"
                else:
                    final, outcome = Decision.HUMAN, await self.release(ns, sec.pod, sec.pod_uid, sec.event_id)
            else:
                final, outcome = await self.act(candidate, hlt, sec, expect_hash=rec.get("spec_hash", ""))
        except (TimeoutError, aiohttp.ClientError, ApiException) as e:   # release() raises; act() maps its own
            final, outcome = candidate, f"failed:{type(e).__name__}"
        except Exception:   # never leave the record "executing"
            log.exception("approved %s on %s/%s crashed", candidate.value, ns, wl)
            final, outcome = candidate, "failed:crash"
        action = ActionEvent(
            event_id=new_event_id("act"), namespace=ns, workload=wl, pod=rec.get("pod", ""), decision=final,
            mode=self.mode, outcome=outcome, score=rec.get("score", 0.0),
            rationale=f"approved by {actor}: {reason}; original: {rec.get('rationale', '')}",
            health_event_id=rec.get("health_event_id", ""), security_event_id=rec.get("security_event_id", ""),
            containment=self.containment, approved_by=actor)
        ok = outcome in ("pod_killed", "pod_already_gone", "patched", "released")   # a dry run (mode flipped meanwhile) is not one
        record = self._seal({**self._plain(rec), "state": "executed" if ok else "failed", "outcome": outcome,
                             "actor": actor, "reason": reason, "result_event_id": action.event_id})
        return result("approval", outcome, "executed" if ok else "failed", rec, action.model_dump_json(), record,
                      result_event_id=action.event_id)

    async def _decide(self, ev: Event, partner: Event | None, partner_decision: Decision | None,
                      partner_outcome: str | None) -> ActionEvent:
        health, security = (ev, partner) if isinstance(ev, HealthEvent) else (partner, ev)
        cscore, reasons = compound_score(health, security) if health and security else (0.0, [])
        label, protected = await self.ns_info(ev.namespace)
        result = decide(health, security, compound=cscore >= COMPOUND_THRESHOLD,
                        tier=None if label == NAMESPACE_GONE else label)
        decision, rationale, self.containment = result.decision, result.rationale, ""
        if label == NAMESPACE_GONE and decision is not Decision.BENIGN:
            # Everything in it is deleted: nothing to act on or escalate, and the name-heuristic tier misleads.
            decision, outcome = Decision.OBSERVE, "namespace_gone"
            rationale = f"namespace gone, nothing to act on (policy alone: {result.decision.value}; {rationale})"
        elif protected and decision is Decision.HUMAN:
            outcome = "skipped_protected"   # no approval is offered for a protected namespace
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
                  security: SecurityEvent | None, expect_hash: str = "") -> tuple[Decision, str]:
        if decision not in AUTOMATIC:
            return decision, "none"
        ev = security if decision is Decision.AUTO_KILL else health
        ns, wl = ev.namespace, ev.workload
        if ns in self.protected or (await self.ns_info(ns))[1]:   # cached by _decide: no extra read on the kill path
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
                outcome = await self.patch(ns, wl, ops, expect_hash)
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
        return (await self.ns_info(ns))[0]

    async def ns_info(self, ns: str) -> tuple[str | None, bool]:
        """(tier, protected): one cached namespace read. protected = the namespace carries PROTECTED_LABEL=true;
        a failed lookup is not protected (name-based tier, as before)."""
        now = time.monotonic()
        if (hit := self.tiers.get(ns)) and hit[0] > now:
            return hit[1], hit[2]
        try:
            labels = _labels(await self._kube(self.core.read_namespace(ns)))
        except (ApiException, TimeoutError, aiohttp.ClientError) as e:
            status = getattr(e, "status", None)
            if status == 404:
                self.tiers[ns] = (now + TIER_FAIL_TTL_S, NAMESPACE_GONE, False)   # short: the name may be re-created
                return NAMESPACE_GONE, False
            log.warning("tier lookup for namespace %s failed (%s); using its name, not protected", ns, status or e)
            self.tiers[ns] = (now + TIER_FAIL_TTL_S, None, False)   # do not hammer a failing API on every event
            return None, False
        label, protected = labels.get(TIER_LABEL), labels.get(PROTECTED_LABEL) == "true"
        if label is not None and label not in TIERS:
            log.warning("namespace %s has invalid %s=%r; using its name", ns, TIER_LABEL, label)
            label = None
        self.tiers[ns] = (now + TIER_TTL_S, label, protected)
        return label, protected

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
        t0 = time.perf_counter()
        try:
            return await self._kill(ns, wl, pod_name, pod_uid, event_id)
        finally:
            KILL_API.observe(time.perf_counter() - t0)

    async def _delete_pod(self, ns: str, pod_name: str, uid: str) -> None:
        """Delete with the UID precondition; a 404/409 is final, anything else is retried (DELETE_BACKOFF_S):
        the pod is frozen by now, so a transient API error must not leave it frozen."""
        waits = (0.0, *DELETE_BACKOFF_S)
        for i, wait in enumerate(waits):
            await asyncio.sleep(wait)
            try:
                await self._kube(self.core.delete_namespaced_pod(
                    pod_name, ns, grace_period_seconds=0,
                    body=client.V1DeleteOptions(preconditions=client.V1Preconditions(uid=uid))))
                return
            except ApiException as e:
                if e.status in (404, 409) or i == len(waits) - 1:
                    raise
            except (TimeoutError, aiohttp.ClientError):
                if i == len(waits) - 1:
                    raise
            log.warning("deleting %s/%s failed; retrying", ns, pod_name)

    async def _kill(self, ns: str, wl: str, pod_name: str, pod_uid: str = "", event_id: str = "") -> str:
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
                await self._delete_pod(ns, pod_name, uid)
            except ApiException as e:
                if e.status == 404:
                    return "pod_already_gone"
                if e.status == 409:
                    return "skipped_stale_pod"      # UID precondition failed
                raise
            finally:
                self.containment = await contain    # bounded by CONTAIN_TIMEOUT_S, never raises
            await circuit_count(self.redis, breaker)
        return "pod_killed"

    async def _contain(self, ns: str, pod: str, uid: str, event_id: str, action: str = "") -> str:
        """Ask every node's security agent to freeze the pod's cgroup now. Best effort: never delays the
        kill by more than CONTAIN_TIMEOUT_S and never fails it; the API delete follows regardless."""
        try:
            fields = {"pod_uid": uid, "namespace": ns, "pod": pod, "event_id": event_id, "ts_ms": str(now_ms())}
            if action:   # "thaw"; a freeze carries no action (the entry stays what older agents understand)
                fields["action"] = action
            if self.contain_key:
                fields["sig"] = contain_sign(self.contain_key, fields)
            await asyncio.wait_for(self.redis.xadd(STREAM_CONTAIN, fields, maxlen=CONTAIN_MAXLEN, approximate=True),
                                   CONTAIN_TIMEOUT_S)
        except Exception:   # any failure here must leave the kill path untouched
            log.warning("containment request for %s/%s failed; deleting via the API only", ns, pod, exc_info=True)
            result = "failed"
        else:
            result = "requested"
        CONTAINMENT.labels(result).inc()
        return result

    async def release(self, ns: str, pod_name: str, pod_uid: str, event_id: str) -> str:
        """Operator release of a pod whose kill failed: lift the quarantine (label, then policy), thaw last, so
        any failure leaves it frozen and isolated. A pod that is gone needs no thaw (its cgroup is gone too)."""
        pod = await self._read("Pod", ns, pod_name)
        if pod is None:
            return "pod_already_gone"
        if pod.metadata.uid != pod_uid:
            return "skipped_stale_pod"
        if self.mode != "enforce":
            return "would_release"
        try:
            await self._kube(self.core.patch_namespaced_pod(
                pod_name, ns, {"metadata": {"uid": pod_uid, "labels": {QUARANTINE_LABEL: None}}}))
        except ApiException as e:
            if e.status == 404:
                return "pod_already_gone"
            raise
        try:
            await self._kube(self.net.delete_namespaced_network_policy(f"kubeheal-quarantine-{pod_name}"[:253], ns))
        except ApiException as e:
            if e.status != 404:
                raise
        return "released" if await self._contain(ns, pod_name, pod_uid, event_id, "thaw") == "requested" \
            else "failed:thaw_request"

    async def _create_quarantine_policy(self, ns: str, pod) -> None:
        try:
            await self._kube(self.net.create_namespaced_network_policy(ns, quarantine_policy(pod)))
        except ApiException as e:
            if e.status != 409:   # 409: policy from an earlier attempt already exists
                raise

    async def patch(self, ns: str, wl: str, ops: list[dict], expect_hash: str = "") -> str:
        dep = await self._read("Deployment", ns, wl)
        if dep is None:
            return "workload_gone"
        if _labels(dep).get(PROTECTED_LABEL) == "true":
            return "skipped_protected"
        if expect_hash and spec_hash(dep) != expect_hash:   # an approved patch applies to the spec the operator saw
            return "refused:spec_changed"
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
        return not self.side_failed and time.monotonic() - self.last_progress < LIVENESS_STALE_S

    async def run(self) -> None:
        log.info("fusion starting mode=%s consumer=%s protected=%s", self.mode, self.consumer, sorted(self.protected))
        await self.refresh_mode()
        # Own tasks: a slow approval or Redis read never holds up the event loop below.
        side = [asyncio.create_task(self.mode_loop()), asyncio.create_task(self.consume((STREAM_APPROVALS,))),
                asyncio.create_task(self.housekeeping_loop())]
        if self.alerter:
            side.append(asyncio.create_task(self.alerter.run()))
        for t in side:
            t.add_done_callback(self._side_done)
        try:
            await self.consume(STREAMS)
        finally:
            for t in side:
                t.cancel()
            await asyncio.gather(*side, return_exceptions=True)

    def _side_done(self, t: asyncio.Task) -> None:
        """A side task ends only by cancellation (shutdown); anything else is a dead kill switch or approvals
        consumer: fail liveness so the pod is restarted instead of running half-blind."""
        if not t.cancelled():
            self.side_failed = True
            log.error("side task %s ended: %r", t.get_name(), t.exception())

    async def consume(self, streams: tuple[str, ...]) -> None:
        start: str | None = "$"
        while True:
            try:
                if start:
                    await self.ensure_groups(start, streams)
                    start = None
                await self.poll_once(streams=streams)
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
    contain_key = os.environ.get("CONTAIN_HMAC_KEY", "")
    if not contain_key:
        log.warning("CONTAIN_HMAC_KEY is unset: containment requests are sent unsigned")
    approval_key = os.environ.get("APPROVAL_HMAC_KEY", "")
    if not approval_key:
        log.warning("APPROVAL_HMAC_KEY is unset: approval records are unsigned and anyone with Redis write "
                    "access can forge one")
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
        alert_url=os.environ.get("ALERT_WEBHOOK_URL", "").strip(),
        contain_key=contain_key,
        approval_key=approval_key,
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
