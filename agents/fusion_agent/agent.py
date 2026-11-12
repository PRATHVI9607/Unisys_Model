"""
Fusion Agent v4 - Three-Signal Decision Engine (PRD Section 07 / 09).
=====================================================================
Consumes kubeheal.health.events + kubeheal.security.events via a Redis
consumer group (each event handled by exactly one replica). Correlates the
two signals with kubeheal.correlation.compound_score (V5-D3: no DCM call by default), runs the pure
decision policy, executes under a heartbeat incident lock, and writes kubeheal.actions. The learned DCM is an
OPTIONAL legacy path: it is used (and kubeheal.dcm.events written) only when DCM_URL is set to a non-empty value.

P1 notes: events are keyed by the explicit workload (Deployment) name, a message is
acknowledged only after it was handled successfully, and every Kubernetes write goes
through the Executor: this agent only publishes requests to kubeheal.exec.

P6 adds (all state in Redis so both replicas agree):
  * models_ok: a missing or late legacy DCM or interpretation answer (only when DCM_URL is set), an event the
    model did not score, or an event that cannot be mapped onto the contract, means HUMAN (S-POL-1).
    Per-call deadlines come from FusionConfig.
  * protected namespaces (label kubeheal/protected, unknown means protected), sliding-window circuit breakers
    counted by incident id, burn-in from a real sample counter.
  * OBSERVE writes a sampling request (agents/common/sampling.py).
  * one incident per security process: the initial and the complete security event (P5) share an incident,
    the second one updates it. Incident ids derive from the event ids, so a redelivered entry maps to the same
    incident and cannot count twice or queue a second request.
  * the restore request: after the Executor reports `contained` on kubeheal.actions (automatic or approved by a
    human), Fusion requests `restore` with t0_ms and workload_kind, only when T0 is known and the containment
    was for a ransomware label (Q2: `restore_after`); otherwise it escalates. After an exfiltration containment
    (`human_followup`) no restore is requested and a human is told once.
  * stream reliability (agents/common/stream_reliability.py): pending reclaim, dead letter after N deliveries.
"""

import asyncio
import base64
import hashlib
import json
import logging
import math
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import numpy as np
import redis.asyncio as aioredis

from agents.common import sampling
from agents.common.killswitch import ModeWatcher
from agents.common.ledger import Ledger, ledger_from_env
from agents.common.metrics import KubeHealMetrics
from agents.common.stream_reliability import ReliabilityConfig, StreamReliability
from agents.fusion_agent.breakers import BurnInCounter, contain_breaker, patch_breaker
from agents.fusion_agent.config import FusionConfig
from agents.fusion_agent import event_mapping as em
from agents.fusion_agent.decision_policy import (
    make_decision, DecisionInput, Decision, TIER_MULTIPLIERS, AUTO_CONTAIN_LABELS, RESTORE_LABEL,
)
from agents.fusion_agent.incident_lock import LockState, acquire_incident_lock
from agents.fusion_agent.interpretation_client import InterpretationClient, build_causal_chain, earliest_t0

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
METRICS = KubeHealMetrics()

GROUP = "fusion"
HEALTH_STREAM = "kubeheal.health.events"
SEC_STREAM = "kubeheal.security.events"
DCM_STREAM = "kubeheal.dcm.events"
ACTIONS_STREAM = "kubeheal.actions"
EXEC_STREAM = "kubeheal.exec"
ESCALATIONS_STREAM = "kubeheal.escalations"

INCIDENT_PREFIX = "kubeheal:fusion:incident"      # hash per incident: context for updates and restore
OPEN_PREFIX = "kubeheal:fusion:open"              # (namespace, pod, pid) -> incident id
RESTORE_PREFIX = "kubeheal:fusion:restore"        # marker: a restore request was queued for this incident
EXEC_REQ_PREFIX = "kubeheal:fusion:execreq"       # SET NX marker: this incident and action was queued once
MODEL_DOWN_PREFIX = "kubeheal:fusion:modelunavail"  # SET NX marker: a health model outage was escalated lately
# Hash per workload, written by the Security Agent (task V5-S2, NOT built yet): fields sec_risk, ts_ms,
# model_scored; the Security Agent sets its TTL. Read by `_security_score` for the rule-based rollback (Q1).
SECURITY_SCORE_PREFIX = "kubeheal:security:score"
AUTOMATIC = (Decision.AUTO_CONTAIN, Decision.AUTO_PATCH)
RESTORE_KINDS = ("Deployment", "StatefulSet")     # what the Executor accepts (agents/executor/validation.py)


def _b64_to_vec(b64: str):
    if not b64:
        return None
    return np.frombuffer(base64.b64decode(b64), dtype=np.float32).tolist()


def workload_of(fields: Dict) -> str:
    """Explicit workload (Deployment/StatefulSet) name carried in the event.
    Falls back to pod_name only for events from older agents."""
    return fields.get("deployment") or fields.get("pod_name") or "unknown"


def owner_unresolved(sec: Dict, ctx_kind: str = "") -> bool:
    """True when a security event does not name a Deployment or StatefulSet owner for its pod: it says so
    (`owner_resolved` false) or carries another workload_kind (Pod, ReplicaSet, ...). An event with neither field
    comes from an older Security Agent and is left to the Executor's own ownerReferences check."""
    if sec and str(sec.get("owner_resolved", "")).strip().lower() == "false":
        return True
    kind = (sec.get("workload_kind") if sec else "") or ctx_kind
    return bool(kind) and kind not in RESTORE_KINDS


def _truthy(v) -> bool:
    return str(v).strip().lower() == "true"


def tier_of(health: Dict, sec: Dict) -> str:
    """The namespace tier named by the events. A missing, unrecognised or conflicting tier is "unknown":
    the policy scores it with the highest multiplier but never lets it act automatically."""
    tiers = {str(e.get("namespace_tier")).strip().lower() for e in (health, sec) if e and e.get("namespace_tier")}
    if len(tiers) == 1:
        tier = tiers.pop()
        if tier in TIER_MULTIPLIERS:
            return tier
    return "unknown"


class RetryLater(Exception):
    """The entry could not be acted on yet (the incident lock is busy or was lost). It is NOT acknowledged: it
    stays pending, is reclaimed (XAUTOCLAIM) and, after the configured number of deliveries, dead-lettered with
    an escalation to a human, so an automatic action is never silently dropped."""


def derive_incident_id(event: Dict) -> str:
    """Deterministic incident id (a lowercase DNS label, at most 63 characters, as the Executor and the
    dashboard require): the same event always maps to the same incident, so a redelivered stream entry
    cannot open a second one."""
    ident = event.get("event_id") or json.dumps(event, sort_keys=True, default=str)
    digest = hashlib.sha1(str(ident).encode("utf-8")).hexdigest()[:8]
    try:
        ts = int(str(event.get("timestamp_ms", "")))
        stamp = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
    except (ValueError, OverflowError, OSError):
        stamp = "00000000-000000"
    return f"inc-{stamp}-{digest}"


class FusionAgentV4:
    # Only correlate a health+security pair if both arrived within this window
    # (else they are independent events that happen to share a workload name).
    CORRELATION_WINDOW_S = 30.0

    def __init__(self, ledger: Optional[Ledger] = None, cfg: Optional[FusionConfig] = None,
                 interp: Optional[InterpretationClient] = None, clock=time.time):
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis-master:6379")
        # V5-D3: the DCM is an optional legacy path. Empty (the default) means no DCM call and no explain call.
        self.dcm_url = (os.environ.get("DCM_URL") or "").strip()
        self.cfg = cfg or FusionConfig.from_env()
        # BURN_IN_MODE can only force burn-in on; the real counter decides when it ends (S-POL-7).
        self.burn_in = self.cfg.burn_in_forced
        self.clock = clock
        self.redis: Optional[aioredis.Redis] = None
        self.consumer = os.environ.get("HOSTNAME") or f"fusion-{uuid.uuid4().hex[:6]}"
        self.mode = ModeWatcher()
        self.interp = interp or InterpretationClient(self.dcm_url)
        self.reliability = StreamReliability(lambda: self.redis, GROUP, self.consumer,
                                             ReliabilityConfig.from_env())
        # The deployment can inject a MinIO-backed Ledger; the in-memory
        # default keeps local/unit-test use explicit until P4-L2 wiring.
        self.ledger = ledger if ledger is not None else ledger_from_env()
        self.running = False
        # short-term correlation buffer: "<ns>:<workload>" -> (event_fields, recv_monotonic)
        self.pending_health: Dict[str, tuple] = {}
        self.pending_sec: Dict[str, tuple] = {}

    async def start(self):
        try:
            from kubernetes_asyncio import client, config
            try:
                config.load_incluster_config()
            except Exception:
                await config.load_kube_config()
            await self._start_mode_watcher(client.CoreV1Api())   # read-only: kubeheal-mode + namespace labels
        except Exception as e:
            logger.warning(f"kill switch watcher not started ({e}); mode stays 'test'")
        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
        for stream, start in ((HEALTH_STREAM, "0"), (SEC_STREAM, "0"),
                              # only results from now on: history must not trigger restores
                              (ACTIONS_STREAM, "$")):
            try:
                await self.redis.xgroup_create(stream, GROUP, id=start, mkstream=True)
            except Exception as e:
                if "BUSYGROUP" not in str(e):
                    logger.warning(f"xgroup_create {stream}: {e}")
        logger.info(f"Fusion Agent v4 started (consumer={self.consumer}, burn_in_forced={self.burn_in})")
        self.running = True
        await self._consume()

    async def _start_mode_watcher(self, core_api):
        """Start the read-only watcher; a failure must leave enforcement disabled."""
        try:
            await self.mode.start(core_api)
        except Exception as e:
            logger.warning(f"kill switch watcher not started ({e}); mode stays 'test'")

    async def stop(self):
        self.running = False
        await self.mode.stop()
        if self.redis:
            await self.redis.aclose()

    # ---- consume loop and stream reliability -------------------------------------------------------
    async def _consume(self):
        last_sweep = None
        while self.running:
            try:
                now = time.monotonic()
                if last_sweep is None or now - last_sweep >= self.reliability.cfg.reclaim_interval_s:
                    last_sweep = now
                    await self._reclaim_pending()
                msgs = await self.redis.xreadgroup(
                    GROUP, self.consumer,
                    {HEALTH_STREAM: ">", SEC_STREAM: ">", ACTIONS_STREAM: ">"}, count=10, block=1000,
                )
                await self._handle_batch(msgs or [])
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"consume error: {e}")
                await asyncio.sleep(1)

    async def _handle_batch(self, msgs):
        """Entries of one read are handled one after another (their order matters for the incident state), so
        EVERY entry is leased when it is read: while a slow entry runs, the idle time of the others stays near
        zero and another replica cannot XAUTOCLAIM them. Each lease ends when its entry is done."""
        leases = []
        try:
            for stream, entries in msgs:
                for msg_id, fields in entries:
                    cm = self.reliability.lease(stream, msg_id)
                    await cm.__aenter__()
                    leases.append((stream, msg_id, fields, cm))
            while leases:
                stream, msg_id, fields, cm = leases.pop(0)
                try:
                    await self._handle_entry(stream, msg_id, fields, leased=True)
                finally:
                    await cm.__aexit__(None, None, None)
        finally:
            for *_, cm in leases:                       # cancelled or crashed: release what is left
                await cm.__aexit__(None, None, None)

    async def _reclaim_pending(self):
        """XAUTOCLAIM the entries a dead replica left pending (S-MQ-3); dead-letter the ones that keep failing."""
        for stream in (HEALTH_STREAM, SEC_STREAM, ACTIONS_STREAM):
            try:
                await self.reliability.reclaim(stream, self._handle_entry, self._dead_letter)
            except Exception as e:
                logger.warning(f"reclaim of {stream} failed: {e}")

    async def _dead_letter(self, stream: str, msg_id: str, fields: Dict, deliveries: int, reason: str):
        incident_id = fields.get("incident_id") or derive_incident_id(fields)
        await self._escalate(incident_id, fields.get("namespace", ""), workload_of(fields) if fields else "",
                             f"{reason} (stream {stream}, entry {msg_id})")

    async def _handle_entry(self, stream: str, msg_id: str, fields: Dict, leased: bool = False) -> bool:
        """Handle one stream entry. XACK only after success; a failed entry stays pending and is reclaimed
        (XAUTOCLAIM) or, after N deliveries, dead-lettered. `leased` says the caller already holds the lease."""
        if leased:
            return await self._handle_entry_body(stream, msg_id, fields)
        async with self.reliability.lease(stream, msg_id):
            return await self._handle_entry_body(stream, msg_id, fields)

    async def _handle_entry_body(self, stream: str, msg_id: str, fields: Dict) -> bool:
        try:
            if stream == HEALTH_STREAM:
                await self._on_health(fields)
            elif stream == ACTIONS_STREAM:
                await self._on_action_result(fields)
            else:
                await self._on_security(fields)
        except RetryLater as e:
            logger.warning(f"{stream}/{msg_id} not handled yet, left pending for a retry: {e}")
            return False
        except Exception as e:
            logger.error(f"handling {stream}/{msg_id} failed, left pending: {e}", exc_info=True)
            return False
        await self.redis.xack(stream, GROUP, msg_id)
        return True

    def _key(self, fields: Dict) -> str:
        return f"{fields.get('namespace', 'default')}:{workload_of(fields)}"

    def _fresh(self, entry) -> Optional[Dict]:
        """Return the paired event only if it arrived within the correlation
        window - otherwise it is an independent event, not a compound one."""
        if not entry:
            return None
        fields, ts = entry
        return fields if (time.monotonic() - ts) <= self.CORRELATION_WINDOW_S else None

    def _prune(self):
        now = time.monotonic()
        for d in (self.pending_health, self.pending_sec):
            for k in [k for k, (_, ts) in d.items() if now - ts > self.CORRELATION_WINDOW_S]:
                d.pop(k, None)

    async def _on_model_unavailable(self, f: Dict):
        """The Health Agent could not get an answer from the Health Model (S-POL-1). Nothing was scored, so there
        is no decision to make: a human is told, once per workload and window (SET NX, so repeated drift events
        during an outage do not flood the escalation stream)."""
        namespace, workload = f.get("namespace", ""), workload_of(f)
        marker = f"{MODEL_DOWN_PREFIX}:{namespace}:{workload}"
        if not await self.redis.set(marker, "1", nx=True, ex=self.cfg.model_unavailable_dedup_ttl_s):
            return
        try:
            await self._escalate(derive_incident_id(f), namespace, workload,
                                 "health_model_unavailable: the Health Agent saw drift but the Health Model did "
                                 "not answer, so nothing was scored and no automatic action is possible; "
                                 "human review required")
        except Exception:
            await self.redis.delete(marker)          # let the redelivery escalate again
            raise

    async def _on_health(self, f: Dict):
        # Q1: an event with failure reasons (the Health Agent's rule evidence) is decided even when the Health
        # Model did not answer, because the rule path does not need the model. Without failure reasons a
        # model_unavailable event stays an escalation.
        if _truthy(f.get("model_unavailable")) and not em.string_list(f.get("failure_reasons_json")):
            await self._on_model_unavailable(f)
            return
        key = self._key(f)
        # P6-D5: one health event is one metric sample. Counted once per event id (a redelivery adds nothing).
        await BurnInCounter(self.redis).observe(f.get("event_id"))
        self.pending_health[key] = (f, time.monotonic())
        sec = self._fresh(self.pending_sec.get(key))
        await self._decide(key, f, sec)
        self._prune()

    async def _on_security(self, f: Dict):
        key = self._key(f)
        self.pending_sec[key] = (f, time.monotonic())
        health = self._fresh(self.pending_health.get(key))
        await self._decide(key, health, f)
        self._prune()

    # ---- incident bookkeeping ---------------------------------------------------------------------------
    def _ctx_key(self, incident_id: str) -> str:
        return f"{INCIDENT_PREFIX}:{incident_id}"

    async def _incident_for(self, namespace: str, pod: str, health: Dict, sec: Dict) -> Tuple[str, Dict]:
        """(incident id, stored context). Two security events of one process (the initial and the complete one
        from P5) name the same namespace, pod and pid and map to ONE incident (SET NX in Redis, so both
        replicas agree). Otherwise the id derives from the event itself."""
        anchor = sec or health
        candidate = derive_incident_id(anchor)
        pid = sec.get("pid_target") if sec else None
        if sec and pod and pid and sec.get("entropy_phase"):
            okey = f"{OPEN_PREFIX}:{namespace}:{pod}:{pid}"
            if not await self.redis.set(okey, candidate, nx=True, ex=self.cfg.incident_dedup_ttl_s):
                existing = await self.redis.get(okey)
                if existing:
                    candidate = existing
        return candidate, await self.redis.hgetall(self._ctx_key(candidate))

    async def _decide(self, key: str, health: Optional[Dict], sec: Optional[Dict]):
        namespace, workload = key.split(":", 1)
        health = health or {}
        sec = sec or {}
        # Only a security event names a real pod. Health events set pod_name to the Deployment name.
        pod = sec.get("pod_name") or ""

        incident_id, ctx = await self._incident_for(namespace, pod, health, sec)
        is_update = bool(ctx.get("opened"))
        prior_state = ctx.get("action_state", "")
        t0_ms = earliest_t0(health, sec, known=int(ctx["t0_ms"]) if str(ctx.get("t0_ms", "")).isdigit() else None)

        # ---- model answers (S-POL-1): every missing or late answer makes models_ok false ----
        issues = []
        if sec and not _truthy(sec.get("model_scored")):
            issues.append("security event not scored by the Security Model "
                          "(heuristic only, no syscall window, or model unreachable)")
        if health and not _truthy(health.get("model_scored")):
            # a missing field counts as not scored: only an explicit "true" from the Health Agent is trusted.
            # The policy ignores models_ok on the rule path (Q1); the issue still reaches the ledger.
            issues.append("health event not scored by the Health Model")
        health_risk = em.safe_float(health.get("health_risk"))

        # An event that cannot be mapped onto the contract (a risk that is not a number in [0, 1], ...) is never
        # trusted: models_ok is false, so a human decides. Mapping never raises.
        health_ev = em.to_health_event(health, namespace, workload) if health else None
        sec_ev = em.to_security_event(sec, namespace, workload) if sec else None
        if health and health_ev is None:
            issues.append("health event is malformed (it cannot be mapped onto the correlation contract)")
        if sec and sec_ev is None:
            issues.append("security event is malformed (it cannot be mapped onto the correlation contract)")

        # Q1: raw security risk and its freshness for the rule-based rollback. A security event in this decision
        # that the Security Model scored counts as fresh. Otherwise the per-workload hash written by the Security
        # Agent (V5-S2) is read. Until V5-S2 writes that key nothing is fresh, so the rule path escalates to a
        # human: the intended fail-closed behaviour, not a bug.
        if sec:
            sec_risk = em.safe_float(sec.get("sec_risk"))
            # a malformed event (sec_ev is None) or an old one is never a fresh Security Model response
            security_fresh = (sec_ev is not None and _truthy(sec.get("model_scored"))
                              and self._event_is_fresh(sec))
            security_source = "event"
        else:
            fresh_hash, hash_risk = await self._security_score(namespace, workload)
            sec_risk = hash_risk if fresh_hash and hash_risk is not None else 0.0
            security_fresh, security_source = fresh_hash, ("hash" if fresh_hash else "none")

        correlation, compound, dcm_chain, nl = 0.0, False, [], None
        corr_reasons: list = []
        legacy = bool(self.dcm_url)
        if health and sec and legacy:
            # Legacy path (DCM_URL set): the learned DCM answers; a missing answer or embedding means HUMAN.
            h_emb = _b64_to_vec(health.get("health_embedding_b64", ""))
            s_emb = _b64_to_vec(sec.get("security_embedding_b64", ""))
            if not (h_emb and s_emb):
                issues.append("a health and a security event are paired but an embedding is missing: "
                              "the DCM cannot be asked")
            else:
                res = await self.interp.correlate(health, sec, h_emb, s_emb, self.cfg.dcm_deadline_s)
                if res.ok:
                    corr = res.data
                    correlation = float(corr.get("correlation_score", 0.0))
                    compound = bool(corr.get("compound_flag", False))
                    dcm_chain = corr.get("causal_chain", []) or []
                    nl = corr.get("nl_summary")
                    await self._publish_dcm(namespace, workload, corr, health, sec)
                else:
                    issues.append(res.error)
        elif health and sec and health_ev is not None and sec_ev is not None:
            correlation, compound, corr_reasons = em.correlate(health_ev, sec_ev)
        if legacy:
            expl = await self.interp.explain(health or None, sec or None, dcm_chain, t0_ms,
                                             self.cfg.interpretation_deadline_s)
            if not expl.ok:
                issues.append(expl.error)
            causal_chain, attributions = expl.causal_chain, expl.attributions
        else:
            # Local, no model call: the plain sentence and the chain come from the correlation reasons and the
            # models' own top factors.
            nl = em.local_summary(health_ev, sec_ev, correlation, compound, corr_reasons) or None
            causal_chain = build_causal_chain(health or None, sec or None, [], t0_ms) + \
                [f"Correlation: {r}" for r in corr_reasons]
            attributions = {
                "health_top_factors": [f.model_dump() for f in health_ev.top_factors] if health_ev else [],
                "security_top_factors": [f.model_dump() for f in sec_ev.top_factors] if sec_ev else [],
                "methods": {"top_factors": "top_factors_json as published by the model services"}}
        models_ok = not issues

        # Replay traces are synthetic verification inputs. Keep them dry even if the global kill switch changes
        # to enforce while the temporary replay is running.
        decision_mode = self.mode.mode_for(namespace)
        if sec.get("syscall_source") == "replay":
            decision_mode = "test"

        health_set = em.prediction_set(health, "health_prediction_set")
        sec_set = em.prediction_set(sec, "sec_prediction_set")
        inp = DecisionInput(
            health_risk=health_risk,
            health_label=health.get("health_label", "benign"),
            health_prediction_set=health_set,
            sec_risk=sec_risk,
            sec_label=sec.get("sec_label", "benign"),
            sec_prediction_set=sec_set,
            sec_syscall_top=sec.get("top_syscall", ""),
            correlation_score=correlation,
            compound_flag=compound,
            namespace_tier=tier_of(health, sec),
            circuit_breaker_containments=await contain_breaker(self.redis, namespace, self.clock).count(),
            circuit_breaker_patches=await patch_breaker(self.redis, namespace, workload, self.clock).count(),
            models_ok=models_ok,
            namespace_protected=self.mode.protected_for(namespace),
            metric_samples_seen=await BurnInCounter(self.redis).seen(),
            burn_in_mode=self.burn_in,
            nl_summary=nl,
            rollback_reasons=em.string_list(health.get("failure_reasons_json")),
            spec_changed=_truthy(health.get("spec_changed")),
            has_baseline=_truthy(health.get("has_baseline")),
            changed_fields=em.string_list(health.get("changed_fields_json")),
            security_fresh=security_fresh,
            mode=decision_mode,
        )
        out = make_decision(inp)
        METRICS.record_decision(getattr(out.decision, "value", str(out.decision)))

        scores = {
            "health": {name: health.get(name) for name in
                       ("health_risk", "health_label", "health_prediction_set", "health_uncertain",
                        "top_factors_json", "top_field", "model_scored", "model_version") if name in health},
            "security": {name: sec.get(name) for name in
                         ("sec_risk", "sec_label", "sec_prediction_set", "sec_uncertain", "top_factors_json",
                          "top_syscall", "model_scored", "model_version", "syscall_source", "entropy_phase",
                          "entropy_valid_samples") if name in sec},
            "correlation_score": correlation,
            "correlation_reasons": corr_reasons,
            "compound": compound,
        }
        decision_payload = {
            "decision": out.decision.value,
            "adjusted_score": out.adjusted_score,
            "rationale": out.rationale,
            "dry_run": out.dry_run,
            "namespace_tier": inp.namespace_tier,
            "compound": compound,
            "causal_chain": causal_chain,
            "attributions": attributions,
            "models_ok": models_ok,
            "model_issues": issues,
            "namespace_protected": inp.namespace_protected,
            "health_prediction_set": health_set,
            "sec_prediction_set": sec_set,
            "health_uncertain": health.get("health_uncertain"),
            "sec_uncertain": sec.get("sec_uncertain"),
            "top_factors_json": {"health": health.get("top_factors_json"), "security": sec.get("top_factors_json")},
            "rule_path": bool(out.action_params.get("rule_path", False)),
            "rule_reasons": out.action_params.get("rule_reasons", []),
            **self._containment_fields(out, inp),
            "patch_fields": out.action_params.get("patch_fields", []),
            "security_fresh": security_fresh,
            "security_fresh_source": security_source,
        }
        if t0_ms:
            decision_payload["t0_ms"] = t0_ms        # absent means unknown, never a guess
        workload_kind = sec.get("workload_kind") or ctx.get("workload_kind", "")
        unresolved_owner = owner_unresolved(sec, ctx.get("workload_kind", ""))

        if not is_update:
            detection = {
                "namespace": namespace, "deployment": workload, "pod": pod,
                "health_event_id": health.get("event_id"),
                "security_event_id": sec.get("event_id"),
                "signals": [name for name, event in (("health", health), ("security", sec)) if event],
            }
            if t0_ms:
                detection["t0_ms"] = t0_ms
            if sec:
                for name in ("workload_kind", "syscall_source", "model_scored", "entropy_phase",
                             "entropy_valid_samples"):
                    if name in sec:
                        detection[name] = sec[name]
            await self._append_ledger(incident_id, "detection", detection)
            await self._append_ledger(incident_id, "scores", scores)
            await self._append_ledger(incident_id, "decision", decision_payload)
        else:
            # The second security event of an incident (or a paired health event) updates it.
            update = {"trigger_event_ids": {"health": health.get("event_id"), "security": sec.get("event_id")},
                      "scores": scores, **decision_payload, "action_state_before": prior_state}
            await self._append_ledger(incident_id, "incident_update", update)

        # context for later updates and for the restore trigger
        new_ctx = {"namespace": namespace, "deployment": workload, "pod": pod,
                   "workload_kind": workload_kind, "namespace_tier": inp.namespace_tier}
        if t0_ms:
            new_ctx["t0_ms"] = str(t0_ms)
        action_blocked = bool(prior_state)           # an action or an approval already exists for this incident
        if out.decision in (Decision.AUTO_CONTAIN, Decision.HUMAN_CONTAIN) and not action_blocked:
            # Q2: what a later `contained` result needs to know. The policy decides it for an automatic
            # containment; for a human-decided one (approved later on the dashboard) it comes from the label.
            label = str(inp.sec_label).strip().lower()
            params = out.action_params
            new_ctx["containment_label"] = label
            new_ctx["restore_after"] = "1" if params.get("restore_after", label == RESTORE_LABEL) else "0"
            new_ctx["human_followup"] = "1" if params.get(
                "human_followup", label in AUTO_CONTAIN_LABELS and label != RESTORE_LABEL) else "0"
        await self.redis.hset(self._ctx_key(incident_id), mapping={k: v for k, v in new_ctx.items() if v})

        state = prior_state
        if out.decision == Decision.OBSERVE:
            written = await sampling.request_observe(self.redis, namespace, workload, pod or None, incident_id,
                                                     self.cfg.observe_period_s, now_ms=int(self.clock() * 1000))
            await self._append_ledger(incident_id, "observe_requested", {
                "factor": sampling.OBSERVE_FACTOR, "period_s": self.cfg.observe_period_s,
                "keys": written, "already_active": not written})
        elif out.decision in {Decision.HUMAN_PATCH, Decision.HUMAN_CONTAIN} and not action_blocked:
            await self._append_ledger(incident_id, "approval_requested", {
                "decision": out.decision.value,
                "status": "pending",
                "rationale": out.rationale,
            })
            state = "human_pending"

        # The incident is opened and its state stored BEFORE the lock: if the lock is held by another replica
        # and this event returns early, the next event of the incident must still see the record and any
        # pending approval (otherwise it would open a second incident and could act past a pending approval).
        final_ctx = {"opened": "1"}
        if state:
            final_ctx["action_state"] = state
        await self.redis.hset(self._ctx_key(incident_id), mapping=final_ctx)
        await self.redis.expire(self._ctx_key(incident_id), self.cfg.incident_context_ttl_s)

        if action_blocked and out.decision not in {Decision.OBSERVE, Decision.BENIGN}:
            logger.info(f"incident {incident_id} already has state {prior_state!r}; "
                        f"{out.decision.value} from the new event only updates the record")
        elif out.requires_incident_lock:
            automatic = out.decision in AUTOMATIC
            lock_state = LockState()
            async with acquire_incident_lock(self.redis, namespace, workload, state=lock_state) as got:
                if not got:
                    if automatic:
                        # Never drop an automatic action: leave the entry pending (not acked) so it is
                        # reclaimed and retried; after the delivery limit it is dead-lettered and escalated.
                        await self._append_ledger(incident_id, "action_deferred", {
                            "decision": out.decision.value, "reason": "incident lock held by another handler",
                            "namespace": namespace, "deployment": workload, "retry": "entry left pending"})
                        raise RetryLater(f"lock held for {key}; {out.decision.value} not queued yet")
                    logger.debug(f"lock held for {key}; the {out.decision.value} record is skipped")
                    return
                # The lock was taken just now: the state read at the start may be stale (a second replica can
                # have queued this incident's action in between), so read it again.
                fresh = (await self.redis.hget(self._ctx_key(incident_id), "action_state")) or ""
                if fresh and fresh != state:
                    logger.info(f"incident {incident_id} got state {fresh!r} while this event waited for the "
                                f"lock; {out.decision.value} from this event is not acted on")
                elif lock_state.lost and automatic:
                    raise RetryLater(f"incident lock for {key} was lost before {out.decision.value} was queued")
                else:
                    outcome = await self._execute(namespace, workload, pod, out, inp, causal_chain, incident_id,
                                                  t0_ms=t0_ms, health_event_id=health.get("event_id"),
                                                  owner_unresolved=unresolved_owner)
                    if outcome in ("queued_for_executor", "already_queued"):
                        await self.redis.hset(self._ctx_key(incident_id), mapping={"action_state": "queued"})
        else:
            await self._execute(namespace, workload, pod, out, inp, causal_chain, incident_id, t0_ms=t0_ms,
                                health_event_id=health.get("event_id"), owner_unresolved=unresolved_owner)

        if is_update and t0_ms:
            # T0 may only have become known now (the complete event): a finished containment can restore now
            await self._maybe_request_restore(incident_id)
        # Pending entries are kept for the correlation window so a partner event arriving
        # within 30 s can still form a compound incident. _prune() expires them; the incident
        # lock and the circuit breakers prevent duplicate actions on the same workload.

    async def _append_ledger(self, incident_id: str, step: str, payload: Dict):
        # MinIO's client is synchronous; keep its network I/O off the event loop.
        await asyncio.to_thread(self.ledger.append, incident_id, step, payload)

    async def _execute(self, namespace, workload, pod, out, inp, causal_chain, incident_id=None, t0_ms=None,
                       health_event_id=None, owner_unresolved=False):
        logger.info(f"DECISION {out.decision.value} {namespace}/{workload} "
                    f"score={out.adjusted_score:.2f} :: {out.rationale}")
        outcome = "logged"
        incident_id = incident_id or f"inc-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        # The Fusion Agent never calls the Kubernetes API. Automatic actions are queued for the
        # Executor, the only component with write permissions (S-EX-1).
        # Circuit breakers count real automatic actions only: record after the request is queued, keyed by the
        # incident id (a failed enqueue or a redelivery does not double count) and never for dry runs,
        # otherwise test mode would use up the budget before the switch to enforce.
        if out.decision == Decision.AUTO_CONTAIN and owner_unresolved:
            # Fail closed: the security event names no Deployment or StatefulSet owner for the pod, so there is no
            # workload to put in the request (the pod name is never one). A human is told; nothing is queued.
            logger.error(f"AUTO_CONTAIN for {namespace}/{pod or workload} not queued: owner of the pod unresolved")
            await self._escalate(incident_id, namespace, workload,
                                 f"contain_not_requested: the security event names no Deployment or StatefulSet "
                                 f"owner for pod {pod or 'unknown'}; no containment request queued")
            outcome = "not_queued_owner_unresolved"
        elif out.decision == Decision.AUTO_CONTAIN and not pod:
            logger.error(f"AUTO_CONTAIN for {namespace}/{workload} without a pod from a security event; "
                         "not queued")
            outcome = "not_queued_no_pod"
        elif out.decision == Decision.AUTO_CONTAIN:
            if not await self._enqueue_exec(incident_id, "contain", namespace, workload, pod, out, inp):
                return "already_queued"
            if not out.dry_run:
                await contain_breaker(self.redis, namespace, self.clock).record(incident_id)
            outcome = "queued_for_executor"
        elif out.decision == Decision.AUTO_PATCH:
            # One health event is patched once even when a later security event re-decides the buffered health
            # event under a different incident id (the per-incident marker alone would not stop that).
            health_marker = None
            if health_event_id:
                health_marker = f"{EXEC_REQ_PREFIX}-health:{health_event_id}:patch"
                if not await self.redis.set(health_marker, "1", nx=True, ex=self.cfg.incident_context_ttl_s):
                    logger.info(f"patch for health event {health_event_id} was already queued; no second request")
                    return "already_queued"
            try:
                queued = await self._enqueue_exec(incident_id, "patch", namespace, workload, pod, out, inp)
            except Exception:
                if health_marker:
                    await self.redis.delete(health_marker)
                raise
            if not queued:
                return "already_queued"
            if not out.dry_run:
                await patch_breaker(self.redis, namespace, workload, self.clock).record(incident_id)
            outcome = "queued_for_executor"
        entry = {
            "incident_id": incident_id,
            "action_type": out.decision.value,
            "target": json.dumps({"namespace": namespace, "deployment": workload, "pod": pod}),
            "confidence": f"{out.adjusted_score:.4f}",
            "rationale": out.rationale,
            "compound": str(out.action_params.get("compound", False)),
            "nl_summary": out.action_params.get("nl_summary") or "",
            "causal_chain": json.dumps(causal_chain),
            "outcome": outcome,
            "dry_run": str(out.dry_run).lower(),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        }
        if t0_ms:
            entry["t0_ms"] = str(t0_ms)
        await self.redis.xadd(ACTIONS_STREAM, entry)
        return outcome

    async def _claim_request(self, incident_id: str, action: str) -> Optional[str]:
        """SET NX marker per incident and action. Returns the marker key when this caller may queue the request,
        None when it was already queued (two replicas handling the initial and the complete event of one
        incident, or a redelivery). TTL is chosen, not measured: the incident context TTL."""
        marker = f"{EXEC_REQ_PREFIX}:{incident_id}:{action}"
        if await self.redis.set(marker, "1", nx=True, ex=self.cfg.incident_context_ttl_s):
            return marker
        return None

    async def _enqueue_exec(self, incident_id, action, namespace, workload, pod, out, inp) -> bool:
        """Queue one request on kubeheal.exec. False when this incident and action was already queued."""
        marker = await self._claim_request(incident_id, action)
        if marker is None:
            logger.info(f"{action} for incident {incident_id} was already queued; no second request")
            return False
        try:
            await self._xadd_exec(incident_id, action, namespace, workload, pod, out, inp)
        except Exception:
            await self.redis.delete(marker)          # nothing was queued: a retry must be able to queue it
            raise
        return True

    @staticmethod
    def _containment_fields(out, inp) -> dict:
        """The Q2 containment fields of a contain decision (automatic or human). They go into the decision record
        so a later dashboard approval sends the SAME label, restore_after and human_followup to the Executor
        (the Executor freezes only for the labels ransomware and exfiltration, and Fusion restores only after a
        containment with restore_after). Empty for any other decision."""
        if out.decision not in (Decision.AUTO_CONTAIN, Decision.HUMAN_CONTAIN):
            return {}
        label = str(inp.sec_label).strip().lower()
        params = out.action_params
        return {
            "containment_label": label,
            "restore_after": bool(params.get("restore_after", label == RESTORE_LABEL)),
            "human_followup": bool(params.get("human_followup",
                                              label in AUTO_CONTAIN_LABELS and label != RESTORE_LABEL)),
        }

    async def _xadd_exec(self, incident_id, action, namespace, workload, pod, out, inp):
        params = out.action_params
        patch_fields = params.get("patch_fields") or []
        # The Executor does not read the Q2 fields below yet (later work); they are carried so it can.
        # patch_field: the model path names it in action_params; the rule path (no model attribution) uses the
        # first changed field of the spec diff, never the unrelated top_field of a model score.
        patch_field = (params.get("patch_field") or (patch_fields[0] if patch_fields else ""))             if action == "patch" else ""
        await self.redis.xadd(EXEC_STREAM, {
            "incident_id": incident_id,
            "action": action,
            "namespace": namespace,
            "deployment": workload,
            "pod": pod,
            "patch_field": patch_field,
            "patch_fields": json.dumps(patch_fields),
            "rule_path": str(bool(params.get("rule_path", False))).lower(),
            "rule_reasons": json.dumps(params.get("rule_reasons") or []),
            "containment_label": str(params.get("containment_label") or ""),
            "restore_after": str(bool(params.get("restore_after", False))).lower(),
            "human_followup": str(bool(params.get("human_followup", False))).lower(),
            "namespace_tier": inp.namespace_tier,
            "approved_by": "auto",
            "dry_run": str(out.dry_run).lower(),
            "source": "fusion",
            "rationale": out.rationale,
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    # ---- restore after a successful containment (P6-D7) ------------------------------------------------
    async def _on_action_result(self, f: Dict):
        """Entries on kubeheal.actions. Fusion's own records and every outcome other than a clean
        `contained` are ignored: a dry run did not contain anything, and a contain with gaps or a failure was
        already escalated to a human by the Executor."""
        if f.get("action_type") != "executed_contain" or f.get("outcome") != "contained":
            return
        incident_id = f.get("incident_id") or ""
        if not incident_id:
            return
        ctx = await self.redis.hgetall(self._ctx_key(incident_id))
        if not ctx:
            await self._escalate(incident_id, "", "",
                                 "restore_not_requested: the incident was contained but Fusion has no context "
                                 "for it (expired or opened elsewhere); no T0 or workload kind known")
            return
        await self.redis.hset(self._ctx_key(incident_id), mapping={
            "contained": "1", "approved_by": f.get("approved_by", "") or ctx.get("approved_by", "")})
        await self._maybe_request_restore(incident_id)

    async def _maybe_request_restore(self, incident_id: str):
        """Queue `restore` on kubeheal.exec when the incident is contained AND T0 is known AND the workload kind
        is one the Executor accepts, and the containment was for a ransomware label (`restore_after`). Otherwise
        escalate (once per reason), or, after an exfiltration containment, tell a human once (`human_followup`);
        a contained incident with neither flag (suspicious, or a context from before this change) requests
        nothing. Never invents T0."""
        ctx = await self.redis.hgetall(self._ctx_key(incident_id))
        if not ctx.get("contained"):
            return
        marker = f"{RESTORE_PREFIX}:{incident_id}"
        if await self.redis.get(marker):
            return
        namespace, workload, pod = ctx.get("namespace", ""), ctx.get("deployment", ""), ctx.get("pod", "")
        if ctx.get("restore_after") != "1":
            # Q2: the restore step is for ransomware only. After an exfiltration containment a human follows up
            # (once per incident); any other label, or a context without the flag, requests nothing.
            if ctx.get("human_followup") == "1":
                esc_key = f"{RESTORE_PREFIX}:escalated:{incident_id}:human_followup"
                if await self.redis.set(esc_key, "1", nx=True, ex=self.cfg.incident_context_ttl_s):
                    try:
                        await self._escalate(
                            incident_id, namespace, workload,
                            f"human_followup_required: containment done for {ctx.get('containment_label') or 'exfiltration'}; "
                            "no restore is requested for this label, human follow-up required")
                    except Exception:
                        await self.redis.delete(esc_key)
                        raise
            return
        t0 = ctx.get("t0_ms", "")
        kind = ctx.get("workload_kind", "")
        problem = None
        if not (t0.isdigit() and int(t0) > 0):
            problem = ("t0_unknown: the containment succeeded but no attack onset T0 is known "
                       "(no security event carried t0_ms); no restore requested")
        elif kind not in RESTORE_KINDS:
            problem = (f"workload_kind_unsupported: {kind or 'unknown'!r} is not Deployment or StatefulSet; "
                       "no restore requested")
        elif not (namespace and workload and pod):
            problem = "target_unknown: namespace, workload or pod missing from the incident; no restore requested"
        elif self.mode.protected_for(namespace):
            problem = ("namespace_protected: the namespace is protected (kubeheal/protected) or its label "
                       "state is unknown, so no automatic restore is requested")
        if problem:
            esc_key = f"{RESTORE_PREFIX}:escalated:{incident_id}:{problem.split(':', 1)[0]}"
            if await self.redis.set(esc_key, "1", nx=True, ex=self.cfg.incident_context_ttl_s):
                await self._escalate(incident_id, namespace, workload, f"restore_not_requested: {problem}")
            return
        dry_run = self.mode.dry_run_for(namespace)
        contain_approved_by = ctx.get("approved_by") or "auto"
        # SET NX before the xadd (it used to be get, xadd, set): of two replicas only one queues the restore.
        if not await self.redis.set(marker, "1", nx=True, ex=self.cfg.incident_context_ttl_s):
            return
        try:
            # Ledger entry BEFORE the request is queued (the ledger-before-corrective-action rule).
            await self._append_ledger(incident_id, "restore_requested", {
                "t0_ms": int(t0), "workload_kind": kind, "namespace": namespace, "deployment": workload,
                "pod": pod, "approved_by": "auto", "contain_approved_by": contain_approved_by,
                "dry_run": dry_run})
            await self._xadd_restore(incident_id, namespace, workload, pod, kind, t0, dry_run, contain_approved_by,
                                     ctx.get("namespace_tier", ""))
        except Exception:
            await self.redis.delete(marker)
            raise
        await self.redis.xadd(ACTIONS_STREAM, {
            "incident_id": incident_id, "action_type": "restore_requested",
            "target": json.dumps({"namespace": namespace, "deployment": workload, "pod": pod}),
            "t0_ms": t0, "outcome": "queued_for_executor", "dry_run": str(dry_run).lower(),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _xadd_restore(self, incident_id, namespace, workload, pod, kind, t0, dry_run, contain_approved_by,
                           tier):
        await self.redis.xadd(EXEC_STREAM, {
            "incident_id": incident_id,
            "action": "restore",
            "namespace": namespace,
            "deployment": workload,
            "pod": pod,
            "workload_kind": kind,
            "t0_ms": t0,
            "namespace_tier": tier,
            # The restore is Fusion's own automatic request: nobody approved it. Who approved the containment
            # that preceded it is kept in a separate field.
            "approved_by": "auto",
            "contain_approved_by": contain_approved_by,
            "dry_run": str(dry_run).lower(),
            "source": "fusion",
            "rationale": "restore after a successful containment, from the last snapshot before T0",
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    async def _escalate(self, incident_id: str, namespace: str, workload: str, reason: str):
        await self._append_ledger(incident_id, "fusion_escalation", {
            "namespace": namespace, "deployment": workload, "reason": reason, "required": "human"})
        await self.redis.xadd(ESCALATIONS_STREAM, {
            "incident_id": incident_id, "namespace": namespace, "deployment": workload,
            "reason": reason, "required": "human", "source": "fusion",
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })

    def _event_is_fresh(self, event: Dict) -> bool:
        """The event's own timestamp_ms is within SECURITY_FRESH_S of now (absent or unparsable: not fresh)."""
        try:
            ts_ms = float(event.get("timestamp_ms"))
        except (TypeError, ValueError):
            return False
        if not math.isfinite(ts_ms):
            return False
        return abs(self.clock() * 1000.0 - ts_ms) <= self.cfg.security_fresh_s * 1000.0

    async def _security_score(self, namespace: str, workload: str) -> Tuple[bool, Optional[float]]:
        """(fresh, risk) from the hash the Security Agent writes per workload (task V5-S2, not built yet):
        `kubeheal:security:score:<namespace>:<workload>` with fields sec_risk, ts_ms, model_scored.
        Fresh only when the hash exists, model_scored is "true", ts_ms parses and is within SECURITY_FRESH_S of
        now (a configuration default, not a measurement), and sec_risk is a finite number. Anything else,
        including a Redis error, is (False, None): the rule path then escalates to a human (Q1)."""
        try:
            h = await self.redis.hgetall(f"{SECURITY_SCORE_PREFIX}:{namespace}:{workload}")
        except Exception as e:
            logger.warning(f"security score hash unreadable ({e}); treated as not fresh")
            return False, None
        if not h or not _truthy(h.get("model_scored")):
            return False, None
        try:
            ts_ms = float(h["ts_ms"])
            risk = float(h["sec_risk"])
        except (KeyError, TypeError, ValueError):
            return False, None
        if not (math.isfinite(ts_ms) and math.isfinite(risk)) or not 0.0 <= risk <= 1.0:
            return False, None
        # abs(): a timestamp slightly ahead of this clock (clock skew) is as fresh as one slightly behind it
        if abs(self.clock() * 1000.0 - ts_ms) > self.cfg.security_fresh_s * 1000.0:
            return False, None
        return True, risk

    async def _publish_dcm(self, namespace, workload, corr, health, sec):
        await self.redis.xadd(DCM_STREAM, {
            "namespace": namespace, "pod_name": workload, "deployment": workload,
            "correlation_score": f"{corr.get('correlation_score', 0):.4f}",
            "compound_flag": str(corr.get("compound_flag", False)),
            "causal_chain_json": json.dumps(corr.get("causal_chain", [])),
            "correlation_confidence": f"{corr.get('correlation_confidence', 0):.4f}",
            "nl_summary": corr.get("nl_summary") or "",
            "health_event_id": health.get("event_id", ""),
            "security_event_id": sec.get("event_id", ""),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        })


async def main():
    METRICS.start_server(int(os.environ.get("METRICS_PORT", "8081")))
    agent = FusionAgentV4()
    try:
        await agent.start()
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
