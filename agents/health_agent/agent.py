"""KubeHeal health agent: watch Deployments, assess real spec changes, publish HealthEvents.

Run: python -m agents.health_agent.agent
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime

import aiohttp
import redis.asyncio as aioredis
from kubernetes_asyncio import client, watch
from kubernetes_asyncio.client.exceptions import ApiException
from prometheus_client import Counter

from agents.common import (
    connect_redis,
    env_list,
    load_kube_config,
    predict,
    protected_namespaces,
    publish_event,
    run,
    setup_logging,
    start_http,
)
from agents.health_agent.prometheus import fetch_window
from kubeheal.contracts import (
    POLICY_REASON_PREFIX,
    STREAM_HEALTH,
    HealthEvent,
    key_baseline,
    key_spec,
    new_event_id,
    now_ms,
)
from kubeheal.features.health import (
    METRIC_FEATURES,
    canonical_spec,
    changed_paths,
    health_features,
    spec_diff_features,
    spec_hash,
)
from kubeheal.features.quantity import parse_cpu, parse_memory

log = logging.getLogger("kubeheal.health")

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus-operated.monitoring.svc:9090").rstrip("/")
# Latest assessment time after a change: the metric window is [change, min(assess time, change + delay)].
# Hard evidence (posture violation, failed rollout) assesses earlier; drift_lab reads the agent's own events
# (and records their delay), so training windows are exactly the windows the agent scores.
ASSESS_DELAY_S = float(os.environ.get("ASSESS_DELAY_S", "60"))
POLL_S = 2.0                  # failed-rollout polling period while a change is pending
RETRY_DELAY_S = 60.0          # re-assess after inference / Redis failures
MAX_CONCURRENT = 8            # assessments in flight
WATCH_TIMEOUT_S = 300         # server-side watch timeout; the loop reconnects (and proves liveness) after it
STALE_AFTER_S = WATCH_TIMEOUT_S + 120
KUBE_TIMEOUT_S = 10           # pod listing inside an assessment
CREATED_SLACK_S = 5           # creationTimestamp is whole seconds and the change is seen after the API write
# Container waiting reasons that mean the new pods cannot run. Not model features: fusion rolls back on them
# by rule (failure_reasons), so the model's inputs stay identical to the collected training data.
WAITING_FAILURES = frozenset({"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CrashLoopBackOff",
                              "CreateContainerConfigError", "CreateContainerError", "RunContainerError"})
# Spec-diff features that mean the change weakens security posture: rolled back by rule, like a failed rollout.
POSTURE_FEATURES = ("privileged_added", "root_user_added", "capabilities_added",
                    "host_namespace_added", "host_path_added")
# Resource unit typos (500m -> 5m): a >=10x cut to below these floors, judged against the baseline. A deliberate
# 2-4x rightsizing, or a 10x cut that still leaves a sane value (2 cores -> 100m), never trips them.
CUT_FACTOR = 10
CUT_FLOORS = {"cpu": (0.05, parse_cpu), "memory": (32 * 2**20, parse_memory)}    # cores, bytes
# Running but never Ready: the probe budget (initialDelay + period x failureThreshold, Kubernetes defaults 0/10/3)
# plus a margin for slow pods and probe timeouts, never below the floor. Containers without a readiness probe
# are Ready as soon as they run, so they can't be the culprit and are ignored.
READY_MARGIN_S = 30
READY_FLOOR_S = 60
TRACK_MARGIN_S = 60           # tracking a changed spec ends this long after its progress deadline
DEFAULT_PROGRESS_DEADLINE_S = 600
HPA_POLL_S = 30               # re-list HorizontalPodAutoscalers this often

ASSESSMENTS = Counter("kubeheal_health_assessments_total", "Health assessments by outcome", ["outcome"])
WATCH_ERRORS = Counter("kubeheal_health_watch_errors_total", "Deployment watch errors")

Key = tuple[str, str]   # (namespace, deployment)


def rollout_complete(dep: dict) -> bool:
    """The controller has rolled the current spec out and every desired replica is available
    (`kubectl rollout status` semantics: no old-ReplicaSet pod is left to count as available).

    Zero desired replicas is never "complete": nothing serving is no evidence the spec is good.
    """
    meta, spec, st = dep.get("metadata") or {}, dep.get("spec") or {}, dep.get("status") or {}
    want, updated = spec.get("replicas", 1), st.get("updatedReplicas") or 0
    return (want > 0 and st.get("observedGeneration", 0) >= meta.get("generation", 1) and updated == want
            and (st.get("replicas") or 0) == updated and (st.get("availableReplicas") or 0) >= updated)


def progress_deadline_exceeded(dep: dict) -> bool:
    """The controller gave up on the current generation's rollout (Progressing=False/ProgressDeadlineExceeded)."""
    meta, st = dep.get("metadata") or {}, dep.get("status") or {}
    return st.get("observedGeneration", 0) >= meta.get("generation", 1) and any(
        c.get("type") == "Progressing" and c.get("status") == "False" and c.get("reason") == "ProgressDeadlineExceeded"
        for c in st.get("conditions") or [])


def _probe_budget_s(p: dict | None) -> float:
    if p is None:
        return 0
    return (p.get("initialDelaySeconds") or 0) + (p.get("periodSeconds") or 10) * (p.get("failureThreshold") or 3)


def readiness_never_passed(pod: dict, now: float) -> bool:
    """Every app container runs, a probed one is not ready, and that has lasted past its readiness budget."""
    st, spec = pod.get("status") or {}, pod.get("spec") or {}
    if any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions") or []):
        return False
    statuses = st.get("containerStatuses") or []
    if not statuses or any("running" not in (cs.get("state") or {}) for cs in statuses):
        return False                            # still starting, or a waiting / terminated state with its own reason
    probes = {c.get("name"): c for c in spec.get("containers") or []}
    for cs in statuses:
        c = probes.get(cs.get("name")) or {}
        started = ((cs.get("state") or {}).get("running") or {}).get("startedAt")
        if cs.get("ready") or c.get("readinessProbe") is None or not started:
            continue
        budget = max(READY_FLOOR_S, _probe_budget_s(c["readinessProbe"]) + _probe_budget_s(c.get("startupProbe"))
                     + READY_MARGIN_S)
        if now - datetime.fromisoformat(started).timestamp() > budget:
            return True
    return False


def owned_by(pod: dict, deployment: str) -> bool:
    """The pod belongs to one of this Deployment's ReplicaSets (named <deployment>-<pod-template-hash>), not to
    another Deployment whose selector overlaps (a canary {app: web, track: canary} matches app=web too)."""
    meta = pod.get("metadata") or {}
    h = (meta.get("labels") or {}).get("pod-template-hash")
    return bool(h) and any(r.get("kind") == "ReplicaSet" and r.get("name") == f"{deployment}-{h}"
                           for r in meta.get("ownerReferences") or [])


def pod_failure_reasons(pods: list[dict], since_s: float, now: float | None = None) -> set[str]:
    """Failure reasons of pods created after `since_s` (epoch s): bad waiting state, an OOM kill, or readiness
    that never passed. Older (previous ReplicaSet) and terminating pods are ignored."""
    out: set[str] = set()
    now = time.time() if now is None else now
    for p in pods:
        meta = p.get("metadata") or {}
        created = meta.get("creationTimestamp")
        if (not created or meta.get("deletionTimestamp")
                or datetime.fromisoformat(created).timestamp() < since_s - CREATED_SLACK_S):
            continue
        if readiness_never_passed(p, now):
            out.add("ReadinessNeverPassed")
        st = p.get("status") or {}
        for cs in (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or []):
            if (r := ((cs.get("state") or {}).get("waiting") or {}).get("reason")) in WAITING_FAILURES:
                out.add(r)
            if ((cs.get("lastState") or {}).get("terminated") or {}).get("reason") == "OOMKilled":
                out.add("OOMKilled")
    return out


def policy_violations(base: dict, spec: dict) -> list[str]:
    """Posture violations `spec` introduces relative to `base` (the restore target), as failure_reasons.

    Pure: both are DeploymentSpecs in any form canonical_spec accepts (API JSON, canonical, a Deployment)."""
    base, spec = canonical_spec(base), canonical_spec(spec)
    f = spec_diff_features(base, spec)
    return [POLICY_REASON_PREFIX + k for k in POSTURE_FEATURES if f[k]] + [
        f"{POLICY_REASON_PREFIX}{r}_cut_{CUT_FACTOR}x" for r in CUT_FLOORS if _resource_cut(base, spec, r)]


def _resource_cut(base: dict, spec: dict, resource: str) -> bool:
    """Some container's limit or request of `resource` fell >=10x vs the baseline to below its floor."""
    floor, parse = CUT_FLOORS[resource]
    old = {c.get("name"): c.get("resources") or {} for c in (base.get("template") or {}).get("spec", {}).get("containers", [])}
    for c in (spec.get("template") or {}).get("spec", {}).get("containers", []):
        for kind in ("limits", "requests"):
            was = parse((old.get(c.get("name"), {}).get(kind) or {}).get(resource))
            now = parse(((c.get("resources") or {}).get(kind) or {}).get(resource))
            if was and now is not None and now < floor and was >= CUT_FACTOR * now:
                return True
    return False


class HealthAgent:
    def __init__(self, redis: aioredis.Redis, session: aiohttp.ClientSession,
                 delay_s: float = ASSESS_DELAY_S, protected: frozenset[str] | None = None,
                 core: client.CoreV1Api | None = None):
        self.redis = redis
        self.session = session
        self.core = core                            # None: no pod evidence (failure_reasons from the Deployment only)
        self.delay_s = delay_s
        self.protected = protected_namespaces() if protected is None else protected
        self.latest: dict[Key, dict] = {}         # newest spec seen per workload, API-shaped (stored as the restore target)
        self.seen_hash: dict[Key, str] = {}
        self.changed_at: dict[Key, float] = {}      # epoch s when the pending spec was first seen
        self.rolled_out: dict[Key, bool] = {}       # latest watch status: rollout of the current spec done
        self.stalled: dict[Key, bool] = {}          # latest watch status: ProgressDeadlineExceeded
        self.timers: dict[Key, asyncio.TimerHandle] = {}
        self.pollers: dict[Key, asyncio.Task] = {}  # early-evidence watcher per pending change
        self.assessing: dict[Key, str] = {}         # spec hash being assessed now: one spec publishes once
        self.pending_promo: dict[Key, tuple[str, str]] = {}   # assessed benign+certain, rollout not done: (hash, blob)
        self.trackers: dict[Key, asyncio.Task] = {}  # published, rollout unfinished: watches for later failures
        self.tasks: set[asyncio.Task] = set()
        self.sem = asyncio.Semaphore(MAX_CONCURRENT)
        self.alive: dict[str, float] = {}           # watch scope → last loop activity (monotonic)
        self.hpa: dict[str, set[Key]] = {}          # watch scope → Deployments an HPA scales

    def _view(self, key: Key, spec: dict) -> dict:
        """What is compared and assessed: spec.replicas is left out while an HPA owns it (scaling is not drift)."""
        return {k: v for k, v in spec.items() if k != "replicas"} if any(key in s for s in self.hpa.values()) else spec

    def _hash(self, key: Key, spec: dict) -> str:
        return spec_hash(self._view(key, spec))

    # ── watch side: cheap, never blocks on Redis / HTTP ──────────────────────
    def on_event(self, etype: str, dep: dict) -> None:
        meta = dep.get("metadata") or {}
        key = (meta.get("namespace", ""), meta.get("name", ""))
        if key[0] in self.protected:
            return
        if etype == "DELETED":
            self._forget(key)
            self._spawn(self._delete_keys(key))
            return
        self.rolled_out[key] = rollout_complete(dep)    # status-only updates count here
        self.stalled[key] = progress_deadline_exceeded(dep)
        # API-shaped spec: canonical_spec camelCases user-data keys (csi volumeAttributes), so only the raw form
        # is a safe AUTO_PATCH restore target. Hashing / diffing canonicalise it.
        spec = dep.get("spec") or {}
        h = self._hash(key, spec)
        if self.rolled_out[key] and not self.stalled[key] and self.pending_promo.get(key, ("",))[0] == h:
            self._spawn(self._promote(key, *self.pending_promo.pop(key)))
        if self.seen_hash.get(key) == h:      # status-only update: nothing to assess
            return
        self.seen_hash[key] = h
        self.pending_promo.pop(key, None)
        self.latest[key] = spec
        # Debounce with a cap: a churning spec (HPA, annotation every 50 s) is assessed at most delay_s after the
        # first change still pending, never postponed forever. The window starts at that first change.
        now = time.time()
        if key not in self.timers or key not in self.changed_at:
            self.changed_at[key] = now
        self.schedule(key, max(0.0, self.changed_at[key] + self.delay_s - now))
        if t := self.pollers.pop(key, None):
            t.cancel()
        if t := self.trackers.pop(key, None):   # a newer spec supersedes the one being tracked
            t.cancel()
        self.pollers[key] = asyncio.create_task(self._poll(key, spec, self.changed_at[key]))

    async def _poll(self, key: Key, spec: dict, t0: float) -> None:
        """Assess now (instead of at the delay) once the pending change has posture or failed-rollout evidence."""
        try:
            raw = await self.redis.get(key_spec(*key))
            if raw is None:                     # first sight: nothing to judge against
                return
            h = self._hash(key, spec)
            if self._hash(key, json.loads(raw)) == h:   # restart replay / no real change: nothing pending
                if self.latest.get(key) is spec and (t := self.timers.pop(key, None)):
                    t.cancel()
                return
            base_raw = await self.redis.get(key_baseline(*key))
            if base_raw is not None and self._hash(key, json.loads(base_raw)) == h:
                return                          # back at the baseline: the timer records it
            early = bool(policy_violations(json.loads(base_raw or raw), spec))
            seen: set[str] = set()
            while not early and time.time() + POLL_S < t0 + self.delay_s:
                await asyncio.sleep(POLL_S)
                async with self.sem:
                    now = set(await self.failure_reasons(key, spec, t0)) if self.latest.get(key) is spec else set()
                if self.latest.get(key) is not spec:
                    return
                early = bool(now & seen)        # a transient (one ErrImagePull) waits for the deadline or a repeat
                seen = now
        except aioredis.RedisError as e:
            log.warning("early-evidence check for %s/%s failed: %s; waiting for the timer", *key, e)
            return
        if early and self.latest.get(key) is spec:
            self._fire(key)

    def schedule(self, key: Key, delay: float) -> None:
        """(Re)start the per-workload debounce timer."""
        if t := self.timers.pop(key, None):
            t.cancel()
        self.timers[key] = asyncio.get_running_loop().call_later(delay, self._fire, key)

    def _fire(self, key: Key) -> None:
        if t := self.timers.pop(key, None):
            t.cancel()
        if (p := self.pollers.pop(key, None)) and p is not asyncio.current_task():
            p.cancel()                          # the assessment starts now; a late poller must not start another
        self._spawn(self.assess(key))

    def _spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    def _forget(self, key: Key) -> None:
        for t in (self.timers.pop(key, None), self.pollers.pop(key, None), self.trackers.pop(key, None)):
            if t:
                t.cancel()
        self.pending_promo.pop(key, None)
        self.latest.pop(key, None)
        self.seen_hash.pop(key, None)
        self.changed_at.pop(key, None)
        self.rolled_out.pop(key, None)
        self.stalled.pop(key, None)

    async def _delete_keys(self, key: Key) -> None:
        try:
            await self.redis.delete(key_spec(*key), key_baseline(*key))
        except aioredis.RedisError as e:
            log.warning("could not clean up keys for deleted %s/%s: %s", *key, e)

    # ── assessment ───────────────────────────────────────────────────────────
    async def assess(self, key: Key) -> None:
        async with self.sem:
            spec = self.latest.get(key)
            if spec is None:                    # deleted meanwhile
                return
            t0 = self.changed_at.get(key, time.time() - self.delay_s)   # read with the spec, before any await
            h = self._hash(key, spec)
            if self.assessing.get(key) == h:    # same spec already in flight
                return
            self.assessing[key] = h
            try:
                outcome = await self._assess(key, spec, t0)
            except aioredis.RedisError as e:
                log.warning("redis error assessing %s/%s: %s; retrying in %.0fs", *key, e, RETRY_DELAY_S)
                outcome = "retry"
            except Exception:
                log.exception("assessment of %s/%s failed", *key)
                outcome = "error"
            finally:
                self.assessing.pop(key, None)
            ASSESSMENTS.labels(outcome).inc()
            if outcome == "retry" and key in self.latest and key not in self.timers:
                self.schedule(key, RETRY_DELAY_S)

    async def _assess(self, key: Key, spec: dict, t0: float) -> str:
        ns, name = key
        blob = json.dumps(spec, sort_keys=True)   # API-shaped: fusion restores baseline["template"] verbatim
        raw = await self.redis.get(key_spec(ns, name))
        if raw is None:                         # first sight: remember, don't assess (nothing to diff against)
            await self.redis.mset({key_spec(ns, name): blob, key_baseline(ns, name): blob})
            log.info("first sight of %s/%s: current spec ASSUMED GOOD and stored as the AUTO_PATCH "
                     "baseline; drift that predates the agent is not detected", ns, name)
            return "first_sight"
        # Stored specs are API-shaped, or canonical (older agents): both canonicalise to the same hash / diff.
        old, new = self._view(key, json.loads(raw)), self._view(key, spec)
        if spec_hash(old) == spec_hash(new):
            return "unchanged"
        base_raw = await self.redis.get(key_baseline(ns, name))
        base = self._view(key, json.loads(base_raw)) if base_raw is not None else None
        if base is not None and spec_hash(base) == spec_hash(new):
            # Back to the known-good spec (an AUTO_PATCH restore or a manual rollback): not drift.
            await self.redis.set(key_spec(ns, name), blob)
            log.info("%s/%s returned to its baseline spec; nothing to assess", ns, name)
            return "baseline_restored"

        window = await fetch_window(self.session, PROMETHEUS_URL, ns, name, t0, min(time.time(), t0 + self.delay_s))
        features = health_features(old, new, window)
        pred = await predict(self.session, "health", features)
        # No metric at all (Prometheus down, app without metrics): the model only saw the spec diff, so its
        # verdict is not actionable. failure_reasons (rules) are unaffected.
        no_metrics = all(features[k] is None for k in METRIC_FEATURES)
        if pred is None:                        # no fake assessment; spec stays unsaved → re-assessed
            log.warning("inference unavailable; %s/%s will be re-assessed in %.0fs", ns, name, RETRY_DELAY_S)
            return "retry"

        # Posture is judged against the baseline, so drift left unfixed (observe mode) stays a violation
        # on every later change instead of disappearing from the old→new diff.
        base = base if base is not None else old
        reasons = sorted(set(await self.failure_reasons(key, spec, t0)) | set(policy_violations(base, new)))
        event = HealthEvent(
            event_id=new_event_id("health"), namespace=ns, workload=name,
            model_version=pred.model_version, label=pred.label, risk=pred.risk,
            uncertain=pred.uncertain or no_metrics, probabilities=pred.probabilities, top_factors=pred.top_factors,
            features=features, spec_changed=True, changed_fields=changed_paths(canonical_spec(old), canonical_spec(new)),
            has_baseline=base_raw is not None, failure_reasons=reasons,
        )
        await publish_event(self.redis, STREAM_HEALTH, "health", event)
        await self.redis.set(key_spec(ns, name), blob)        # only after a successful publish
        # Known-good needs evidence and no rule hit: a spec that failed its rollout or violates posture
        # is never promoted, whatever the model says (no extra inference call either).
        vs_base = None
        if not reasons and not no_metrics:
            # Promote against the baseline, not the previous spec: a harmless change stacked on
            # unfixed drift must never become the AUTO_PATCH restore target.
            vs_base = pred if spec_hash(base) == spec_hash(old) else await predict(
                self.session, "health", health_features(base, new, window))
        if vs_base is not None and vs_base.label == "benign" and not vs_base.uncertain:
            if self.rolled_out.get(key, False):
                await self.redis.set(key_baseline(ns, name), blob)
            else:                               # slow rollout: promote when the watch reports it complete
                self.pending_promo[key] = (self._hash(key, spec), blob)
        if self.latest.get(key) is spec and not (self.rolled_out.get(key) and not self.stalled.get(key)):
            self.trackers[key] = asyncio.create_task(self._track(key, spec, t0, event))
        log.info("assessed %s/%s: %s risk=%.2f uncertain=%s changed=%s failures=%s", ns, name, pred.label,
                 pred.risk, pred.uncertain, event.changed_fields[:5], event.failure_reasons)
        return "published"

    async def _track(self, key: Key, spec: dict, t0: float, event: HealthEvent) -> None:
        """After the first event, a rollout can still fail (never Ready, ProgressDeadlineExceeded): publish one
        follow-up for the same spec whenever new failure reasons are confirmed on two consecutive polls. Ends when
        the rollout completes, the spec is superseded or deleted, or the progress deadline plus a margin passes."""
        end = t0 + (spec.get("progressDeadlineSeconds") or DEFAULT_PROGRESS_DEADLINE_S) + TRACK_MARGIN_S
        reported, seen = set(event.failure_reasons), set()
        try:
            while self.latest.get(key) is spec and time.time() < end:
                await asyncio.sleep(POLL_S)
                if self.rolled_out.get(key) and not self.stalled.get(key):
                    return
                async with self.sem:
                    now = set(await self.failure_reasons(key, spec, t0)) if self.latest.get(key) is spec else set()
                new = (now & seen) - reported
                seen = now
                if not new or self.latest.get(key) is not spec:
                    continue
                self.pending_promo.pop(key, None)       # failing: never promote
                follow = event.model_copy(update={"event_id": new_event_id("health"), "timestamp_ms": now_ms(),
                                                  "failure_reasons": sorted(reported | new)})
                try:
                    await publish_event(self.redis, STREAM_HEALTH, "health", follow)
                except aioredis.RedisError as e:
                    log.warning("follow-up for %s/%s not published: %s; retrying", *key, e)
                    continue
                reported |= new
                log.info("follow-up for %s/%s: %s", *key, follow.failure_reasons)
        finally:
            if self.trackers.get(key) is asyncio.current_task():
                self.trackers.pop(key)

    async def _promote(self, key: Key, h: str, blob: str) -> None:
        """A rollout that finished after its assessment: the benign verdict can now become the baseline."""
        try:
            if await self.redis.get(key_spec(*key)) == blob and self._hash(key, self.latest.get(key) or {}) == h:
                await self.redis.set(key_baseline(*key), blob)
                log.info("%s/%s rollout completed; spec promoted to baseline", *key)
        except aioredis.RedisError as e:
            log.warning("could not promote %s/%s to baseline: %s", *key, e)

    async def failure_reasons(self, key: Key, spec: dict, since_s: float) -> list[str]:
        """Authoritative failed-rollout evidence for the new spec; a pod-listing error only loses pod evidence."""
        out = {"ProgressDeadlineExceeded"} if self.stalled.get(key) else set()
        match = (spec.get("selector") or {}).get("matchLabels") or {}
        if self.core is not None and match:
            try:
                resp = await self.core.list_namespaced_pod(
                    key[0], label_selector=",".join(f"{k}={v}" for k, v in match.items()),
                    _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
                pods = [p for p in json.loads(await resp.read())["items"] if owned_by(p, key[1])]
                out |= pod_failure_reasons(pods, since_s)
            except (ApiException, aiohttp.ClientError, TimeoutError, ValueError, KeyError) as e:
                log.warning("pod listing for %s/%s failed (%s); no pod failure evidence", *key, getattr(e, "status", e))
        return sorted(out)

    # ── watch loop ───────────────────────────────────────────────────────────
    async def watch_loop(self, apps: client.AppsV1Api, namespace: str | None) -> None:
        scope = namespace or "*"
        rv: str | None = None
        backoff = 1.0
        self.alive[scope] = time.monotonic()
        while True:
            try:
                if namespace:
                    fn, args = apps.list_namespaced_deployment, (namespace,)
                else:
                    fn, args = apps.list_deployment_for_all_namespaces, ()
                if rv is None:                  # start / 410: full list, then watch from its resourceVersion
                    rv = await self.relist(fn, args, namespace)
                    self.alive[scope] = time.monotonic()
                async with watch.Watch() as w:
                    async for ev in w.stream(fn, *args, resource_version=rv, timeout_seconds=WATCH_TIMEOUT_S,
                                             allow_watch_bookmarks=True):
                        self.alive[scope] = time.monotonic()
                        rv = w.resource_version
                        if ev["type"] in ("ADDED", "MODIFIED", "DELETED"):
                            self.on_event(ev["type"], ev["raw_object"])
                self.alive[scope] = time.monotonic()    # clean server-side timeout: still healthy
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                WATCH_ERRORS.inc()
                if isinstance(e, ApiException) and e.status == 410:
                    rv = None                   # history expired: re-list (as ADDED events)
                log.warning("deployment watch (%s) failed: %r; retrying in %.0fs", scope, e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    async def relist(self, fn, args: tuple, namespace: str | None) -> str:
        """Replay every Deployment as ADDED (seen_hash / stored spec make that idempotent), then drop the state of
        Deployments deleted while no watch was open (a missed DELETE): in memory and their Redis spec/baseline."""
        resp = await fn(*args, _preload_content=False, _request_timeout=KUBE_TIMEOUT_S * 6)
        body = json.loads(await resp.read())
        live: set[Key] = set()
        for dep in body.get("items") or []:
            meta = dep.get("metadata") or {}
            live.add((meta.get("namespace", ""), meta.get("name", "")))
            self.on_event("ADDED", dep)
        for key in [k for k in self.seen_hash if k not in live and namespace in (None, k[0])]:
            self._forget(key)
        try:
            stale = []
            for key_fn in (key_spec, key_baseline):
                async for k in self.redis.scan_iter(match=key_fn(namespace or "*", "*"), count=500):
                    ns, name = k.split(":")[-2:]     # namespace and name are DNS names: no ':'
                    if (ns, name) not in live:
                        stale.append(k)
            if stale:
                await self.redis.delete(*stale)
                log.info("removed %d spec/baseline keys of Deployments deleted while unwatched", len(stale))
        except aioredis.RedisError as e:
            log.warning("could not reconcile stored specs after a re-list: %s", e)
        return body["metadata"]["resourceVersion"]

    async def hpa_loop(self, autoscaling: client.AutoscalingV2Api, namespace: str | None) -> None:
        """Keep `hpa` current: Deployments whose spec.replicas an HPA owns. A failure keeps the last known set."""
        while True:                             # main() did the first listing
            await asyncio.sleep(HPA_POLL_S)
            await self.refresh_hpas(autoscaling, namespace)

    async def refresh_hpas(self, autoscaling: client.AutoscalingV2Api, namespace: str | None) -> None:
        try:
            if namespace:
                resp = await autoscaling.list_namespaced_horizontal_pod_autoscaler(
                    namespace, _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
            else:
                resp = await autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces(
                    _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
            items = json.loads(await resp.read())["items"]
        except (ApiException, aiohttp.ClientError, TimeoutError, ValueError, KeyError) as e:
            log.warning("HPA listing (%s) failed (%s); replicas changes count as drift for unknown HPAs",
                        namespace or "*", getattr(e, "status", e))
            return
        targets = set()
        for h in items:
            ref = (h.get("spec") or {}).get("scaleTargetRef") or {}
            if ref.get("kind") == "Deployment":
                targets.add(((h.get("metadata") or {}).get("namespace", ""), ref.get("name", "")))
        self.hpa[namespace or "*"] = targets

    def healthy(self) -> bool:
        now = time.monotonic()
        return bool(self.alive) and all(now - t < STALE_AFTER_S for t in self.alive.values())


async def main() -> None:
    setup_logging()
    await load_kube_config()
    redis = await connect_redis()
    async with aiohttp.ClientSession() as session, client.ApiClient() as api:
        agent = HealthAgent(redis, session, core=client.CoreV1Api(api))
        runner = await start_http(agent.healthy)
        scopes = env_list("WATCH_NAMESPACES") or [None]
        apps, autoscaling = client.AppsV1Api(api), client.AutoscalingV2Api(api)
        log.info("health agent watching %s (assess delay %.0fs)", scopes, agent.delay_s)
        for ns in scopes:                       # before the first list: an HPA's scaling is never assessed as drift
            await agent.refresh_hpas(autoscaling, ns)
        try:
            await asyncio.gather(*(agent.watch_loop(apps, ns) for ns in scopes),
                                 *(agent.hpa_loop(autoscaling, ns) for ns in scopes))
        finally:
            await runner.cleanup()
            await redis.aclose()


if __name__ == "__main__":
    run(main)
