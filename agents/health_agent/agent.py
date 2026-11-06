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
)
from kubeheal.features.health import (
    canonical_spec,
    changed_paths,
    health_features,
    spec_diff_features,
    spec_hash,
)

log = logging.getLogger("kubeheal.health")

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus-operated.monitoring.svc:9090").rstrip("/")
# Assess this long after a change, on the metric window [change, change + delay]. drift_lab uses the same
# delay and fetch_window, so training windows are exactly the windows the agent scores.
ASSESS_DELAY_S = float(os.environ.get("ASSESS_DELAY_S", "120"))
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

ASSESSMENTS = Counter("kubeheal_health_assessments_total", "Health assessments by outcome", ["outcome"])
WATCH_ERRORS = Counter("kubeheal_health_watch_errors_total", "Deployment watch errors")

Key = tuple[str, str]   # (namespace, deployment)


def rollout_complete(dep: dict) -> bool:
    """The controller has rolled the current spec out and every desired replica is available.

    Zero desired replicas is never "complete": nothing serving is no evidence the spec is good.
    """
    meta, spec, st = dep.get("metadata") or {}, dep.get("spec") or {}, dep.get("status") or {}
    want = spec.get("replicas", 1)
    return (want > 0 and st.get("observedGeneration", 0) >= meta.get("generation", 1)
            and (st.get("updatedReplicas") or 0) == want and (st.get("availableReplicas") or 0) == want)


def progress_deadline_exceeded(dep: dict) -> bool:
    """The controller gave up on the current generation's rollout (Progressing=False/ProgressDeadlineExceeded)."""
    meta, st = dep.get("metadata") or {}, dep.get("status") or {}
    return st.get("observedGeneration", 0) >= meta.get("generation", 1) and any(
        c.get("type") == "Progressing" and c.get("status") == "False" and c.get("reason") == "ProgressDeadlineExceeded"
        for c in st.get("conditions") or [])


def pod_failure_reasons(pods: list[dict], since_s: float) -> set[str]:
    """Failure reasons of pods created after `since_s` (epoch s): bad waiting state or an OOM kill."""
    out: set[str] = set()
    for p in pods:
        created = (p.get("metadata") or {}).get("creationTimestamp")
        if not created or datetime.fromisoformat(created).timestamp() < since_s - CREATED_SLACK_S:
            continue
        st = p.get("status") or {}
        for cs in (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or []):
            if (r := ((cs.get("state") or {}).get("waiting") or {}).get("reason")) in WAITING_FAILURES:
                out.add(r)
            if ((cs.get("lastState") or {}).get("terminated") or {}).get("reason") == "OOMKilled":
                out.add("OOMKilled")
    return out


def policy_violations(base: dict, spec: dict) -> list[str]:
    """Posture violations `spec` introduces relative to `base` (the restore target), as failure_reasons."""
    f = spec_diff_features(base, spec)
    return [POLICY_REASON_PREFIX + k for k in POSTURE_FEATURES if f[k]]


class HealthAgent:
    def __init__(self, redis: aioredis.Redis, session: aiohttp.ClientSession,
                 delay_s: float = ASSESS_DELAY_S, protected: frozenset[str] | None = None,
                 core: client.CoreV1Api | None = None):
        self.redis = redis
        self.session = session
        self.core = core                            # None: no pod evidence (failure_reasons from the Deployment only)
        self.delay_s = delay_s
        self.protected = protected_namespaces() if protected is None else protected
        self.latest: dict[Key, dict] = {}         # newest canonical spec seen per workload
        self.seen_hash: dict[Key, str] = {}
        self.changed_at: dict[Key, float] = {}      # epoch s when the pending spec was first seen
        self.rolled_out: dict[Key, bool] = {}       # latest watch status: rollout of the current spec done
        self.stalled: dict[Key, bool] = {}          # latest watch status: ProgressDeadlineExceeded
        self.timers: dict[Key, asyncio.TimerHandle] = {}
        self.tasks: set[asyncio.Task] = set()
        self.sem = asyncio.Semaphore(MAX_CONCURRENT)
        self.alive: dict[str, float] = {}           # watch scope → last loop activity (monotonic)

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
        spec = canonical_spec(dep)
        h = spec_hash(spec)
        if self.seen_hash.get(key) == h:      # status-only update: nothing to assess
            return
        self.seen_hash[key] = h
        self.latest[key] = spec
        self.changed_at[key] = time.time()
        self.schedule(key, self.delay_s)

    def schedule(self, key: Key, delay: float) -> None:
        """(Re)start the per-workload debounce timer."""
        if t := self.timers.pop(key, None):
            t.cancel()
        self.timers[key] = asyncio.get_running_loop().call_later(delay, self._fire, key)

    def _fire(self, key: Key) -> None:
        self.timers.pop(key, None)
        self._spawn(self.assess(key))

    def _spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    def _forget(self, key: Key) -> None:
        if t := self.timers.pop(key, None):
            t.cancel()
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
            try:
                outcome = await self._assess(key, spec)
            except aioredis.RedisError as e:
                log.warning("redis error assessing %s/%s: %s; retrying in %.0fs", *key, e, RETRY_DELAY_S)
                outcome = "retry"
            except Exception:
                log.exception("assessment of %s/%s failed", *key)
                outcome = "error"
            ASSESSMENTS.labels(outcome).inc()
            if outcome == "retry" and key in self.latest and key not in self.timers:
                self.schedule(key, RETRY_DELAY_S)

    async def _assess(self, key: Key, spec: dict) -> str:
        ns, name = key
        raw = await self.redis.get(key_spec(ns, name))
        if raw is None:                         # first sight: remember, don't assess (nothing to diff against)
            blob = json.dumps(spec, sort_keys=True)
            await self.redis.mset({key_spec(ns, name): blob, key_baseline(ns, name): blob})
            log.info("first sight of %s/%s: current spec ASSUMED GOOD and stored as the AUTO_PATCH "
                     "baseline; drift that predates the agent is not detected", ns, name)
            return "first_sight"
        old = json.loads(raw)
        if spec_hash(old) == spec_hash(spec):
            return "unchanged"
        base_raw = await self.redis.get(key_baseline(ns, name))
        if base_raw is not None and spec_hash(json.loads(base_raw)) == spec_hash(spec):
            # Back to the known-good spec (an AUTO_PATCH restore or a manual rollback): not drift.
            await self.redis.set(key_spec(ns, name), json.dumps(spec, sort_keys=True))
            log.info("%s/%s returned to its baseline spec; nothing to assess", ns, name)
            return "baseline_restored"

        t0 = self.changed_at.get(key, time.time() - self.delay_s)
        window = await fetch_window(self.session, PROMETHEUS_URL, ns, name, t0, t0 + self.delay_s)
        features = health_features(old, spec, window)
        pred = await predict(self.session, "health", features)
        if pred is None:                        # no fake assessment; spec stays unsaved → re-assessed
            log.warning("inference unavailable; %s/%s will be re-assessed in %.0fs", ns, name, RETRY_DELAY_S)
            return "retry"

        # Posture is judged against the baseline, so drift left unfixed (observe mode) stays a violation
        # on every later change instead of disappearing from the old→new diff.
        base = json.loads(base_raw) if base_raw else old
        reasons = sorted(set(await self.failure_reasons(key, spec, t0)) | set(policy_violations(base, spec)))
        event = HealthEvent(
            event_id=new_event_id("health"), namespace=ns, workload=name,
            model_version=pred.model_version, label=pred.label, risk=pred.risk,
            uncertain=pred.uncertain, probabilities=pred.probabilities, top_factors=pred.top_factors,
            features=features, spec_changed=True, changed_fields=changed_paths(old, spec),
            has_baseline=base_raw is not None, failure_reasons=reasons,
        )
        await publish_event(self.redis, STREAM_HEALTH, "health", event)
        blob = json.dumps(spec, sort_keys=True)
        await self.redis.set(key_spec(ns, name), blob)        # only after a successful publish
        # Known-good needs evidence and no rule hit: a spec that failed its rollout or violates posture
        # is never promoted, whatever the model says (no extra inference call either).
        if reasons or not self.rolled_out.get(key, False):
            vs_base = None
        else:
            # Promote against the baseline, not the previous spec: a harmless change stacked on
            # unfixed drift must never become the AUTO_PATCH restore target.
            vs_base = pred if spec_hash(base) == spec_hash(old) else await predict(
                self.session, "health", health_features(base, spec, window))
        if vs_base is not None and vs_base.label == "benign" and not vs_base.uncertain:
            await self.redis.set(key_baseline(ns, name), blob)
        log.info("assessed %s/%s: %s risk=%.2f uncertain=%s changed=%s failures=%s", ns, name, pred.label,
                 pred.risk, pred.uncertain, event.changed_fields[:5], event.failure_reasons)
        return "published"

    async def failure_reasons(self, key: Key, spec: dict, since_s: float) -> list[str]:
        """Authoritative failed-rollout evidence for the new spec; a pod-listing error only loses pod evidence."""
        out = {"ProgressDeadlineExceeded"} if self.stalled.get(key) else set()
        match = (spec.get("selector") or {}).get("matchLabels") or {}
        if self.core is not None and match:
            try:
                resp = await self.core.list_namespaced_pod(
                    key[0], label_selector=",".join(f"{k}={v}" for k, v in match.items()),
                    _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
                out |= pod_failure_reasons(json.loads(await resp.read())["items"], since_s)
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
                async with watch.Watch() as w:
                    # rv=None replays every Deployment as ADDED; seen_hash/stored spec make that idempotent.
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
        apps = client.AppsV1Api(api)
        log.info("health agent watching %s (assess delay %.0fs)", scopes, agent.delay_s)
        try:
            await asyncio.gather(*(agent.watch_loop(apps, ns) for ns in scopes))
        finally:
            await runner.cleanup()
            await redis.aclose()


if __name__ == "__main__":
    run(main)
