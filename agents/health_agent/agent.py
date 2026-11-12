"""
KubeHeal Health Agent (V5-D4): watch Deployments, assess real spec changes, publish health events.
================================================================================================
Ported from the teammate's "v5" Health Agent and fitted into our architecture (Watch API, golden baseline,
Redis stream events, OBSERVE sampling, shared ApiClient). The agent never writes to Kubernetes: the Executor is
the only writer (tests/test_no_writes_outside_executor.py).

Flow
  watch      full list of the labelled Deployments, then a watch from the list's resourceVersion; a 410 Gone
             (or any other failure) re-lists. WATCH_NAMESPACES (default prod,staging,dev; "*" = cluster wide)
             scopes the Deployment lists and watches, the HPA lists and the pod lists.
  change     only a CHANGED canonical spec hash counts (status-only and metadata-only updates do nothing).
             The hash covers the drift view of the spec: `replicas` is left out, scaling is not drift.
  debounce   per workload. The first pending change sets a deadline of ASSESS_DELAY_S (chosen, not measured).
             Later changes replace the pending spec but never move the deadline. Every POLL_S the pending
             spec is checked for hard evidence (a posture violation, or failure reasons seen on two
             consecutive polls); with evidence the assessment starts at once.
  assess     spec diff against the GOLDEN baseline, a Prometheus window, `health_features`, the inference
             service. At most MAX_CONCURRENT_ASSESSMENTS run at the same time.
  publish    one event per assessed spec on kubeheal.health.events, then follow-up events when failure
             reasons appear late (bounded by FOLLOWUP_WINDOW_S).
  fail closed  no answer from the inference service means NO score: the model_unavailable notice (or, when
             Kubernetes itself shows failure reasons, a rule-evidence event that says model_unavailable). A spec
             that cannot be read (PostureError) is a failed assessment and publishes a no-score notice with the
             error for a human; it is never a model verdict or rule-evidence event.
  OBSERVE    a Fusion OBSERVE request (bounded, in Redis) triples the sampling of a drifted workload. Each
             sample does a LIVE GET of the Deployment, so it scores the current spec, never the object that
             arrived with an old watch event.

  promote    (V5-D5, owner decision D3) once a spec is judged benign AND certain (prediction set exactly
             {benign}), its rollout is complete, no failure reason and no posture violation exists and it
             differs from the golden baseline, it replaces the golden baseline: AUTOMATICALLY in dev and
             staging (needs a ledger; HEALTH_BASELINE_PROMOTION=off disables it), as a stored CANDIDATE that
             waits for approval in prod and in an unknown tier. The ledger entry that keeps the previous
             baseline is written BEFORE the overwrite; a failed ledger write means no promotion (fail
             closed). Never while the spec is superseded or a newer assessment is in flight; a candidate is
             dropped when the live spec changes again. Also refused (no promotion, no candidate): any metric
             series missing, failure evidence that could not be read, a golden baseline that moved since the
             assessment, a veto (an earlier non-benign or uncertain verdict for the same spec), a cool-off after
             such an event, a pending Executor rollback, a held incident lock, an open Fusion incident, a fresh
             Security score at or above 0.4, and (optional) a spec younger than HEALTH_PROMOTION_MIN_SOAK_S.
             Environment: HEALTH_BASELINE_PROMOTION (on|off, default on), HEALTH_PROMOTION_COOLOFF_S (default 300,
             chosen), HEALTH_PROMOTION_MIN_SOAK_S (default 0 = off, chosen), HEALTH_PROMOTION_REQUIRE_SECURITY
             (default off: a missing or stale Security score does not block; on: it blocks), SECURITY_FRESH_S
             (default 30, same as Fusion).
             Kill switch: the golden record is overwritten only in mode enforce. In mode test, or when the mode is
             unknown (the default: no ModeWatcher is started unless HEALTH_MODE_WATCH=on) an automatic promotion
             writes a baseline_promotion_dry_run ledger entry only; a prod candidate is still stored.

The golden baseline (agents/health_agent/baseline.py) is written once with SET NX on first sight and is
overwritten only by a promotion (auto in dev and staging, approved in prod) and by scripts/baseline_tool.py. The
agent never writes to Kubernetes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import kubernetes_asyncio
import redis.asyncio as aioredis
from kubernetes_asyncio import client, config, watch
from kubernetes_asyncio.client.exceptions import ApiException
from kubernetes_asyncio.config import load_incluster_config
from prometheus_client import Counter

from agents.common.killswitch import ModeWatcher
from agents.common.ledger import Ledger, ledger_from_env
from agents.common.metrics import KubeHealMetrics
from agents.common.tiers import namespace_tier as _namespace_tier
from agents.common.sampling import sampling_factor, scaled_interval
from agents.health_agent import baseline
from agents.health_agent import inference_client
from agents.health_agent.failure_reasons import failure_reasons, progress_deadline_exceeded, rollout_complete
from agents.health_agent.metric_window import fetch_window, missing_metrics
from kubeheal.contracts import Prediction
from kubeheal.features.health import (
    METRIC_FEATURES, canonical_spec, changed_paths, health_features, spec_hash,
)
from kubeheal.posture import PostureError, policy_violations


def namespace_tier(namespace: str) -> str:
    """See agents/common/tiers.py: NAMESPACE_TIER_MAP first, then the name rule; otherwise "unknown"."""
    return _namespace_tier(namespace)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
METRICS = KubeHealMetrics()
ASSESSMENTS = Counter("kubeheal_health_assessments_total", "Health assessments by outcome", ["outcome"],
                      registry=METRICS.registry)
PROMOTIONS = Counter("kubeheal_health_baseline_promotions_total", "Baseline promotion attempts by outcome",
                     ["outcome"], registry=METRICS.registry)
WATCH_ERRORS = Counter("kubeheal_health_watch_errors_total", "Deployment watch errors",
                       registry=METRICS.registry)

HEALTH_STREAM = "kubeheal.health.events"
WATCH_LABEL_SELECTOR = "kubeheal.io/watch=true"
DEFAULT_WATCH_NAMESPACES = ("prod", "staging", "dev")
ASSESSED_PREFIX = "kubeheal:healthagent:assessed"   # last assessed spec hash per workload (restart replays)
PUBLISH_HEALTH_EVENT_LUA = """
-- kubeheal:publish_health_event
if redis.call('EXISTS', KEYS[3]) == 1 then
  return 0
end
redis.call('HSET', KEYS[2], unpack(ARGV))
redis.call('EXPIRE', KEYS[2], 86400)
local entry_id = redis.call('XADD', KEYS[1], '*', unpack(ARGV))
redis.call('SET', KEYS[3], entry_id, 'EX', 86400)
return 1
"""

# All timings below are chosen defaults, not measured, and configurable where an env name is given.
DEFAULT_ASSESS_DELAY_S = 60.0     # ASSESS_DELAY_S: latest assessment time after the first pending change
DEFAULT_MAX_CONCURRENT = 8        # MAX_CONCURRENT_ASSESSMENTS
HEALTH_OBSERVE_BASE_S = 60.0      # HEALTH_OBSERVE_BASE_S: base interval of OBSERVE samples (divided by the factor)
POLL_S = 2.0                      # early-evidence and follow-up polling period
TICK_S = 1.0                      # scheduler resolution
RETRY_DELAY_S = 60.0              # re-assess after an inference or Redis failure
WATCH_TIMEOUT_S = 300             # server-side watch timeout; the loop reconnects after it
WATCH_RETRY_MIN_S = 1.0            # chosen minimum interval between watch attempts (idle timeout, 410 Gone, normal stream end)
FIRST_SIGHT_RETRY_S = 5.0         # chosen: how soon a failed first look at a workload (Redis error) is retried
KUBE_TIMEOUT_S = 10               # one Kubernetes read (pod list, Deployment get, HPA list)
HPA_POLL_S = 30                   # re-list HorizontalPodAutoscalers this often
# Follow-up window after the first event: the Deployment's progress deadline (or its default) plus a margin;
# FOLLOWUP_WINDOW_S overrides the whole window.
DEFAULT_PROGRESS_DEADLINE_S = 600
FOLLOWUP_MARGIN_S = 60
DEFAULT_PROMOTION_COOLOFF_S = 300.0   # HEALTH_PROMOTION_COOLOFF_S: chosen, not measured
DEFAULT_SECURITY_FRESH_S = 30.0       # SECURITY_FRESH_S: same default as the Fusion Agent

Key = Tuple[str, str]   # (namespace, deployment)
_LEDGER_FROM_ENV = object()   # constructor default: build the ledger from LEDGER_BACKEND when that is set


def _positive_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0 or not math.isfinite(value):
        raise ValueError(f"{name} must be a positive finite number")
    return value


def _nonneg_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative number") from exc
    if value < 0 or not math.isfinite(value):
        raise ValueError(f"{name} must be a non-negative finite number")
    return value


def observe_base_s_from_env() -> float:
    return _positive_env("HEALTH_OBSERVE_BASE_S", HEALTH_OBSERVE_BASE_S)


def assess_delay_s_from_env() -> float:
    return _positive_env("ASSESS_DELAY_S", DEFAULT_ASSESS_DELAY_S)


def max_concurrent_from_env() -> int:
    return max(1, int(_positive_env("MAX_CONCURRENT_ASSESSMENTS", DEFAULT_MAX_CONCURRENT)))


def watch_namespaces_from_env() -> List[Optional[str]]:
    """Scopes to watch: a list of namespaces, None meaning cluster wide ("*")."""
    raw = os.environ.get("WATCH_NAMESPACES", "")
    names = [n.strip() for n in raw.split(",") if n.strip()] or list(DEFAULT_WATCH_NAMESPACES)
    return [None if n == "*" else n for n in names]


@dataclass
class Pending:
    """A changed spec waiting for its debounce deadline. One per workload."""
    spec: Dict
    dep: Dict
    hash: str
    t0_wall: float            # epoch s when the first still-pending change was seen
    deadline: float           # clock() time at which the assessment starts at the latest
    next_poll: float
    event_id: str = ""               # stable across retries of this assessment
    unavailable_event_id: str = ""   # stable no-score notice for the same pending spec
    seen: set = field(default_factory=set)       # failure reasons seen on the last poll
    posture_early: Optional[bool] = None
    polling: bool = False
    notified_unavailable: bool = False


@dataclass
class Tracked:
    """A published spec whose rollout is unfinished: watched for failure reasons that appear late."""
    hash: str
    t0_wall: float
    end: float                # clock() time at which following up stops
    next_poll: float
    payload: Dict
    reported: set
    seen: set = field(default_factory=set)
    polling: bool = False
    verdict: Optional[Dict] = None     # the assessment, kept so a promotion can follow once the rollout completes


class HealthAgent:
    """Kubernetes operator for the Health Agent."""

    def __init__(
        self,
        namespace: str = "kubeheal",
        redis_url: str = None,
        inference_url: str = None,
        prometheus_url: str = None,
        observe_base_s: Optional[float] = None,
        delay_s: Optional[float] = None,
        max_concurrent: Optional[int] = None,
        followup_window_s: Optional[float] = None,
        ledger: Any = _LEDGER_FROM_ENV,
        auto_promotion: Optional[bool] = None,
        cooloff_s: Optional[float] = None,
        min_soak_s: Optional[float] = None,
        require_security: Optional[bool] = None,
        security_fresh_s: Optional[float] = None,
        mode: Any = None,
        clock=time.monotonic,
        wall=time.time,
    ):
        self.namespace = namespace
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.inference_url = inference_url or inference_client.inference_url_from_env()
        self.inference_timeout_s = inference_client.timeout_from_env()
        self.prometheus_url = prometheus_url or os.environ.get(
            "PROMETHEUS_URL", "http://prometheus-operated.monitoring.svc.cluster.local:9090")

        self.redis: Optional[aioredis.Redis] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None
        self.autoscaling_api: Optional[client.AutoscalingV2Api] = None

        self.running = False
        self._watchers: List[Any] = []

        self.delay_s = delay_s if delay_s is not None else assess_delay_s_from_env()
        self.observe_base_s = (observe_base_s if observe_base_s is not None
                               else observe_base_s_from_env())
        self.max_concurrent = max_concurrent if max_concurrent is not None else max_concurrent_from_env()
        if followup_window_s is None and os.environ.get("FOLLOWUP_WINDOW_S"):
            followup_window_s = _positive_env("FOLLOWUP_WINDOW_S", 0.0)
        self.followup_window_s = followup_window_s     # None: the Deployment's progress deadline plus a margin
        # Baseline promotion (V5-D5). The ledger is injected (tests: in-memory) or built from the environment only when
        # LEDGER_BACKEND is set; without a ledger automatic promotion is off and prod candidates are still stored.
        self.ledger: Optional[Ledger] = self._ledger_from_env() if ledger is _LEDGER_FROM_ENV else ledger
        self.auto_promotion = (baseline.promotion_enabled_from_env() if auto_promotion is None
                               else bool(auto_promotion))
        self._promoting: set = set()                # workloads with a promotion in progress
        self.cooloff_s = cooloff_s if cooloff_s is not None else _positive_env(
            "HEALTH_PROMOTION_COOLOFF_S", DEFAULT_PROMOTION_COOLOFF_S)
        self.min_soak_s = min_soak_s if min_soak_s is not None else _nonneg_env("HEALTH_PROMOTION_MIN_SOAK_S", 0.0)
        self.require_security = (require_security if require_security is not None else
                                 os.environ.get("HEALTH_PROMOTION_REQUIRE_SECURITY", "").strip().lower()
                                 in ("1", "true", "on", "yes"))
        self.security_fresh_s = security_fresh_s if security_fresh_s is not None else _positive_env(
            "SECURITY_FRESH_S", DEFAULT_SECURITY_FRESH_S)
        # Kill-switch view (anything with mode_for(namespace) / dry_run_for(namespace), the ModeWatcher interface).
        # The default is a ModeWatcher that is never started: its mode is unknown, which is `test`, so an automatic
        # promotion only writes a dry-run ledger entry. HEALTH_MODE_WATCH=on starts it in start() (it needs the
        # kubeheal-mode ConfigMap read rule for the health-agent ServiceAccount); a test injects its own.
        self.mode = mode if mode is not None else ModeWatcher()
        self._mode_started = False
        self._dry_run_noted: Dict[Key, Tuple[str, str]] = {}   # (spec hash, golden digest) already written as dry run
        self._vetoed: Dict[Key, set] = {}           # spec hashes with a non-benign or uncertain verdict published
        self._cooloff_until: Dict[Key, float] = {}  # clock() time until which a promotion waits (Redis backs it up)
        # a promotion refused only because the soak time has not passed: key -> (hash, verdict, retry not before)
        self._promote_retry: Dict[Key, Tuple[str, Dict, float]] = {}
        self.clock = clock          # deadlines (monotonic)
        self.wall = wall            # epoch seconds: metric windows, pod creation times, event timestamps

        self.sem = asyncio.Semaphore(self.max_concurrent)
        self.latest_dep: Dict[Key, Dict] = {}       # newest API-shaped Deployment seen (status included)
        self.seen_hash: Dict[Key, str] = {}         # last seen spec hash: only a changed hash is a change
        # first look at a workload failed (Redis error): key -> (deployment, spec, hash, retry not before). A quiet
        # drifted workload produces no further event, so the scheduler retries it; a newer event supersedes it.
        self._first_sight_retry: Dict[Key, Tuple[Dict, Dict, str, float]] = {}
        # Counts the spec changes seen per workload. It is part of the OBSERVE no-score notice id, so a spec that
        # flaps A, B, A during an outage is told to a human again instead of being absorbed by the 24 h marker.
        self._spec_epoch: Dict[Key, int] = {}
        self.pending: Dict[Key, Pending] = {}
        self.tracking: Dict[Key, Tracked] = {}
        self.assessing: Dict[Key, str] = {}         # workload -> spec hash being assessed now
        # OBSERVE: workloads whose spec differs from the golden baseline.
        self._drifted: Dict[Key, Dict[str, Any]] = {}
        self.hpa: Dict[str, set] = {}               # watch scope -> Deployments an HPA scales
        self.tasks: set = set()
        self._scheduler_task: Optional[asyncio.Task] = None
        self._seq = 0
        # One shared ApiClient: the typed APIs and the serializer all use it; closed in stop(). Created lazily
        # because constructing an ApiClient opens an aiohttp session.
        self._serializer: Optional[client.ApiClient] = None

        # Injection points (tests replace them; production uses the real ones).
        self._fetch_window = fetch_window
        self._predict = inference_client.predict_health

        self.baseline_configmap = "kubeheal-baselines"

    @staticmethod
    def _ledger_from_env() -> Optional[Ledger]:
        if not os.environ.get("LEDGER_BACKEND"):
            return None
        try:
            return ledger_from_env()
        except Exception as e:
            logger.error(f"ledger configuration is invalid ({e}); baseline promotion has no ledger")
            return None

    def log_promotion_config(self) -> None:
        if self.ledger is None and os.environ.get("LEDGER_BACKEND"):
            logger.error("baseline promotion: automatic promotion in dev and staging is DISABLED, LEDGER_BACKEND is "
                         "set but the ledger could not be built (see the earlier error: MinIO credentials, or the "
                         "minio package missing from the image); prod candidates are still stored")
        elif self.ledger is None:
            logger.warning("baseline promotion: automatic promotion in dev and staging is DISABLED, no ledger is "
                           "configured (set LEDGER_BACKEND, MINIO_ENDPOINT, MINIO_BUCKET and the MinIO "
                           "credentials); prod promotion candidates are still stored, but approving one needs "
                           "the ledger")
        elif not self.auto_promotion:
            logger.warning("baseline promotion: automatic promotion in dev and staging is DISABLED "
                           "(HEALTH_BASELINE_PROMOTION is off); prod promotion candidates are still stored")
        else:
            logger.info("baseline promotion: automatic in dev and staging, candidates in prod and unknown tiers")
            logger.info("baseline promotion: the golden record is overwritten only in kill-switch mode enforce; in "
                        "mode test or when the mode is unreadable an automatic promotion writes a dry-run ledger "
                        "entry only")
            if os.environ.get("HEALTH_MODE_WATCH", "").strip().lower() not in ("1", "true", "on", "yes"):
                logger.warning("baseline promotion: HEALTH_MODE_WATCH is off, so the kill-switch mode is unknown and "
                               "treated as test: automatic promotion stays a dry run")
            if os.environ.get("LEDGER_BACKEND", "").strip().lower() == "memory":
                logger.warning("baseline promotion: the ledger is in memory (LEDGER_BACKEND=memory): promotion "
                               "history is lost on restart")

    # ── lifecycle ────────────────────────────────────────────────────────────
    async def start(self) -> None:
        logger.info("Starting Health Agent (V5-D4)...")
        logger.info(f"Redis URL: {self.redis_url}")
        logger.info(f"Inference URL: {self.inference_url}")
        logger.info(f"Prometheus URL: {self.prometheus_url}")
        self.log_promotion_config()

        try:
            load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes config")
        except kubernetes_asyncio.config.ConfigException:
            try:
                await config.load_kube_config()
                logger.info("Loaded kubeconfig")
            except Exception as e2:
                logger.error(f"Failed to load kubeconfig: {e2}")
                raise

        if self._serializer is None:
            self._serializer = client.ApiClient()
        self.core_api = client.CoreV1Api(self._serializer)
        self.apps_api = client.AppsV1Api(self._serializer)
        self.networking_api = client.NetworkingV1Api(self._serializer)
        self.autoscaling_api = client.AutoscalingV2Api(self._serializer)
        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
        self.session = aiohttp.ClientSession()
        if os.environ.get("HEALTH_MODE_WATCH", "").strip().lower() in ("1", "true", "on", "yes") \
                and hasattr(self.mode, "start"):
            try:
                await self.mode.start(self.core_api)       # read-only: kubeheal-mode ConfigMap and namespace labels
                self._mode_started = True
            except Exception as e:
                logger.warning(f"kill switch watcher not started ({e}); mode stays 'test'")

        scopes = watch_namespaces_from_env()
        logger.info(f"Health Agent watching {[s or '*' for s in scopes]} "
                    f"(assess delay {self.delay_s}s, at most {self.max_concurrent} concurrent)")
        for scope in scopes:   # before the first list, so HPA ownership is known
            await self.refresh_hpas(scope)

        self.running = True
        self._scheduler_task = asyncio.create_task(self.scheduler_loop())
        await asyncio.gather(*(self.watch_loop(s) for s in scopes), *(self.hpa_loop(s) for s in scopes))

    async def stop(self) -> None:
        logger.info("Stopping Health Agent...")
        self.running = False
        for w in list(self._watchers):
            try:
                w.stop()
            except Exception:
                pass

        if self._scheduler_task:
            task = self._scheduler_task
            self._scheduler_task = None
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                # Swallow only the task's own cancellation. If this coroutine itself is being
                # cancelled, re-raise so the caller's cancellation is not lost.
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    raise
            except Exception:
                logger.exception("Health scheduler task ended with an error")

        for t in list(self.tasks):
            t.cancel()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)

        if self._mode_started:
            self._mode_started = False
            try:
                await self.mode.stop()
            except Exception as e:
                logger.debug(f"mode watcher stop failed: {e}")
        if self.session is not None:
            session, self.session = self.session, None
            await session.close()
        if self._serializer is not None:
            serializer, self._serializer = self._serializer, None
            await serializer.close()
        if self.redis:
            await self.redis.aclose()
        logger.info("Health Agent stopped")

    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)
        return t

    async def drain(self) -> None:
        """Wait for every spawned task (tests)."""
        while self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)

    # ── spec forms and hashing ───────────────────────────────────────────────
    def _spec_json(self, deployment) -> Dict:
        """Deployment spec as camelCase JSON (what kubectl and the patch API use)."""
        if not getattr(deployment, "spec", None):
            return {}
        if self._serializer is None:
            self._serializer = client.ApiClient()
        return self._serializer.sanitize_for_serialization(deployment.spec)

    def _dep_json(self, deployment) -> Dict:
        """One API-shaped dict per Deployment, metadata and status included, in ONE normal form: the output of
        the shared serializer on the client's model object. Golden baselines and the Executor's live view use
        that form (it drops null values such as the pod template's `creationTimestamp: null` and fields the
        client does not model), so a raw JSON dict (list item, live GET) is first deserialized into the model."""
        if self._serializer is None:
            self._serializer = client.ApiClient()
        if isinstance(deployment, dict):
            deployment = self._serializer.deserialize(SimpleNamespace(data=json.dumps(deployment)), "V1Deployment")
        return self._serializer.sanitize_for_serialization(deployment) or {}

    @staticmethod
    def _hash(spec: Dict) -> str:
        """Change detector: the canonical hash of the drift view (no `replicas`)."""
        return spec_hash(baseline.drift_view(spec))

    def hpa_owned(self, key: Key) -> bool:
        """An HPA scales this Deployment. Informational: the drift view already ignores `replicas` (S-HA-3)."""
        return any(key in targets for targets in self.hpa.values())

    # ── events ───────────────────────────────────────────────────────────────
    async def handle_deployment_event(self, event_type: str, deployment) -> None:
        try:
            dep = self._dep_json(deployment)
            meta = dep.get("metadata") or {}
            namespace, name = meta.get("namespace", ""), meta.get("name", "")
            if not namespace or not name:
                return
            key = (namespace, name)
            if event_type == "DELETED":
                self._forget(key)
                self._spawn(self._drop_workload_candidate(key))
                try:
                    await self.redis.delete(self._assessed_key(key))
                except Exception as e:
                    logger.debug(f"could not clean up the assessed hash of {namespace}/{name}: {e}")
                return
            self.latest_dep[key] = dep            # status-only updates refresh the rollout evidence
            if key in self.pending:
                self.pending[key].dep = dep
            spec = dep.get("spec") or {}
            h = self._hash(spec)
            if self.seen_hash.get(key) == h:      # status-only or metadata-only update: nothing to assess
                return
            first = key not in self.seen_hash
            self._set_seen(key, h)
            if first:
                await self._first_sight(key, dep, spec, h)
            else:
                self._mark_change(key, dep, spec, h)
        except Exception as e:
            logger.error(f"Error handling deployment event: {e}", exc_info=True)

    def _forget(self, key: Key) -> None:
        for d in (self.pending, self.tracking, self.latest_dep, self.seen_hash, self._drifted, self._first_sight_retry,
                  self._vetoed, self._promote_retry, self._dry_run_noted):
            d.pop(key, None)

    def _still_current(self, key: Key, h: str) -> bool:
        """The spec hash this call works on is still the newest one seen for a workload that still exists."""
        return self.seen_hash.get(key) == h and key in self.latest_dep

    def _set_seen(self, key: Key, h: str) -> None:
        if self.seen_hash.get(key) != h:
            self._spec_epoch[key] = self._spec_epoch.get(key, 0) + 1
            if self.redis is not None:
                self._spawn(self._housekeep_candidate(key))
        self.seen_hash[key] = h

    @staticmethod
    def _assessed_key(key: Key) -> str:
        return f"{ASSESSED_PREFIX}:{key[0]}:{key[1]}"

    async def _first_sight(self, key: Key, dep: Dict, spec: Dict, h: str) -> None:
        """First event for this workload in this process: the golden baseline is written once (SET NX); a
        workload that already differs from it is tracked for OBSERVE and, when this spec was not assessed
        before (an earlier process life), put on the debounce."""
        namespace, name = key
        try:
            golden, created = await baseline.get_or_set_baseline(self.redis, namespace, name, spec)
            if created:
                logger.info(f"Golden baseline recorded for {namespace}/{name}; no drift to assess")
                return
            if not baseline.is_drifted(golden, spec):
                logger.info(f"{namespace}/{name} matches its golden baseline")
                return
            self._drifted.setdefault(key, {"hash": h, "t0_wall": self.wall(), "last_assessed": self.clock()})
            if await self.redis.get(self._assessed_key(key)) == h:
                logger.info(f"{namespace}/{name} drifted spec was already assessed; waiting for a change")
                return
        except Exception as e:
            if not self._still_current(key, h):          # a newer event or a deletion owns the state now
                return
            logger.warning(f"first sight of {namespace}/{name} failed ({e}); will retry in {FIRST_SIGHT_RETRY_S:.0f}s "
                           "or on the next event")
            self.seen_hash.pop(key, None)
            self._first_sight_retry[key] = (dep, spec, h, self.clock() + FIRST_SIGHT_RETRY_S)
            return
        if not self._still_current(key, h):
            return
        self._first_sight_retry.pop(key, None)
        self._mark_change(key, dep, spec, h)

    def _mark_change(self, key: Key, dep: Dict, spec: Dict, h: str) -> None:
        """Debounce with a cap: the first pending change fixes the deadline; later changes replace the pending
        spec and never postpone it."""
        now = self.clock()
        self.tracking.pop(key, None)              # a newer spec supersedes the one being followed up
        p = self.pending.get(key)
        if p is None:
            self.pending[key] = Pending(spec=spec, dep=dep, hash=h, t0_wall=self.wall(),
                                        deadline=now + self.delay_s, next_poll=now,
                                        event_id=self._new_event_id(key[1]),
                                        unavailable_event_id=self._new_event_id(key[1]))
        else:
            p.spec, p.dep, p.hash = spec, dep, h
            p.seen, p.posture_early = set(), None
            p.event_id = self._new_event_id(key[1])
            p.unavailable_event_id = self._new_event_id(key[1])
            p.notified_unavailable = False

    # ── scheduler ────────────────────────────────────────────────────────────
    async def scheduler_loop(self) -> None:
        try:
            while self.running:
                await asyncio.sleep(TICK_S)
                try:
                    await self.tick()
                except Exception:
                    logger.exception("Health scheduler pass failed; will retry")
        except asyncio.CancelledError:
            raise

    async def tick(self) -> None:
        """One scheduler pass (split out so tests drive it with a fake clock): fire due assessments, poll for
        early evidence, poll followed-up rollouts, schedule OBSERVE samples."""
        now = self.clock()
        for key, (dep, spec, h, due) in list(self._first_sight_retry.items()):
            if now < due:
                continue
            self._first_sight_retry.pop(key, None)
            if key in self.seen_hash or key not in self.latest_dep:    # a newer event handled it, or it was deleted
                continue
            self._set_seen(key, h)
            self._spawn(self._first_sight(key, dep, spec, h))     # not inline: a slow Redis must not stall the tick
        for key, (h, verdict, due) in list(self._promote_retry.items()):
            if now >= due:
                self._promote_retry.pop(key, None)
                self._spawn(self._maybe_promote(key, h, verdict))
        for key, p in list(self.pending.items()):
            if now >= p.deadline:
                self._fire(key)
            elif now >= p.next_poll and not p.polling and now + POLL_S < p.deadline:
                p.polling = True
                self._spawn(self._early_check(key, p))
        for key, t in list(self.tracking.items()):
            if now >= t.end:
                self.tracking.pop(key, None)
            elif now >= t.next_poll and not t.polling:
                t.polling = True
                self._spawn(self._follow_up(key, t))
        await self.observe_tick()

    def _fire(self, key: Key) -> None:
        p = self.pending.pop(key, None)
        if p is not None:
            self._spawn(self.assess(key, p))

    async def _early_check(self, key: Key, p: Pending) -> None:
        """Assess now instead of at the deadline once the pending spec shows posture or failed-rollout evidence."""
        h0, spec0, dep0 = p.hash, p.spec, p.dep
        early = False
        try:
            golden = await baseline.load_baseline(self.redis, *key)
            if golden is None or p.hash != h0:
                return
            view = baseline.drift_view(spec0)
            if not baseline.is_drifted(golden, view):
                return                              # back at the baseline: the deadline records it
            if p.posture_early is None:
                try:
                    p.posture_early = bool(policy_violations(golden["spec"], view))
                except PostureError as e:
                    logger.warning(f"posture of {key[0]}/{key[1]} unreadable ({e}); waiting for the deadline")
                    p.posture_early = False
            if p.posture_early:
                early = True
            else:
                async with self.sem:
                    reasons = set(await self._failure_reasons(key, dep0, p.t0_wall))
                if p.hash != h0:
                    return
                early = bool(reasons & p.seen)      # a transient (one ErrImagePull) waits for a repeat
                p.seen = reasons
        except Exception as e:
            logger.warning(f"early-evidence check for {key[0]}/{key[1]} failed: {e}; waiting for the deadline")
            return
        finally:
            p.polling = False
            p.next_poll = self.clock() + POLL_S
        if early and self.pending.get(key) is p and p.hash == h0:
            self._fire(key)

    # ── assessment ───────────────────────────────────────────────────────────
    async def assess(self, key: Key, p: Pending) -> None:
        async with self.sem:
            # A queued assessment can wait behind the semaphore while a newer watch event
            # supersedes it. Never score or publish the stale spec after acquiring capacity.
            if self.seen_hash.get(key) != p.hash:
                return
            if key in self.assessing:
                # An assessment or OBSERVE sample of this workload is in flight: wait, never score twice at once.
                self._repend(key, p, POLL_S)
                return
            self.assessing[key] = p.hash
            try:
                outcome = await self._assess(key, p.spec, p.dep, since_wall=p.t0_wall,
                                             window=(p.t0_wall, min(self.wall(), p.t0_wall + self.delay_s)), p=p)
            except aioredis.RedisError as e:
                logger.warning(f"redis error assessing {key[0]}/{key[1]}: {e}; retrying in {RETRY_DELAY_S:.0f}s")
                outcome = "retry"
            except Exception as e:
                logger.exception(f"assessment of {key[0]}/{key[1]} failed")
                outcome = await self._failed(p, key[0], key[1], f"assessment failed: {e!r}")
            finally:
                self.assessing.pop(key, None)
        ASSESSMENTS.labels(outcome).inc()
        if outcome == "retry":
            self._repend(key, p, RETRY_DELAY_S)

    def _repend(self, key: Key, p: Pending, delay: float) -> None:
        """Put an assessment back on the debounce, unless the workload is gone or a newer change is pending."""
        if key in self.pending or self.seen_hash.get(key) != p.hash:
            return
        now = self.clock()
        p.deadline, p.next_poll, p.polling = now + delay, now + delay, False
        self.pending[key] = p

    async def _assess(self, key: Key, spec: Dict, dep: Dict, since_wall: float, window: Tuple[float, float],
                      p: Optional[Pending] = None) -> str:
        """Score one spec against the golden baseline and publish. Returns the outcome label."""
        ns, name = key
        h = self._hash(spec)
        held = await baseline.load_baseline_raw(self.redis, ns, name)
        if held is None:
            logger.error(f"Golden baseline missing for {ns}/{name}; refusing to use the live spec as baseline")
            return await self._failed(p, ns, name, "golden baseline missing; assessment refused")
        golden = held[1]
        golden_sha = baseline.raw_digest(held[0])
        view = baseline.drift_view(spec)
        if not baseline.is_drifted(golden, view):
            self._drifted.pop(key, None)
            await self._mark_assessed(key, h)
            logger.info(f"{ns}/{name} matches its golden baseline; skipping assessment")
            return "baseline"
        st = self._drifted.get(key)
        if st is None or st.get("hash") != h:
            self._drifted[key] = {"hash": h, "t0_wall": since_wall, "last_assessed": self.clock()}
        else:
            st["last_assessed"] = self.clock()

        # A new assessment of this spec replaces the earlier verdict: until it publishes a new one, a tracker or a
        # soak retry must not promote on the old one (an OBSERVE sample that fails or scores worse).
        tracker = self.tracking.get(key)
        if tracker is not None and tracker.hash == h:
            tracker.verdict = None
        self._promote_retry.pop(key, None)

        if not await self._validate_baseline(ns, name, self._get_baseline_sha(dep)):
            logger.warning(f"Baseline stale or invalid for {ns}/{name}")
            return "baseline_invalid"

        old = golden["spec"]
        try:
            violations = policy_violations(old, view)
        except PostureError as e:
            # A failed assessment, never a verdict: only a no-score notice (assessment_error) is published, so a human is
            # told, and no rule-based rollback can follow.
            logger.error(f"posture of {ns}/{name} unreadable ({e}); no verdict, a human is told")
            return await self._failed(p, ns, name, f"posture unreadable: {e}")

        try:
            win = await self._fetch_window(self.session, self.prometheus_url, ns, name, window[0], window[1])
        except ValueError as e:
            logger.error(f"cannot query metrics for {ns}/{name}: {e}; no verdict, a human is told")
            return await self._failed(p, ns, name, f"metric query refused: {e}")
        missing = missing_metrics(win)
        features = health_features(old, view, win)
        no_metrics = all(features.get(k) is None for k in METRIC_FEATURES)
        if no_metrics:
            logger.warning(f"{ns}/{name}: no metric data at all (Prometheus down or no series); "
                           "the model sees the spec diff only")

        started = time.perf_counter()
        pred = await self._predict_features(features)
        METRICS.observe_model_latency("health", time.perf_counter() - started)

        # Do not publish a result for a spec that was superseded while the model call was
        # in flight. This check also protects OBSERVE samples against a newer watch event.
        if self.seen_hash.get(key) != h:
            logger.info(f"Discarding superseded health assessment for {ns}/{name}")
            return "superseded"

        reasons = sorted(set(await self._failure_reasons(key, dep, since_wall)) | set(violations))
        changed = changed_paths(canonical_spec(old), canonical_spec(view))
        blast = await self._query_blast_radius(ns, spec)
        short_window = window[1] - window[0] < self.delay_s
        payload = self._event_payload(ns, name, pred, reasons, changed, missing, no_metrics, blast,
                                      event_id=p.event_id if p is not None else None,
                                      short_window=short_window)

        if pred is None and not reasons:
            # Fail closed: no score and no rule evidence. A human is told (once per spec); the same spec is
            # tried again later. Nothing is stored as assessed.
            logger.error(f"inference unavailable for {ns}/{name}; no score published (fail closed)")
            await self._notify_unavailable(p, ns, name)
            return "retry" if p is not None else "unavailable"

        if self.seen_hash.get(key) != h:
            logger.info(f"Discarding superseded health assessment for {ns}/{name} before publish")
            return "superseded"

        await self._publish_event(payload)
        await self._mark_assessed(key, h)
        verdict = None if pred is None else self._verdict(pred, payload, reasons, changed, since_wall, missing,
                                                          golden_sha)
        if verdict is None or not self._clean(verdict):
            await self._note_harmful(key, h)          # veto of this spec and a cool-off, before any promotion check
        self._start_tracking(key, h, since_wall, payload, set(reasons), verdict)
        if verdict is not None:
            await self._maybe_promote(key, h, verdict)
        if pred is None:
            logger.error(f"inference unavailable for {ns}/{name}; published rule evidence only: {reasons}")
            # Do not emit a second event after model recovery: Fusion may already have
            # acted on this rule evidence, and a new event could duplicate remediation.
            return "published_rule"
        logger.info(f"Assessment {ns}/{name}: label={pred.label} risk={pred.risk:.2f} set={pred.prediction_set} "
                    f"changed={changed[:5]} failures={reasons}")
        return "published"

    async def _notify_unavailable(self, p: Optional[Pending], ns: str, name: str, error: str = "") -> None:
        """The no-score notice, once per pending spec (a retry does not repeat it)."""
        if p is not None:
            if p.notified_unavailable:
                return
            event_id = p.unavailable_event_id
        else:
            h = self.seen_hash.get((ns, name), "unknown")
            event_id = self._stable_event_id(ns, name, h, f"unavailable-{self._spec_epoch.get((ns, name), 0)}")
        published = await self._publish_model_unavailable(ns, name, error, event_id=event_id)
        if published and p is not None:
            p.notified_unavailable = True

    async def _failed(self, p: Optional[Pending], ns: str, name: str, error: str) -> str:
        """A failed assessment is never a verdict: nothing is scored and no rule-based rollback can follow, but a
        human is told once (the same notice as an inference outage, with the cause). Not retried: the spec
        itself is the problem, and a changed spec is assessed again."""
        await self._notify_unavailable(p, ns, name, error)
        return "error"

    async def _predict_features(self, features: Dict) -> Optional[Prediction]:
        try:
            return await self._predict(self.session, self.inference_url, features, self.inference_timeout_s)
        except Exception as e:
            logger.warning(f"inference call failed: {e!r}; no score")
            return None

    async def _mark_assessed(self, key: Key, h: str) -> None:
        try:
            await self.redis.set(self._assessed_key(key), h)
        except Exception as e:
            logger.debug(f"could not store the assessed hash of {key[0]}/{key[1]}: {e}")

    def _new_event_id(self, name: str) -> str:
        self._seq += 1
        stamp = datetime.fromtimestamp(self.wall(), tz=timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        return f"health-{stamp}-{name}-{self._seq}"

    @staticmethod
    def _stable_event_id(namespace: str, name: str, spec_hash_value: str, kind: str) -> str:
        material = f"{namespace}\0{name}\0{spec_hash_value}\0{kind}".encode()
        digest = hashlib.sha256(material).hexdigest()[:24]
        return f"health-{kind}-{digest}"

    def _event_payload(self, ns: str, name: str, pred: Optional[Prediction], reasons: List[str],
                      changed: List[str], missing: List[str], no_metrics: bool, blast: str,
                      event_id: Optional[str] = None, short_window: bool = False) -> Dict[str, str]:
        """The fields Fusion reads (agents/fusion_agent/event_mapping.py) plus the dashboard fields. Every value
        is a string (Redis stream)."""
        payload = {
            "event_id": event_id or self._new_event_id(name), "namespace": ns, "pod_name": name, "deployment": name,
            "namespace_tier": namespace_tier(ns),
            "timestamp_ms": str(int(self.wall() * 1000)),
            "spec_changed": "true", "has_baseline": "true",
            "changed_fields_json": json.dumps(changed),
            "failure_reasons_json": json.dumps(reasons),
            # Not model attribution: the first changed field of the spec diff (the rule path uses the same).
            "top_field": changed[0] if changed else "",
            "patch_proposal_json": json.dumps({"restore_field": changed[0], "note": "restore to recorded baseline"}
                                              if changed else {}),
            "blast_radius": blast,
            "metrics_missing_json": json.dumps(missing),
        }
        if pred is None:
            # Rule evidence without a score: model_unavailable, no risk (Fusion reads it as 0), empty set.
            payload.update({
                "health_label": "model_unavailable", "health_prediction_set": "[]", "health_uncertain": "true",
                "model_scored": "false", "model_unavailable": "true", "inference_method": "none",
            })
            return payload
        payload.update({
            "health_label": pred.label, "health_risk": f"{pred.risk:.4f}",
            # No metrics or an early, undersized window means the health model has no reliable
            # time series. An empty set is fail-closed because Fusion gates on this field.
            "health_prediction_set": "[]" if (no_metrics or short_window) else json.dumps(list(pred.prediction_set)),
            "health_uncertain": "true" if (pred.uncertain or no_metrics or short_window) else "false",
            "top_factors_json": json.dumps([f.model_dump() for f in pred.top_factors]),
            "model_scored": "true", "model_version": pred.model_version, "inference_method": "lightgbm",
        })
        return payload

    async def _publish_event(self, payload: Dict[str, str]) -> bool:
        """Atomically publish one idempotent stream event and its detail hash."""
        hkey = f"kubeheal:health:{payload['event_id']}"
        marker = f"kubeheal:health:published:{payload['event_id']}"
        fields = [part for key, value in payload.items() for part in (key, value)]
        result = await self.redis.eval(PUBLISH_HEALTH_EVENT_LUA, 3, HEALTH_STREAM, hkey, marker, *fields)
        if result:
            logger.info(f"Published {payload['event_id']}")
        else:
            logger.info(f"Health event {payload['event_id']} was already published")
        return bool(result)

    async def _publish_model_unavailable(self, namespace: str, name: str, error: str = "",
                                         event_id: Optional[str] = None) -> bool:
        """Tell the Fusion Agent that no score could be obtained for this workload. The event carries NO score:
        model_scored=false and model_unavailable=true, an empty prediction set. Fusion does not decide on it; it
        escalates to a human once per workload and window. A publish failure is only logged."""
        payload = {
            "event_id": event_id or self._new_event_id(name), "namespace": namespace, "pod_name": name,
            "deployment": name,
            "namespace_tier": namespace_tier(namespace),
            "health_label": "model_unavailable",
            "health_prediction_set": "[]",
            "health_uncertain": "true",
            "model_scored": "false",
            "model_unavailable": "true",
            "inference_method": "none",
            "timestamp_ms": str(int(self.wall() * 1000)),
        }
        if error:
            payload["assessment_error"] = error[:300]
        try:
            if await self._publish_event(payload):
                logger.error(f"Published {payload['event_id']}: no health score for {namespace}/{name}")
                await self._note_cooloff((namespace, name))
            return True
        except Exception as e:
            logger.error(f"Could not publish the model_unavailable event for {namespace}/{name}: {e}")
            return False

    # ── follow-up events ─────────────────────────────────────────────────────
    def _start_tracking(self, key: Key, h: str, t0_wall: float, payload: Dict, reported: set,
                        verdict: Optional[Dict] = None) -> None:
        """After the first event the rollout can still fail (never Ready, ProgressDeadlineExceeded): follow up
        until it completes, the spec is superseded or deleted, or the window ends."""
        dep = self.latest_dep.get(key)
        if dep is None or self.seen_hash.get(key) != h:
            return
        if key in self.tracking and self.tracking[key].hash == h:
            self.tracking[key].verdict = verdict  # an OBSERVE sample of the same spec keeps the running follow-up,
            return                                # but its verdict replaces the earlier one (None clears it)
        if rollout_complete(dep) and not progress_deadline_exceeded(dep):
            return
        window = self.followup_window_s
        if window is None:
            window = ((dep.get("spec") or {}).get("progressDeadlineSeconds") or DEFAULT_PROGRESS_DEADLINE_S) \
                + FOLLOWUP_MARGIN_S
        now = self.clock()
        self.tracking[key] = Tracked(hash=h, t0_wall=t0_wall, end=now + window, next_poll=now + POLL_S,
                                     payload=dict(payload), reported=set(reported), verdict=verdict)

    async def _follow_up(self, key: Key, t: Tracked) -> None:
        """One follow-up poll: publish one more event when new failure reasons are confirmed on two consecutive
        polls. The event is the first one with a new event_id and the union of reasons."""
        try:
            dep = self.latest_dep.get(key)
            if self.tracking.get(key) is not t or dep is None or self.seen_hash.get(key) != t.hash:
                self.tracking.pop(key, None) if self.tracking.get(key) is t else None
                return
            if rollout_complete(dep) and not progress_deadline_exceeded(dep):
                self.tracking.pop(key, None)
                if t.verdict is not None and not t.reported - set(t.verdict["reasons"]):
                    await self._maybe_promote(key, t.hash, t.verdict)    # the rollout finished after the verdict
                return
            async with self.sem:
                now_reasons = set(await self._failure_reasons(key, dep, t.t0_wall))
            new = (now_reasons & t.seen) - t.reported
            t.seen = now_reasons
            if not new or self.tracking.get(key) is not t or self.seen_hash.get(key) != t.hash:
                return
            follow = dict(t.payload)
            combined_reasons = sorted(t.reported | new)
            reason_digest = hashlib.sha256(json.dumps(combined_reasons).encode()).hexdigest()[:16]
            follow.update({"event_id": self._stable_event_id(key[0], key[1], t.hash,
                                                              f"followup-{reason_digest}"),
                           "timestamp_ms": str(int(self.wall() * 1000)),
                           "failure_reasons_json": json.dumps(combined_reasons)})
            try:
                await self._publish_event(follow)
            except Exception as e:
                logger.warning(f"follow-up for {key[0]}/{key[1]} not published: {e}; retrying")
                return
            t.reported |= new
            await self._note_harmful(key, t.hash)
            logger.info(f"follow-up for {key[0]}/{key[1]}: {follow['failure_reasons_json']}")
        except Exception as e:
            logger.warning(f"follow-up poll for {key[0]}/{key[1]} failed: {e}")
        finally:
            t.polling = False
            t.next_poll = self.clock() + POLL_S

    # ── baseline promotion (V5-D5) ───────────────────────────────────────────
    @staticmethod
    def _verdict(pred: Prediction, payload: Dict[str, str], reasons: List[str], changed: List[str],
                 since_wall: float, missing: Optional[List[str]] = None, golden_sha: str = "") -> Dict:
        """What a promotion needs from one assessment. The set and the uncertainty are the PUBLISHED ones: a window
        with no metrics or an undersized window publishes an empty set, which is never certain."""
        return {"label": pred.label, "prediction_set": json.loads(payload["health_prediction_set"]),
                "uncertain": payload["health_uncertain"] == "true", "risk": pred.risk,
                "model_version": pred.model_version, "event_id": payload["event_id"],
                "reasons": list(reasons), "changed_fields": list(changed), "since_wall": since_wall,
                "missing_metrics": list(missing or []), "golden_sha256": golden_sha}

    @staticmethod
    def _clean(verdict: Dict) -> bool:
        """A benign, certain verdict with no failure reasons: the only kind that does not veto its spec."""
        return (verdict["label"] == "benign" and verdict["prediction_set"] == ["benign"]
                and not verdict["uncertain"] and not verdict["reasons"])

    async def _note_cooloff(self, key: Key) -> None:
        """A decision-relevant event was published for this workload: promotions wait for the cool-off. The marker
        is in Redis (the dashboard side reads it too) and in memory (if Redis refuses the write)."""
        self._cooloff_until[key] = self.clock() + self.cooloff_s
        try:
            await self.redis.set(baseline.cooloff_key(*key), "1", ex=max(1, int(math.ceil(self.cooloff_s))))
        except Exception as e:
            logger.warning(f"could not store the promotion cool-off of {key[0]}/{key[1]}: {e!r}; kept in memory")

    async def _note_harmful(self, key: Key, h: str) -> None:
        """A non-benign or uncertain verdict (or rule evidence) was published for spec `h`: veto its promotion and
        start the cool-off. Later re-scoring of the same spec can never lift the veto."""
        self._vetoed.setdefault(key, set()).add(h)
        try:
            await baseline.add_veto(self.redis, key[0], key[1], h)
        except Exception as e:
            logger.warning(f"could not store the promotion veto of {key[0]}/{key[1]}: {e!r}; kept in memory")
        await self._note_cooloff(key)

    def _promotable_now(self, key: Key, h: str) -> bool:
        """The spec is still the newest known, and no assessment of a different spec is in flight."""
        newer = self.pending.get(key)
        return (self._still_current(key, h) and self.assessing.get(key) in (None, h)
                and (newer is None or newer.hash == h))

    def _final_check(self, key: Key, h: str) -> bool:
        """Synchronous, in-memory, right before the overwrite (after the ledger write): the spec is still the
        newest, the kill switch still says enforce, and no veto or cool-off appeared meanwhile."""
        until = self._cooloff_until.get(key)
        return (self._promotable_now(key, h) and not self.mode.dry_run_for(key[0])
                and h not in self._vetoed.get(key, ()) and not (until is not None and self.clock() < until))

    async def _maybe_promote(self, key: Key, h: str, verdict: Dict) -> str:
        """Promote (dev, staging) or store a candidate (prod, unknown) when the assessment of spec hash `h` allows
        it. Never raises: a failure is logged and the golden baseline stays as it is."""
        ns, name = key
        if key in self._promoting:
            return "busy"
        self._promoting.add(key)
        try:
            outcome = await self._promote_checked(key, h, verdict)
        except Exception as e:
            logger.exception(f"baseline promotion of {ns}/{name} failed ({e!r}); the golden baseline is unchanged")
            outcome = "error"
        finally:
            self._promoting.discard(key)
        PROMOTIONS.labels(outcome).inc()
        return outcome

    async def _promote_checked(self, key: Key, h: str, verdict: Dict) -> str:
        ns, name = key
        blocker = baseline.verdict_blocker(verdict["label"], verdict["prediction_set"], verdict["uncertain"],
                                           verdict["reasons"], rollout_done=True)
        if blocker:
            return "not_eligible"
        if verdict.get("missing_metrics"):
            logger.info(f"no baseline promotion or candidate for {ns}/{name}: metric series missing "
                        f"{verdict['missing_metrics']}")
            return "metrics_missing"
        if not self._promotable_now(key, h):
            logger.info(f"no baseline promotion for {ns}/{name}: the spec was superseded or another assessment "
                        "is in flight")
            return "superseded"
        dep = self.latest_dep.get(key) or {}
        if not rollout_complete(dep) or progress_deadline_exceeded(dep):
            return "rollout_incomplete"           # a follow-up promotes it when the rollout completes
        spec = dep.get("spec") or {}
        if self._hash(spec) != h:
            return "superseded"
        held = await baseline.load_baseline_raw(self.redis, ns, name)
        if held is None:
            return "no_baseline"
        golden_raw, golden = held
        if baseline.raw_digest(golden_raw) != verdict.get("golden_sha256"):
            logger.info(f"no baseline promotion for {ns}/{name}: the golden baseline moved since the assessment")
            return "golden_moved"
        view = baseline.drift_view(spec)
        if not baseline.is_drifted(golden, view):
            return "nothing_to_promote"
        if h in self._vetoed.get(key, ()):
            logger.info(f"no baseline promotion or candidate for {ns}/{name}: the spec is vetoed")
            return "vetoed"
        until = self._cooloff_until.get(key)
        if until is not None and self.clock() < until:
            logger.info(f"no baseline promotion or candidate for {ns}/{name}: cool-off")
            return "coordination_blocked"
        soak_left = self.min_soak_s - (self.wall() - verdict["since_wall"])
        if soak_left > 0:
            logger.info(f"no baseline promotion for {ns}/{name} yet: {soak_left:.0f}s of soak time left")
            self._promote_retry[key] = (h, verdict, self.clock() + soak_left)
            return "soak"
        # Fresh evidence just before the decision: failure reasons and posture of exactly this spec. Failure
        # evidence that cannot be read is not "no failure": nothing is promoted and no candidate is made.
        try:
            violations = policy_violations(golden["spec"], view)
        except PostureError as e:
            logger.warning(f"no baseline promotion for {ns}/{name}: posture unreadable ({e})")
            return "posture_unreadable"
        found = await self._failure_reasons(key, dep, verdict["since_wall"], strict=True)
        if found is None:
            logger.warning(f"no baseline promotion or candidate for {ns}/{name}: failure evidence unavailable")
            return "evidence_unavailable"
        reasons = sorted(set(found) | set(violations))
        if reasons:
            logger.info(f"no baseline promotion for {ns}/{name}: failure reasons {reasons}")
            return "failure_reasons"
        blocked = await baseline.coordination_blocker(self.redis, ns, name, h)
        if blocked:
            logger.info(f"no baseline promotion or candidate for {ns}/{name}: {blocked}")
            return "vetoed" if "vetoed" in blocked else "coordination_blocked"
        blocked = await baseline.security_blocker(self.redis, ns, name, now_ms=self.wall() * 1000.0,
                                                  fresh_s=self.security_fresh_s, require=self.require_security)
        if blocked:
            logger.info(f"no baseline promotion or candidate for {ns}/{name}: {blocked}")
            return "security_blocked"
        if not self._promotable_now(key, h):
            return "superseded"
        tier = namespace_tier(ns)
        route, why = baseline.promotion_route(tier, self.auto_promotion, self.ledger is not None)
        if route == "none":
            logger.warning(f"baseline promotion of {ns}/{name} skipped: {why}")
            return "disabled"
        evidence = {"label": verdict["label"], "risk": verdict["risk"],
                    "prediction_set": verdict["prediction_set"], "model_version": verdict["model_version"],
                    "event_id": verdict["event_id"], "rollout_complete": True, "failure_reasons": []}
        if route == "candidate":
            res = await baseline.store_candidate(self.redis, self.ledger, ns, name, new_spec=view, spec_hash=h,
                                                 golden_raw=golden_raw, tier=tier,
                                                 changed_fields=verdict["changed_fields"], assessment=evidence)
            if res["status"] == "stored":
                if not self._promotable_now(key, h):
                    # a newer spec arrived while the candidate was being written: its housekeeping may already
                    # have run, so do not leave a candidate for a spec that is no longer live
                    await baseline.drop_candidate(self.redis, self.ledger, ns, name, "superseded during store")
                    return "superseded"
                logger.info(f"baseline promotion candidate stored for {ns}/{name} ({tier}); waiting for approval")
            return "candidate_" + res["status"]
        if self.mode.dry_run_for(ns):
            # Mode test, or the mode is unknown or unreadable (fail safe to test): the golden record is NOT touched.
            mark = (h, baseline.raw_digest(golden_raw))
            if self._dry_run_noted.get(key) == mark:
                return "dry_run"
            res = await baseline.record_dry_run(
                self.ledger, ns, name, new_spec=view, spec_hash=h, golden_raw=golden_raw, kind="auto",
                actor=baseline.AUTO_ACTOR, tier=tier, evidence=evidence, changed_fields=verdict["changed_fields"],
                mode=self.mode.mode_for(ns))
            if res["status"] == "dry_run":
                self._dry_run_noted[key] = mark
            return "dry_run" if res["status"] == "dry_run" else "dry_run_" + res["status"]
        res = await baseline.promote_baseline(
            self.redis, self.ledger, ns, name, new_spec=view, spec_hash=h, golden_raw=golden_raw, kind="auto",
            actor=baseline.AUTO_ACTOR, tier=tier, evidence=evidence, changed_fields=verdict["changed_fields"],
            proceed=lambda: self._final_check(key, h))
        if res["status"] == "promoted":
            self._drifted.pop(key, None)          # the live spec is the golden baseline now: OBSERVE stops
            self.tracking.pop(key, None)
            logger.info(f"{ns}/{name}: golden baseline promoted to spec {h[:12]} (benign, certain, rollout complete)")
        return res["status"]

    async def _housekeep_candidate(self, key: Key) -> None:
        """The live spec of a workload changed: a candidate for another spec no longer applies, and a remembered
        rejection of another spec is forgotten."""
        ns, name = key
        try:
            current = self.seen_hash.get(key)
            if current is None:
                return
            cand = await baseline.get_candidate(self.redis, ns, name)
            if cand is not None and cand.get("spec_hash") != current and self.seen_hash.get(key) == current:
                await baseline.drop_candidate(self.redis, self.ledger, ns, name, "the live spec changed again")
            await baseline.clear_rejected_if_changed(self.redis, ns, name, current)
        except Exception as e:
            logger.warning(f"candidate housekeeping for {ns}/{name} failed: {e!r}")

    async def _drop_workload_candidate(self, key: Key) -> None:
        ns, name = key
        try:
            await baseline.drop_candidate(self.redis, self.ledger, ns, name, "the workload was deleted")
            await self.redis.delete(baseline.rejected_key(ns, name))
        except Exception as e:
            logger.warning(f"candidate cleanup for deleted {ns}/{name} failed: {e!r}")

    # ── Kubernetes reads ─────────────────────────────────────────────────────
    async def _failure_reasons(self, key: Key, dep: Dict, since_wall: float,
                               strict: bool = False) -> Optional[List[str]]:
        """Authoritative failed-rollout evidence for the new spec. Pods are listed in the Deployment's own
        namespace; an error (a 403 included) only loses the pod evidence, it is never a failure reason.

        strict=True (the promotion check) does not accept a lost listing as "no failure": it returns None when
        the Kubernetes client is missing, the selector has no matchLabels (matchExpressions only, or none), or the
        pod listing fails for any reason."""
        match = ((dep.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
        pods: List[Dict] = []
        if self.core_api is None or not match:
            if strict:
                return None
        else:
            try:
                resp = await self.core_api.list_namespaced_pod(
                    key[0], label_selector=",".join(f"{k}={v}" for k, v in match.items()),
                    _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
                pods = json.loads(await resp.read())["items"]
            except (ApiException, aiohttp.ClientError, TimeoutError, ValueError, KeyError) as e:
                logger.warning(f"pod listing for {key[0]}/{key[1]} failed ({getattr(e, 'status', e)}); "
                               "no pod failure evidence")
                if strict:
                    return None
            except Exception as e:
                if not strict:
                    raise
                logger.warning(f"pod listing for {key[0]}/{key[1]} failed ({e!r}); no pod failure evidence")
                return None
        return failure_reasons(dep, pods, since_wall, now=self.wall())

    async def _read_deployment(self, namespace: str, name: str) -> Dict:
        resp = await self.apps_api.read_namespaced_deployment(
            name, namespace, _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
        return self._dep_json(json.loads(await resp.read()))

    @staticmethod
    def _get_baseline_sha(dep: Dict) -> Optional[str]:
        return ((dep.get("metadata") or {}).get("annotations") or {}).get("kubeheal.io/baseline-sha")

    async def _validate_baseline(self, namespace: str, name: str, baseline_sha: Optional[str]) -> bool:
        """Validate baseline integrity. Returns False only on confirmed mismatch."""
        if not baseline_sha:
            return True
        try:
            cm = await self.core_api.read_namespaced_config_map(self.baseline_configmap, namespace)
            stored_sha = cm.data.get(name, "") if cm.data else ""
            if stored_sha and stored_sha != baseline_sha:
                logger.warning(f"Baseline SHA mismatch for {namespace}/{name}")
                return False
            return True
        except Exception as e:
            logger.debug(f"Baseline validation skipped (ConfigMap not found): {e}")
            return True  # proceed if ConfigMap doesn't exist yet

    async def _query_blast_radius(self, namespace: str, spec: Dict) -> str:
        """Blast radius: Services + Ingresses."""
        selector = ((spec or {}).get("selector") or {}).get("matchLabels") or {}
        try:
            services = await self.core_api.list_namespaced_service(
                namespace, label_selector=",".join([f"{k}={v}" for k, v in selector.items()]))
            for svc in services.items:
                if svc.spec.type == "LoadBalancer":
                    return "High"
            ingresses = await self.networking_api.list_namespaced_ingress(namespace)
            for ing in ingresses.items:
                if ing.spec.backend and ing.spec.backend.service:
                    return "High"
            return "Low"
        except Exception as e:
            logger.debug(f"Blast radius query error: {e}")
            return "unknown"

    # ── OBSERVE sampling ─────────────────────────────────────────────────────
    async def observe_tick(self) -> None:
        """Rescore known drift only while Fusion's bounded OBSERVE request is active."""
        if not self.redis or not self.observe_base_s:
            return
        now = self.clock()
        due: List[Key] = []
        for key, state in list(self._drifted.items()):
            namespace, name = key
            factor = await sampling_factor(self.redis, namespace, workload=name)
            interval = scaled_interval(self.observe_base_s, factor)
            if factor > 1 and now - state["last_assessed"] >= interval:
                # Advance before the sample runs so the next tick cannot duplicate it.
                state["last_assessed"] = now
                due.append(key)
        for key in due:
            self._spawn(self.observe_sample(key))

    async def observe_sample(self, key: Key) -> None:
        """One OBSERVE sample: a LIVE read of the Deployment, then a normal assessment of that current spec.
        The object of an old watch event is never used (it can be stale)."""
        namespace, name = key
        async with self.sem:
            if key in self.assessing:
                logger.info(f"Skipping OBSERVE sample for {namespace}/{name}: scoring in flight")
                return
            self.assessing[key] = ""          # claimed before the first await
            try:
                try:
                    dep = await self._read_deployment(namespace, name)
                except ApiException as e:
                    if e.status == 404:
                        logger.info(f"{namespace}/{name} is gone; dropping it from OBSERVE tracking")
                        self._forget(key)
                    else:
                        logger.warning(f"OBSERVE live read of {namespace}/{name} failed ({e.status}); skipped")
                    return
                except Exception as e:
                    logger.warning(f"OBSERVE live read of {namespace}/{name} failed ({e!r}); skipped")
                    return
                spec = dep.get("spec") or {}
                h = self._hash(spec)
                st = self._drifted.get(key)
                same = bool(st) and st.get("hash") == h
                now_wall = self.wall()
                self.latest_dep[key] = dep
                # The live spec is now the newest known: an older pending change is superseded, and the watch
                # event that reports this same spec later finds the hash already seen.
                self._set_seen(key, h)
                self.pending.pop(key, None)
                self.assessing[key] = h
                try:
                    outcome = await self._assess(
                        key, spec, dep, since_wall=st["t0_wall"] if same else now_wall,
                        window=(now_wall - self.delay_s, now_wall))
                except aioredis.RedisError as e:
                    logger.warning(f"redis error in OBSERVE sample of {namespace}/{name}: {e}")
                    outcome = "error"
                except Exception as e:
                    logger.exception(f"OBSERVE sample of {namespace}/{name} failed")
                    outcome = await self._failed(None, namespace, name, f"assessment failed: {e!r}")
                ASSESSMENTS.labels("observe_" + outcome).inc()
            finally:
                self.assessing.pop(key, None)

    # ── watch loop ───────────────────────────────────────────────────────────
    def _list_fn(self, scope: Optional[str]):
        if scope:
            return self.apps_api.list_namespaced_deployment, (scope,)
        return self.apps_api.list_deployment_for_all_namespaces, ()

    async def watch_loop(self, scope: Optional[str]) -> None:
        """Full list, then watch from the list's resourceVersion; re-list on 410 Gone or any other failure of the
        resourceVersion. The agent never exits on a normal watch timeout."""
        rv: Optional[str] = None
        backoff = 1.0
        while self.running:
            attempt_started = self.clock()
            try:
                fn, args = self._list_fn(scope)
                if rv is None:
                    rv = await self.relist(scope)
                async with watch.Watch() as w:
                    self._watchers.append(w)
                    try:
                        async for ev in w.stream(fn, *args, label_selector=WATCH_LABEL_SELECTOR,
                                                 resource_version=rv, timeout_seconds=WATCH_TIMEOUT_S,
                                                 allow_watch_bookmarks=True):
                            if not self.running:
                                break
                            rv = getattr(w, "resource_version", None) or rv
                            if ev["type"] in ("ADDED", "MODIFIED", "DELETED"):
                                await self.handle_deployment_event(ev["type"], ev["object"])
                    finally:
                        if w in self._watchers:
                            self._watchers.remove(w)
                backoff = 1.0
                if self.running and self.clock() - attempt_started < WATCH_RETRY_MIN_S:
                    await asyncio.sleep(WATCH_RETRY_MIN_S - (self.clock() - attempt_started))   # no hot loop
            except asyncio.CancelledError:
                break
            except asyncio.TimeoutError:
                logger.debug("Watch idle timeout; reconnecting")        # resume from the last resourceVersion
                await asyncio.sleep(WATCH_RETRY_MIN_S)
            except ApiException as e:
                WATCH_ERRORS.inc()
                if e.status == 410:
                    logger.warning("Watch expired (410); re-listing")
                    rv = None
                    await asyncio.sleep(WATCH_RETRY_MIN_S)
                else:
                    logger.error(f"Watch API error: {e}; retry in {backoff:.0f}s")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 60.0)
            except Exception as e:
                WATCH_ERRORS.inc()
                logger.error(f"Watch error: {e!r}; re-listing in {backoff:.0f}s", exc_info=True)
                rv = None
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
        logger.info("Deployment watch stopped")

    async def relist(self, scope: Optional[str]) -> str:
        """Replay every labelled Deployment as ADDED (the seen hash makes that idempotent), forget the in-memory
        state of Deployments deleted while no watch was open, and return the list's resourceVersion. Golden
        baselines in Redis are never touched."""
        fn, args = self._list_fn(scope)
        resp = await fn(*args, label_selector=WATCH_LABEL_SELECTOR, _preload_content=False,
                        _request_timeout=KUBE_TIMEOUT_S * 6)
        body = json.loads(await resp.read())
        live: set = set()
        for dep in body.get("items") or []:
            meta = dep.get("metadata") or {}
            live.add((meta.get("namespace", ""), meta.get("name", "")))
            await self.handle_deployment_event("ADDED", dep)
        known = {*self.seen_hash, *self._first_sight_retry, *self.latest_dep}
        for key in [k for k in known if k not in live and scope in (None, k[0])]:
            self._forget(key)
        return body["metadata"]["resourceVersion"]

    # ── HPAs ─────────────────────────────────────────────────────────────────
    async def hpa_loop(self, scope: Optional[str]) -> None:
        while self.running:
            await asyncio.sleep(HPA_POLL_S)
            await self.refresh_hpas(scope)

    async def refresh_hpas(self, scope: Optional[str]) -> None:
        """Deployments an HPA scales, listed PER namespace (a cluster-wide HPA list is a 403 under our RBAC).
        A failure keeps the last known set."""
        try:
            if scope:
                resp = await self.autoscaling_api.list_namespaced_horizontal_pod_autoscaler(
                    scope, _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
            else:
                resp = await self.autoscaling_api.list_horizontal_pod_autoscaler_for_all_namespaces(
                    _preload_content=False, _request_timeout=KUBE_TIMEOUT_S)
            items = json.loads(await resp.read())["items"]
        except (ApiException, aiohttp.ClientError, TimeoutError, ValueError, KeyError) as e:
            logger.warning(f"HPA listing ({scope or '*'}) failed ({getattr(e, 'status', e)}); keeping the last set")
            return
        targets = set()
        for h in items:
            ref = (h.get("spec") or {}).get("scaleTargetRef") or {}
            if ref.get("kind") == "Deployment":
                targets.add(((h.get("metadata") or {}).get("namespace", ""), ref.get("name", "")))
        self.hpa[scope or "*"] = targets


async def main():
    """Run Health Agent."""
    METRICS.start_server(int(os.environ.get("METRICS_PORT", "8080")))
    agent = HealthAgent()

    try:
        await agent.start()
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
