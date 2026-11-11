import asyncio
import base64
import json
import logging
import hashlib
import os
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, watch, config
from kubernetes_asyncio.config import load_incluster_config
from agents.health_agent import baseline
from agents.common.sampling import sampling_factor, scaled_interval
from agents.common.metrics import KubeHealMetrics
from pydantic import BaseModel, ConfigDict, Field


def emb_b64(vec) -> str:
    """Pack a float list as base64 float32 bytes for the Redis stream."""
    vec = list(vec or [])
    return base64.b64encode(struct.pack(f"{len(vec)}f", *vec)).decode() if vec else ""


def namespace_tier(namespace: str) -> str:
    """Map a namespace to its risk tier (prod / staging / dev / unknown).

    A namespace that matches none of the known names is "unknown", not "dev": the decision policy scores an
    unknown tier with the highest multiplier and never acts automatically on it. (The `kubeheal/tier` namespace
    label is set by the manifests but is not read by any agent yet; the name rule is all there is.)"""
    n = (namespace or "").lower()
    if "prod" in n:
        return "prod"
    if "stag" in n:
        return "staging"
    if "dev" in n:
        return "dev"
    return "unknown"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
METRICS = KubeHealMetrics()

# Chosen default cadence, not a measured profile. During an active OBSERVE request,
# the workload's next assessment is scheduled at base/factor. No periodic assessment
# runs when no OBSERVE request is active.
HEALTH_OBSERVE_BASE_S = 60.0


def observe_base_s_from_env() -> float:
    raw = os.environ.get("HEALTH_OBSERVE_BASE_S")
    if raw is None:
        return HEALTH_OBSERVE_BASE_S
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("HEALTH_OBSERVE_BASE_S must be a positive number") from exc
    if value <= 0 or not value < float("inf"):
        raise ValueError("HEALTH_OBSERVE_BASE_S must be a positive finite number")
    return value


class SeverityLevel(str, Enum):
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HealthAssessment(BaseModel):
    model_config = ConfigDict(protected_namespaces=())  # allow model_* fields
    event_id: str
    target: Dict[str, str]
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    patch_proposal: Optional[Dict[str, Any]] = None
    explainability: Optional[Dict[str, Any]] = None
    confidence_interval: Optional[Tuple[float, float]] = None
    blast_radius: str = "unknown"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    # Fields from the Health Model server's score response
    model_used: Optional[str] = None  # "pytorch" or "heuristic"
    model_score: Optional[float] = None  # model risk score, 0-1
    heuristic_score: Optional[float] = None  # Score from heuristic, 0-1
    inference_method: Optional[str] = (
        None  # e.g., "health_model_v4"/"security_model_v4" or "heuristic"
    )


class HealthAgent:
    """
    Kubernetes operator for Health Agent.
    Watches YAML drift, assesses with the Health Model, publishes HealthAssessment.
    """

    def __init__(
        self,
        namespace: str = "kubeheal",
        redis_url: str = None,
        health_model_url: str = None,
        cooldown_ttl: int = 300,
        prometheus_url: str = None,
        observe_base_s: Optional[float] = None,
        clock=time.monotonic,
    ):
        self.namespace = namespace
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://redis-master:6379")
        # v4: dedicated Health Model server (was the v3 DIT-Sec monolith)
        self.health_model_url = health_model_url or os.environ.get(
            "HEALTH_MODEL_URL", "http://kubeheal-health-model:8001"
        )
        self.cooldown_ttl = cooldown_ttl
        self.prometheus_url = prometheus_url or os.environ.get(
            "PROMETHEUS_URL",
            "http://prometheus-operated.monitoring.svc.cluster.local:9090",
        )

        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        self.custom_api: Optional[client.CustomObjectsApi] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None

        self.running = False
        self.watcher = None

        # P6-D2: periodic rescoring is limited to workloads with an active OBSERVE request.
        self.observe_base_s = (observe_base_s if observe_base_s is not None
                               else observe_base_s_from_env())
        self.clock = clock
        # (namespace, deployment) -> latest Deployment and clock() time of last assessment.
        # Only workloads whose spec differs from the golden baseline are tracked.
        self._drifted: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._observe_task: Optional[asyncio.Task] = None
        # One shared serializer for _spec_json; closed in stop(). Created lazily because
        # constructing an ApiClient opens an aiohttp session.
        self._serializer: Optional[client.ApiClient] = None
        # Per-workload guard so a watch event and an OBSERVE_SAMPLE never score the same
        # workload at the same time.
        self._workload_locks: Dict[Tuple[str, str], asyncio.Lock] = {}

        self.baseline_configmap = "kubeheal-baselines"

    async def start(self) -> None:
        """Start the Health Agent."""
        logger.info("Starting Health Agent (v4)...")
        logger.info(f"Redis URL: {self.redis_url}")
        logger.info(f"Health Model URL: {self.health_model_url}")
        logger.info(f"Prometheus URL: {self.prometheus_url}")

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

        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.custom_api = client.CustomObjectsApi()

        self.networking_api = client.NetworkingV1Api()

        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)

        logger.info("Health Agent started successfully")

        # Set before the task exists so observe_loop never depends on watch_deployments ordering.
        self.running = True
        self._observe_task = asyncio.create_task(self.observe_loop())
        logger.info(f"OBSERVE rescheduling enabled: base interval {self.observe_base_s}s "
                    "while an OBSERVE request is active")

        await self.watch_deployments()

    async def stop(self) -> None:
        """Stop the Health Agent."""
        logger.info("Stopping Health Agent...")
        self.running = False

        if self.watcher:
            self.watcher.stop()

        if self._observe_task:
            task = self._observe_task
            self._observe_task = None
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
                logger.exception("Health OBSERVE task ended with an error")

        if self._serializer is not None:
            serializer, self._serializer = self._serializer, None
            await serializer.close()

        if self.redis:
            await self.redis.aclose()

        logger.info("Health Agent stopped")

    async def observe_loop(self) -> None:
        """Rescore known drift only while Fusion's bounded OBSERVE request is active."""
        try:
            while self.running:
                await asyncio.sleep(1)
                try:
                    await self.observe_tick()
                except Exception:
                    logger.exception("Health OBSERVE rescheduler pass failed; will retry")
        except asyncio.CancelledError:
            raise

    async def observe_tick(self) -> None:
        """Perform one scheduler pass; split out for deterministic unit tests."""
        if not self.redis or not self.observe_base_s:
            return
        now = self.clock()
        due = []
        for key, state in list(self._drifted.items()):
            namespace, name = key
            factor = await sampling_factor(self.redis, namespace, workload=name)
            interval = scaled_interval(self.observe_base_s, factor)
            if factor > 1 and now - state["last_assessed"] >= interval:
                # Advance before awaiting the handler so the next tick cannot duplicate it.
                state["last_assessed"] = now
                due.append(state["deployment"])
        for deployment in due:
            await self.handle_deployment_event("OBSERVE_SAMPLE", deployment)

    async def watch_deployments(self) -> None:
        """Watch Deployment changes, reconnecting across watch timeouts.

        K8s closes watch streams every few minutes; v3 exited on the first
        timeout. We wrap the watch in a reconnect loop, resume from the last
        resourceVersion, and restart on 410 Gone — the agent never exits on a
        normal timeout.
        """
        logger.info("Starting Deployment watch (reconnecting)...")
        resource_version = None
        while self.running:
            try:
                async with watch.Watch() as w:
                    self.watcher = w
                    async for event in w.stream(
                        self.apps_api.list_deployment_for_all_namespaces,
                        label_selector="kubeheal.io/watch=true",
                        resource_version=resource_version,
                        timeout_seconds=300,
                    ):
                        if not self.running:
                            break
                        obj = event["object"]
                        if obj.metadata and obj.metadata.resource_version:
                            resource_version = obj.metadata.resource_version
                        await self.handle_deployment_event(event["type"], obj)
            except asyncio.CancelledError:
                break
            except asyncio.TimeoutError:
                # Expected: the watch hit timeout_seconds with no new events.
                # Reconnect immediately, resuming from the last resourceVersion.
                logger.debug("Watch idle timeout; reconnecting")
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 410:   # resourceVersion too old → restart fresh
                    logger.warning("Watch expired (410); restarting fresh")
                    resource_version = None
                else:
                    logger.error(f"Watch API error: {e}; retry in 5s")
                    await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Watch error: {e}; reconnecting in 5s", exc_info=True)
                await asyncio.sleep(5)
        logger.info("Deployment watch stopped")

    async def handle_deployment_event(self, event_type: str, deployment) -> None:
        try:
            name = deployment.metadata.name
            namespace = deployment.metadata.namespace
            drift_key = (namespace, name)
            if event_type == "DELETED":
                self._drifted.pop(drift_key, None)
                if not self._workload_locks.get(drift_key, asyncio.Lock()).locked():
                    self._workload_locks.pop(drift_key, None)
                return
            lock = self._workload_locks.setdefault(drift_key, asyncio.Lock())
            if event_type == "OBSERVE_SAMPLE":
                # A periodic sample yields to any scoring already in flight for this workload.
                if lock.locked():
                    logger.info(f"Skipping OBSERVE sample for {namespace}/{name}: scoring in flight")
                    return
            async with lock:
                await self._handle_locked(event_type, deployment, namespace, name, drift_key)
        except Exception as e:
            logger.error(f"Error handling deployment event: {e}", exc_info=True)

    async def _handle_locked(self, event_type: str, deployment, namespace: str, name: str,
                             drift_key: Tuple[str, str]) -> None:
        try:
            logger.info(f"handle_deployment_event STARTED: {event_type}")
            generation = deployment.metadata.generation or 0
            observed_gen = deployment.status.observed_generation or 0

            logger.info(
                f"Event {event_type} for {namespace}/{name} gen={generation}, observed_gen={observed_gen}"
            )

            # TEMPORARILY DISABLED FOR DEMO - re-enable after baseline system is set up
            # should_skip = (generation == observed_gen and event_type == "MODIFIED")
            # if should_skip:
            #     logger.info(f"Skipping {namespace}/{name} - only status changed")
            #     return

            logger.info(f"Processing event for {namespace}/{name}...")

            # Scheduler-triggered samples are already bounded by the active OBSERVE key.
            # Watch events retain the regular cooldown to avoid duplicate scoring.
            in_cooldown = (event_type != "OBSERVE_SAMPLE" and
                           await self._check_cooldown(namespace, name))
            logger.info(f"Cooldown check for {namespace}/{name}: {in_cooldown}")
            if in_cooldown:
                # Keep a tracked workload pointed at its newest watch object. If it has
                # returned to baseline, stop scheduling it even though scoring is cooling down.
                state = self._drifted.get(drift_key)
                if state:
                    state["deployment"] = deployment
                    try:
                        golden = await baseline.load_baseline(self.redis, namespace, name)
                        if golden and not baseline.is_drifted(golden, self._spec_json(deployment)):
                            self._drifted.pop(drift_key, None)
                    except Exception as e:
                        logger.debug(f"Could not refresh tracked drift state for {namespace}/{name}: {e}")
                logger.info(f"Skipping {namespace}/{name} - in cooldown")
                return

            baseline_sha = await self._get_baseline_sha(namespace, name)

            if not await self._validate_baseline(namespace, name, baseline_sha):
                logger.warning(f"Baseline stale or invalid for {namespace}/{name}")
                return

            blast_radius = await self._query_blast_radius(namespace, deployment)

            # camelCase JSON, the same shape the API server stores and that a patch needs.
            new_spec = self._spec_json(deployment)

            # Golden baseline: SET NX on first sight, never overwritten (S-HA-2). The diff is
            # live versus golden (S-HA-3). The health model scores absolute state, so a spec
            # equal to the golden baseline (steady state, status-only event) is not assessed.
            golden, created = await baseline.get_or_set_baseline(
                self.redis, namespace, name, new_spec)
            if created:
                logger.info(f"Golden baseline recorded for {namespace}/{name}; no drift to assess")
                return
            if not baseline.is_drifted(golden, new_spec):
                self._drifted.pop(drift_key, None)
                logger.info(f"{namespace}/{name} matches its golden baseline; skipping assessment")
                return
            self._drifted.setdefault(drift_key, {
                "deployment": deployment,
                "last_assessed": self.clock(),
            })["deployment"] = deployment
            old_spec = golden["spec"]
            new_spec = baseline.drift_view(new_spec)
            logger.info(f"Spec drift vs golden baseline detected for {namespace}/{name}; assessing")

            # P5: a real 60-step query_range window (5 s step) per metric, with missing metrics
            # flagged. No window at all (Prometheus down, every metric empty) means no assessment:
            # the model must never be fed an invented all-zero window (fail closed).
            from agents.health_agent.prometheus_client import (
                wait_for_fresh_metric_window, PrometheusUnavailable,
            )
            try:
                window = await wait_for_fresh_metric_window(namespace, name, self.prometheus_url)
            except PrometheusUnavailable as e:
                logger.error(f"No Prometheus window for {namespace}/{name}: {e}; "
                             "no assessment published (fail closed)")
                return

            replicas = getattr(deployment.spec, "replicas", None) if deployment.spec else None
            assessment = await self._assess_health(
                namespace, name, old_spec, new_spec, window, blast_radius, replicas=replicas
            )

            if assessment:
                await self._publish_assessment(assessment)
                await self._set_cooldown(namespace, name)
                if drift_key in self._drifted:
                    self._drifted[drift_key]["last_assessed"] = self.clock()
                logger.info(f"Assessment {namespace}/{name}: "
                            f"health_risk={assessment['health_risk']:.2f} "
                            f"label={assessment['health_label']}")
            else:
                # The Health Model did not answer. Nothing is scored (fail closed), but the Fusion Agent is
                # told so a human hears about it (S-POL-1). No cooldown: the next drift event retries.
                await self._publish_model_unavailable(namespace, name)
        except Exception as e:
            logger.error(f"Error handling deployment event: {e}", exc_info=True)

    async def _check_cooldown(self, namespace: str, name: str) -> bool:
        """Check if resource is in cooldown period."""
        key = f"kubeheal:cooldown:{namespace}:{name}"
        return await self.redis.exists(key)

    async def _set_cooldown(self, namespace: str, name: str) -> None:
        """Set cooldown period."""
        key = f"kubeheal:cooldown:{namespace}:{name}"
        await self.redis.setex(key, self.cooldown_ttl, "1")

    async def _get_baseline_sha(self, namespace: str, name: str) -> Optional[str]:
        """Get baseline SHA from annotation."""
        try:
            deployment = await self.apps_api.read_namespaced_deployment(name, namespace)
            return deployment.metadata.annotations.get("kubeheal.io/baseline-sha")
        except Exception as e:
            logger.debug(f"Could not get baseline: {e}")
            return None

    async def _validate_baseline(
        self, namespace: str, name: str, baseline_sha: Optional[str]
    ) -> bool:
        """Validate baseline integrity. Returns False only on confirmed mismatch."""
        if not baseline_sha:
            return True

        try:
            cm = await self.core_api.read_namespaced_config_map(
                self.baseline_configmap, namespace
            )
            stored_sha = cm.data.get(name, "") if cm.data else ""

            if stored_sha and stored_sha != baseline_sha:
                logger.warning(f"Baseline SHA mismatch for {namespace}/{name}")
                return False

            annotation_date = await self._get_baseline_date(namespace, name)
            if annotation_date:
                age = datetime.utcnow() - annotation_date
                if age > timedelta(days=30):
                    logger.warning(f"Baseline stale (>30d) for {namespace}/{name} — reducing confidence")
                    # Don't block, but caller can reduce confidence score

            return True
        except Exception as e:
            logger.debug(f"Baseline validation skipped (ConfigMap not found): {e}")
            return True  # proceed if ConfigMap doesn't exist yet

    async def _get_baseline_date(self, namespace: str, name: str) -> Optional[datetime]:
        """Get baseline annotation date."""
        try:
            deployment = await self.apps_api.read_namespaced_deployment(name, namespace)
            date_str = deployment.metadata.annotations.get("kubeheal.io/baseline-date")
            if date_str:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except:
            pass
        return None

    def _spec_json(self, deployment) -> Dict:
        """Deployment spec as camelCase JSON (what kubectl and the patch API use)."""
        if not deployment.spec:
            return {}
        if self._serializer is None:
            self._serializer = client.ApiClient()
        return self._serializer.sanitize_for_serialization(deployment.spec)

    async def _query_blast_radius(self, namespace: str, deployment) -> str:
        """Query blast radius: Services + Ingresses."""
        selector = (
            deployment.spec.selector.match_labels or {}
            if deployment.spec and deployment.spec.selector
            else {}
        )

        try:
            services = await self.core_api.list_namespaced_service(
                namespace,
                label_selector=",".join([f"{k}={v}" for k, v in selector.items()]),
            )

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

    async def _fetch_telemetry(self, namespace: str, name: str) -> Dict:
        """Fetch Prometheus telemetry."""
        try:
            import aiohttp

            query = (
                f'avg(rate(container_cpu_usage_seconds_total{{namespace="{namespace}",'
                f'pod=~"{name}.*"}}[5s])) by (pod) * 100'
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.prometheus_url}/api/v1/query", params={"query": query}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", {}).get("result", [])

            return {}
        except Exception as e:
            logger.debug(f"Telemetry fetch error: {e}")
            return {}

    async def _assess_health(
        self,
        namespace: str,
        name: str,
        old_spec: Optional[Dict],
        new_spec: Dict,
        metrics,                 # MetricWindow (or a bare np.ndarray [60,15], treated as no missing info)
        blast_radius: str,
        replicas: Optional[int] = None,
    ) -> Optional[Dict]:
        """Score the drift with the v4 Health Model server. Returns a v4 dict
        (the schema the Fusion Agent + dashboard consume), or None when the
        server is unreachable or not ready (fail closed, no heuristic score)."""
        import aiohttp

        values = getattr(metrics, "values", metrics)
        missing = list(getattr(metrics, "missing", []) or [])
        payload = {
            "old_spec": old_spec or {},
            "new_spec": new_spec or {},
            "metrics": values.tolist() if hasattr(values, "tolist") else values,
            # Extra keys: the Health Model server ignores them today (ScoreRequest has no such field);
            # they are sent so the server can use the flags once it supports them (see P5 report).
            "metrics_missing": missing,
            # P5-Q2a: the server scales the RAW window with models/health_model/preprocess.py (the same
            # code as training). The replica count feeds the channel that held app_instance_count in training.
            "replicas": replicas,
        }
        result = None
        started = time.perf_counter()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.health_model_url}/health/score",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                    else:
                        logger.warning(f"Health Model returned {resp.status}")
        except Exception as e:
            logger.debug(f"Health Model call failed: {e}")
        METRICS.observe_model_latency("health", time.perf_counter() - started)

        event_id = f"health-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}-{name}"

        if result is None:
            # Fail closed (P1 review): no model score means no assessment. The old local heuristic
            # could emit risk 0.85 without a model, which can lead to an automatic action. The next
            # drift event for this workload is assessed again because no cooldown is set.
            logger.error(f"Health Model unavailable for {namespace}/{name}; "
                         "no assessment published (fail closed)")
            return None

        return {
            "event_id": event_id, "namespace": namespace, "pod_name": name,
                "deployment": name,
            # Explicit: True only because the Health Model answered. Fusion treats a missing value as false.
            "model_scored": True,
            "namespace_tier": namespace_tier(namespace),
            "health_risk": float(result.get("risk_score", 0.0)),
            "health_label": result.get("label", "benign"),
            # The Health Model server drops the missing-metric mask and scores the zero-filled columns, so
            # with any missing metric its interval is not trustworthy: publish the maximum width (the policy
            # then treats the assessment as uncertain) and keep the flags in metrics_missing_json. The
            # assessment itself is not dropped. The real fix is a mask-aware server (tracked for P6 or
            # later). The http_* columns will be missing for every workload that does not export them.
            "health_ci_width": 1.0 if missing else float(result.get("ci_width", 0.0)),
            "top_field": result.get("top_field", ""),
            "top_metric": result.get("top_metric", ""),
            "field_attribution": result.get("field_attention_weights", {}),
            "health_embedding": result.get("health_embedding", []),
            "patch_proposal": self._patch_from_field(result.get("top_field", ""), old_spec, new_spec),
            "blast_radius": blast_radius,
            "inference_method": "health_model_v4",
            # P5: which of the 15 metrics had no real data (their window columns were 0.0 placeholders).
            "metrics_missing": missing,
            "metrics_observed": dict(getattr(metrics, "observed", {}) or {}),
            **self._throttle_logging(values, missing),
        }

    @staticmethod
    def _throttle_logging(values, missing) -> Dict:
        """The REAL CFS throttle ratio is logged on its own: it is not a model input (the model's
        throttle channel is the usage/limit proxy it was trained with, models/health_model/preprocess.py)."""
        import numpy as np
        from models.health_model.preprocess import cfs_throttle_percent
        arr = np.asarray(values, dtype=np.float64)
        if arr.ndim != 2 or arr.shape[0] == 0 or "cpu_throttle_percent" in (missing or []):
            return {"cfs_throttle_percent": None}
        return {"cfs_throttle_percent": float(cfs_throttle_percent(arr)[-1])}

    def _patch_from_field(self, top_field: str, old_spec, new_spec) -> Optional[Dict]:
        """Propose restoring the highest-attribution field to its baseline value."""
        if not top_field or not old_spec:
            return None
        return {"restore_field": top_field, "note": "restore to recorded baseline"}

    def _local_assessment(self, new_spec: Dict, telemetry: Dict) -> Dict:
        """Local assessment fallback."""
        risk_score = 0.0
        patch_proposal = None
        explainability = {}

        containers = new_spec.get("template", {}).get("spec", {}).get("containers", [])

        for i, container in enumerate(containers):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})

            cpu_limit = str(limits.get("cpu", "0"))   # may be int in some specs
            if cpu_limit.endswith("m"):
                cpu_millicores = int(cpu_limit.rstrip("m"))
                if cpu_millicores < 100:
                    risk_score = max(risk_score, 0.85)
                    patch_proposal = {
                        "containers": [
                            {
                                "name": container["name"],
                                "resources": {"limits": {"cpu": "500m"}},
                            }
                        ]
                    }
                    explainability = {"cpu_limit": cpu_millicores, "attention": 0.89}

                elif cpu_millicores < 200:
                    risk_score = max(risk_score, 0.65)

        return {
            "risk_score": risk_score,
            "patch_proposal": patch_proposal,
            "explainability": explainability,
            "confidence_interval": (risk_score - 0.05, risk_score + 0.05)
            if risk_score > 0
            else None,
            "model_used": "heuristic",
            "model_score": None,
            "heuristic_score": risk_score,
            "inference_method": "Heuristic fallback (local assessment)",
        }

    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convert risk score to severity."""
        if score >= 0.85:
            return SeverityLevel.CRITICAL
        elif score >= 0.65:
            return SeverityLevel.HIGH
        elif score >= 0.40:
            return SeverityLevel.MEDIUM
        elif score >= 0.20:
            return SeverityLevel.LOW
        return SeverityLevel.BENIGN

    async def _publish_model_unavailable(self, namespace: str, name: str) -> None:
        """Tell the Fusion Agent that the Health Model did not answer for this workload. The event carries NO
        score and NO embedding: model_scored=false and model_unavailable=true, maximum CI width. Fusion does not
        decide on it; it escalates to a human once per workload and window. A publish failure is only logged
        (the drift event is assessed again next time)."""
        event_id = f"health-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}-{name}"
        payload = {
            "event_id": event_id, "namespace": namespace, "pod_name": name, "deployment": name,
            "namespace_tier": namespace_tier(namespace),
            "health_label": "model_unavailable",
            "health_ci_width": "1.0000",
            "model_scored": "false",
            "model_unavailable": "true",
            "inference_method": "none",
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        }
        try:
            await self.redis.xadd("kubeheal.health.events", payload)
            logger.error(f"Published {event_id}: Health Model unavailable for {namespace}/{name}")
        except Exception as e:
            logger.error(f"Could not publish the model_unavailable event for {namespace}/{name}: {e}")

    async def _publish_assessment(self, a: Dict) -> None:
        """Publish the v4 HealthAssessment schema (Section 15.A.1) to the
        kubeheal.health.events stream + a hash for dashboard detail lookup."""
        payload = {
            "event_id": a["event_id"],
            "namespace": a["namespace"],
            "pod_name": a["pod_name"],
            "deployment": a.get("deployment", a["pod_name"]),
            "namespace_tier": a["namespace_tier"],
            "health_risk": f"{a['health_risk']:.4f}",
            "health_label": a["health_label"],
            "model_scored": "true" if a.get("model_scored") is True else "false",
            "health_ci_width": f"{a['health_ci_width']:.4f}",
            "field_attribution_json": json.dumps(a.get("field_attribution", {})),
            "top_field": a.get("top_field", ""),
            "top_metric": a.get("top_metric", ""),
            "health_embedding_b64": emb_b64(a.get("health_embedding", [])),
            "patch_proposal_json": json.dumps(a.get("patch_proposal") or {}),
            "blast_radius": a.get("blast_radius", "unknown"),
            "inference_method": a.get("inference_method", ""),
            "metrics_missing_json": json.dumps(a.get("metrics_missing", [])),
            "metrics_observed_json": json.dumps(a.get("metrics_observed", {})),
            # real CFS ratio, last step, logged only ("" when unavailable); not a model input
            "cfs_throttle_percent": ("" if a.get("cfs_throttle_percent") is None
                                     else f"{a['cfs_throttle_percent']:.4f}"),
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        }
        await self.redis.xadd("kubeheal.health.events", payload)
        # hash (sans large embedding) for the dashboard detail endpoint
        hkey = f"kubeheal:health:{a['event_id']}"
        await self.redis.hset(hkey, mapping={k: v for k, v in payload.items()
                                             if k != "health_embedding_b64"})
        await self.redis.expire(hkey, 86400)
        logger.info(f"Published {a['event_id']}")


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
