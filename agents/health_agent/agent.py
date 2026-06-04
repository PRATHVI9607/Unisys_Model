import asyncio
import base64
import json
import logging
import hashlib
import os
import struct
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, watch, config
from kubernetes_asyncio.config import load_incluster_config
from pydantic import BaseModel, Field


def emb_b64(vec) -> str:
    """Pack a float list as base64 float32 bytes for the Redis stream."""
    vec = list(vec or [])
    return base64.b64encode(struct.pack(f"{len(vec)}f", *vec)).decode() if vec else ""


def namespace_tier(namespace: str) -> str:
    """Map a namespace to its risk tier (prod / staging / dev)."""
    n = (namespace or "").lower()
    if "prod" in n:
        return "prod"
    if "stag" in n:
        return "staging"
    return "dev"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HealthAssessment(BaseModel):
    event_id: str
    target: Dict[str, str]
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    patch_proposal: Optional[Dict[str, Any]] = None
    explainability: Optional[Dict[str, Any]] = None
    confidence_interval: Optional[Tuple[float, float]] = None
    blast_radius: str = "unknown"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    # New fields from DIT-Sec model comparison
    model_used: Optional[str] = None  # "pytorch" or "heuristic"
    model_score: Optional[float] = None  # Score from ONNX model, 0-1
    heuristic_score: Optional[float] = None  # Score from heuristic, 0-1
    inference_method: Optional[str] = (
        None  # e.g., "ONNX inference" or "Heuristic fallback"
    )


class HealthAgent:
    """
    Kubernetes operator for Health Agent.
    Watches YAML drift, assesses with DIT-Sec, publishes HealthAssessment.
    """

    def __init__(
        self,
        namespace: str = "kubeheal",
        redis_url: str = None,
        dit_sec_url: str = None,
        cooldown_ttl: int = 300,
        prometheus_url: str = None,
    ):
        self.namespace = namespace
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://redis-master:6379")
        # v4: dedicated Health Model server (was the v3 DIT-Sec monolith)
        self.health_model_url = dit_sec_url or os.environ.get(
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

        self.redis = aioredis.from_url(self.redis_url)

        logger.info("Health Agent started successfully")

        await self.watch_deployments()

    async def stop(self) -> None:
        """Stop the Health Agent."""
        logger.info("Stopping Health Agent...")
        self.running = False

        if self.watcher:
            self.watcher.stop()

        if self.redis:
            await self.redis.aclose()

        logger.info("Health Agent stopped")

    async def watch_deployments(self) -> None:
        """Watch for Deployment changes in all namespaces."""
        logger.info("Starting Deployment watch...")

        async with watch.Watch() as w:
            self.watcher = w
            self.running = True

            async for event in w.stream(
                self.apps_api.list_deployment_for_all_namespaces,
                label_selector="kubeheal.io/watch=true",
                resource_version=None,
            ):
                logger.info(f"Watch loop received event: {event['type']}")
                if not self.running:
                    break

                obj = event["object"]
                event_type = event["type"]

                await self.handle_deployment_event(event_type, obj)
                logger.info(f"handle_deployment_event returned for {event_type}")

    async def handle_deployment_event(self, event_type: str, deployment) -> None:
        try:
            logger.info(f"handle_deployment_event STARTED: {event_type}")
            name = deployment.metadata.name
            namespace = deployment.metadata.namespace
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

            in_cooldown = await self._check_cooldown(namespace, name)
            logger.info(f"Cooldown check for {namespace}/{name}: {in_cooldown}")
            if in_cooldown:
                logger.info(f"Skipping {namespace}/{name} - in cooldown")
                return

            baseline_sha = await self._get_baseline_sha(namespace, name)

            if not await self._validate_baseline(namespace, name, baseline_sha):
                logger.warning(f"Baseline stale or invalid for {namespace}/{name}")
                return

            blast_radius = await self._query_blast_radius(namespace, deployment)

            old_spec = await self._get_previous_spec(namespace, name)
            new_spec = deployment.spec.to_dict() if deployment.spec else {}
            await self._save_spec(namespace, name, new_spec)

            # v4: poll for fresh 60×15 Prometheus window (shared cache, backoff)
            # — replaces the v3 hard-coded sleep(15) + single-metric fetch.
            from agents.health_agent.prometheus_client import wait_for_fresh_metrics
            metrics = await wait_for_fresh_metrics(namespace, name, self.prometheus_url)

            assessment = await self._assess_health(
                namespace, name, old_spec, new_spec, metrics, blast_radius
            )

            if assessment:
                await self._publish_assessment(assessment)
                await self._set_cooldown(namespace, name)
                logger.info(f"Assessment {namespace}/{name}: "
                            f"health_risk={assessment['health_risk']:.2f} "
                            f"label={assessment['health_label']}")
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

    async def _get_previous_spec(self, namespace: str, name: str) -> Optional[Dict]:
        """Get previous spec from cache."""
        key = f"kubeheal:spec:{namespace}:{name}"
        spec = await self.redis.get(key)
        if spec:
            return json.loads(spec)
        return None

    async def _save_spec(self, namespace: str, name: str, spec: Dict) -> None:
        """Save current spec to cache for next comparison."""
        key = f"kubeheal:spec:{namespace}:{name}"
        await self.redis.set(key, json.dumps(spec))

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
        metrics,                 # np.ndarray [60,15] from wait_for_fresh_metrics
        blast_radius: str,
    ) -> Optional[Dict]:
        """Score the drift with the v4 Health Model server. Returns a v4 dict
        (the schema the Fusion Agent + dashboard consume), or a heuristic
        fallback if the server is unreachable."""
        import aiohttp

        payload = {
            "old_spec": old_spec or {},
            "new_spec": new_spec or {},
            "metrics": metrics.tolist() if hasattr(metrics, "tolist") else metrics,
        }
        result = None
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

        event_id = f"health-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}-{name}"

        if result is None:
            # local heuristic fallback → still emit the v4 schema
            local = self._local_assessment(new_spec, {})
            return {
                "event_id": event_id, "namespace": namespace, "pod_name": name,
                "namespace_tier": namespace_tier(namespace),
                "health_risk": float(local["risk_score"]),
                "health_label": local.get("model_used", "heuristic"),
                "health_ci_width": 1.0,            # unknown → max uncertainty
                "top_field": "", "field_attribution": {},
                "health_embedding": [], "patch_proposal": local.get("patch_proposal"),
                "blast_radius": blast_radius, "inference_method": "heuristic_fallback",
            }

        return {
            "event_id": event_id, "namespace": namespace, "pod_name": name,
            "namespace_tier": namespace_tier(namespace),
            "health_risk": float(result.get("risk_score", 0.0)),
            "health_label": result.get("label", "benign"),
            "health_ci_width": float(result.get("ci_width", 0.0)),
            "top_field": result.get("top_field", ""),
            "top_metric": result.get("top_metric", ""),
            "field_attribution": result.get("field_attention_weights", {}),
            "health_embedding": result.get("health_embedding", []),
            "patch_proposal": self._patch_from_field(result.get("top_field", ""), old_spec, new_spec),
            "blast_radius": blast_radius,
            "inference_method": "health_model_v4",
        }

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

            cpu_limit = limits.get("cpu", "0")
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

    async def _publish_assessment(self, a: Dict) -> None:
        """Publish the v4 HealthAssessment schema (Section 15.A.1) to the
        kubeheal.health.events stream + a hash for dashboard detail lookup."""
        payload = {
            "event_id": a["event_id"],
            "namespace": a["namespace"],
            "pod_name": a["pod_name"],
            "namespace_tier": a["namespace_tier"],
            "health_risk": f"{a['health_risk']:.4f}",
            "health_label": a["health_label"],
            "health_ci_width": f"{a['health_ci_width']:.4f}",
            "field_attribution_json": json.dumps(a.get("field_attribution", {})),
            "top_field": a.get("top_field", ""),
            "top_metric": a.get("top_metric", ""),
            "health_embedding_b64": emb_b64(a.get("health_embedding", [])),
            "patch_proposal_json": json.dumps(a.get("patch_proposal") or {}),
            "blast_radius": a.get("blast_radius", "unknown"),
            "inference_method": a.get("inference_method", ""),
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
    agent = HealthAgent()

    try:
        await agent.start()
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
