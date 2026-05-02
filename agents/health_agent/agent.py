import asyncio
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

import aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, watch
from kubernetes_asyncio.config import load_incluster_config, load_config
from pydantic import BaseModel, Field

try:
    from .config import load_config as load_agent_config
    from .exceptions import K8sAPIError, RedisError, DitSecError, DitSecTimeoutError
    from .spec_differ import SpecDiffer
except ImportError:
    from config import load_config as load_agent_config
    from exceptions import K8sAPIError, RedisError, DitSecError, DitSecTimeoutError
    from spec_differ import SpecDiffer

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
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class HealthAgent:
    """
    Kubernetes operator for Health Agent.
    Watches YAML drift, assesses with DIT-Sec, publishes HealthAssessment.
    """

    def __init__(
        self,
        namespace: str = "kubeheal",
        redis_url: str = "redis://redis-master:6379",
        dit_sec_url: str = "http://dit-sec-server:8000",
        cooldown_ttl: int = 300,
        prometheus_url: str = "http://prometheus:9090",
    ):
        self.namespace = namespace
        self.redis_url = redis_url
        self.dit_sec_url = dit_sec_url
        self.cooldown_ttl = cooldown_ttl
        self.prometheus_url = prometheus_url

        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        self.custom_api: Optional[client.CustomObjectsApi] = None

        self.running = False
        self.watcher = None

        self.baseline_configmap = "kubeheal-baselines"

    async def start(self) -> None:
        """Start the Health Agent."""
        logger.info("Starting Health Agent...")

        try:
            await load_incluster_config()
        except kubernetes_asyncio.config.ConfigException:
            await load_config()

        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.custom_api = client.CustomObjectsApi()

        self.redis = await aioredis.create_redis_pool(self.redis_url)

        logger.info("Health Agent started successfully")

        await self.watch_deployments()

    async def stop(self) -> None:
        """Stop the Health Agent."""
        logger.info("Stopping Health Agent...")
        self.running = False

        if self.watcher:
            self.watcher.stop()

        if self.redis:
            self.redis.close()
            await self.redis.wait_closed()

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
                if not self.running:
                    break

                obj = event["object"]
                event_type = event["type"]

                await self.handle_deployment_event(event_type, obj)

    async def handle_deployment_event(self, event_type: str, deployment: Dict) -> None:
        """Handle Deployment watch event."""
        name = deployment["metadata"]["name"]
        namespace = deployment["metadata"]["namespace"]
        generation = deployment.get("metadata", {}).get("generation", 0)
        observed_gen = deployment.get("status", {}).get("observedGeneration", 0)

        logger.info(f"Event {event_type} for {namespace}/{name} gen={generation}")

        if generation == observed_gen and event_type == "MODIFIED":
            logger.debug("Skipping - only status changed")
            return

        if await self._check_cooldown(namespace, name):
            logger.debug("Skipping - in cooldown")
            return

        baseline_sha = await self._get_baseline_sha(namespace, name)

        if not await self._validate_baseline(namespace, name, baseline_sha):
            logger.warning(f"Baseline stale or invalid for {namespace}/{name}")
            return

        blast_radius = await self._query_blast_radius(namespace, deployment)

        old_spec = await self._get_previous_spec(namespace, name)
        new_spec = deployment.get("spec", {})

        await asyncio.sleep(15)

        telemetry = await self._fetch_telemetry(namespace, name)

        assessment = await self._assess_health(
            namespace, name, old_spec, new_spec, telemetry, blast_radius
        )

        if assessment:
            await self._publish_assessment(assessment)
            await self._set_cooldown(namespace, name)

            logger.info(f"Assessment: risk_score={assessment.risk_score:.2f}")

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
        """Validate baseline integrity."""
        if not baseline_sha:
            return True

        try:
            cm = await self.core_api.read_namespaced_config_map(
                self.baseline_configmap, namespace
            )
            stored_sha = cm.data.get(name, "")

            if stored_sha != baseline_sha:
                logger.warning(f"Baseline SHA mismatch for {namespace}/{name}")
                return False

            annotation_date = await self._get_baseline_date(namespace, name)
            if annotation_date:
                age = datetime.utcnow() - annotation_date
                if age > timedelta(days=30):
                    logger.warning(f"Baseline >30 days old for {namespace}/{name}")
                    return False

            return True
        except Exception as e:
            logger.debug(f"Baseline validation error: {e}")
            return True

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

    async def _query_blast_radius(self, namespace: str, deployment: Dict) -> str:
        """Query blast radius: Services + Ingresses."""
        selector = deployment.get("spec", {}).get("selector", {})

        try:
            services = await self.core_api.list_namespaced_service(
                namespace,
                label_selector=",".join([f"{k}={v}" for k, v in selector.items()]),
            )

            for svc in services.items:
                if svc.spec.type == "LoadBalancer":
                    return "High"

            ingresses = await self.core_api.list_namespaced_ingress(namespace)

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
        telemetry: Dict,
        blast_radius: str,
    ) -> Optional[HealthAssessment]:
        """Assess health with DIT-Sec model."""
        try:
            import aiohttp

            payload = {
                "old_spec": old_spec,
                "new_spec": new_spec,
                "telemetry": telemetry,
                "blast_radius": blast_radius,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.dit_sec_url}/score",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                    else:
                        result = self._local_assessment(new_spec, telemetry)
        except Exception as e:
            logger.debug(f"DIT-Sec call failed: {e}")
            result = self._local_assessment(new_spec, telemetry)

        if not result:
            return None

        event_id = f"health-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{name}"

        return HealthAssessment(
            event_id=event_id,
            target={"namespace": namespace, "name": name, "kind": "Deployment"},
            risk_score=result.get("risk_score", 0.0),
            severity=self._score_to_severity(result.get("risk_score", 0.0)),
            patch_proposal=result.get("patch_proposal"),
            explainability=result.get("explainability"),
            confidence_interval=result.get("confidence_interval"),
            blast_radius=blast_radius,
        )

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

    async def _publish_assessment(self, assessment: HealthAssessment) -> None:
        """Publish HealthAssessment to Redis Stream."""
        key = f"kubeheal:health:{assessment.event_id}"

        await self.redis.hset(
            key,
            mapping={
                "event_id": assessment.event_id,
                "target": json.dumps(assessment.target),
                "risk_score": str(assessment.risk_score),
                "severity": assessment.severity.value,
                "patch_proposal": json.dumps(assessment.patch_proposal)
                if assessment.patch_proposal
                else "",
                "explainability": json.dumps(assessment.explainability)
                if assessment.explainability
                else "",
                "blast_radius": assessment.blast_radius,
                "timestamp": assessment.timestamp,
            },
        )

        await self.redis.xadd(
            "kubeheal.health.events",
            {
                "event_id": assessment.event_id,
                "target": json.dumps(assessment.target),
                "risk_score": str(assessment.risk_score),
                "severity": assessment.severity.value,
                "blast_radius": assessment.blast_radius,
                "confidence_interval": str(assessment.confidence_interval),
                "timestamp": assessment.timestamp,
            },
        )

        logger.info(f"Published {assessment.event_id}")


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
