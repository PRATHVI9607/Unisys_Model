import asyncio
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import numpy as np

import aioredis
from pydantic import BaseModel, Field

# Kubernetes client imports - conditionally imported for testing
try:
    from kubernetes import client as k8s_client
    from kubernetes import watch as k8s_watch
    from kubernetes.config import load_incluster_config, load_config
except ImportError:
    # Mock for testing environments
    k8s_client = None
    k8s_watch = None
    load_incluster_config = None
    load_config = None

try:
    from .config import HealthAgentConfig
    from .exceptions import K8sAPIError, RedisError, DitSecError, DitSecTimeoutError
    from .spec_differ import SpecDiffer
except ImportError:
    from config import HealthAgentConfig
    from exceptions import K8sAPIError, RedisError, DitSecError, DitSecTimeoutError
    from spec_differ import SpecDiffer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to load trained DIT-Sec v3.0 model for inference
_DITSEC_MODEL = None
try:
    # Look for inference module in parent directory structure
    import sys

    project_root = Path(__file__).parent.parent.parent
    models_path = project_root / "models" / "dit_sec_v3"
    if models_path.exists():
        sys.path.insert(0, str(models_path))
        from inference import DITSecInference

        _DITSEC_MODEL = DITSecInference(device="cpu")
        logger.info("✓ Loaded DIT-Sec v3.0 trained model for inference")
except Exception as e:
    logger.warning(f"Could not load trained DIT-Sec model: {e}")
    _DITSEC_MODEL = None


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
        """
        Local assessment with DIT-Sec v3.0 trained model.

        Falls back to simple heuristics if model not loaded.
        """
        # If trained model is available, use it
        if _DITSEC_MODEL is not None:
            try:
                return self._model_based_assessment(new_spec, telemetry)
            except Exception as e:
                logger.warning(f"Model assessment failed, using fallback: {e}")

        # Fallback to simple heuristics
        return self._heuristic_assessment(new_spec, telemetry)

    def _model_based_assessment(self, new_spec: Dict, telemetry: Dict) -> Dict:
        """
        Assessment using DIT-Sec v3.0 trained model.

        Extracts 32D feature vector (12D YAML + 14D telemetry + 6D drift)
        and runs inference on trained model.
        """
        try:
            # Extract YAML features (12D)
            yaml_features = self._extract_yaml_features(new_spec)

            # Extract telemetry features (14D)
            telemetry_features = self._extract_telemetry_features(telemetry)

            # Extract drift semantics (6D)
            drift_features = self._extract_drift_features(new_spec, telemetry)

            # Stack into single feature vector (1, 32)
            yaml_arr = np.array(yaml_features, dtype=np.float32).reshape(1, 12)
            telem_arr = np.array(telemetry_features, dtype=np.float32).reshape(1, 14)
            drift_arr = np.array(drift_features, dtype=np.float32).reshape(1, 6)

            # Run inference
            result = _DITSEC_MODEL.predict(
                yaml_arr, telem_arr, drift_arr, return_probabilities=True
            )

            # Map model class to risk score
            class_name = result["class_name"]
            class_confidence = result["class_confidence"]

            # Map DIT-Sec classes to risk scores
            class_to_risk = {
                "Benign_Or_Subtle": 0.1,
                "Harmful_Performance_Degradation": 0.6,
                "Harmful_Security_Breach": 0.9,
                "Harmful_Multi_Vector": 0.85,
                "Harmful_Critical_Outage": 0.95,
            }

            base_risk = class_to_risk.get(class_name, 0.5)
            # Adjust risk by confidence
            risk_score = base_risk * class_confidence

            return {
                "risk_score": float(risk_score),
                "patch_proposal": None,  # Model doesn't generate patches
                "explainability": {
                    "model": "DIT-Sec v3.0",
                    "class": class_name,
                    "confidence": float(class_confidence),
                    "severity_level": result.get("severity_name", "unknown"),
                    "class_probabilities": result.get("class_probabilities", {}),
                },
                "confidence_interval": (
                    max(0, risk_score - 0.1),
                    min(1, risk_score + 0.1),
                ),
            }
        except Exception as e:
            logger.error(f"Model-based assessment failed: {e}")
            raise

    def _extract_yaml_features(self, spec: Dict) -> List[float]:
        """
        Extract 12D YAML configuration features.

        Features:
        1. CPU limit normalized
        2. Memory limit normalized
        3. Replica count normalized
        4. Image pull policy (0/1)
        5. Security context presence (0/1)
        6. Service account presence (0/1)
        7. Resource requests presence (0/1)
        8. Volume mounts count normalized
        9. Env vars count normalized
        10. Labels count normalized
        11. Annotations count normalized
        12. Init containers count normalized
        """
        features = []
        containers = spec.get("template", {}).get("spec", {}).get("containers", [])

        if not containers:
            return [0.0] * 12

        container = containers[0]  # Use first container
        resources = container.get("resources", {})
        limits = resources.get("limits", {})

        # 1. CPU limit (normalize to 0-1, assume 0-4000 millicores)
        cpu_limit = limits.get("cpu", "0")
        if isinstance(cpu_limit, str) and cpu_limit.endswith("m"):
            cpu_millicores = int(cpu_limit.rstrip("m"))
        else:
            cpu_millicores = int(cpu_limit) * 1000 if cpu_limit else 0
        features.append(min(cpu_millicores / 4000.0, 1.0))

        # 2. Memory limit (normalize to 0-1, assume 0-4Gi)
        mem_limit = limits.get("memory", "0")
        if isinstance(mem_limit, str) and mem_limit.endswith("Mi"):
            mem_mi = int(mem_limit.rstrip("Mi"))
        elif isinstance(mem_limit, str) and mem_limit.endswith("Gi"):
            mem_mi = int(mem_limit.rstrip("Gi")) * 1024
        else:
            mem_mi = int(mem_limit) if mem_limit else 0
        features.append(min(mem_mi / 4096.0, 1.0))

        # 3. Replica count (normalize to 0-1, assume 0-100 replicas)
        replicas = spec.get("replicas", 1)
        features.append(min(replicas / 100.0, 1.0))

        # 4. Image pull policy (0=IfNotPresent, 1=Always)
        pull_policy = container.get("imagePullPolicy", "IfNotPresent")
        features.append(1.0 if pull_policy == "Always" else 0.0)

        # 5. Security context presence
        sec_context = spec.get("template", {}).get("spec", {}).get("securityContext")
        features.append(1.0 if sec_context else 0.0)

        # 6. Service account presence
        sa_name = spec.get("template", {}).get("spec", {}).get("serviceAccountName")
        features.append(1.0 if sa_name else 0.0)

        # 7. Resource requests presence
        requests = resources.get("requests", {})
        features.append(1.0 if requests else 0.0)

        # 8. Volume mounts count (normalize to 0-1)
        vol_mounts = container.get("volumeMounts", [])
        features.append(min(len(vol_mounts) / 10.0, 1.0))

        # 9. Environment variables count (normalize to 0-1)
        env_vars = container.get("env", [])
        features.append(min(len(env_vars) / 30.0, 1.0))

        # 10. Labels count (normalize to 0-1)
        labels = spec.get("template", {}).get("metadata", {}).get("labels", {})
        features.append(min(len(labels) / 20.0, 1.0))

        # 11. Annotations count (normalize to 0-1)
        annotations = (
            spec.get("template", {}).get("metadata", {}).get("annotations", {})
        )
        features.append(min(len(annotations) / 20.0, 1.0))

        # 12. Init containers count (normalize to 0-1)
        init_containers = (
            spec.get("template", {}).get("spec", {}).get("initContainers", [])
        )
        features.append(min(len(init_containers) / 5.0, 1.0))

        return features

    def _extract_telemetry_features(self, telemetry: Dict) -> List[float]:
        """
        Extract 14D telemetry features from Prometheus metrics.

        Features (normalized to -2 to +2 range):
        1-7. CPU usage, memory usage, disk I/O, network I/O, request rate,
             error rate, latency
        8-14. Same as above but as 1-hour averages
        """
        features = [0.0] * 14

        # Try to extract from telemetry dict
        # This is a placeholder - actual implementation depends on telemetry format
        if isinstance(telemetry, dict):
            # Current metrics (1-7)
            features[0] = min(telemetry.get("cpu_usage", 0) / 50.0, 2.0)  # CPU %
            features[1] = min(telemetry.get("memory_usage", 0) / 80.0, 2.0)  # Mem %
            features[2] = min(telemetry.get("disk_io", 0) / 100.0, 2.0)  # Disk I/O MB/s
            features[3] = min(
                telemetry.get("network_io", 0) / 100.0, 2.0
            )  # Network Mbps
            features[4] = min(
                telemetry.get("request_rate", 0) / 1000.0, 2.0
            )  # Requests/s
            features[5] = min(telemetry.get("error_rate", 0) / 50.0, 2.0)  # Errors/s
            features[6] = min(
                telemetry.get("latency_ms", 0) / 1000.0, 2.0
            )  # Latency ms

            # 1-hour averages (8-14)
            features[7:] = features[0:7]  # Use same for simplicity

        return features

    def _extract_drift_features(self, new_spec: Dict, telemetry: Dict) -> List[float]:
        """
        Extract 6D drift semantics features.

        Features:
        1. Change magnitude (0-1)
        2. Breaking change presence (0-1)
        3. Resource change (0-1)
        4. Config change (0-1)
        5. Security change (0-1)
        6. Performance impact potential (0-1)
        """
        features = []

        # 1. Change magnitude (count of top-level keys changed)
        change_magnitude = 0.0  # Assume new deployment
        features.append(min(change_magnitude / 10.0, 1.0))

        # 2. Breaking change presence (heuristic: security context or image changes)
        has_breaking = 0.0
        if "securityContext" in str(new_spec):
            has_breaking = 1.0
        features.append(has_breaking)

        # 3. Resource change (presence of resource limits/requests)
        containers = new_spec.get("template", {}).get("spec", {}).get("containers", [])
        has_resource_change = (
            1.0 if any(c.get("resources") for c in containers) else 0.0
        )
        features.append(has_resource_change)

        # 4. Config change (env vars or volume changes)
        has_config_change = (
            1.0
            if any(c.get("env") or c.get("volumeMounts") for c in containers)
            else 0.0
        )
        features.append(has_config_change)

        # 5. Security change (security context or rbac)
        has_security_change = (
            1.0
            if any(
                "security" in str(c).lower() or "rbac" in str(new_spec).lower()
                for c in containers
            )
            else 0.0
        )
        features.append(has_security_change)

        # 6. Performance impact potential (resource limits reduction)
        has_perf_impact = 0.0
        for container in containers:
            cpu_limit = container.get("resources", {}).get("limits", {}).get("cpu", "")
            if isinstance(cpu_limit, str) and cpu_limit.endswith("m"):
                cpu_millicores = int(cpu_limit.rstrip("m"))
                if cpu_millicores < 200:  # Low CPU limit
                    has_perf_impact = 1.0
        features.append(has_perf_impact)

        return features

    def _heuristic_assessment(self, new_spec: Dict, telemetry: Dict) -> Dict:
        """Fallback heuristic assessment (original implementation)."""
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
