import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, config
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    AUTO_KILL = "auto_kill"
    AUTO_PATCH = "auto_patch"
    HUMAN_APPROVAL = "human_approval"
    OBSERVE = "observe"
    BENIGN = "benign"


class DecisionResult(BaseModel):
    action: ActionType
    target: Dict[str, str]
    adjusted_score: float
    circuit_breaker_state: Optional[Dict[str, Any]] = None
    message: str = ""


class FusionAgent:
    """
    Fusion Agent - correlates Health + Security events, makes decisions.
    Implements decision policy with circuit breakers, namespace tiers.
    """
    
    def __init__(
        self,
        namespace: str = "kubeheal",
        redis_url: str = "redis://redis-master:6379",
        max_auto_kill_per_ns_per_hour: int = 3,
        max_auto_patch_per_dep_per_hour: int = 10,
        ci_width_threshold: float = 0.15,
        namespace_tiers: Dict[str, float] = None
    ):
        self.namespace = namespace
        self.redis_url = redis_url
        self.max_auto_kill_per_ns_per_hour = max_auto_kill_per_ns_per_hour
        self.max_auto_patch_per_dep_per_hour = max_auto_patch_per_dep_per_hour
        self.ci_width_threshold = ci_width_threshold
        
        self.namespace_tiers = namespace_tiers or {
            "prod": 1.20,
            "staging": 1.00,
            "dev": 0.70
        }
        
        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        
        self.running = False
        
        self.active_incidents: Dict[str, Dict] = {}
        
        self.decision_counts: Dict[str, int] = defaultdict(int)
    
    async def start(self) -> None:
        """Start the Fusion Agent."""
        logger.info("Starting Fusion Agent...")
        
        try:
            await config.load_incluster_config()
        except config.ConfigException:
            await config.load_config()
        
        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        
        self.redis = aioredis.from_url(self.redis_url)

        logger.info("Fusion Agent started successfully")

        self.running = True
        await self._consume_events()
    
    async def stop(self) -> None:
        """Stop the Fusion Agent."""
        logger.info("Stopping Fusion Agent...")
        self.running = False
        
        if self.redis:
            await self.redis.aclose()
        
        logger.info("Fusion Agent stopped")
    
    async def _consume_events(self) -> None:
        """Consume events from Redis Streams."""
        logger.info("Consuming events from Redis Streams...")
        
        last_ids = {
            "kubeheal.health.events": "0",
            "kubeheal.security.events": "0"
        }
        
        while self.running:
            try:
                for stream_name, last_id in last_ids.items():
                    messages = await self.redis.xread(
                        {stream_name: last_id},
                        count=10,
                        block=1000
                    )
                    
                    if messages:
                        for stream, entries in messages:
                            for msg_id, fields in entries:
                                last_ids[stream_name] = msg_id.decode() if isinstance(msg_id, bytes) else msg_id

                                if stream_name == "kubeheal.health.events":
                                    await self._handle_health_event(msg_id, fields)
                                elif stream_name == "kubeheal.security.events":
                                    await self._handle_security_event(msg_id, fields)
                
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Event consume error: {e}")
                await asyncio.sleep(1)
    
    async def _handle_health_event(self, msg_id: str, fields: Dict) -> None:
        """Handle Health Assessment event."""
        try:
            event = {
                "event_id": fields.get(b"event_id", b"").decode(),
                "target": json.loads(fields.get(b"target", b"{}")),
                "risk_score": float(fields.get(b"risk_score", b"0")),
                "severity": fields.get(b"severity", b"benign").decode(),
                "blast_radius": fields.get(b"blast_radius", b"unknown").decode(),
                "confidence_interval": json.loads(fields.get(b"confidence_interval", b"null")),
                "timestamp": fields.get(b"timestamp", b"").decode()
            }
            
            await self._process_decision(event, "health")
            
            await self.redis.xack("kubeheal.health.events", "fusion", msg_id)
        except Exception as e:
            logger.debug(f"Health event error: {e}")
    
    async def _handle_security_event(self, msg_id: str, fields: Dict) -> None:
        """Handle Security Event."""
        try:
            event = {
                "event_id": fields.get(b"event_id", b"").decode(),
                "target": json.loads(fields.get(b"target", b"{}")),
                "risk_score": float(fields.get(b"risk_score", b"0")),
                "label": fields.get(b"label", b"benign").decode(),
                "early_signals": json.loads(fields.get(b"early_signals", b"{}")),
                "timestamp": fields.get(b"timestamp", b"").decode()
            }
            
            await self._process_decision(event, "security")
            
            await self.redis.xack("kubeheal.security.events", "fusion", msg_id)
        except Exception as e:
            logger.debug(f"Security event error: {e}")
    
    async def _process_decision(self, event: Dict, event_type: str) -> None:
        """Process decision for event."""
        target = event.get("target", {})
        namespace = target.get("namespace", "default")
        pod_name = target.get("name", target.get("pod", "unknown"))
        
        incident_key = f"{namespace}:{pod_name}"
        
        if await self._acquire_incident_lock(namespace, pod_name):
            logger.debug(f"Lock acquired for {incident_key}")
        else:
            logger.debug(f"Incident already active for {incident_key}")
            return
        
        try:
            risk_score = event.get("risk_score", 0.0)
            
            tier = await self._get_namespace_tier(namespace)
            tier_multiplier = self.namespace_tiers.get(tier, 1.0)
            adjusted_score = risk_score * tier_multiplier
            
            ci_width = self._parse_confidence_interval(event.get("confidence_interval"))
            
            if ci_width and ci_width > self.ci_width_threshold:
                result = await self._decide_human_escalation(
                    event, adjusted_score, "wide_ci"
                )
                await self._publish_action(result)
                return
            
            label = event.get("label", event.get("severity", "benign"))
            
            if event_type == "security" and adjusted_score >= 0.85:
                result = await self._decide_auto_kill(event, adjusted_score, label)
            elif event_type == "health" and adjusted_score >= 0.85:
                result = await self._decide_auto_patch(event, adjusted_score)
            elif adjusted_score >= 0.65:
                result = await self._decide_human_approval(event, adjusted_score)
            elif adjusted_score >= 0.40:
                result = await self._decide_observe(event, adjusted_score)
            else:
                result = await self._decide_benign(event, adjusted_score)
            
            await self._publish_action(result)
            
            await self._log_incident(event, result, event_type)
            
        finally:
            await self._release_incident_lock(namespace, pod_name)
    
    async def _acquire_incident_lock(self, namespace: str, pod_name: str) -> bool:
        """Acquire incident lock using Redis SETNX."""
        key = f"kubeheal:incident-lock:{namespace}:{pod_name}"
        result = await self.redis.set(key, "1", nx=True, ex=30)
        return result
    
    async def _release_incident_lock(self, namespace: str, pod_name: str) -> None:
        """Release incident lock."""
        key = f"kubeheal:incident-lock:{namespace}:{pod_name}"
        await self.redis.delete(key)
    
    async def _get_namespace_tier(self, namespace: str) -> str:
        """Get namespace tier."""
        try:
            ns = await self.core_api.read_namespace(namespace)
            tier = ns.metadata.labels.get("kubeheal.io/namespace-tier")
            if tier:
                return tier
        except:
            pass
        
        if "prod" in namespace:
            return "prod"
        elif "staging" in namespace:
            return "staging"
        else:
            return "dev"
    
    def _parse_confidence_interval(self, ci: Any) -> Optional[float]:
        """Parse confidence interval to get width."""
        if not ci:
            return None
        
        try:
            if isinstance(ci, str):
                ci = json.loads(ci)
            
            if isinstance(ci, list) and len(ci) == 2:
                return abs(ci[1] - ci[0])
        except:
            pass
        
        return None
    
    async def _decide_auto_kill(
        self,
        event: Dict,
        adjusted_score: float,
        label: str
    ) -> DecisionResult:
        """Decide AUTO-KILL."""
        namespace = event.get("target", {}).get("namespace", "default")
        
        cb_key = f"kubeheal:cb:{namespace}"
        cb_count = await self.redis.incr(cb_key)
        
        if cb_count and cb_count <= self.max_auto_kill_per_ns_per_hour:
            return DecisionResult(
                action=ActionType.AUTO_KILL,
                target=event.get("target", {}),
                adjusted_score=adjusted_score,
                circuit_breaker_state={"count": cb_count, "limit": self.max_auto_kill_per_ns_per_hour},
                message=f"Auto-kill approved (CB: {cb_count}/{self.max_auto_kill_per_ns_per_hour})"
            )
        
        return DecisionResult(
            action=ActionType.HUMAN_APPROVAL,
            target=event.get("target", {}),
            adjusted_score=adjusted_score,
            message=f"Circuit breaker reached ({cb_count}), escalating to human"
        )
    
    async def _decide_auto_patch(
        self,
        event: Dict,
        adjusted_score: float
    ) -> DecisionResult:
        """Decide AUTO-PATCH."""
        namespace = event.get("target", {}).get("namespace", "default")
        name = event.get("target", {}).get("name", "unknown")
        
        cb_key = f"kubeheal:patch:{namespace}:{name}"
        patch_count = await self.redis.incr(cb_key)
        
        if patch_count and patch_count <= self.max_auto_patch_per_dep_per_hour:
            return DecisionResult(
                action=ActionType.AUTO_PATCH,
                target=event.get("target", {}),
                adjusted_score=adjusted_score,
                circuit_breaker_state={"count": patch_count, "limit": self.max_auto_patch_per_dep_per_hour},
                message=f"Auto-patch approved (CB: {patch_count}/{self.max_auto_patch_per_dep_per_hour})"
            )
        
        return DecisionResult(
            action=ActionType.HUMAN_APPROVAL,
            target=event.get("target", {}),
            adjusted_score=adjusted_score,
            message=f"Too many patches, human approval required"
        )
    
    async def _decide_human_approval(
        self,
        event: Dict,
        adjusted_score: float
    ) -> DecisionResult:
        """Decide human approval required."""
        return DecisionResult(
            action=ActionType.HUMAN_APPROVAL,
            target=event.get("target", {}),
            adjusted_score=adjusted_score,
            message="Score in medium range, human approval required"
        )
    
    async def _decide_observe(
        self,
        event: Dict,
        adjusted_score: float
    ) -> DecisionResult:
        """Decide observe (increase monitoring)."""
        return DecisionResult(
            action=ActionType.OBSERVE,
            target=event.get("target", {}),
            adjusted_score=adjusted_score,
            message=f"Low risk, monitoring increased"
        )
    
    async def _decide_benign(
        self,
        event: Dict,
        adjusted_score: float
    ) -> DecisionResult:
        """Decide benign (dismiss)."""
        return DecisionResult(
            action=ActionType.BENIGN,
            target=event.get("target", {}),
            adjusted_score=adjusted_score,
            message="Event marked benign"
        )
    
    async def _decide_human_escalation(
        self,
        event: Dict,
        adjusted_score: float,
        reason: str
    ) -> DecisionResult:
        """Decide human escalation due to uncertainty."""
        return DecisionResult(
            action=ActionType.HUMAN_APPROVAL,
            target=event.get("target", {}),
            adjusted_score=adjusted_score,
            message=f"High uncertainty ({reason}), human escalation required"
        )
    
    async def _publish_action(self, result: DecisionResult) -> None:
        """Publish action to Redis Stream."""
        action_data = {
            "action": result.action.value,
            "target": json.dumps(result.target),
            "adjusted_score": str(result.adjusted_score),
            "circuit_breaker_state": json.dumps(result.circuit_breaker_state) if result.circuit_breaker_state else "",
            "message": result.message,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.xadd("kubeheal.actions", action_data)
        
        logger.info(f"Action: {result.action.value} for {result.target}, score={result.adjusted_score:.2f}")
        
        if result.action == ActionType.AUTO_KILL:
            await self._execute_kill(result.target)
        elif result.action == ActionType.AUTO_PATCH:
            await self._execute_patch(result.target)
    
    async def _execute_kill(self, target: Dict) -> None:
        """Execute auto-kill action."""
        logger.warning(f"EXECUTING AUTO-KILL: {target}")
        
        namespace = target.get("namespace", "default")
        pod_name = target.get("name", target.get("pod"))
        
        if not pod_name:
            return
        
        try:
            await self.core_api.delete_namespaced_pod(
                pod_name,
                namespace,
                grace_period_seconds=0
            )
            logger.info(f"Pod {namespace}/{pod_name} killed")
        except Exception as e:
            logger.error(f"Failed to kill pod: {e}")
    
    async def _execute_patch(self, target: Dict) -> None:
        """Execute auto-patch action."""
        logger.info(f"EXECUTING AUTO-PATCH: {target}")
        
        namespace = target.get("namespace", "default")
        dep_name = target.get("name")
        
        if not dep_name:
            return
        
        logger.info(f"Patch would be applied to {namespace}/{dep_name}")
    
    async def _log_incident(
        self,
        event: Dict,
        result: DecisionResult,
        event_type: str
    ) -> None:
        """Log incident to audit trail."""
        incident_record = {
            "incident_id": f"{event_type}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "type": event_type,
            "target": json.dumps(event.get("target", {})),
            "risk_score": str(event.get("risk_score", 0.0)),
            "adjusted_score": str(result.adjusted_score),
            "action": result.action.value,
            "outcome": "pending",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.xadd("kubeheal.incidents", incident_record)
        
        logger.info(f"Incident logged: {incident_record['incident_id']}")


async def main():
    """Run Fusion Agent."""
    agent = FusionAgent()
    
    try:
        await agent.start()
        while agent.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())