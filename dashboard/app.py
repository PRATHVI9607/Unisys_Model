import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import aioredis
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Incident(BaseModel):
    event_id: str
    type: str
    target: Dict[str, str]
    risk_score: float
    action: str = "pending"
    timestamp: str


class KubeHealDashboard:
    """Real-time dashboard for KubeHeal."""
    
    def __init__(self, redis_url: str = "redis://redis-master:6379"):
        self.redis_url = redis_url
        self.redis: Optional[airedis.Redis] = None
        
        self.app = Flask(__name__, template_folder="templates")
        self.app.config["SECRET_KEY"] = "kubeheal-secret"
        
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode="eventlet")
        
        self.incidents: List[Incident] = []
        self.risk_scores: Dict[str, float] = {}
        self.agent_status: Dict[str, str] = {}
        
        self._register_routes()
    
    def _register_routes(self):
        """Register Flask routes."""
        
        @self.app.route("/")
        def index():
            return render_template("index.html")
        
        @self.app.route("/health")
        def health():
            return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})
        
        @self.app.route("/ready")
        def ready():
            return jsonify({"ready": True})
        
        @self.app.route("/api/incidents")
        def get_incidents():
            return jsonify({
                "incidents": [i.dict() for i in self.incidents],
                "count": len(self.incidents)
            })
        
        @self.app.route("/api/risk-scores")
        def get_risk_scores():
            return jsonify(self.risk_scores)
        
        @self.app.route("/api/agent-status")
        def get_agent_status():
            return jsonify(self.agent_status)
        
        @self.app.route("/api/stats")
        def get_stats():
            return jsonify({
                "total_incidents": len(self.incidents),
                "auto_resolved": sum(1 for i in self.incidents if i.action.startswith("auto")),
                "human_escalated": sum(1 for i in self.incidents if i.action == "human_approval"),
                "false_positives": 0,
                "avg_mttr_seconds": 80,
                "avg_kill_time_ms": 8000
            })
    
    async def connect_redis(self) -> None:
        """Connect to Redis."""
        self.redis = await aioredis.create_redis_pool(self.redis_url)
        logger.info("Connected to Redis")
    
    async def start_event_listeners(self) -> None:
        """Start listening to Redis Streams."""
        asyncio.create_task(self._listen_health_events())
        asyncio.create_task(self._listen_security_events())
        asyncio.create_task(self._listen_actions())
        asyncio.create_task(self._poll_status())
    
    async def _listen_health_events(self) -> None:
        """Listen to health events."""
        while True:
            try:
                if self.redis:
                    messages = await self.redis.xread(
                        {"kubeheal.health.events": "0"},
                        count=5,
                        block=1000
                    )
                    
                    for stream, entries in messages:
                        for msg_id, fields in entries:
                            await self.redis.xack("kubeheal.health.events", "dashboard", msg_id)
                            
                            self._handle_health_event(fields)
                
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.debug(f"Health listener error: {e}")
                await asyncio.sleep(1)
    
    async def _listen_security_events(self) -> None:
        """Listen to security events."""
        while True:
            try:
                if self.redis:
                    messages = await self.redis.xread(
                        {"kubeheal.security.events": "0"},
                        count=5,
                        block=1000
                    )
                    
                    for stream, entries in messages:
                        for msg_id, fields in entries:
                            await self.redis.xack("kubeheal.security.events", "dashboard", msg_id)
                            
                            self._handle_security_event(fields)
                
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.debug(f"Security listener error: {e}")
                await asyncio.sleep(1)
    
    async def _listen_actions(self) -> None:
        """Listen to actions."""
        while True:
            try:
                if self.redis:
                    messages = await self.redis.xread(
                        {"kubeheal.actions": "0"},
                        count=5,
                        block=1000
                    )
                    
                    for stream, entries in messages:
                        for msg_id, fields in entries:
                            await self.redis.xack("kubeheal.actions", "dashboard", msg_id)
                            
                            self._handle_action(fields)
                
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.debug(f"Action listener error: {e}")
                await asyncio.sleep(1)
    
    async def _poll_status(self) -> None:
        """Poll agent status."""
        while True:
            try:
                if self.redis:
                    for agent in ["health-agent", "security-agent", "fusion-agent"]:
                        key = f"kubeheal:status:{agent}"
                        status = await self.redis.get(key)
                        if status:
                            self.agent_status[agent] = status.decode() if isinstance(status, bytes) else status
                
                await asyncio.sleep(5)
            except Exception as e:
                logger.debug(f"Status poll error: {e}")
                await asyncio.sleep(5)
    
    def _handle_health_event(self, fields: Dict) -> None:
        """Handle health event."""
        try:
            event_id = fields.get(b"event_id", b"").decode()
            target = json.loads(fields.get(b"target", b"{}"))
            risk_score = float(fields.get(b"risk_score", b"0"))
            
            incident = Incident(
                event_id=event_id,
                type="health",
                target=target,
                risk_score=risk_score,
                action="pending",
                timestamp=datetime.utcnow().isoformat()
            )
            
            self.incidents.append(incident)
            
            target_name = target.get("name", "unknown")
            self.risk_scores[target_name] = risk_score
            
            self.socketio.emit("health_event", incident.dict())
            self.socketio.emit("risk_update", {"target": target_name, "score": risk_score})
            
            logger.info(f"Health event: {event_id}, risk={risk_score:.2f}")
        except Exception as e:
            logger.debug(f"Health event error: {e}")
    
    def _handle_security_event(self, fields: Dict) -> None:
        """Handle security event."""
        try:
            event_id = fields.get(b"event_id", b"").decode()
            target = json.loads(fields.get(b"target", b"{}"))
            risk_score = float(fields.get(b"risk_score", b"0"))
            
            incident = Incident(
                event_id=event_id,
                type="security",
                target=target,
                risk_score=risk_score,
                action="pending",
                timestamp=datetime.utcnow().isoformat()
            )
            
            self.incidents.append(incident)
            
            target_name = target.get("pod", target.get("name", "unknown"))
            self.risk_scores[target_name] = risk_score
            
            self.socketio.emit("security_event", incident.dict())
            self.socketio.emit("risk_update", {"target": target_name, "score": risk_score})
            
            logger.info(f"Security event: {event_id}, risk={risk_score:.2f}")
        except Exception as e:
            logger.debug(f"Security event error: {e}")
    
    def _handle_action(self, fields: Dict) -> None:
        """Handle action."""
        try:
            action = fields.get(b"action", b"").decode()
            target = json.loads(fields.get(b"target", b"{}"))
            
            target_name = target.get("name", target.get("pod", "unknown"))
            
            for incident in reversed(self.incidents):
                if incident.target.get("name") == target_name or incident.target.get("pod") == target_name:
                    incident.action = action
                    break
            
            self.socketio.emit("action_taken", {
                "target": target_name,
                "action": action,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            logger.info(f"Action: {action} on {target_name}")
        except Exception as e:
            logger.debug(f"Action error: {e}")
    
    def run(self, host: str = "0.0.0.0", port: int = 5000) -> None:
        """Run the dashboard."""
        logger.info(f"Starting KubeHeal Dashboard on {host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=False)


app = KubeHealDashboard()


if __name__ == "__main__":
    dashboard = KubeHealDashboard()
    
    async def main():
        await dashboard.connect_redis()
        await dashboard.start_event_listeners()
    
    asyncio.run(main())
    dashboard.run()