import json
import logging
import os
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _normalize_v4(d: dict, kind: str) -> None:
    """Map v4 hash fields → the EventDetails shape (risk_score, target,
    timestamp, label) so the detail endpoint works on the v4 schema."""
    if d.get("risk_score") in (None, ""):
        v = d.get("health_risk") if kind == "health" else d.get("sec_risk")
        try:
            d["risk_score"] = float(v) if v not in (None, "") else 0.0
        except (TypeError, ValueError):
            d["risk_score"] = 0.0
    if not d.get("timestamp"):
        d["timestamp"] = d.get("timestamp_ms") or ""
    if not d.get("target"):
        d["target"] = {"namespace": d.get("namespace", "default"),
                       "name" if kind == "health" else "pod": d.get("pod_name", "unknown")}
    if kind == "health" and not d.get("severity"):
        d["severity"] = d.get("health_label")
    if kind == "security" and not d.get("label"):
        d["label"] = d.get("sec_label")


class HealthAssessment(BaseModel):
    model_config = ConfigDict(protected_namespaces=())  # allow model_* fields
    event_id: str
    target: Dict[str, Any]  # Values can be int or str
    risk_score: float
    severity: str
    blast_radius: str
    timestamp: str
    # Extra fields for detailed view (from stream, not in model definition)
    model_used: Optional[str] = None
    model_score: Optional[float] = None
    heuristic_score: Optional[float] = None
    inference_method: Optional[str] = None
    explainability: Optional[Dict[str, Any]] = None
    patch_proposal: Optional[Dict[str, Any]] = None


class SecurityEvent(BaseModel):
    model_config = ConfigDict(protected_namespaces=())  # allow model_* fields
    event_id: str
    target: Dict[str, Any]  # PID can be int or str
    risk_score: float
    label: str
    early_signals: Dict[str, Any]
    timestamp: str
    # Extra fields for detailed view (from stream, not in model definition)
    model_used: Optional[str] = None
    model_score: Optional[float] = None
    heuristic_score: Optional[float] = None
    inference_method: Optional[str] = None
    entropy: Optional[float] = None
    pid_target: Optional[str] = None


class Incident(BaseModel):
    event_id: str
    type: str
    target: Dict[str, str]
    risk_score: float
    severity: str
    timestamp: str


class EventDetails(BaseModel):
    """Complete event details with all fields including model comparison data."""
    model_config = ConfigDict(protected_namespaces=())  # allow model_* fields

    model_config = {"extra": "ignore"}

    event_id: str = ""
    target: Dict[str, Any] = {}
    risk_score: float = 0.0
    timestamp: str = ""

    # Health-specific fields
    severity: Optional[str] = None
    blast_radius: Optional[str] = None
    patch_proposal: Optional[Dict[str, Any]] = None
    explainability: Optional[Dict[str, Any]] = None

    # Security-specific fields
    label: Optional[str] = None
    early_signals: Optional[Dict[str, Any]] = None
    pid_target: Optional[str] = None
    action: Optional[str] = None
    entropy: Optional[float] = None

    # Model comparison fields (present in both health and security events)
    model_used: Optional[str] = None
    model_score: Optional[float] = None
    heuristic_score: Optional[float] = None
    inference_method: Optional[str] = None
    confidence_interval: Optional[float] = None

    # Event type indicator
    event_type: Optional[str] = None  # "health" or "security"


class KubeHealDashboard:
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None

        self.incidents: List[Incident] = []
        self.health_events: List[HealthAssessment] = []
        self.security_events: List[SecurityEvent] = []
        self.active_connections: List[WebSocket] = []
        self.running = False

    async def connect_redis(self) -> None:
        """Connect to Redis."""
        try:
            self.redis = await aioredis.from_url(self.redis_url, decode_responses=False)
            await self.redis.ping()
            logger.info(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis = None

    async def disconnect_redis(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()

    async def start_listeners(self) -> None:
        """Start listening to Redis streams."""
        if not self.redis:
            logger.warning("Redis not connected, skipping listeners")
            return

        self.running = True
        asyncio.create_task(self._listen_health_events())
        asyncio.create_task(self._listen_security_events())
        asyncio.create_task(self._broadcast_stats())

    async def stop_listeners(self) -> None:
        """Stop listeners."""
        self.running = False

    async def _listen_health_events(self) -> None:
        """Listen to health assessment events."""
        last_id = "0"
        while self.running:
            try:
                if not self.redis:
                    await asyncio.sleep(1)
                    continue

                messages = await self.redis.xread(
                    {"kubeheal.health.events": last_id}, count=5, block=1000
                )

                if messages:
                    for stream, entries in messages:
                        for msg_id, fields in entries:
                            last_id = (
                                msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                            )

                            # Parse v4 health event
                            def _g(k, d=b""):
                                return fields.get(k, d).decode()
                            event_id = _g(b"event_id")
                            namespace = _g(b"namespace", b"default")
                            pod_name = _g(b"pod_name", b"unknown")
                            target = {"namespace": namespace, "name": pod_name, "kind": "Deployment"}
                            risk_score = float(_g(b"health_risk", b"0") or 0)
                            severity = _g(b"health_label", b"benign")  # v4 label as severity
                            blast_radius = _g(b"blast_radius", b"unknown")
                            timestamp = _g(b"timestamp_ms")
                            inference_method = _g(b"inference_method") or None
                            field_attr = fields.get(b"field_attribution_json", b"{}")
                            patch_proposal = fields.get(b"patch_proposal_json", b"{}")

                            assessment = HealthAssessment(
                                event_id=event_id,
                                target=target,
                                risk_score=risk_score,
                                severity=severity,
                                blast_radius=blast_radius,
                                timestamp=timestamp,
                            )
                            assessment.model_used = "health_model_v4"
                            assessment.model_score = risk_score
                            assessment.heuristic_score = None
                            assessment.inference_method = inference_method
                            assessment.explainability = (
                                json.loads(field_attr)
                                if field_attr and field_attr != b"{}" else {}
                            )
                            assessment.patch_proposal = (
                                json.loads(patch_proposal)
                                if patch_proposal and patch_proposal != b"{}" else None
                            )

                            self.health_events.append(assessment)
                            if len(self.health_events) > 100:
                                self.health_events.pop(0)

                            logger.info(
                                f"Health event: {event_id}, risk={risk_score:.2f}"
                            )

                            # Broadcast to WebSocket clients
                            await self._broadcast(
                                {
                                    "type": "health_event",
                                    "data": assessment.model_dump(),
                                }
                            )

            except Exception as e:
                logger.error(f"Health listener error: {e}")
                await asyncio.sleep(1)

    async def _listen_security_events(self) -> None:
        """Listen to security events."""
        last_id = "0"
        while self.running:
            try:
                if not self.redis:
                    await asyncio.sleep(1)
                    continue

                messages = await self.redis.xread(
                    {"kubeheal.security.events": last_id}, count=5, block=1000
                )

                if messages:
                    for stream, entries in messages:
                        for msg_id, fields in entries:
                            last_id = (
                                msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                            )

                            # Parse v4 security event
                            def _g(k, d=b""):
                                return fields.get(k, d).decode()
                            event_id = _g(b"event_id")
                            namespace = _g(b"namespace", b"default")
                            pod_name = _g(b"pod_name", b"unknown")
                            target = {"namespace": namespace, "pod": pod_name}
                            risk_score = float(_g(b"sec_risk", b"0") or 0)
                            label = _g(b"sec_label", b"benign")
                            early_signals = json.loads(fields.get(b"early_signals_json", b"{}"))
                            timestamp = _g(b"timestamp_ms")
                            inference_method = "security_model_v4"
                            entropy = _g(b"entropy")
                            pid_target = _g(b"pid_target") or None
                            top_syscall = _g(b"top_syscall") or None

                            event = SecurityEvent(
                                event_id=event_id,
                                target=target,
                                risk_score=risk_score,
                                label=label,
                                early_signals=early_signals,
                                timestamp=timestamp,
                            )
                            event.model_used = "security_model_v4"
                            event.model_score = risk_score
                            event.heuristic_score = None
                            event.inference_method = inference_method
                            event.entropy = float(entropy) if entropy else None
                            event.pid_target = pid_target

                            self.security_events.append(event)
                            if len(self.security_events) > 100:
                                self.security_events.pop(0)

                            logger.info(
                                f"Security event: {event_id}, risk={risk_score:.2f}"
                            )

                            # Broadcast to WebSocket clients
                            await self._broadcast(
                                {"type": "security_event", "data": event.model_dump()}
                            )

            except Exception as e:
                logger.error(f"Security listener error: {e}")
                await asyncio.sleep(1)

    async def _broadcast_stats(self) -> None:
        """Broadcast stats periodically."""
        while self.running:
            try:
                stats = {
                    "total_health_events": len(self.health_events),
                    "total_security_events": len(self.security_events),
                    "high_risk_events": len(
                        [e for e in self.health_events if e.risk_score > 0.7]
                    )
                    + len([e for e in self.security_events if e.risk_score > 0.7]),
                    "timestamp": datetime.utcnow().isoformat(),
                }

                await self._broadcast({"type": "stats", "data": stats})

                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Stats broadcast error: {e}")
                await asyncio.sleep(1)

    async def _broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast message to all connected WebSocket clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"WebSocket send error: {e}")
                disconnected.append(connection)

        for connection in disconnected:
            self.active_connections.remove(connection)

    async def connect_websocket(self, websocket: WebSocket) -> None:
        """Add WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Total connections: {len(self.active_connections)}"
        )

    async def disconnect_websocket(self, websocket: WebSocket) -> None:
        """Remove WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Total connections: {len(self.active_connections)}"
        )

    async def get_event_details(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve event details from Redis.

        Tries to find the event in Redis hashes:
        - kubeheal:health:{event_id} for health events
        - kubeheal.security.{event_id} for security events (if pattern is used)

        Returns dict with event details or None if not found.
        """
        if not self.redis:
            logger.warning("Redis not connected")
            return None

        try:
            # Try health event key pattern first
            health_key = f"kubeheal:health:{event_id}"
            event_data = await self.redis.hgetall(health_key)

            if event_data:
                # Decode bytes to strings and parse JSON fields
                decoded = {}
                for key, value in event_data.items():
                    if isinstance(key, bytes):
                        key = key.decode()
                    if isinstance(value, bytes):
                        value = value.decode()
                    decoded[key] = value

                # Parse JSON fields
                if "target" in decoded and decoded["target"]:
                    try:
                        decoded["target"] = json.loads(decoded["target"])
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse target JSON for {event_id}")
                        decoded["target"] = {}

                if "patch_proposal" in decoded and decoded["patch_proposal"]:
                    try:
                        decoded["patch_proposal"] = json.loads(
                            decoded["patch_proposal"]
                        )
                    except json.JSONDecodeError:
                        logger.warning(
                            f"Failed to parse patch_proposal JSON for {event_id}"
                        )
                        decoded["patch_proposal"] = None

                if "explainability" in decoded and decoded["explainability"]:
                    try:
                        decoded["explainability"] = json.loads(
                            decoded["explainability"]
                        )
                    except json.JSONDecodeError:
                        logger.warning(
                            f"Failed to parse explainability JSON for {event_id}"
                        )
                        decoded["explainability"] = None

                # Convert numeric fields
                if "risk_score" in decoded:
                    try:
                        decoded["risk_score"] = float(decoded["risk_score"])
                    except (ValueError, TypeError):
                        decoded["risk_score"] = 0.0

                if "model_score" in decoded and decoded["model_score"]:
                    try:
                        decoded["model_score"] = float(decoded["model_score"])
                    except (ValueError, TypeError):
                        decoded["model_score"] = None

                if "heuristic_score" in decoded and decoded["heuristic_score"]:
                    try:
                        decoded["heuristic_score"] = float(decoded["heuristic_score"])
                    except (ValueError, TypeError):
                        decoded["heuristic_score"] = None

                if "confidence_interval" in decoded and decoded["confidence_interval"]:
                    try:
                        decoded["confidence_interval"] = float(
                            decoded["confidence_interval"]
                        )
                    except (ValueError, TypeError):
                        decoded["confidence_interval"] = None

                # Remove empty strings for optional fields
                decoded = {k: v if v != "" else None for k, v in decoded.items()}
                decoded["event_type"] = "health"
                _normalize_v4(decoded, kind="health")
                return decoded

            # Try security event key pattern
            security_key = f"kubeheal.security.{event_id}"
            event_data = await self.redis.hgetall(security_key)

            if event_data:
                # Decode bytes to strings and parse JSON fields
                decoded = {}
                for key, value in event_data.items():
                    if isinstance(key, bytes):
                        key = key.decode()
                    if isinstance(value, bytes):
                        value = value.decode()
                    decoded[key] = value

                # Parse JSON fields
                if "target" in decoded and decoded["target"]:
                    try:
                        decoded["target"] = json.loads(decoded["target"])
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse target JSON for {event_id}")
                        decoded["target"] = {}

                if "early_signals" in decoded and decoded["early_signals"]:
                    try:
                        decoded["early_signals"] = json.loads(decoded["early_signals"])
                    except json.JSONDecodeError:
                        logger.warning(
                            f"Failed to parse early_signals JSON for {event_id}"
                        )
                        decoded["early_signals"] = None

                # Convert numeric fields
                if "risk_score" in decoded:
                    try:
                        decoded["risk_score"] = float(decoded["risk_score"])
                    except (ValueError, TypeError):
                        decoded["risk_score"] = 0.0

                if "model_score" in decoded and decoded["model_score"]:
                    try:
                        decoded["model_score"] = float(decoded["model_score"])
                    except (ValueError, TypeError):
                        decoded["model_score"] = None

                if "heuristic_score" in decoded and decoded["heuristic_score"]:
                    try:
                        decoded["heuristic_score"] = float(decoded["heuristic_score"])
                    except (ValueError, TypeError):
                        decoded["heuristic_score"] = None

                if "entropy" in decoded and decoded["entropy"]:
                    try:
                        decoded["entropy"] = float(decoded["entropy"])
                    except (ValueError, TypeError):
                        decoded["entropy"] = None

                # Remove empty strings for optional fields
                decoded = {k: v if v != "" else None for k, v in decoded.items()}
                decoded["event_type"] = "security"
                _normalize_v4(decoded, kind="security")
                return decoded

            # Event not found
            return None

        except Exception as e:
            logger.error(f"Error retrieving event {event_id} from Redis: {e}")
            return None


# Global dashboard instance
dashboard: Optional[KubeHealDashboard] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage dashboard lifecycle."""
    global dashboard

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    logger.info(f"Initializing dashboard with REDIS_URL: {redis_url}")

    dashboard = KubeHealDashboard(redis_url=redis_url)
    await dashboard.connect_redis()
    await dashboard.start_listeners()

    logger.info("Dashboard started")
    yield

    logger.info("Shutting down dashboard")
    await dashboard.stop_listeners()
    await dashboard.disconnect_redis()


app = FastAPI(title="KubeHeal Dashboard", lifespan=lifespan)

# Mount static files directory for CSS, JS, etc.
import os.path

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/ready")
async def ready():
    """Readiness check endpoint."""
    return {
        "ready": dashboard is not None and dashboard.redis is not None,
        "redis_connected": dashboard is not None and dashboard.redis is not None,
    }


@app.get("/api/health-events")
async def get_health_events(limit: int = 50):
    """Get recent health assessment events."""
    if not dashboard:
        return {"events": [], "count": 0}

    events = dashboard.health_events[-limit:]
    return {"events": [e.model_dump() for e in events], "count": len(events)}


@app.get("/api/security-events")
async def get_security_events(limit: int = 50):
    """Get recent security events."""
    if not dashboard:
        return {"events": [], "count": 0}

    events = dashboard.security_events[-limit:]
    return {"events": [e.model_dump() for e in events], "count": len(events)}


@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics."""
    if not dashboard:
        return {
            "total_health_events": 0,
            "total_security_events": 0,
            "high_risk_events": 0,
            "redis_connected": False,
        }

    health_high_risk = len([e for e in dashboard.health_events if e.risk_score > 0.7])
    security_high_risk = len(
        [e for e in dashboard.security_events if e.risk_score > 0.7]
    )

    return {
        "total_health_events": len(dashboard.health_events),
        "total_security_events": len(dashboard.security_events),
        "high_risk_health_events": health_high_risk,
        "high_risk_security_events": security_high_risk,
        "redis_connected": dashboard.redis is not None,
        "active_connections": len(dashboard.active_connections),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/combined-events")
async def get_combined_events(limit: int = 20):
    """Get combined health and security events sorted by time."""
    if not dashboard:
        return {"events": []}

    combined = []

    for event in dashboard.health_events:
        combined.append(
            {
                "type": "health",
                "event_id": event.event_id,
                "target": event.target,
                "risk_score": event.risk_score,
                "severity": event.severity,
                "timestamp": event.timestamp,
            }
        )

    for event in dashboard.security_events:
        combined.append(
            {
                "type": "security",
                "event_id": event.event_id,
                "target": event.target,
                "risk_score": event.risk_score,
                "label": event.label,
                "timestamp": event.timestamp,
            }
        )

    # Sort by timestamp descending
    combined.sort(key=lambda x: x["timestamp"], reverse=True)

    return {"events": combined[-limit:] if limit else combined, "count": len(combined)}


@app.get("/api/events/{event_id}", response_model=EventDetails)
async def get_event_details(event_id: str):
    """Get detailed information for a specific event.

    First tries Redis (has full enriched data), then falls back to in-memory lists.

    Returns:
        EventDetails: Complete event information

    Raises:
        HTTPException: 404 if event not found, 503 if Redis unavailable
    """
    if not dashboard:
        raise HTTPException(status_code=503, detail="Dashboard not initialized")

    # First, try Redis hashes (has all enriched data including model comparison)
    if dashboard.redis:
        try:
            event_data = await dashboard.get_event_details(event_id)
            if event_data:
                return EventDetails(**event_data)
        except Exception as e:
            logger.error(f"Error fetching from Redis for {event_id}: {e}")

    # Fallback: try in-memory lists
    for event in reversed(dashboard.health_events):
        if event.event_id == event_id:
            # Include all fields including model comparison from stream
            data = {
                "event_id": event.event_id,
                "target": event.target,
                "risk_score": event.risk_score,
                "severity": event.severity,
                "blast_radius": event.blast_radius,
                "timestamp": event.timestamp,
                "event_type": "health",
                "model_used": getattr(event, "model_used", None),
                "model_score": getattr(event, "model_score", None),
                "heuristic_score": getattr(event, "heuristic_score", None),
                "inference_method": getattr(event, "inference_method", None),
                "explainability": getattr(event, "explainability", None),
                "patch_proposal": getattr(event, "patch_proposal", None),
            }
            return EventDetails(**data)

    for event in reversed(dashboard.security_events):
        if event.event_id == event_id:
            # Include extra fields that may have been set from stream data
            data = {
                "event_id": event.event_id,
                "target": event.target,
                "risk_score": event.risk_score,
                "label": event.label,
                "early_signals": event.early_signals,
                "timestamp": event.timestamp,
                "event_type": "security",
                "model_used": getattr(event, "model_used", None),
                "model_score": getattr(event, "model_score", None),
                "heuristic_score": getattr(event, "heuristic_score", None),
                "inference_method": getattr(event, "inference_method", None),
                "entropy": getattr(event, "entropy", None),
                "pid_target": getattr(event, "pid_target", None),
            }
            return EventDetails(**data)

    raise HTTPException(status_code=404, detail=f"Event {event_id} not found")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await dashboard.connect_websocket(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await dashboard.disconnect_websocket(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await dashboard.disconnect_websocket(websocket)


_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


@app.get("/")
async def root():
    """Serve the dashboard HTML."""
    return FileResponse(os.path.join(_TEMPLATES_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))

    uvicorn.run(app, host=host, port=port)
