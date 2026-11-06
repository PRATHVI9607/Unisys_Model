"""KubeHeal dashboard: read-only live view of the health, security and action streams.

One background task tails all three Redis streams (backfill with XREVRANGE, then a
single blocking XREAD), keeps the newest events per kind in memory, and pushes each
new batch to every WebSocket client. Run: `uvicorn dashboard.fastapi_app:app --port 8080`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from itertools import islice
from pathlib import Path
from typing import Any, Literal

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from kubeheal.contracts import (
    STREAM_ACTIONS,
    STREAM_HEALTH,
    STREAM_SECURITY,
    ActionEvent,
    HealthEvent,
    SecurityEvent,
    key_event,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("kubeheal.dashboard")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-master.kubeheal.svc:6379/0")
BUFFER = 200            # events kept in memory per kind
HIGH_RISK = 0.7
SEND_TIMEOUT_S = 2.0    # a client slower than this is dropped (it reconnects and refetches)
READY_WINDOW_S = 10.0   # /readyz is 200 if Redis answered within this window

Kind = Literal["health", "security", "action"]
KINDS: dict[str, tuple[str, Any]] = {
    "health": (STREAM_HEALTH, HealthEvent),
    "security": (STREAM_SECURITY, SecurityEvent),
    "action": (STREAM_ACTIONS, ActionEvent),
}
KIND_BY_STREAM = {stream: kind for kind, (stream, _) in KINDS.items()}
DIR = Path(__file__).parent


def make_redis() -> aioredis.Redis:
    # socket_timeout must exceed the XREAD BLOCK (1 s).
    return aioredis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5, socket_connect_timeout=3)


def parse(kind: str, entry_id: str, fields: dict) -> dict | None:
    """Contract-validated event as JSON-ready dict, or None (logged) if malformed."""
    try:
        event = KINDS[kind][1].from_fields(fields).model_dump(mode="json")
    except Exception:
        log.warning("skipping malformed %s entry %s", kind, entry_id, exc_info=True)
        return None
    event["kind"] = kind
    return event


class Hub:
    def __init__(self) -> None:
        self.buffers: dict[str, deque[dict]] = {k: deque(maxlen=BUFFER) for k in KINDS}
        self.clients: set[WebSocket] = set()
        self.redis: aioredis.Redis | None = None
        self.last_ok = 0.0   # monotonic time of the last successful Redis call

    @property
    def redis_ok(self) -> bool:
        return self.redis is not None and time.monotonic() - self.last_ok < READY_WINDOW_S

    def stats(self) -> dict:
        h, s, a = (self.buffers[k] for k in KINDS)
        return {
            "health_events": len(h),
            "health_high_risk": sum(e["risk"] >= HIGH_RISK for e in h),
            "security_events": len(s),
            "security_high_risk": sum(e["risk"] >= HIGH_RISK for e in s),
            "actions": len(a),
            "actions_dry_run": sum(e["mode"] == "observe" for e in a),
            "redis_connected": self.redis_ok,
            "window": BUFFER,
        }

    def find(self, kind: str, event_id: str) -> dict | None:
        return next((e for e in self.buffers[kind] if e["event_id"] == event_id), None)

    async def broadcast(self, msg: dict) -> None:
        if not self.clients:
            return
        text = json.dumps(msg)

        async def send(ws: WebSocket) -> None:
            try:
                await asyncio.wait_for(ws.send_text(text), SEND_TIMEOUT_S)
            except Exception:
                self.clients.discard(ws)
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(ws.close(code=1013), 1.0)

        await asyncio.gather(*(send(ws) for ws in list(self.clients)))

    async def run(self) -> None:
        """Tail all streams forever; reconnects with capped backoff, including when Redis is down at start."""
        backoff = 1.0
        while True:
            client = make_redis()
            try:
                await client.ping()
                last_ids: dict[str, str] = {}
                for kind, (stream, _) in KINDS.items():
                    entries = await client.xrevrange(stream, count=BUFFER)
                    last_ids[stream] = entries[0][0] if entries else "0-0"
                    # Replace (not extend) so a reconnect never duplicates events.
                    self.buffers[kind] = deque(
                        filter(None, (parse(kind, i, f) for i, f in reversed(entries))), maxlen=BUFFER)
                self.redis, self.last_ok, backoff = client, time.monotonic(), 1.0
                log.info("connected to redis, backfilled %s", {k: len(b) for k, b in self.buffers.items()})
                await self.broadcast({"type": "resync", "stats": self.stats()})
                while True:
                    resp = await client.xread(last_ids, count=100, block=1000)
                    self.last_ok = time.monotonic()
                    batch = []
                    for stream, entries in resp or []:
                        kind = KIND_BY_STREAM[stream]
                        for entry_id, fields in entries:
                            last_ids[stream] = entry_id
                            if event := parse(kind, entry_id, fields):
                                self.buffers[kind].append(event)
                                batch.append(event)
                    if batch:
                        await self.broadcast({"type": "events", "events": batch, "stats": self.stats()})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                was_up, self.redis = self.redis is not None, None
                log.warning("redis unavailable (%s); retrying in %.0fs", exc, backoff)
                if was_up:
                    await self.broadcast({"type": "stats", "stats": self.stats()})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
            finally:
                with contextlib.suppress(Exception):
                    await client.aclose()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.hub = hub = Hub()
    task = asyncio.create_task(hub.run())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="KubeHeal Dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=DIR / "static"), name="static")


@app.get("/")
async def index():
    return FileResponse(DIR / "templates" / "index.html")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz(request: Request):
    ok = request.app.state.hub.redis_ok
    return JSONResponse({"ready": ok}, status_code=200 if ok else 503)


@app.get("/api/stats")
async def stats(request: Request):
    return request.app.state.hub.stats()


@app.get("/api/events")
async def list_events(request: Request, kind: Kind, limit: int = Query(50, ge=1, le=BUFFER)):
    """Newest first."""
    return {"kind": kind, "events": list(islice(reversed(request.app.state.hub.buffers[kind]), limit))}


@app.get("/api/events/{kind}/{event_id}")
async def event_detail(request: Request, kind: Kind, event_id: str):
    hub: Hub = request.app.state.hub
    if event := hub.find(kind, event_id):
        return event
    try:
        if hub.redis is None:
            raise aioredis.ConnectionError("not connected")
        fields = await hub.redis.hgetall(key_event(kind, event_id))
    except aioredis.RedisError as exc:
        raise HTTPException(503, "redis unavailable") from exc
    if not fields or not (event := parse(kind, event_id, fields)):
        raise HTTPException(404, "event not found")
    return event


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    hub: Hub = websocket.app.state.hub
    await websocket.accept()
    await websocket.send_json({"type": "stats", "stats": hub.stats()})
    hub.clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()   # clients send nothing; this just detects disconnect
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.clients.discard(websocket)
