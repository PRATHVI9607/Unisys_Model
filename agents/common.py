"""Small helpers shared by the KubeHeal agents (env, logging, Redis, HTTP, K8s)."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from collections.abc import Awaitable, Callable

import aiohttp
import prometheus_client
import redis.asyncio as aioredis
from aiohttp import web
from kubernetes_asyncio import config as k8s_config

from kubeheal.contracts import PROTECTED_NAMESPACES, STREAM_MAXLEN, Prediction, key_event, key_event_index

log = logging.getLogger("kubeheal.agents")

EVENT_TTL_S = 24 * 3600
EVENT_COPIES = STREAM_MAXLEN   # hash copies kept per kind: the same horizon as the stream
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis-master.kubeheal.svc:6379/0")
INFERENCE_URL = os.environ.get("INFERENCE_URL", "http://kubeheal-inference.kubeheal.svc:8000").rstrip("/")


def run(main: Callable[[], Awaitable[None]]) -> None:
    """asyncio.run(main()) that exits cleanly on SIGTERM/SIGINT.

    As PID 1 in a container Python ignores SIGTERM, so a deleted pod would keep consuming for the
    whole grace period next to its replacement (two fusion consumers at once).
    """
    async def wrapper() -> None:
        task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, task.cancel)
        try:
            await main()
        except asyncio.CancelledError:
            log.info("signal received; shut down")

    asyncio.run(wrapper())


def env_list(name: str) -> list[str]:
    """Comma-separated env var → list of non-empty, stripped items."""
    return [s.strip() for s in os.environ.get(name, "").split(",") if s.strip()]


def protected_namespaces() -> frozenset[str]:
    return PROTECTED_NAMESPACES | frozenset(env_list("EXTRA_PROTECTED_NAMESPACES"))


def setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def connect_redis(attempts: int = 30) -> aioredis.Redis:
    """Connect and PING, retrying with backoff (Redis may start after us)."""
    delay, attempt = 1.0, 0
    while True:
        # socket_timeout > fusion's XREADGROUP BLOCK (1 s); without it a half-open connection hangs forever.
        r = aioredis.from_url(REDIS_URL, decode_responses=True, socket_timeout=10, socket_connect_timeout=5)
        try:
            await r.ping()
            return r
        except (aioredis.ConnectionError, aioredis.TimeoutError, OSError) as e:
            await r.aclose()
            attempt += 1
            if attempt >= attempts:
                raise
            log.warning("redis not reachable (%s), retry %d/%d in %.0fs", e, attempt, attempts, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 15.0)


async def load_kube_config() -> None:
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        await k8s_config.load_kube_config()


async def start_http(is_healthy: Callable[[], bool]) -> web.AppRunner:
    """Serve /healthz (200 iff is_healthy()) and /metrics (default prometheus registry)."""

    async def healthz(_: web.Request) -> web.Response:
        ok = is_healthy()
        return web.Response(status=200 if ok else 503, text="ok" if ok else "unhealthy")

    async def metrics(_: web.Request) -> web.Response:
        return web.Response(body=prometheus_client.generate_latest(),
                            headers={"Content-Type": prometheus_client.CONTENT_TYPE_LATEST})

    app = web.Application()
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/metrics", metrics)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8080).start()
    return runner


async def predict(session: aiohttp.ClientSession, task: str, features: dict) -> Prediction | None:
    """POST features to the inference service; None (logged at WARNING) on any failure."""
    try:
        async with session.post(f"{INFERENCE_URL}/v1/{task}/predict", json={"features": features},
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                log.warning("inference %s predict returned HTTP %d: %s", task, resp.status,
                            (await resp.text())[:200])
                return None
            return Prediction.model_validate(await resp.json())
    except (aiohttp.ClientError, TimeoutError, ValueError) as e:
        log.warning("inference %s predict failed: %r", task, e)
        return None


async def predict_batch(session: aiohttp.ClientSession, task: str, rows: list[dict]) -> list[Prediction] | None:
    """One POST for many feature dicts (<= 256, the server's cap); None (logged at WARNING) on any failure."""
    try:
        async with session.post(f"{INFERENCE_URL}/v1/{task}/predict_batch",
                                json={"items": [{"features": f} for f in rows]},
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                log.warning("inference %s predict_batch returned HTTP %d: %s", task, resp.status,
                            (await resp.text())[:200])
                return None
            body = await resp.json()
            if not isinstance(body, list) or len(body) != len(rows):
                raise ValueError(f"expected {len(rows)} predictions")
            return [Prediction.model_validate(p) for p in body]
    except (aiohttp.ClientError, TimeoutError, ValueError) as e:
        log.warning("inference %s predict_batch failed: %r", task, e)
        return None


async def publish_event(r: aioredis.Redis, stream: str, kind: str, event,
                        ack: tuple[str, str, str] | None = None) -> None:
    """XADD the event (approximate MAXLEN) plus a hash copy at key_event(kind, id), in one MULTI.

    Copies expire after 24 h and are capped at EVENT_COPIES per kind (an index list; the oldest copies
    are deleted), so a busy cluster cannot fill Redis with them: Redis runs noeviction, and a full Redis
    fails every write. ack=(stream, group, entry id) XACKs the consumed entry in the same transaction,
    so the event is published and the entry acked, or neither.
    """
    fields = event.to_fields()
    key, index = key_event(kind, event.event_id), key_event_index(kind)
    async with r.pipeline(transaction=True) as p:
        p.xadd(stream, fields, maxlen=STREAM_MAXLEN, approximate=True)
        p.hset(key, mapping=fields)
        p.expire(key, EVENT_TTL_S)
        p.lpush(index, key)
        p.lrange(index, EVENT_COPIES, -1)
        p.ltrim(index, 0, EVENT_COPIES - 1)
        if ack:
            p.xack(*ack)
        overflow = (await p.execute())[4]
    if overflow:
        try:
            await r.delete(*overflow)
        except aioredis.RedisError as e:   # published already; the copies still expire with their TTL
            log.warning("could not delete %d old %s copies: %s", len(overflow), kind, e)
