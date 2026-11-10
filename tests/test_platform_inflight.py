"""P9: kubeheal_model_inflight_requests, the per-pod gauge behind the model server HPA."""
import asyncio
import importlib
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.common.metrics import KubeHealMetrics, add_inflight_middleware, add_metrics_route  # noqa: E402

NAME = "kubeheal_model_inflight_requests"


def gauge(metrics):
    return metrics.inflight_requests._value.get()


def test_concurrent_requests_raise_the_gauge_and_it_returns_to_zero():
    metrics = KubeHealMetrics()
    app = FastAPI()
    add_inflight_middleware(app, metrics, ["/score"])
    gate = {}

    @app.post("/score")
    async def score():
        await gate["event"].wait()
        return {"ok": True}

    @app.get("/health")
    async def health():
        await gate["event"].wait()
        return {"ok": True}

    async def run():
        gate["event"] = asyncio.Event()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            scoring = [asyncio.create_task(c.post("/score")) for _ in range(3)]
            other = asyncio.create_task(c.get("/health"))     # not counted
            for _ in range(100):
                await asyncio.sleep(0.01)
                if gauge(metrics) == 3:
                    break
            peak = gauge(metrics)
            gate["event"].set()
            await asyncio.gather(*scoring, other)
            return peak

    assert asyncio.run(run()) == 3
    assert gauge(metrics) == 0


def test_gauge_returns_to_zero_when_the_handler_raises():
    metrics = KubeHealMetrics()
    app = FastAPI()
    add_inflight_middleware(app, metrics, ["/boom", "/http_error"])

    @app.post("/boom")
    def boom():
        raise RuntimeError("handler failed")

    @app.post("/http_error")
    def http_error():
        raise HTTPException(status_code=503, detail="not ready")

    client = TestClient(app, raise_server_exceptions=False)
    assert client.post("/boom").status_code == 500
    assert client.post("/http_error").status_code == 503
    assert gauge(metrics) == 0


def test_waiting_requests_are_counted_with_a_single_worker_thread():
    """Sync handler, one worker thread: two requests wait for a worker and still count."""
    import anyio.to_thread
    metrics = KubeHealMetrics()
    app = FastAPI()
    add_inflight_middleware(app, metrics, ["/score"])
    release = threading.Event()
    running = []

    @app.post("/score")
    def score():
        running.append(1)
        release.wait(10)
        return {"ok": True}

    async def run():
        anyio.to_thread.current_default_thread_limiter().total_tokens = 1
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            tasks = [asyncio.create_task(c.post("/score")) for _ in range(3)]
            for _ in range(200):
                await asyncio.sleep(0.01)
                if gauge(metrics) == 3 and running:
                    break
            await asyncio.sleep(0.1)      # give the other two a chance to (wrongly) start
            peak, started = gauge(metrics), len(running)
            release.set()
            codes = [r.status_code for r in await asyncio.gather(*tasks)]
            return peak, started, codes

    peak, started, codes = asyncio.run(run())
    assert peak == 3 and started == 1 and codes == [200, 200, 200]   # 1 running, 2 waiting, all counted
    assert gauge(metrics) == 0


def test_metrics_route_exports_the_gauge_and_other_paths_do_not_count():
    metrics = KubeHealMetrics()
    app = FastAPI()
    add_metrics_route(app, metrics)
    add_inflight_middleware(app, metrics, ["/score"])
    client = TestClient(app)
    body = client.get("/metrics").text
    assert f"{NAME} 0.0" in body
    assert gauge(metrics) == 0


SERVERS = [
    ("services.health_model_server.main", "/health/score",
     {"old_spec": {}, "new_spec": {}, "metrics": [[0.0] * 15] * 60}),
    ("services.security_model_server.main", "/security/score",
     {"events": [{"syscall": "write", "fd_path": "/data/f"}], "entropy_series": [2.0] * 30, "early_signals": {}}),
    ("services.dcm_server.main", "/dcm/correlate",
     {"health_embedding": [0.0] * 128, "security_embedding": [0.0] * 64}),
]


@pytest.mark.parametrize("modname,path,body", SERVERS)
def test_each_server_exports_and_counts_its_scoring_path(modname, path, body, monkeypatch, tmp_path):
    mod = importlib.import_module(modname)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "missing.pt"))
    monkeypatch.delenv("ALLOW_RANDOM_WEIGHTS", raising=False)
    monkeypatch.delenv("MODEL_FORMAT", raising=False)
    mod._load_model()                                   # not loaded: scoring answers 503
    client = TestClient(mod.app)
    assert f"{NAME} 0.0" in client.get("/metrics").text
    assert client.get("/health").status_code == 503     # never counted
    assert client.post(path, json=body).status_code == 503
    assert gauge(mod.METRICS) == 0                      # 503 path also returns to 0

    release = threading.Event()
    entered = []

    def blocking_ready(_status):
        entered.append(1)
        release.wait(10)
        raise HTTPException(status_code=503, detail="released")

    monkeypatch.setattr(mod, "require_ready", blocking_ready)
    threads = [threading.Thread(target=lambda: TestClient(mod.app).post(path, json=body)) for _ in range(3)]
    for t in threads:
        t.start()
    deadline = time.time() + 10
    while time.time() < deadline and gauge(mod.METRICS) < 3:
        time.sleep(0.01)
    peak = gauge(mod.METRICS)
    assert f"{NAME} {float(peak)}" in client.get("/metrics").text
    release.set()
    for t in threads:
        t.join(15)
    assert peak == 3
    assert gauge(mod.METRICS) == 0
