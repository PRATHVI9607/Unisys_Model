"""Browser tests for the console. They start the real FastAPI app on a free port against fake Redis seeded with
realistic data, so they need Chromium (`uv run playwright install chromium`) and fail loudly without it."""

import socket
import threading
import time
from pathlib import Path

import fakeredis
import pytest
import uvicorn

from dashboard import admin, auth, fastapi_app
from tests.dashboard_seed import seed

TOKEN = "ui-test-token"


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            return Path(p.chromium.executable_path).exists()
    except Exception:
        return False


CHROMIUM = _chromium_available()   # at import: sync_playwright() refuses to start inside a running event loop


def pytest_configure(config):
    config.addinivalue_line("markers", "ui: browser test (needs Chromium)")


@pytest.fixture(autouse=True)
def require_chromium():
    if not CHROMIUM:
        pytest.fail("Chromium not installed: run `uv run playwright install chromium` (CI does this)", pytrace=False)


def assert_pngs(paths):
    assert paths
    for p in paths:
        assert Path(p).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", p


@pytest.fixture
def redis_sync():
    return fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)


@pytest.fixture
def server(monkeypatch, redis_sync):
    """Live console URL; `redis_sync` writes to the same fake Redis the app reads."""
    auth.failed_auth.reset()
    for bucket in admin.read_limit.values():
        bucket.reset()
    monkeypatch.setenv(auth.ADMIN_TOKEN_ENV, TOKEN)
    monkeypatch.setattr(admin, "_fetch_ready", lambda: {"ready": True, "models": {"health": "health-5.0.0-a374e498",
                                                                                 "security": "security-5.0.0-c6fa12d8"}})
    monkeypatch.setattr(admin, "_models_cache", None)
    server_state = redis_sync.connection_pool.connection_kwargs["server"]
    monkeypatch.setattr(fastapi_app, "make_redis", lambda: fakeredis.FakeAsyncRedis(server=server_state, decode_responses=True))
    seed(redis_sync)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(fastapi_app.app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    end = time.monotonic() + 10
    while not srv.started and time.monotonic() < end:
        time.sleep(0.05)
    assert srv.started
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(5)


@pytest.fixture
def app_page(page, server):
    """A page that fails the test on console errors, page errors and CSP violations."""
    problems: list[str] = []
    page.add_init_script("window.__csp = []; addEventListener('securitypolicyviolation', e => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));")
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("console", lambda m: problems.append(f"console.{m.type}: {m.text}") if m.type == "error" and "Failed to load resource" not in m.text else None)
    page.server = server
    page.goto(server + "/#/overview")
    yield page
    csp = page.evaluate("window.__csp")
    assert not csp, f"CSP violations: {csp}"
    assert not problems, problems
