"""Read-only walk of a DEPLOYED console (port-forward it, then set KUBEHEAL_UI_BASE_URL=http://localhost:8080).
The other UI tests assert seeded fake-Redis data, so they cannot run against a live cluster. This one only checks
that every page renders without console errors or CSP violations; KUBEHEAL_SHOTS=<dir> also writes live-<page>.png."""

import os
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

BASE = os.environ.get("KUBEHEAL_UI_BASE_URL", "")
pytestmark = [pytest.mark.ui, pytest.mark.skipif(not BASE, reason="set KUBEHEAL_UI_BASE_URL to test a live console")]
PAGES = ("overview", "approvals", "ledger", "mode", "models")


def test_live_pages_render_clean():
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.add_init_script("window.__csp = []; addEventListener('securitypolicyviolation', e => window.__csp.push(e.violatedDirective));")
        page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
        page.on("console", lambda m: problems.append(m.text) if m.type == "error" and "Failed to load resource" not in m.text else None)
        shots = os.environ.get("KUBEHEAL_SHOTS")
        for route in PAGES:
            page.goto(f"{BASE}/#/{route}")
            page.wait_for_load_state("networkidle")
            assert page.locator("main, #app, body").first.inner_text().strip(), route
            problems += page.evaluate("window.__csp")
            if shots:
                Path(shots).mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(Path(shots) / f"live-{route}.png"), full_page=True)
        page.goto(f"{BASE}/#/overview")   # the incident page needs a real action to open
        page.wait_for_load_state("networkidle")
        if page.locator("#actions tr").count():
            page.locator("#actions tr").first.click()
            page.wait_for_url("**/#/incident/**")
            problems += page.evaluate("window.__csp")
            if shots:
                page.screenshot(path=str(Path(shots) / "live-incident.png"), full_page=True)
        browser.close()
    assert not problems, problems
