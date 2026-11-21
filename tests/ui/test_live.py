"""Read-only walk of the console. Against a DEPLOYED one when KUBEHEAL_UI_BASE_URL is set (port-forward it, then
http://localhost:8080); otherwise against the real app started in-process on seeded fake Redis. It only checks that every
page renders without console errors or CSP violations, and writes live-<page>.png to KUBEHEAL_SHOTS or a tmp dir."""

import os
from pathlib import Path

import pytest

from tests.ui.conftest import assert_pngs

pytestmark = pytest.mark.ui
PAGES = ("overview", "approvals", "ledger", "mode", "models")


def test_live_pages_render_clean(request, tmp_path, browser):
    base = os.environ.get("KUBEHEAL_UI_BASE_URL") or request.getfixturevalue("server")
    problems: list[str] = []
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.add_init_script("window.__csp = []; addEventListener('securitypolicyviolation', e => window.__csp.push(e.violatedDirective));")
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("console", lambda m: problems.append(m.text) if m.type == "error" and "Failed to load resource" not in m.text else None)
    shots = Path(os.environ.get("KUBEHEAL_SHOTS") or tmp_path)
    shots.mkdir(parents=True, exist_ok=True)
    for route in PAGES:
        page.goto(f"{base}/#/{route}")
        page.wait_for_load_state("networkidle")
        assert page.locator("main, #app, body").first.inner_text().strip(), route
        problems += page.evaluate("window.__csp")
        page.screenshot(path=str(shots / f"live-{route}.png"), full_page=True)
    page.goto(f"{base}/#/overview")   # the incident page needs a real action to open
    page.wait_for_load_state("networkidle")
    if page.locator("#actions tr").count():
        page.locator("#actions tr").first.click()
        page.wait_for_url("**/#/incident/**")
        problems += page.evaluate("window.__csp")
        page.screenshot(path=str(shots / "live-incident.png"), full_page=True)
    assert_pngs(sorted(shots.glob("live-*.png")))
    assert not problems, problems
