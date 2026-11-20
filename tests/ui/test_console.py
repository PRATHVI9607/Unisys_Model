import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import expect

from kubeheal.contracts import STREAM_ACTIONS, STREAM_LEDGER, ActionEvent, Decision, key_approval
from tests.dashboard_seed import HUMAN_PENDING
from tests.ui.conftest import TOKEN

pytestmark = pytest.mark.ui


def sign_in(page, name="Priya"):
    page.get_by_label("Admin token").fill(TOKEN)
    page.get_by_label("Your name for the ledger").fill(name)
    page.get_by_role("button", name="Sign in").click()


def test_overview_renders_incidents_and_kpis(app_page):
    page = app_page
    expect(page.locator("#actions tr")).to_have_count(7)
    kpi = lambda label: page.locator(".kpi", has_text=label)   # noqa: E731
    expect(kpi("Pods killed").locator(".fig")).to_have_text("1")
    expect(kpi("Awaiting approval").locator(".fig")).to_have_text("2")
    expect(kpi("Guard rails hit").locator(".fig")).to_have_text("1")
    expect(kpi("Detection to kill").locator(".fig")).to_have_text("840 ms")
    expect(kpi("Containment requested").locator(".fig")).to_have_text("1")
    expect(page.locator("#actions tr", has_text="shop-prod/billing")).to_contain_text("auto kill")
    expect(page.locator("#signals li")).to_have_count(4)
    page.get_by_role("button", name="Human").click()
    expect(page.locator("#actions tr")).to_have_count(3)
    expect(page.locator("#modebar")).to_contain_text("Observe")   # newest action ran dry-run


def test_live_websocket_update(app_page, redis_sync):
    page = app_page
    expect(page.locator("#actions tr")).to_have_count(7)
    expect(page.locator("#modebar .conn")).to_contain_text("Live")
    redis_sync.xadd(STREAM_ACTIONS, ActionEvent(
        event_id="a-live-1", namespace="payments", workload="ledger-writer", pod="ledger-writer-0", decision=Decision.AUTO_KILL,
        mode="enforce", outcome="pod_killed", score=0.99, rationale="live").to_fields())
    row = page.locator("#actions tr", has_text="payments/ledger-writer")
    expect(row).to_be_visible()
    expect(page.locator("#actions tr")).to_have_count(8)
    expect(page.locator("#announce")).to_contain_text("auto kill: payments/ledger-writer")
    expect(page.locator(".kpi", has_text="Pods killed").locator(".fig")).to_have_text("2")


def test_incident_detail(app_page):
    page = app_page
    page.get_by_role("link", name="shop-prod/billing", exact=True).click()
    expect(page).to_have_url(re.compile(r"#/incident/action/a-kill-1"))
    expect(page.get_by_role("heading", level=1)).to_have_text("shop-prod/billing")
    expect(page.locator(".trail")).to_contain_text("840 ms after detection")
    expect(page.locator(".trail")).to_contain_text("Containment requested")
    expect(page.locator(".bars").first).to_contain_text("frac_rename")
    expect(page.get_by_text("Ransomware certain")).to_be_visible()
    page.get_by_role("link", name="Detection").click()
    expect(page.get_by_text("Syscall events")).to_be_visible()
    page.go_back()
    page.go_back()
    expect(page.get_by_role("heading", level=1)).to_have_text("Overview")


def test_approval_flow_end_to_end(app_page, redis_sync):
    page = app_page
    page.keyboard.press("2")
    expect(page.get_by_role("heading", name="Needs a decision")).to_be_visible()
    expect(page.get_by_role("button", name="Approve auto patch")).to_have_count(0)   # signed out: no write buttons
    page.get_by_label("Admin token").fill("not-the-token")
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_role("alert")).to_have_text("Token rejected")
    sign_in(page)
    item = page.locator(".appr", has_text="shop-prod/search")
    item.get_by_role("button", name="Approve auto patch").click()
    expect(item.get_by_text("Approving runs auto patch")).to_be_visible()
    item.get_by_label(re.compile("Approving runs")).fill("no baseline, patch is the safe move")
    item.get_by_role("button", name="Confirm approve").click()
    expect(page.locator(".appr", has_text="shop-prod/search").locator("[data-state]")).to_have_text("approve requested")
    entries = redis_sync.xrange("kubeheal.approvals")
    assert [(e["action_event_id"], e["actor"], e["reason"]) for _, e in entries] == [(HUMAN_PENDING, "admin:Priya", "no baseline, patch is the safe move")]
    # fusion picks it up
    import json
    key = key_approval(HUMAN_PENDING)
    for state in ("executing", "executed"):
        redis_sync.set(key, json.dumps({**json.loads(redis_sync.get(key)), "state": state}), keepttl=True)
        expect(page.locator(".appr", has_text="shop-prod/search").locator("[data-state]")).to_have_text(state, timeout=8000)
    expect(page.get_by_role("heading", name="Resolved")).to_be_visible()
    # a second admin deciding the same item is told no
    other = page.locator(".appr", has_text="shop-prod/reports")
    other.get_by_role("button", name="Reject").click()
    other.get_by_role("button", name="Confirm reject").click()
    expect(page.locator(".appr", has_text="shop-prod/reports").locator("[data-state]")).to_have_text("reject requested")


def test_mode_switch_with_inline_confirmation(app_page, redis_sync):
    page = app_page
    page.keyboard.press("4")
    expect(page.get_by_label("Enforce")).to_be_disabled()
    sign_in(page)
    page.get_by_label("Enforce").check()
    expect(page.get_by_text("This lets fusion act on live workloads")).to_be_visible()
    assert redis_sync.get("kubeheal:mode") is None   # nothing happens before the confirmation
    page.get_by_role("button", name="Confirm switch to enforce").click()
    expect(page.get_by_text("Runtime mode is now enforce")).to_be_visible()
    expect(page.locator("#modebar")).to_contain_text("Enforce")
    assert redis_sync.get("kubeheal:mode") == "enforce"
    page.keyboard.press("3")
    page.get_by_label("Kind").select_option("mode")
    expect(page.locator("#rows tr")).to_have_count(2)   # the seeded one and this switch
    expect(page.locator("#rows")).to_contain_text("admin:Priya")


def test_ledger_filter_and_paging(app_page, redis_sync):
    for i in range(70):
        redis_sync.xadd(STREAM_LEDGER, {"ts_ms": str(i), "kind": "action", "actor": "fusion", "namespace": "bulk", "decision": "AUTO_KILL"})
    page = app_page
    page.keyboard.press("3")
    expect(page.locator("#rows tr")).to_have_count(50)
    page.get_by_role("button", name="Load more").click()
    expect(page.locator("#rows tr")).to_have_count(75)
    expect(page.get_by_role("button", name="Load more")).to_be_hidden()
    page.get_by_label("Namespace").fill("staging")
    expect(page.locator("#rows tr")).to_have_count(1)
    expect(page.locator("#rows")).to_contain_text("admin:maria")
    page.get_by_label("Namespace").fill("nowhere")
    expect(page.get_by_text("No ledger entries match")).to_be_visible()


def test_models_page(app_page):
    page = app_page
    page.keyboard.press("5")
    expect(page.get_by_text("health-5.0.0-a374e498")).to_be_visible()
    expect(page.get_by_text("Inference is ready")).to_be_visible()


def test_keyboard_navigation(app_page):
    page = app_page
    expect(page.locator("#actions tr")).to_have_count(7)
    page.keyboard.press("Tab")
    expect(page.get_by_role("link", name="Skip to content")).to_be_focused()
    first = page.locator("#actions a").first
    first.focus()
    page.keyboard.press("ArrowDown")
    expect(page.locator("#actions a").nth(1)).to_be_focused()
    page.keyboard.press("ArrowUp")
    expect(first).to_be_focused()
    page.keyboard.press("Enter")
    expect(page).to_have_url(re.compile(r"#/incident/action/"))
    for key, heading in (("2", "Approvals"), ("3", "Ledger"), ("4", "Mode"), ("5", "Models"), ("1", "Overview")):
        page.keyboard.press(key)
        expect(page.get_by_role("heading", level=1)).to_have_text(heading)
    # focus is visible
    page.locator("#nav a").first.focus()
    assert page.evaluate("getComputedStyle(document.activeElement).outlineStyle") == "solid"


def test_themes(app_page):
    page = app_page
    bg = lambda: page.evaluate("getComputedStyle(document.body).backgroundColor")   # noqa: E731
    page.emulate_media(color_scheme="light")
    assert bg() == "rgb(250, 250, 250)"
    page.get_by_role("button", name=re.compile("Theme")).click()   # system -> light
    page.get_by_role("button", name=re.compile("Theme")).click()   # -> dark
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
    assert bg() == "rgb(20, 20, 21)"
    page.reload()   # remembered
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
    page.get_by_role("button", name=re.compile("Theme")).click()   # -> system, follows the OS
    page.emulate_media(color_scheme="dark")
    assert bg() == "rgb(20, 20, 21)"


@pytest.mark.parametrize("route", ["overview", "approvals", "ledger", "mode", "models", "incident/action/a-kill-1"])
def test_narrow_screen_does_not_scroll_sideways(app_page, route):
    page = app_page
    page.set_viewport_size({"width": 400, "height": 800})
    page.goto(page.server + f"/#/{route}")
    page.wait_for_load_state("networkidle")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_page_is_interactive_fast(app_page):
    t = app_page.evaluate("performance.getEntriesByType('navigation')[0].domInteractive")
    assert t < 200


@pytest.mark.skipif(not os.environ.get("KUBEHEAL_SHOTS"), reason="set KUBEHEAL_SHOTS=<dir> to write screenshots")
def test_screenshots(app_page):
    page, out = app_page, Path(os.environ["KUBEHEAL_SHOTS"])
    out.mkdir(parents=True, exist_ok=True)
    page.set_viewport_size({"width": 1280, "height": 800})
    expect(page.locator("#actions tr")).to_have_count(7)
    for theme in ("light", "dark"):
        page.emulate_media(color_scheme=theme)
        page.evaluate(f"document.documentElement.dataset.theme = '{theme}'")
        for route in ("overview", "incident/action/a-kill-1", "approvals", "ledger", "mode", "models"):
            page.goto(page.server + f"/#/{route}")
            page.wait_for_timeout(500)
            if route == "approvals":
                if page.get_by_label("Admin token").count():
                    sign_in(page)
                page.locator(".appr", has_text="shop-prod/search").get_by_role("button", name="Approve auto patch").click()
            page.screenshot(path=str(out / f"after-{theme}-{route.split('/')[0]}.png"), full_page=False)
        page.set_viewport_size({"width": 400, "height": 800})
        page.goto(page.server + "/#/overview")
        page.wait_for_timeout(400)
        page.screenshot(path=str(out / f"after-{theme}-overview-400.png"))
        page.set_viewport_size({"width": 1280, "height": 800})
