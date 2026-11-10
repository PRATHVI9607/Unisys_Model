"""Server side HTML for the approvals and incident pages.

Every value that originates in an event, a ledger entry or the request path goes through `esc()`
(html.escape with quotes). Markup is assembled only from literals and escaped values; the only
numbers placed in `style` attributes are floats computed here and clamped to 0..100. No inline
script exists: behaviour lives in /static/admin.js, which uses textContent only.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from string import Template
from typing import Any, Dict, List, Optional

from dashboard.incident_view import NOT_AVAILABLE

_LAYOUT = os.path.join(os.path.dirname(__file__), "templates", "admin_layout.html")


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _na(value: Any, fmt: str = "{}") -> str:
    return f'<span class="na">{NOT_AVAILABLE}</span>' if value is None else esc(fmt.format(value))


def _layout(title: str, body: str) -> str:
    with open(_LAYOUT, encoding="utf-8") as fh:
        return Template(fh.read()).safe_substitute(title=esc(title), body=body)


def _pct(value: float, maximum: float) -> float:
    if maximum <= 0:
        return 0.0
    return max(0.0, min(100.0, round(100.0 * value / maximum, 1)))


def _bar(label: str, value: Optional[float], maximum: float, text: Optional[str] = None) -> str:
    if value is None:
        return f'<div class="row"><span class="lab">{esc(label)}</span><span class="na">{NOT_AVAILABLE}</span></div>'
    shown = esc(text if text is not None else f"{value:.4f}")
    return (f'<div class="row"><span class="lab">{esc(label)}</span>'
            f'<span class="bar"><i style="width:{_pct(value, maximum)}%"></i></span>'
            f'<span class="val">{shown}</span></div>')


def _ts(value: Any) -> str:
    return esc(value) if value else f'<span class="na">{NOT_AVAILABLE}</span>'


# ------------------------------------------------------------------ approvals page

def _token_box() -> str:
    return ('<section class="card"><h2>Admin token</h2>'
            '<p class="hint">Needed for approve, reject and the kill switch. It is kept in this tab only '
            '(sessionStorage) and sent as a Bearer header. It is never shown again.</p>'
            '<input type="password" id="admin-token" autocomplete="off" placeholder="admin token">'
            '<p id="admin-result" role="status"></p></section>')


def _kill_switch_card(status: Dict[str, Any]) -> str:
    mode = status.get("mode")
    readable = status.get("readable")
    rows = "".join(
        f"<tr><td>{_ts(h.get('timestamp'))}</td><td>{_na(h.get('from'))}</td><td>{_na(h.get('to'))}</td>"
        f"<td>{_na(h.get('source'))}</td><td>{_na(h.get('actor'))}</td></tr>"
        for h in reversed(status.get("history") or [])
    ) or '<tr><td colspan="5" class="na">no mode changes recorded</td></tr>'
    note = "" if readable else '<p class="warn">The ConfigMap could not be read. Components treat this as test mode.</p>'
    other = "enforce" if mode == "test" else "test"
    return (
        '<section class="card"><h2>Kill switch</h2>'
        f'<p>Current mode: <strong class="mode mode-{esc(mode)}">{esc(mode)}</strong> '
        f'({"dry run, no cluster writes" if status.get("dry_run") else "enforcing"})</p>{note}'
        f'<button type="button" data-action="mode" data-mode="{esc(other)}">Switch to {esc(other)}</button>'
        '<h3>History</h3><table><thead><tr><th>Time</th><th>From</th><th>To</th><th>Source</th><th>Actor</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></section>"
    )


def approvals_page(pending: List[Dict[str, Any]], incidents: List[Dict[str, Any]], kill_switch: Dict[str, Any]) -> str:
    prow = "".join(
        f'<tr><td><a href="/incidents/{esc(p["incident_id"])}">{esc(p["incident_id"])}</a></td>'
        f'<td>{_na(p.get("decision"))}</td><td>{_na(p.get("adjusted_score"), "{:.4f}")}</td>'
        f'<td>{esc(p.get("namespace"))}/{esc(p.get("deployment"))}</td><td>{esc(p.get("rationale"))}</td></tr>'
        for p in pending
    ) or '<tr><td colspan="5" class="na">no pending approvals</td></tr>'
    irow = "".join(
        f'<tr><td><a href="/incidents/{esc(i["incident_id"])}">{esc(i["incident_id"])}</a></td>'
        f'<td>{esc(i["status"])}</td><td>{esc(", ".join(str(s) for s in i["steps"]))}</td></tr>'
        for i in incidents
    ) or '<tr><td colspan="3" class="na">no incidents in the ledger</td></tr>'
    body = (
        '<h1>Approvals and incidents</h1>' + _token_box() + _kill_switch_card(kill_switch) +
        '<section class="card"><h2>Pending approvals</h2><table><thead><tr><th>Incident</th><th>Decision</th>'
        f'<th>Score</th><th>Target</th><th>Rationale</th></tr></thead><tbody>{prow}</tbody></table></section>'
        '<section class="card"><h2>Incidents</h2><table><thead><tr><th>Incident</th><th>Approval</th>'
        f'<th>Ledger steps</th></tr></thead><tbody>{irow}</tbody></table></section>'
    )
    return _layout("Approvals", body)


# ------------------------------------------------------------------ incident page

def _score_block(name: str, s: Optional[Dict[str, Any]]) -> str:
    if not s:
        return f'<div class="card"><h3>{esc(name)}</h3><p class="na">{NOT_AVAILABLE}</p></div>'
    return (f'<div class="card"><h3>{esc(name)}</h3>'
            f'{_bar("risk", s.get("risk"), 1.0)}'
            f'{_bar("CI width", s.get("ci_width"), 1.0)}'
            f'<p>label: {_na(s.get("label"))}; top: {_na(s.get("top"))}</p></div>')


def _weights(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return f'<p class="na">{NOT_AVAILABLE}</p>'
    peak = max(abs(r["weight"]) for r in rows) or 1.0
    return "".join(_bar(r["name"], r["weight"], peak, f'{r["weight"]:.4f}') for r in rows)


def _json_block(value: Any) -> str:
    if value in (None, {}, []):
        return f'<p class="na">{NOT_AVAILABLE}</p>'
    return f"<pre>{esc(json.dumps(value, indent=2, sort_keys=True, default=str))}</pre>"


def _t0(t0: Dict[str, Any]) -> str:
    if not t0.get("available"):
        return f'<p>Attack onset T0: <span class="na">{NOT_AVAILABLE}</span> (no record or event of this incident carries it)</p>'
    ms = int(t0["t0_ms"])
    try:
        iso = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        iso = NOT_AVAILABLE
    return f"<p>Attack onset T0: {esc(ms)} ms since the epoch ({esc(iso)}), from the {esc(t0['source'])}</p>"


def _actions(incident_id: str, status: str) -> str:
    if status != "pending":
        return f'<p>Approval status: <strong>{esc(status)}</strong></p>'
    return ('<p>Approval status: <strong>pending</strong></p>'
            f'<button type="button" data-action="approve" data-incident="{esc(incident_id)}">Approve</button> '
            f'<button type="button" class="danger" data-action="reject" data-incident="{esc(incident_id)}">Reject</button>')


def incident_page(inc: Dict[str, Any]) -> str:
    d = inc.get("decision") or {}
    tgt = inc["target"]
    sc = inc["scores"]
    att = inc["attribution"]
    chain = inc["causal_chain"]
    steps = "".join(f"<li>{esc(s)}</li>" for s in chain["steps"]) or f'<li class="na">{NOT_AVAILABLE}</li>'
    timeline = "".join(
        f"<tr><td>{esc(r['sequence'])}</td><td>{_ts(r['timestamp'])}</td><td>{esc(r['step'])}</td>"
        f"<td><pre>{esc(json.dumps(r['payload'], sort_keys=True, default=str))}</pre></td></tr>"
        for r in inc["timeline"]
    )
    body = (
        f'<h1>Incident <code>{esc(inc["incident_id"])}</code></h1>'
        '<section class="card"><h2>Decision</h2>'
        f'<p>Target: {_na(tgt.get("namespace"))}/{_na(tgt.get("deployment"))}, pod {_na(tgt.get("pod"))}</p>'
        f'<p>Decision: <strong>{_na(d.get("decision"))}</strong>; adjusted score {_na(d.get("adjusted_score"), "{:.4f}")}; '
        f'tier {_na(d.get("namespace_tier"))}; dry run {_na(d.get("dry_run"))}</p>'
        f'<p>Rationale: {_na(d.get("rationale"))}</p>'
        + _token_box() + _actions(inc["incident_id"], inc["status"]) + '</section>'
        '<section class="grid"><h2>Scores</h2>'
        + _score_block("Health model", sc.get("health")) + _score_block("Security model", sc.get("security")) +
        f'<div class="card"><h3>Correlation</h3>{_bar("correlation", sc.get("correlation_score"), 1.0)}'
        f'<p>compound: {_na(sc.get("compound"))}</p></div></section>'
        '<p class="hint">Bars show the published values. "CI width" is the width of the conformal interval; '
        'its position is not published, so no bounds are drawn.</p>'
        '<section class="grid"><h2>Attribution (SHAP / attention)</h2>'
        f'<div class="card"><h3>Config fields (health)</h3>{_weights(att["health"]["fields"])}'
        f'<p>top metric: {_na(att["health"].get("top_metric"))}</p></div>'
        f'<div class="card"><h3>Syscalls (security)</h3>{_weights(att["security"]["syscalls"])}'
        f'<h4>Early signals</h4>{_json_block(att["security"].get("early_signals"))}'
        f'<h4>Entropy spike</h4>{_json_block(att["security"].get("entropy_spike"))}</div></section>'
        '<section class="card"><h2>Causal chain</h2>' + _t0(chain["t0"]) +
        f'<ol>{steps}</ol><p class="hint">Offsets in the chain are as published by the DCM chain builder, '
        'not wall clock measurements.</p></section>'
        '<section class="card"><h2>Ledger timeline</h2><table><thead><tr><th>#</th><th>Time</th><th>Step</th>'
        f'<th>Payload</th></tr></thead><tbody>{timeline}</tbody></table></section>'
    )
    return _layout(f"Incident {inc['incident_id']}", body)
