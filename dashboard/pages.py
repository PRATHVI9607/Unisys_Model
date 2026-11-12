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

def _set_marker(view: Dict[str, Any]) -> str:
    """The prediction set with a clear certain or not certain marker (rule M2: an automatic action needs a
    one-label set)."""
    cls = "pset-certain" if view.get("certain") else "pset-uncertain"
    return f'<span class="pset {cls}">{esc(view.get("summary"))}</span>'


def _factor_rows(factors: List[Dict[str, Any]], total: int) -> str:
    """Signed TreeSHAP contributions: the bar length is the absolute value, the text keeps the sign."""
    if not factors:
        return f'<p class="na">{NOT_AVAILABLE}</p>'
    peak = max(abs(f["contribution"]) for f in factors) or 1.0
    rows = []
    for f in factors:
        c = f["contribution"]
        cls = "pos" if c >= 0 else "neg"
        value = "" if f.get("value") is None else f' (value {f["value"]:.4g})'
        rows.append(
            f'<div class="row"><span class="lab">{esc(f["feature"])}{esc(value)}</span>'
            f'<span class="bar"><i class="{cls}" style="width:{_pct(abs(c), peak)}%"></i></span>'
            f'<span class="val">{c:+.4f}</span></div>')
    more = f'<p class="hint">Showing {len(factors)} of {total} factors.</p>' if total > len(factors) else ""
    return "".join(rows) + more


def _legacy_note(legacy: Optional[Dict[str, Any]]) -> str:
    """Fields an older incident carries (CI width) or that are kept for compatibility (top field, the first changed
    field). Shown only when present, never required."""
    if not legacy:
        return ""
    parts = []
    ci_width, top = legacy.get("ci_width"), legacy.get("top")
    if ci_width is not None:
        parts.append(f"CI width {ci_width:.4f}")
    if top:
        parts.append(f"top field {esc(top)}")
    return f'<p class="hint">Legacy or compatibility fields (not required): {"; ".join(parts)}</p>' if parts else ""


def _score_block(name: str, s: Optional[Dict[str, Any]]) -> str:
    if not s:
        return f'<div class="card"><h3>{esc(name)}</h3><p class="na">{NOT_AVAILABLE}</p></div>'
    scored = s.get("model_scored")
    meta = []
    if s.get("model_version"):
        meta.append(f'model version {esc(s["model_version"])}')
    if scored is not None:
        meta.append("model scored" if scored else "NOT model scored")
    return (f'<div class="card"><h3>{esc(name)}</h3>'
            f'{_bar("risk", s.get("risk"), 1.0)}'
            f'<p>label: {_na(s.get("label"))}</p>'
            f'<p>prediction set: {_set_marker(s["prediction_set"])}</p>'
            '<h4>Top factors (TreeSHAP)</h4>'
            f'{_factor_rows(s.get("top_factors") or [], s.get("top_factors_total") or 0)}'
            + (f'<p class="hint">{"; ".join(meta)}</p>' if meta else "")
            + _legacy_note(s.get("legacy")) + '</div>')


def _yes_no(value: Optional[bool]) -> str:
    return f'<span class="na">{NOT_AVAILABLE}</span>' if value is None else ("yes" if value else "no")


def _decision_details(d: Dict[str, Any]) -> str:
    """Containment, rule path and patch fields of the decision record (absent on older incidents)."""
    out = []
    c = d.get("containment")
    if c:
        out.append(f'<p>Containment label: <strong>{_na(c.get("label"))}</strong>; restore after: '
                   f'{_yes_no(c.get("restore_after"))}; human follow-up: {_yes_no(c.get("human_followup"))}</p>')
    if d.get("rule_path") is not None:
        out.append(f'<p>Decided by the rule path: {_yes_no(d.get("rule_path"))}</p>')
    if d.get("rule_reasons"):
        out.append("<p>Rule reasons:</p><ul>" + "".join(f"<li>{esc(r)}</li>" for r in d["rule_reasons"]) + "</ul>")
    if d.get("patch_fields"):
        out.append("<p>Changed fields (spec diff, patch candidates):</p><ul>"
                   + "".join(f"<li><code>{esc(f)}</code></li>" for f in d["patch_fields"]) + "</ul>")
    if d.get("security_fresh") is not None:
        out.append(f'<p>Security score fresh: {_yes_no(d.get("security_fresh"))}</p>')
    return "".join(out)


def _weights(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return f'<p class="na">{NOT_AVAILABLE}</p>'
    peak = max(abs(r["weight"]) for r in rows) or 1.0
    return "".join(_bar(r["name"], r["weight"], peak, f'{r["weight"]:.4f}') for r in rows)


def _legacy_attribution(att: Dict[str, Any]) -> str:
    """Attribution of older incidents (removed in V5). Rendered only when the event still carries it."""
    out = ""
    health = att.get("health") or {}
    if health.get("available") or health.get("top_metric"):
        out += (f'<div class="card"><h3>Legacy config field attribution (health)</h3>{_weights(health.get("fields") or [])}'
                f'<p>top metric: {_na(health.get("top_metric"))}</p></div>')
    sec = att.get("security") or {}
    if sec.get("available"):
        out += f'<div class="card"><h3>Legacy syscall attribution (security)</h3>{_weights(sec.get("syscalls") or [])}</div>'
    return out


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


def _dry_runs(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return ""
    items = "".join(
        f"<li>{_ts(r.get('timestamp'))}: dry-run approved by {_na(r.get('approved_by'))} "
        f"({_na(r.get('action'))}, mode {_na(r.get('mode'))}, stream {_na(r.get('exec_stream_id'))})</li>"
        for r in rows
    )
    return (f'<h3>Dry-run approvals</h3><ul>{items}</ul>'
            '<p class="hint">A dry-run approval queued a request that changes nothing in the cluster. '
            'The incident stays pending until it is approved while the mode is enforce, or rejected.</p>')


def _actions(incident_id: str, status: str, dry_runs: Optional[List[Dict[str, Any]]] = None) -> str:
    history = _dry_runs(dry_runs or [])
    if status != "pending":
        return f'<p>Approval status: <strong>{esc(status)}</strong></p>{history}'
    return (f'<p>Approval status: <strong>pending</strong></p>{history}'
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
        + _decision_details(d) + _token_box() + _actions(inc["incident_id"], inc["status"], inc.get("dry_run_approvals")) + '</section>'
        '<section class="grid"><h2>Scores</h2>'
        + _score_block("Health model", sc.get("health")) + _score_block("Security model", sc.get("security")) +
        f'<div class="card"><h3>Correlation</h3>{_bar("correlation", sc.get("correlation_score"), 1.0)}'
        f'<p>compound: {_na(sc.get("compound"))}</p></div></section>'
        '<p class="hint">Bars show the published values. The prediction set is the set of labels the model cannot '
        'rule out: exactly one label is certain, anything else is not certain, and an automatic action needs a '
        'certain set (rule M2). Factors are TreeSHAP contributions toward the predicted class; the sign is kept.</p>'
        '<section class="grid"><h2>Observed signals</h2>'
        f'<div class="card"><h3>Security signals</h3>'
        f'<h4>Early signals</h4>{_json_block(att["security"].get("early_signals"))}'
        f'<h4>Entropy spike</h4>{_json_block(att["security"].get("entropy_spike"))}</div>'
        + _legacy_attribution(att) + '</section>'
        '<section class="card"><h2>Causal chain</h2>' + _t0(chain["t0"]) +
        f'<ol>{steps}</ol><p class="hint">Offsets in the chain are as published by the DCM chain builder, '
        'not wall clock measurements.</p></section>'
        '<section class="card"><h2>Ledger timeline</h2><table><thead><tr><th>#</th><th>Time</th><th>Step</th>'
        f'<th>Payload</th></tr></thead><tbody>{timeline}</tbody></table></section>'
    )
    return _layout(f"Incident {inc['incident_id']}", body)


# ------------------------------------------------------------------ baseline promotion candidates (V5-I3)

def baseline_candidates_page(candidates: List[Dict[str, Any]], kill_switch: Dict[str, Any]) -> str:
    mode = kill_switch.get("mode")
    if kill_switch.get("dry_run"):
        why = "" if kill_switch.get("readable") else " (the ConfigMap could not be read, which counts as test)"
        note = (f'<p class="warn">The kill switch mode is {esc(mode)}{esc(why)}. Approving now only writes a dry-run '
                'entry to the ledger: the golden baseline is NOT replaced and the candidate stays pending. '
                'Rejecting works in every mode.</p>')
    else:
        note = '<p>The kill switch mode is enforce: an approval replaces the golden baseline.</p>'
    rows = ""
    for c in candidates:
        a = c.get("assessment") or {}
        fields = "".join(f"<li><code>{esc(f)}</code></li>" for f in c.get("changed_fields") or []) or             f'<li class="na">{NOT_AVAILABLE}</li>'
        attrs = (f'data-namespace="{esc(c.get("namespace"))}" data-deployment="{esc(c.get("deployment"))}" '
                 f'data-candidate="{esc(c.get("candidate_id"))}"')
        rows += (
            f'<tr><td>{esc(c.get("namespace"))}/{esc(c.get("deployment"))}</td><td>{_na(c.get("tier"))}</td>'
            f'<td><ul>{fields}</ul></td>'
            f'<td>label {_na(a.get("label"))}, risk {_na(a.get("risk"), "{:.4f}")}<br>'
            f'{_set_marker(a["prediction_set"]) if a.get("prediction_set") else _na(None)}<br>'
            f'model {_na(a.get("model_version"))}</td>'
            f'<td>{_ts(c.get("created_at"))}<br><code>{esc(c.get("candidate_id"))}</code></td>'
            f'<td><button type="button" data-action="baseline-approve" {attrs}>Approve</button> '
            f'<button type="button" class="danger" data-action="baseline-reject" {attrs}>Reject</button></td></tr>')
    rows = rows or '<tr><td colspan="6" class="na">no pending baseline candidates</td></tr>'
    body = (
        '<h1>Baseline promotion candidates</h1>'
        '<p class="hint">In prod the Health Agent only proposes a new golden baseline (the live spec was judged '
        'benign and certain, the rollout is complete). Nothing replaces the baseline until it is approved here, and '
        'every decision is a ledger entry that keeps the previous baseline.</p>'
        + _token_box() + f'<section class="card"><h2>Mode</h2>{note}</section>'
        '<section class="card"><h2>Pending candidates</h2>'
        '<label for="baseline-reason">Reason (optional, at most 512 characters)</label> '
        '<input type="text" id="baseline-reason" maxlength="512" autocomplete="off">'
        '<table><thead><tr><th>Workload</th><th>Tier</th><th>Changed fields</th><th>Assessment</th>'
        f'<th>Candidate</th><th>Decision</th></tr></thead><tbody>{rows}</tbody></table></section>'
    )
    return _layout("Baseline candidates", body)
