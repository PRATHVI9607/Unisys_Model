// Every value from the API goes through esc(); ids travel in data-* attributes, never inline JS.
const KINDS = ['action', 'health', 'security'];
const MAX_ROWS = 50;
const SVG = p => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const ICON = {
    action: SVG('<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/>'),
    health: SVG('<path d="M3 12h4l2.5 7 5-14L17 12h4"/>'),
    security: SVG('<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>'),
    quiet: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5 11 15l4.5-5.5"/></svg>'
};
const EMPTY = {
    action: ['No actions yet', 'Fusion decisions land here, dry-run ones included'],
    health: ['No health assessments yet', 'Published when a workload spec actually changes'],
    security: ['No security events yet', 'Published per pod syscall / entropy window'],
};

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const isNum = v => typeof v === 'number' && Number.isFinite(v);
const dash = v => (v === null || v === undefined || v === '') ? '—' : v;
const pct = v => isNum(v) ? `${Math.round(v * 100)}%` : '—';
const riskClass = v => !isNum(v) ? 'low' : v >= 0.7 ? 'high' : v >= 0.4 ? 'medium' : 'low';
const pretty = s => s ? String(s).replace(/_/g, ' ') : '—';
const fmtTime = ms => isNum(ms) && ms > 0
    ? new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
const target = e => `${dash(e.namespace)}/${dash(e.workload)}${e.pod ? ` · ${e.pod}` : ''}`;
const tag = (text, cls = '') => `<span class="tag ${cls}">${esc(text)}</span>`;
const $ = id => document.getElementById(id);
const feedEl = kind => document.querySelector(`.feed[data-kind="${kind}"]`);

function windowText(e) {
    const s = e.window_end_ms - e.window_start_ms;
    return isNum(s) && e.window_start_ms > 0 && s >= 0 ? `${Math.round(s / 1000)}s window` : 'window —';
}

function row(e) {
    const k = e.kind;
    let tags, extra = '', right;
    if (k === 'action') {
        tags = [tag(pretty(e.decision)), e.mode === 'observe' ? tag('dry-run', 'dry') : '',
                tag(pretty(e.outcome), String(e.outcome || '').startsWith('failed') ? 'warn' : '')];
        extra = `<div class="summary">${esc(e.summary || e.rationale || '—')}</div>`;
        right = `<span class="pill ${riskClass(e.score)}">${pct(e.score)}</span>
                 <span class="sub">compound ${pct(e.compound_score)}</span>`;
    } else {
        tags = [tag(pretty(e.label)), e.uncertain ? tag('uncertain', 'dry') : '',
                k === 'health' ? tag(`${(e.changed_fields || []).length} fields changed`)
                               : tag(`${dash(e.n_events)} events · ${windowText(e)}`),
                ...(e.failure_reasons || []).map(r => tag(r, 'warn'))];
        const rc = riskClass(e.risk), w = isNum(e.risk) ? Math.max(6, Math.round(e.risk * 100)) : 0;
        right = `<span class="pill ${rc}">${pct(e.risk)}</span>
                 <span class="bar"><i class="${rc}" style="width:${w}%"></i></span>`;
    }
    return `
        <div class="row" tabindex="0" role="button" data-kind="${esc(k)}" data-id="${esc(e.event_id)}">
            <span class="swatch ${esc(k)}">${ICON[k] || ''}</span>
            <div class="body">
                <div class="target">${esc(target(e))}</div>
                <div class="meta">${tags.join('')}<span class="time">${fmtTime(e.timestamp_ms)}</span></div>
                ${extra}
            </div>
            <div class="right">${right}</div>
        </div>`;
}

function emptyState(kind) {
    const [msg, hint] = EMPTY[kind];
    return `<div class="empty">${ICON.quiet}<p>${esc(msg)}</p><div class="hint">${esc(hint)}</div></div>`;
}

function render(kind, events) {   // events newest first
    const el = feedEl(kind);
    el.innerHTML = events.length ? events.slice(0, MAX_ROWS).map(row).join('') : emptyState(kind);
}

function prepend(kind, events) {  // events newest first; skips rows already shown
    const el = feedEl(kind);
    const fresh = events.filter(e => !el.querySelector(`.row[data-id="${CSS.escape(String(e.event_id))}"]`));
    if (!fresh.length) return;
    if (!el.querySelector('.row')) el.innerHTML = '';
    el.insertAdjacentHTML('afterbegin', fresh.map(row).join(''));
    while (el.children.length > MAX_ROWS) el.lastElementChild.remove();
}

let wsUp = false, redisUp = true;
function setConn() {
    const ok = wsUp && redisUp;
    $('connectionDot').classList.toggle('disconnected', !ok);
    $('connectionText').textContent = !wsUp ? 'Reconnecting' : redisUp ? 'Live' : 'Redis unavailable';
}

function setStats(s) {
    if (!s) return;
    $('kpiActions').textContent = s.actions ?? '—';
    $('kpiActionsFoot').textContent = `${s.actions_dry_run ?? 0} dry-run · last ${s.window ?? '—'}`;
    $('kpiHealth').textContent = s.health_events ?? '—';
    $('kpiHealthFoot').textContent = `${s.health_high_risk ?? 0} high-risk · last ${s.window ?? '—'}`;
    $('kpiSecurity').textContent = s.security_events ?? '—';
    $('kpiSecurityFoot').textContent = `${s.security_high_risk ?? 0} high-risk · last ${s.window ?? '—'}`;
    $('kpiHighRisk').textContent = (s.health_high_risk ?? 0) + (s.security_high_risk ?? 0);
    $('actionTally').textContent = s.actions ?? 0;
    $('healthTally').textContent = s.health_events ?? 0;
    $('securityTally').textContent = s.security_events ?? 0;
    redisUp = s.redis_connected !== false;
    setConn();
}

async function getJSON(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
    return r.json();
}

// WS events that arrive while a full load is in flight wait for it, then dedupe against it.
let loading = null;
function loadAll() {
    const p = Promise.all([
        getJSON('/api/stats').then(setStats),
        ...KINDS.map(k => getJSON(`/api/events?kind=${k}&limit=${MAX_ROWS}`).then(d => render(k, d.events || []))),
    ]).catch(err => console.error('load failed', err));
    loading = p;
    p.finally(() => { if (loading === p) loading = null; });
    return p;
}

let attempts = 0;
function connect() {
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`);
    ws.onopen = () => { attempts = 0; wsUp = true; setConn(); loadAll(); };
    ws.onmessage = async m => {
        let msg;
        try { msg = JSON.parse(m.data); } catch { return; }
        if (msg.stats) setStats(msg.stats);
        if (msg.type === 'resync') return loadAll();
        if (msg.type === 'events' && Array.isArray(msg.events)) {
            if (loading) await loading;
            for (const k of KINDS) prepend(k, msg.events.filter(e => e.kind === k).reverse());
        }
    };
    ws.onclose = () => {   // retry forever, capped exponential backoff
        wsUp = false; setConn();
        setTimeout(connect, Math.min(1000 * 2 ** attempts++, 30000));
    };
}

for (const kind of KINDS) {
    const el = feedEl(kind);
    el.innerHTML = '<div class="skel">' + '<div class="line"></div>'.repeat(4) + '</div>';
    const openRow = ev => {
        const r = ev.target.closest('.row');
        if (r) openEventDetails(r.dataset.kind, r.dataset.id);
    };
    el.addEventListener('click', openRow);
    el.addEventListener('keydown', ev => {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openRow(ev); }
    });
}
loadAll();   // also covers a proxy that blocks WebSockets
connect();
