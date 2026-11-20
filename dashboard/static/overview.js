import { live, subscribe } from './live.js';
import { dash, decisionClass, dur, esc, isNum, paint, pct, pretty, riskClass, target, time, ago, bar } from './util.js';

const FILTERS = [
    ['all', 'All', () => true],
    ['kill', 'Kills', a => a.decision === 'AUTO_KILL'],
    ['patch', 'Patches', a => a.decision === 'AUTO_PATCH'],
    ['human', 'Human', a => a.decision === 'HUMAN'],
    ['skipped', 'Guard rails', a => String(a.outcome).startsWith('skipped_')],
];

const kpi = (label, value, foot) =>
    `<div class="kpi"><dt>${esc(label)}</dt><dd class="fig">${esc(value)}</dd><dd class="foot">${esc(foot)}</dd></div>`;

function kpis() {
    const s = live.stats;
    if (!s) return kpi('Pods killed', '—', '') + kpi('Workloads patched', '—', '') + kpi('Awaiting approval', '—', '')
        + kpi('Guard rails hit', '—', '') + kpi('Detection to kill', '—', '') + kpi('Containment requested', '—', '');
    const l = s.latency_ms || {};
    return kpi('Pods killed', s.kills, `${s.kills_dry_run} more in dry-run`)
        + kpi('Workloads patched', s.patches, `${s.patches_dry_run} more in dry-run`)
        + kpi('Awaiting approval', live.pending, `of ${s.human} human decisions`)
        + kpi('Guard rails hit', s.guard_rails, 'actions skipped by a safety rail')
        + kpi('Detection to kill', isNum(l.p50) ? dur(l.p50) : '—', isNum(l.p95) ? `p95 ${dur(l.p95)} over ${l.n} kills` : 'no kills with a security window yet')
        + kpi('Containment requested', s.containment_requested, 'network freeze before delete');
}

function actionRow(a, fresh) {
    const dry = a.mode === 'observe';
    const contain = a.containment ? `<span class="tag ${a.containment === 'failed' ? 'neg' : ''}">containment ${esc(a.containment)}</span>` : '';
    return `<tr class="rail ${decisionClass(a.decision)}${fresh ? ' fresh' : ''}" data-href="#/incident/action/${encodeURIComponent(a.event_id)}">
        <td class="mono muted">${time(a.timestamp_ms)}</td>
        <td><a href="#/incident/action/${encodeURIComponent(a.event_id)}" data-focus="a-${esc(a.event_id)}">${esc(target(a))}</a>
            ${a.pod ? `<div class="sub mono">${esc(a.pod)}</div>` : ''}</td>
        <td>${esc(pretty(a.decision).toLowerCase())}${dry ? ' <span class="tag">dry-run</span>' : ''}</td>
        <td class="hide-sm">${esc(pretty(a.outcome))} ${contain}</td>
        <td class="num">${pct(a.score)}</td></tr>`;
}

function signalRow(e, fresh) {
    const rc = riskClass(e.risk);
    return `<li class="signal${fresh ? ' fresh' : ''}"><a href="#/incident/${esc(e.kind)}/${encodeURIComponent(e.event_id)}" data-focus="s-${esc(e.event_id)}">
        <span class="sig-main"><span class="sig-kind">${e.kind === 'health' ? 'Health' : 'Security'}</span> ${esc(target(e))}</span>
        <span class="sub">${esc(pretty(e.label))}${e.uncertain ? ', uncertain' : ''}${(e.failure_reasons || []).length ? ', ' + esc(e.failure_reasons.join(', ')) : ''} · ${ago(e.timestamp_ms)}</span></a>
        <span class="risk ${rc}"><span class="num">${pct(e.risk)}</span>${bar(e.risk, 1, rc)}</span></li>`;
}

export function mount(root) {
    let filter = 'all', fresh = new Set(), tick;
    root.innerHTML = `
        <header class="page-head"><h1>Overview</h1><p class="sub">Counts cover the newest 200 actions</p></header>
        <dl class="kpis" id="kpis" aria-label="Summary"></dl>
        <div class="cols">
            <section class="panel" aria-labelledby="h-actions">
                <header class="panel-head"><h2 id="h-actions">Actions</h2>
                    <div class="seg" role="group" aria-label="Filter actions">${FILTERS.map(([k, t]) =>
                        `<button type="button" data-filter="${k}" aria-pressed="${k === 'all'}">${t}</button>`).join('')}</div></header>
                <div class="scroll"><table class="grid"><thead><tr><th>Time</th><th>Target</th><th>Decision</th><th class="hide-sm">Outcome</th><th class="num">Score</th></tr></thead>
                <tbody id="actions"></tbody></table></div>
            </section>
            <section class="panel" aria-labelledby="h-signals">
                <header class="panel-head"><h2 id="h-signals">Signals</h2><span class="sub">health and security, newest first</span></header>
                <ul class="signals" id="signals"></ul>
            </section>
        </div>`;
    const draw = (arrived = []) => {
        for (const e of arrived) fresh.add(e.event_id);
        paint(root.querySelector('#kpis'), kpis());
        const test = FILTERS.find(f => f[0] === filter)[2];
        const rows = live.action.filter(test).slice(0, 60);
        paint(root.querySelector('#actions'), rows.length ? rows.map(a => actionRow(a, fresh.has(a.event_id))).join('')
            : `<tr><td colspan="5" class="empty">${live.action.length ? 'No actions match this filter' : 'No actions yet. Fusion decisions appear here, dry-run ones included.'}</td></tr>`);
        const sig = [...live.health, ...live.security].sort((a, b) => b.timestamp_ms - a.timestamp_ms).slice(0, 30);
        paint(root.querySelector('#signals'), sig.length ? sig.map(e => signalRow(e, fresh.has(e.event_id))).join('')
            : '<li class="empty">No health or security signals yet</li>');
        fresh = new Set();
    };
    root.addEventListener('click', ev => {
        const f = ev.target.closest('[data-filter]');
        if (f) {
            filter = f.dataset.filter;
            root.querySelectorAll('[data-filter]').forEach(b => b.setAttribute('aria-pressed', String(b === f)));
            return draw();
        }
        const tr = ev.target.closest('tr[data-href]');
        if (tr && !ev.target.closest('a')) location.hash = tr.dataset.href;
    });
    draw();
    const off = subscribe(draw);
    tick = setInterval(() => draw(), 30000);   // relative times
    return () => { off(); clearInterval(tick); };
}
