import { api, datetime, dash, esc, pretty } from './util.js';

const KINDS = ['action', 'approval_pending', 'approval', 'rejection', 'mode'];

const row = e => `<tr><td class="mono muted">${esc(datetime(+e.ts_ms))}</td><td>${esc(pretty(e.kind))}</td><td>${esc(dash(e.actor))}</td>
    <td>${e.namespace ? esc(`${e.namespace}/${e.workload}`) : '—'}${e.pod ? `<div class="sub mono">${esc(e.pod)}</div>` : ''}</td>
    <td>${esc(pretty(e.decision))}</td><td class="hide-sm">${esc(pretty(e.outcome))}${e.detail ? `<div class="sub clamp" title="${esc(e.detail)}">${esc(e.detail)}</div>` : ''}</td>
    <td class="hide-sm">${esc(dash(e.mode))}</td></tr>`;

export function mount(root) {
    let cursor = null, seq = 0, timer;
    root.innerHTML = `<header class="page-head"><h1>Ledger</h1><p class="sub">Every automatic and approved action, approval, rejection and mode change. Read-only, kept 90 days.</p></header>
        <section class="panel">
        <form class="filters" id="f" role="search" aria-label="Filter ledger">
            <label>Namespace<input name="namespace" autocomplete="off" spellcheck="false"></label>
            <label>Kind<select name="kind"><option value="">All</option>${KINDS.map(k => `<option value="${k}">${pretty(k)}</option>`).join('')}</select></label>
            <label>Actor<input name="actor" autocomplete="off" spellcheck="false" placeholder="admin:name or fusion"></label>
        </form>
        <div class="scroll"><table class="grid"><thead><tr><th>Time</th><th>Kind</th><th>Actor</th><th>Target</th><th>Decision</th><th class="hide-sm">Outcome</th><th class="hide-sm">Mode</th></tr></thead>
        <tbody id="rows"></tbody></table></div>
        <div class="more"><button type="button" id="more" hidden>Load more</button><span class="sub" id="status" role="status"></span></div></section>`;
    const f = root.querySelector('#f'), rows = root.querySelector('#rows'), more = root.querySelector('#more'), status = root.querySelector('#status');
    async function load(reset) {
        const mine = ++seq;
        if (reset) { cursor = null; rows.innerHTML = ''; }
        const q = new URLSearchParams({ limit: '50' });
        for (const k of ['namespace', 'kind', 'actor']) if (f[k].value.trim()) q.set(k, f[k].value.trim());
        if (cursor) q.set('cursor', cursor);
        status.textContent = 'Loading';
        try {
            const d = await api(`/api/ledger?${q}`);
            if (mine !== seq) return;
            rows.insertAdjacentHTML('beforeend', d.entries.map(row).join(''));
            cursor = d.next_cursor;
            more.hidden = !cursor;
            status.textContent = rows.children.length ? `${rows.children.length} shown` : '';
            if (!rows.children.length) rows.innerHTML = '<tr><td colspan="7" class="empty">No ledger entries match</td></tr>';
        } catch (e) { if (mine === seq) status.textContent = `Could not load the ledger (${e.message})`; }
    }
    f.addEventListener('submit', ev => ev.preventDefault());
    f.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => load(true), 250); });
    more.addEventListener('click', () => load(false));
    load(true);
    return () => { seq++; clearTimeout(timer); };
}
