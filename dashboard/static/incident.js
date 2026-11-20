import { ApiError, api, bar, datetime, decisionClass, dash, dur, esc, icon, isNum, pct, pretty, riskClass, target, time } from './util.js';

const kv = (k, v, cls = '') => `<div><dt>${esc(k)}</dt><dd class="${cls}">${esc(dash(v))}</dd></div>`;
const yesNo = v => v === true ? 'yes' : v === false ? 'no' : '—';
const section = (title, body) => `<section class="panel pad"><h2>${esc(title)}</h2>${body}</section>`;

function factors(e) {
    const f = Array.isArray(e.top_factors) ? e.top_factors : [];
    if (!f.length) return '';
    const max = Math.max(...f.map(x => Math.abs(x.contribution) || 0), 1e-9);
    return section('Top factors', `<ul class="bars">${f.map(x => `<li>
        <span class="bar-label" title="${esc(x.feature)}">${esc(x.feature)} <span class="muted mono">${isNum(x.value) ? '= ' + +x.value.toFixed(4) : '= —'}</span></span>
        ${bar(Math.abs(x.contribution), max, x.contribution < 0 ? 'neg' : '')}
        <span class="num">${x.contribution >= 0 ? '+' : ''}${(+x.contribution).toFixed(3)}</span></li>`).join('')}</ul>
        <p class="hint">Contribution to the predicted label. Positive pushes toward it.</p>`);
}

function probabilities(e) {
    const p = Object.entries(e.probabilities || {}).sort((a, b) => b[1] - a[1]);
    if (!p.length) return '';
    return section('Class probabilities', `<ul class="bars">${p.map(([l, v]) =>
        `<li><span class="bar-label">${esc(pretty(l))}</span>${bar(v, 1)}<span class="num">${pct(v, 1)}</span></li>`).join('')}</ul>
        <p class="hint">${e.uncertain ? 'Uncertain: more than one label is plausible at the configured confidence.' : 'Certain: one label in the conformal set.'}</p>`);
}

function signal(e) {
    const security = e.kind === 'security';
    const win = e.window_end_ms - e.window_start_ms;
    const head = section(security ? 'Security event' : 'Health assessment', `<dl class="kv">
        ${kv('Label', pretty(e.label))}${kv('Risk', pct(e.risk, 1), `risk-text ${riskClass(e.risk)}`)}
        ${kv('Uncertain', yesNo(e.uncertain))}${kv('Model', e.model_version)}${kv('Time', datetime(e.timestamp_ms))}
        ${security ? kv('Pod', e.pod) + kv('Syscall events', e.n_events) + kv('Window', e.window_start_ms > 0 && isNum(win) ? `${Math.round(win / 1000)} s` : '—')
            : kv('Spec changed', yesNo(e.spec_changed)) + kv('Restore baseline', e.has_baseline ? 'available' : 'none')}</dl>
        ${(e.failure_reasons || []).length ? `<p class="callout"><span>Rollback rule</span> ${esc(e.failure_reasons.join(', '))}</p>` : ''}
        ${(e.changed_fields || []).length ? `<h3>Changed fields</h3><ul class="chips">${e.changed_fields.map(f => `<li class="mono">${esc(f)}</li>`).join('')}</ul>` : ''}`);
    return head + factors(e) + probabilities(e);
}

function trail(a, h, s) {
    const step = (when, title, sub, href) => `<li><span class="when mono">${esc(when)}</span><span>${href ? `<a href="${href}">${esc(title)}</a>` : esc(title)}<span class="sub">${esc(sub)}</span></span></li>`;
    const steps = [];
    if (h) steps.push([h.timestamp_ms, step(time(h.timestamp_ms), 'Spec change assessed', `${pretty(h.label)}, risk ${pct(h.risk)}`, `#/incident/health/${encodeURIComponent(h.event_id)}`)]);
    if (s) {
        if (s.window_start_ms > 0) steps.push([s.window_start_ms, step(time(s.window_start_ms), 'Syscall window opened', `${s.n_events} events`, '')]);
        steps.push([s.window_end_ms || s.timestamp_ms, step(time(s.window_end_ms || s.timestamp_ms), 'Detection', `${pretty(s.label)}, risk ${pct(s.risk)}`, `#/incident/security/${encodeURIComponent(s.event_id)}`)]);
    }
    const lag = s && s.window_end_ms > 0 ? a.timestamp_ms - s.window_end_ms : null;
    steps.push([a.timestamp_ms, step(time(a.timestamp_ms), `Fusion: ${pretty(a.decision).toLowerCase()}`,
        `${pretty(a.outcome)}${isNum(lag) && lag >= 0 ? `, ${dur(lag)} after detection` : ''}`, '')]);
    if (a.containment) steps.push([a.timestamp_ms + 1, step(time(a.timestamp_ms), `Containment ${a.containment}`, 'network freeze command to the node agent', '')]);
    return section('Decision trail', `<ol class="trail">${steps.sort((x, y) => x[0] - y[0]).map(x => x[1]).join('')}</ol>`);
}

function action(a, h, s) {
    const body = section('Decision', `<dl class="kv">
        ${kv('Decision', pretty(a.decision).toLowerCase())}${kv('Mode', a.mode === 'observe' ? 'observe (dry-run)' : a.mode)}
        ${kv('Outcome', pretty(a.outcome))}${kv('Score', pct(a.score, 1))}${kv('Compound score', pct(a.compound_score, 1))}
        ${kv('Containment', a.containment || 'not attempted')}${kv('Pod', a.pod)}${kv('Time', datetime(a.timestamp_ms))}</dl>
        <h3>Rationale</h3><p class="prose">${esc(dash(a.rationale))}</p>
        ${a.summary ? `<h3>Summary</h3><p class="prose">${esc(a.summary)}</p>` : ''}`);
    return `<div class="stack">${body}${s ? signal(s) : ''}${h ? signal(h) : ''}</div><aside class="stack">${trail(a, h, s)}</aside>`;
}

export function mount(root, { kind, id }) {
    let dead = false;
    root.innerHTML = `<a class="back" href="#/overview">${icon('back')}Overview</a><p class="sub" role="status">Loading</p>`;
    (async () => {
        let ev, h = null, s = null;
        try {
            ev = await api(`/api/events/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`);
            if (kind === 'action') {
                const get = (k, i) => i ? api(`/api/events/${k}/${encodeURIComponent(i)}`).catch(() => null) : null;
                [h, s] = await Promise.all([get('health', ev.health_event_id), get('security', ev.security_event_id)]);
            }
        } catch (e) {
            if (!dead) root.querySelector('.sub').textContent = e instanceof ApiError && e.status === 404 ? 'Event not found. It may have expired.' : `Could not load this event (${e.message})`;
            return;
        }
        if (dead) return;
        const dc = kind === 'action' ? decisionClass(ev.decision) : '';
        root.innerHTML = `<a class="back" href="#/overview">${icon('back')}Overview</a>
            <header class="page-head"><div><h1>${esc(target(ev))}</h1>
                <p class="sub mono">${esc(kind)} ${esc(ev.event_id)}${ev.pod ? ' · ' + esc(ev.pod) : ''}</p></div>
                ${kind === 'action' ? `<p class="verdict ${dc}"><span>${esc(pretty(ev.decision).toLowerCase())}</span> ${esc(pretty(ev.outcome))}${ev.mode === 'observe' ? ' <span class="tag">dry-run</span>' : ''}</p>` : ''}</header>
            <div class="cols detail">${kind === 'action' ? action(ev, h, s) : `<div class="stack">${signal(ev)}</div>`}</div>`;
        root.querySelector('h1')?.focus?.();
    })();
    return () => { dead = true; };
}
