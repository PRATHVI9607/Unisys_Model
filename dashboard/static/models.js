import { api, dash, esc, isNum, pct } from './util.js';

const row = (k, v) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(dash(v))}</dd></div>`;
const f = v => isNum(v) ? v.toFixed(3) : '—';

function card(task, version, m) {
    return `<section class="panel pad"><h2>${esc(task)}</h2>
        <dl class="kv stack-kv">${row('Serving', version || 'not loaded')}
        ${m ? row('Trained', m.created_at && m.created_at.slice(0, 10)) + row('Held-out test macro F1', f(m.test_macro_f1))
            + row('Grouped 5-fold macro F1', f(m.cv_macro_f1)) + row('Leave-one-family-out macro F1', f(m.heldout_macro_f1))
            + row('Conformal coverage', pct(m.coverage, 1) + (isNum(m.alpha) ? ` (target ${pct(1 - m.alpha)})` : ''))
            + row('Prediction latency p50 / p99', isNum(m.latency_p50_ms) ? `${m.latency_p50_ms.toFixed(1)} / ${m.latency_p99_ms.toFixed(1)} ms` : '—')
            + (m.synthetic ? row('Training data', 'partly synthetic') : '') : ''}</dl>
        ${m ? '' : '<p class="hint">Training metrics are not shipped with this dashboard image.</p>'}</section>`;
}

export function mount(root) {
    let dead = false;
    root.innerHTML = '<header class="page-head"><h1>Models</h1><p class="sub">Deployed bundles, read-only</p></header><p class="sub" role="status">Loading</p>';
    api('/api/models').then(d => {
        if (dead) return;
        const inf = d.inference;
        root.innerHTML = `<header class="page-head"><h1>Models</h1><p class="sub">${inf.reachable ? (inf.ready ? 'Inference is ready' : 'Inference is up but not ready') : 'Inference service not reachable'}</p></header>
            <div class="cols even">${['health', 'security'].map(t => card(t, inf.versions?.[t], d.meta[t])).join('')}</div>`;
    }).catch(e => { if (!dead) root.querySelector('p.sub').textContent = `Could not load model info (${e.message})`; });
    return () => { dead = true; };
}
