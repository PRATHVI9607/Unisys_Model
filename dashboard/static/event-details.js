/* Event detail modal. Fetches /api/events/{kind}/{id} and renders the contract fields as they are:
   a missing value shows "—", never a made-up default. Exposes window.openEventDetails(kind, id). */
(() => {
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const isNum = v => typeof v === 'number' && Number.isFinite(v);
    const dash = v => (v === null || v === undefined || v === '') ? '—' : v;
    const pct = v => isNum(v) ? `${(v * 100).toFixed(1)}%` : '—';
    const riskClass = v => !isNum(v) ? '' : v >= 0.7 ? 'risk-high' : v >= 0.4 ? 'risk-medium' : 'risk-low';
    const pretty = s => s ? String(s).replace(/_/g, ' ') : '—';
    const yesNo = v => v === true ? 'yes' : v === false ? 'no' : '—';
    const when = ms => isNum(ms) && ms > 0 ? new Date(ms).toLocaleString() : '—';
    const TITLE = { action: 'Action', health: 'Health assessment', security: 'Security event' };

    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    const dialog = document.createElement('div');
    dialog.className = 'modal-dialog';
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'modalTitle');
    document.body.append(backdrop, dialog);

    let seq = 0;          // bumps on every open/close; a response for an older request is dropped
    let returnFocus = null;

    function close() {
        seq++;
        backdrop.classList.remove('active');
        dialog.classList.remove('active');
        dialog.innerHTML = '';
        returnFocus?.focus?.();
    }

    function switchTab(name) {
        dialog.querySelectorAll('.modal-tab-button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
        dialog.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.dataset.pane === name));
    }

    const pane = name => dialog.querySelector(`.tab-pane[data-pane="${name}"]`);

    backdrop.addEventListener('click', close);
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && dialog.classList.contains('active')) close();
    });
    dialog.addEventListener('click', e => {
        if (e.target.closest('.modal-close')) return close();
        const tab = e.target.closest('.modal-tab-button');
        if (tab) return switchTab(tab.dataset.tab);
        const link = e.target.closest('[data-open-id]');
        if (link) open(link.dataset.openKind, link.dataset.openId);
    });

    const item = (label, value, cls = '') => `
        <div class="summary-item">
            <div class="summary-label">${esc(label)}</div>
            <div class="summary-value ${cls}">${esc(dash(value))}</div>
        </div>`;
    const section = (title, body) => `<div class="analysis-section"><div class="analysis-title">${esc(title)}</div>${body}</div>`;
    const textBox = (title, text) => `
        <div class="remediation-box"><div class="remediation-title">${esc(title)}</div>
        <div class="remediation-text">${esc(dash(text))}</div></div>`;
    const bar = (label, widthPct, valueText, cls = '') => `
        <div class="score-bar">
            <span class="score-label" title="${esc(label)}">${esc(label)}</span>
            <div class="score-visual"><div class="score-fill ${cls}" style="width:${Math.max(0, Math.min(100, Math.round(widthPct)))}%"></div></div>
            <span class="score-percent">${esc(valueText)}</span>
        </div>`;

    function eventSummary(e) {
        const win = e.window_end_ms - e.window_start_ms;
        return '<div class="summary-grid">' + [
            item('Target', `${dash(e.namespace)}/${dash(e.workload)}`),
            e.kind === 'security' ? item('Pod', e.pod) : '',
            item('Label', pretty(e.label)),
            item('Risk', pct(e.risk), riskClass(e.risk)),
            item('Uncertain', e.uncertain ? 'yes (conformal set has more than one label)' : yesNo(e.uncertain)),
            item('Model version', e.model_version),
            item('Time', when(e.timestamp_ms), 'timestamp'),
            ...(e.kind === 'health' ? [
                item('Spec changed', yesNo(e.spec_changed)),
                item('Restore baseline', e.has_baseline ? 'available' : e.has_baseline === false ? 'none' : '—'),
                item('Rollback rule', (e.failure_reasons || []).length ? e.failure_reasons.join(', ') : 'no'),
            ] : [
                item('Syscall events', e.n_events),
                item('Window', e.window_start_ms > 0 && isNum(win) ? `${(win / 1000).toFixed(0)}s from ${when(e.window_start_ms)}` : '—'),
            ]),
        ].join('') + '</div>';
    }

    function eventAnalysis(e) {
        let html = '';
        const factors = Array.isArray(e.top_factors) ? e.top_factors : [];
        if (factors.length) {
            const max = Math.max(...factors.map(f => Math.abs(f.contribution) || 0), 1e-9);
            html += section('Top factors (contribution to predicted label)', factors.map(f => bar(
                isNum(f.value) ? `${f.feature} = ${+f.value.toFixed(4)}` : `${f.feature} = —`,
                Math.abs(f.contribution) / max * 100,
                `${f.contribution >= 0 ? '+' : ''}${(+f.contribution).toFixed(3)}`,
                f.contribution < 0 ? 'neg' : '')).join(''));
        }
        const probs = Object.entries(e.probabilities || {}).sort((a, b) => b[1] - a[1]);
        if (probs.length) html += section('Class probabilities', probs.map(([l, p]) => bar(pretty(l), p * 100, pct(p))).join(''));
        if (e.kind === 'health' && (e.changed_fields || []).length) {
            html += section('Changed fields', '<div class="explainability-fields">' +
                e.changed_fields.map(f => `<div class="field-item"><span class="field-name">${esc(f)}</span></div>`).join('') + '</div>');
        }
        return html || '<div class="empty-section"><p class="empty-section-text">No factors, probabilities or changed fields on this event.</p></div>';
    }

    function actionSummary(a) {
        return '<div class="summary-grid">' + [
            item('Decision', pretty(a.decision)),
            item('Mode', a.mode === 'observe' ? 'dry-run (observe)' : a.mode),
            item('Outcome', pretty(a.outcome)),
            item('Score', pct(a.score), riskClass(a.score)),
            item('Compound score', pct(a.compound_score)),
            item('Target', `${dash(a.namespace)}/${dash(a.workload)}`),
            item('Pod', a.pod),
            item('Time', when(a.timestamp_ms), 'timestamp'),
        ].join('') + '</div><div style="margin-top:16px">' + textBox('Fusion summary', a.summary) + '</div>';
    }

    function actionRationale(a) {
        const link = (kind, id) => id
            ? `<button class="field-item event-link" data-open-kind="${kind}" data-open-id="${esc(id)}">
                   <span class="field-name">${esc(TITLE[kind])}</span><span class="field-weight">${esc(id)}</span></button>`
            : `<div class="field-item"><span class="field-name">${esc(TITLE[kind])}</span><span class="field-weight">—</span></div>`;
        return '<div class="remediation-content">' + textBox('Rationale', a.rationale) +
            section('Linked events', '<div class="explainability-fields">' +
                link('health', a.health_event_id) + link('security', a.security_event_id) + '</div>') + '</div>';
    }

    async function open(kind, id) {
        const req = ++seq;
        if (!dialog.classList.contains('active')) returnFocus = document.activeElement;
        dialog.innerHTML = `
            <div class="modal-header">
                <div class="modal-title"><span id="modalTitle">${esc(TITLE[kind] || 'Event')}</span>
                    <span class="modal-event-id">${esc(id)}</span></div>
                <button class="modal-close" aria-label="Close">&times;</button>
            </div>
            <div class="modal-tabs">
                <button class="modal-tab-button active" data-tab="summary">Summary</button>
                <button class="modal-tab-button" data-tab="analysis">${kind === 'action' ? 'Rationale' : 'Analysis'}</button>
            </div>
            <div class="modal-content">
                <div class="tab-pane active" data-pane="summary">
                    <div class="modal-loading"><div class="modal-spinner"></div><span>Loading…</span></div></div>
                <div class="tab-pane" data-pane="analysis"></div>
            </div>`;
        backdrop.classList.add('active');
        dialog.classList.add('active');
        dialog.querySelector('.modal-close').focus();

        let ev;
        try {
            const r = await fetch(`/api/events/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`);
            if (!r.ok) throw new Error(r.status === 404 ? 'Event not found (it may have expired).' : `Request failed (HTTP ${r.status}).`);
            ev = await r.json();
        } catch (err) {
            if (req === seq) pane('summary').innerHTML = `<div class="modal-error"><p>${esc(err.message)}</p></div>`;
            return;
        }
        if (req !== seq) return;
        pane('summary').innerHTML = kind === 'action' ? actionSummary(ev) : eventSummary(ev);
        pane('analysis').innerHTML = kind === 'action' ? actionRationale(ev) : eventAnalysis(ev);
    }

    window.openEventDetails = open;
})();
