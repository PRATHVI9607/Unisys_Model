import { authed, bindGate, expired, gateHtml, onAuth } from './auth.js';
import { api, esc } from './util.js';

const COPY = {
    observe: ['Observe', 'Fusion decides and records, and changes nothing in the cluster. Takes effect at once.'],
    enforce: ['Enforce', 'Fusion may delete pods and patch workloads. Applies only if the fusion deployment also allows enforcement.'],
};

export function mount(root, _p, ctx) {
    let state = null, pick = null, err = '', done = '', busy = false, reason = '';
    root.innerHTML = `<header class="page-head"><h1>Mode</h1><p class="sub">Runtime kill switch for fusion</p></header><div id="gate"></div><section class="panel pad" id="body"></section>`;
    bindGate(root);
    async function fetchMode() { try { state = await api('/api/mode'); } catch { state = null; } draw(); ctx.refreshMode(); }
    function draw() {
        root.querySelector('#gate').innerHTML = authed() ? '' : gateHtml('Changing the mode');
        const cur = state?.runtime;
        const body = root.querySelector('#body');
        body.innerHTML = `<dl class="kv"><div><dt>Runtime switch</dt><dd>${esc(cur || 'not set (fusion uses its deployment setting)')}</dd></div>
            <div><dt>Last action ran in</dt><dd>${esc(state?.last_action_mode || '—')}</dd></div></dl>
            <fieldset class="modes" ${authed() ? '' : 'disabled'}><legend>Set runtime mode</legend>
            ${Object.entries(COPY).map(([m, [t, d]]) => `<label class="mode-opt"><input type="radio" name="mode" value="${m}" ${pick === m ? 'checked' : ''}>
                <span><strong>${t}</strong><span class="sub">${esc(d)}</span></span></label>`).join('')}</fieldset>
            ${pick && pick !== cur && authed() ? `<form class="confirm" data-mode>
                <label>${pick === 'enforce' ? 'This lets fusion act on live workloads.' : 'This stops all cluster changes at once.'} Record why.
                <textarea name="reason" rows="2" maxlength="500" placeholder="Reason, recorded in the ledger (optional)">${esc(reason)}</textarea></label>
                <div class="btns"><button type="submit" class="${pick === 'enforce' ? 'danger' : 'primary'}" ${busy ? 'disabled' : ''}>Confirm switch to ${pick}</button>
                <button type="button" data-cancel>Cancel</button></div></form>` : ''}
            ${err ? `<p class="err" role="alert">${esc(err)}</p>` : ''}${done ? `<p class="ok" role="status">${esc(done)}</p>` : ''}`;
    }
    root.addEventListener('change', ev => { if (ev.target.name === 'mode') { pick = ev.target.value; err = done = ''; draw(); root.querySelector('textarea')?.focus(); } });
    root.addEventListener('input', ev => { if (ev.target.name === 'reason') reason = ev.target.value; });
    root.addEventListener('click', ev => { if (ev.target.closest('[data-cancel]')) { pick = null; draw(); } });
    root.addEventListener('submit', async ev => {
        if (!ev.target.closest('[data-mode]')) return;
        ev.preventDefault(); busy = true; err = ''; draw();
        try {
            await api('/api/mode', { method: 'POST', body: { mode: pick, reason } });
            done = `Runtime mode is now ${pick}`; pick = null; reason = '';
        } catch (e) { if (!expired(e)) err = e.message; }
        busy = false; await fetchMode();
    });
    const off = onAuth(draw);
    fetchMode();
    return off;
}
