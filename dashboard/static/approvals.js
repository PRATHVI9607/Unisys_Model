import { authed, bindGate, expired, gateHtml, onAuth } from './auth.js';
import { live, refreshApprovals, subscribe } from './live.js';
import { api, ago, decisionClass, esc, left, pct, pretty, target, targetHtml } from './util.js';

const GROUPS = [
    ['Needs a decision', i => i.state === 'pending' && !i.requested],
    ['In progress', i => (i.state === 'pending' && i.requested) || i.state === 'executing'],
    ['Resolved', i => ['executed', 'failed', 'rejected', 'expired'].includes(i.state)],
];
const STATE_CLASS = { executed: 'ok', failed: 'neg', rejected: 'quiet', expired: 'quiet' };
const DECIDED = { approve: 'Approved by', reject: 'Rejected by', release: 'Released by' };

function item(i, open, msg) {
    const overdue = i.state === 'pending' && !i.requested && left(i.expires_ms) === 'overdue';
    const can = authed() && i.state === 'pending' && !i.requested && !overdue;
    const verb = open && open.id === i.action_event_id ? open.decision : null;
    const cand = pretty(i.candidate).toLowerCase();
    return `<li class="appr rail ${decisionClass(i.candidate)}" data-id="${esc(i.action_event_id)}">
        <div class="appr-head">
            <a href="#/incident/action/${encodeURIComponent(i.action_event_id)}" data-focus="i-${esc(i.action_event_id)}">${targetHtml(i)}</a>
            <span class="state ${STATE_CLASS[i.state] || ''}" data-state>${esc(i.display_state)}</span></div>
        <dl class="kv inline"><div><dt>Candidate action</dt><dd>${esc(cand)}</dd></div>
            <div><dt>Score</dt><dd>${pct(i.score)}</dd></div>
            ${i.pod ? `<div><dt>Pod</dt><dd class="mono">${esc(i.pod)}</dd></div>` : ''}
            <div><dt>Raised</dt><dd>${ago(i.created_ms)}</dd></div>
            ${i.state === 'pending' && !i.requested ? `<div><dt>Expires</dt><dd>${esc(left(i.expires_ms))}</dd></div>` : ''}
            ${i.requested ? `<div><dt>${esc(DECIDED[i.requested.decision] || 'Requested by')}</dt><dd>${esc(i.requested.actor)}</dd></div>` : ''}
            ${i.outcome ? `<div><dt>${i.state === 'pending' ? 'Held because' : 'Result'}</dt><dd>${esc(pretty(i.outcome))}</dd></div>` : ''}</dl>
        <p class="prose">${esc(i.rationale || '')}</p>
        ${msg && msg.id === i.action_event_id ? `<p class="err" role="alert">${esc(msg.text)}</p>` : ''}
        ${can && !verb ? `<div class="btns"><button type="button" class="primary" data-ask="approve" data-focus="ap-${esc(i.action_event_id)}">${i.releasable ? 'Retry kill' : `Approve ${esc(cand)}`}</button>
            ${i.releasable ? `<button type="button" data-ask="release" data-focus="rl-${esc(i.action_event_id)}">Release</button>` : ''}
            <button type="button" data-ask="reject" data-focus="rj-${esc(i.action_event_id)}">Reject</button></div>` : ''}
        ${can && verb ? `<form class="confirm" data-confirm><label>${verb === 'release' ? `Releasing thaws ${esc(i.pod)} and removes its quarantine: the pod runs again` : verb === 'approve' ? `Approving runs ${esc(cand)} on ${esc(target(i))} with every safety rail re-checked` : 'Rejecting closes this item without touching the cluster'}.
            <textarea name="reason" rows="2" maxlength="500" placeholder="Reason, recorded in the ledger (optional)" data-focus="reason">${esc(open.reason)}</textarea></label>
            <div class="btns"><button type="submit" class="${verb === 'reject' ? 'danger' : 'primary'}">Confirm ${verb}</button><button type="button" data-cancel>Cancel</button></div></form>` : ''}
    </li>`;
}

export function mount(root) {
    let open = null, msg = null, sig = '', busy = false;
    root.innerHTML = `<header class="page-head"><h1>Approvals</h1><p class="sub">Human decisions fusion held back</p></header>
        <div id="gate"></div><div id="lists"></div>`;
    bindGate(root);
    const draw = () => {
        const items = live.approvals;
        const next = JSON.stringify([items, open && [open.id, open.decision], msg, authed(), Math.floor(Date.now() / 60000)]);   // typing alone never redraws
        if (next === sig) return;
        sig = next;
        const typing = document.activeElement?.matches?.('textarea[name="reason"]') && root.contains(document.activeElement)
            ? [document.activeElement.selectionStart, document.activeElement.selectionEnd] : null;
        root.querySelector('#gate').innerHTML = authed() ? '' : gateHtml('Approving or rejecting');
        root.querySelector('#lists').innerHTML = items.length ? GROUPS.map(([title, test]) => {
            const rows = items.filter(test);
            return rows.length || title === GROUPS[0][0] ? `<section class="panel"><header class="panel-head"><h2>${title}</h2><span class="sub">${rows.length}</span></header>
                <ul class="appr-list">${rows.length ? rows.map(i => item(i, open, msg)).join('') : '<li class="empty">Nothing waiting for a decision</li>'}</ul></section>` : '';
        }).join('') : '<section class="panel"><p class="empty">No human decisions in the last 24 hours</p></section>';
        if (typing) {   // a redraw while the reason is being typed keeps focus and caret
            const ta = root.querySelector('textarea[name="reason"]');
            ta?.focus({ preventScroll: true });
            ta?.setSelectionRange(...typing);
        }
    };
    root.addEventListener('click', ev => {
        const ask = ev.target.closest('[data-ask]');
        if (ask) { open = { id: ask.closest('.appr').dataset.id, decision: ask.dataset.ask, reason: '' }; msg = null; draw(); root.querySelector('[data-focus="reason"]')?.focus(); }
        if (ev.target.closest('[data-cancel]')) { const id = open.id; open = null; draw(); root.querySelector(`[data-focus="ap-${CSS.escape(id)}"]`)?.focus(); }
    });
    root.addEventListener('input', ev => { if (open && ev.target.name === 'reason') open.reason = ev.target.value; });
    root.addEventListener('submit', async ev => {
        const f = ev.target.closest('[data-confirm]');
        if (!f || busy) return;
        ev.preventDefault();
        busy = true;
        const { id, decision, reason } = open;
        try {
            await api(`/api/approvals/${encodeURIComponent(id)}/${decision}`, { method: 'POST', body: { reason } });
            open = null; msg = null;
        } catch (e) {
            if (!expired(e)) { msg = { id, text: e.status === 409 ? `Someone already decided this (${e.message})` : e.message }; open = null; }
        }
        busy = false;
        await refreshApprovals(); sig = ''; draw();
    });
    const offs = [subscribe(draw), onAuth(() => { sig = ''; draw(); })];
    refreshApprovals();
    const poll = setInterval(refreshApprovals, 3000);   // executing -> executed/failed lands without a page reload
    draw();
    return () => { offs.forEach(f => f()); clearInterval(poll); };
}
