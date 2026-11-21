// Every value from the API goes through esc(); ids travel in data-* attributes and hrefs, never inline JS.
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const isNum = v => typeof v === 'number' && Number.isFinite(v);
export const dash = v => (v === null || v === undefined || v === '') ? '—' : v;
export const pct = (v, d = 0) => isNum(v) ? `${(v * 100).toFixed(d)}%` : '—';
export const pretty = s => s ? String(s).replace(/_/g, ' ') : '—';
export const target = e => `${dash(e.namespace)}/${dash(e.workload)}`;
// namespace/workload that can only break after the slash, never inside "kube-system".
export const targetHtml = e => `<span class="nw">${esc(dash(e.namespace))}/</span><wbr><span class="nw">${esc(dash(e.workload))}</span>`;
export const riskClass = v => !isNum(v) ? 'low' : v >= 0.7 ? 'high' : v >= 0.4 ? 'mid' : 'low';
export const time = ms => isNum(ms) && ms > 0
    ? new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '—';
export const datetime = ms => isNum(ms) && ms > 0
    ? new Date(ms).toLocaleString([], { hour12: false, dateStyle: 'medium', timeStyle: 'medium' }) : '—';
export const dur = ms => !isNum(ms) ? '—' : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;
export const ago = ms => {
    if (!isNum(ms) || ms <= 0) return '—';
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;
};

export const left = ms => {
    if (!isNum(ms)) return '—';
    const m = Math.round((ms - Date.now()) / 60000);
    return m <= 0 ? 'overdue' : m < 60 ? `in ${m}m` : `in ${Math.floor(m / 60)}h ${m % 60}m`;
};

const P = {
    overview: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    approvals: '<path d="m9 11 3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
    ledger: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    mode: '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>',
    models: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>',
    back: '<path d="m15 18-6-6 6-6"/>',
};
export const icon = n => `<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">${P[n]}</svg>`;

// Admin session: the token lives in sessionStorage only (gone with the tab), never in a cookie.
const S = { get: k => { try { return sessionStorage.getItem(k) || ''; } catch { return ''; } },
            set: (k, v) => { try { v ? sessionStorage.setItem(k, v) : sessionStorage.removeItem(k); } catch { /* private mode */ } } };
export const session = {
    get token() { return S.get('kh.token'); },
    get actor() { return S.get('kh.actor'); },
    set(token, actor) { S.set('kh.token', token); S.set('kh.actor', actor); },
    clear() { S.set('kh.token', ''); S.set('kh.actor', ''); },
};

export class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

export async function api(url, { method = 'GET', body, auth = false } = {}) {
    const headers = {};
    if (method !== 'GET' || auth) {
        headers['X-Kubeheal-CSRF'] = '1';
        if (body) headers['Content-Type'] = 'application/json';
        headers.Authorization = `Bearer ${session.token}`;
        if (session.actor) headers['X-Actor'] = session.actor;
    }
    const r = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
    let data = null;
    try { data = await r.json(); } catch { /* empty body */ }
    if (!r.ok) throw new ApiError(r.status, (data && data.detail && String(data.detail)) || `HTTP ${r.status}`);
    return data;
}

// Replace a container's markup but keep keyboard focus on the same logical element across live re-renders.
export function paint(el, html) {
    const key = el.contains(document.activeElement) ? document.activeElement.dataset?.focus : null;
    el.innerHTML = html;
    if (key) el.querySelector(`[data-focus="${CSS.escape(key)}"]`)?.focus({ preventScroll: true });
}

export const decisionClass = d => ({ AUTO_KILL: 'kill', AUTO_PATCH: 'patch', HUMAN: 'human' }[d] || 'quiet');
export const bar = (value, max, cls = '') => `<progress class="meter ${cls}" value="${isNum(value) ? Math.max(0, Math.min(max, value)) : 0}" max="${max}"></progress>`;
