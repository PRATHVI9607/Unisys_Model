import { authed, onAuth, signOut } from './auth.js';
import { live, start, subscribe } from './live.js';
import { api, esc, icon, pretty, session, target } from './util.js';

const PAGES = [['overview', 'Overview'], ['approvals', 'Approvals'], ['ledger', 'Ledger'], ['mode', 'Mode'], ['models', 'Models']];
const $ = id => document.getElementById(id);
const main = $('main');
let unmount = null, runtimeMode = null;

// theme: system by default, then light, then dark
const THEMES = ['system', 'light', 'dark'];
let theme = 'system';
try { theme = localStorage.getItem('kh.theme') || 'system'; } catch { /* storage blocked */ }
const applyTheme = () => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.dataset.theme = theme;
    $('theme').textContent = `Theme: ${theme}`;
    try { localStorage.setItem('kh.theme', theme); } catch { /* storage blocked */ }
};
$('theme').addEventListener('click', () => { theme = THEMES[(THEMES.indexOf(theme) + 1) % 3]; applyTheme(); });
applyTheme();

function route() {
    const [, page = 'overview', a, b] = location.hash.split('/');
    return page === 'incident' && a && b ? { page, view: 'incident', params: { kind: decodeURIComponent(a), id: decodeURIComponent(b) } }
        : { page: PAGES.some(p => p[0] === page) ? page : 'overview', view: PAGES.some(p => p[0] === page) ? page : 'overview', params: {} };
}

let navSig = '';
function drawNav(page) {
    const html = PAGES.map(([k, t], i) => `<a href="#/${k}" ${k === page ? 'aria-current="page"' : ''}>${icon(k)}<span>${t}</span>
        ${k === 'approvals' && live.pending ? `<span class="count mono" aria-label="${live.pending} pending">${live.pending}</span>` : `<kbd aria-hidden="true">${i + 1}</kbd>`}</a>`).join('');
    if (html !== navSig) { navSig = html; $('nav').innerHTML = html; }   // untouched while idle, so nav focus survives live updates
}

function drawWho() {
    $('who').innerHTML = authed()
        ? `<span>${esc(session.actor || 'admin')}</span><button type="button" class="quiet" id="signout">Sign out</button>`
        : '<span class="muted">Read-only</span>';
    $('signout')?.addEventListener('click', signOut);
}

export async function refreshMode() {
    try { runtimeMode = (await api('/api/mode')).runtime; } catch { /* keep the last value */ }
    drawBar();
}
function drawBar() {
    const last = live.action[0]?.mode;
    const m = runtimeMode || last;
    const bar = $('modebar');
    bar.className = `modebar ${m === 'enforce' ? 'enforce' : m === 'observe' ? 'observe' : ''}`;
    const conn = !live.ws ? 'Reconnecting' : live.redis ? 'Live' : 'Redis unavailable';
    bar.innerHTML = `<span class="mode-text">${m === 'enforce' ? '<strong>Enforce</strong> fusion acts on the cluster'
        : m === 'observe' ? '<strong>Observe</strong> dry-run, the cluster is not changed' : '<strong>Mode unknown</strong> no runtime switch and no actions yet'}
        ${runtimeMode ? '<span class="sub">runtime switch</span>' : m ? '<span class="sub">from the latest action</span>' : ''}</span>
        <span class="conn ${live.ws && live.redis ? 'ok' : 'bad'}"><i></i>${conn}</span>`;
}

let gen = 0;   // a slow import must not mount over a newer navigation
async function render() {
    const r = route(), mine = ++gen;
    unmount?.(); unmount = null;
    drawNav(r.page);
    const mod = await import(`./${r.view}.js`);
    if (mine !== gen) return;
    main.replaceChildren();
    unmount = mod.mount(main, r.params, { refreshMode }) || null;
    document.title = `${r.view === 'incident' ? 'Incident' : pretty(r.page).replace(/^./, c => c.toUpperCase())} · KubeHeal`;
    if (main.dataset.nav) main.focus({ preventScroll: true });
}
addEventListener('hashchange', () => { main.dataset.nav = '1'; render(); });
addEventListener('keydown', ev => {   // 1-5 jump between sections; arrows walk the table rows
    if (ev.metaKey || ev.ctrlKey || ev.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)) return;
    const n = PAGES[+ev.key - 1];
    if (n) { location.hash = `#/${n[0]}`; return; }
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
        const links = [...main.querySelectorAll('tbody a[href], .signals a, .appr-head a')];
        const i = links.indexOf(document.activeElement);
        if (i >= 0 || (ev.key === 'ArrowDown' && links.length && document.activeElement === document.body)) {
            ev.preventDefault();
            links[Math.max(0, Math.min(links.length - 1, i + (ev.key === 'ArrowDown' ? 1 : -1)))].focus();
        }
    }
});

const say = text => { const el = $('announce'); el.textContent = ''; setTimeout(() => { el.textContent = text; }, 50); };
subscribe(arrived => {
    drawNav(route().page); drawBar();
    for (const e of arrived || []) {
        if (e.kind === 'action' && e.decision !== 'OBSERVE' && e.decision !== 'BENIGN') say(`${pretty(e.decision).toLowerCase()}: ${target(e)}, ${pretty(e.outcome)}`);
        else if (e.kind === 'security' && e.risk >= 0.7) say(`High-risk security event: ${target(e)}`);
    }
});
onAuth(() => { drawWho(); });

drawWho();
start();
refreshMode();
render();
