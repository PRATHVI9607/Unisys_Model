// Shared admin sign-in. Reads stay open; this only unlocks the write buttons.
// SSO (KUBEHEAL_AUTH_MODE=proxy): oauth2-proxy has already signed the user in; /api/me says who and whether admin.
import { ApiError, api, esc, session } from './util.js';

const subs = new Set();
export const sso = { on: false, user: '', admin: false };
export const onAuth = fn => { subs.add(fn); return () => subs.delete(fn); };
export const authed = () => sso.on ? sso.admin : !!session.token;
export const signOut = () => { session.clear(); subs.forEach(f => f()); };
export async function loadMe() {
    try {
        const me = await api('/api/me');
        Object.assign(sso, { on: me.mode === 'proxy', user: me.user || '', admin: !!me.admin });
        subs.forEach(f => f());
    } catch { /* token mode or API down: keep the token flow */ }
}

export const gateHtml = what => sso.on ? `
    <div class="gate"><h3>Admin only</h3>
        <p class="hint">${esc(what)} needs membership of an admin group. You are signed in as ${esc(sso.user)} (viewer).</p></div>` : `
    <form class="gate" data-gate autocomplete="off">
        <h3>Admin sign-in</h3>
        <p class="hint">${esc(what)} needs the admin token. It stays in this tab's session storage and is sent only as a bearer header.</p>
        <div class="fields">
            <label>Admin token<input name="token" type="password" required autocomplete="off" spellcheck="false"></label>
            <label>Your name for the ledger<input name="actor" type="text" maxlength="40" autocomplete="off" placeholder="optional"></label>
        </div>
        <div class="gate-actions"><button class="primary" type="submit">Sign in</button><span class="err" data-err role="alert"></span></div>
    </form>`;

export function bindGate(root) {
    root.addEventListener('submit', async ev => {
        const form = ev.target.closest('form[data-gate]');
        if (!form) return;
        ev.preventDefault();
        const err = form.querySelector('[data-err]');
        const token = form.token.value.trim(), actor = form.actor.value.trim();
        session.set(token, actor);
        try {
            await api('/api/admin/session', { auth: true });
            subs.forEach(f => f());
        } catch (e) {
            session.clear();
            err.textContent = e instanceof ApiError && e.status === 503 ? 'Admin is disabled on this deployment'
                : e instanceof ApiError && (e.status === 401 || e.status === 403) ? 'Token rejected' : 'Could not reach the console API';
        }
    });
}

// A write failed because the token stopped working: drop the session so the gate comes back.
export const expired = e => { if (sso.on) return false; if (e instanceof ApiError && (e.status === 401 || e.status === 403)) { signOut(); return true; } return false; };
