// Shared admin sign-in. Reads stay open; this only unlocks the write buttons.
import { ApiError, api, esc, session } from './util.js';

const subs = new Set();
export const onAuth = fn => { subs.add(fn); return () => subs.delete(fn); };
export const authed = () => !!session.token;
export const signOut = () => { session.clear(); subs.forEach(f => f()); };

export const gateHtml = what => `
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
export const expired = e => { if (e instanceof ApiError && (e.status === 401 || e.status === 403)) { signOut(); return true; } return false; };
