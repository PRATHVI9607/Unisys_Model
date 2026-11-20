// One shared view of the streams: REST backfill, then WebSocket pushes. Views subscribe and re-render.
import { api } from './util.js';

const KINDS = ['action', 'health', 'security'];
const MAX = 200;
export const live = { action: [], health: [], security: [], approvals: [], pending: 0, stats: null, ws: false, redis: true, fresh: new Set() };
const subs = new Set();
export const subscribe = fn => { subs.add(fn); return () => subs.delete(fn); };
const emit = (arrived = []) => subs.forEach(fn => { try { fn(arrived); } catch (e) { console.error('view update failed', e); } });
let loading = null;

export async function refreshApprovals() {
    try {
        const d = await api('/api/approvals');
        live.approvals = d.items; live.pending = d.pending;
        emit();
    } catch { /* redis down: the connection indicator already says so */ }
}

export function load() {
    const p = Promise.all([
        api('/api/stats').then(s => { live.stats = s; live.redis = s.redis_connected !== false; }),
        ...KINDS.map(k => api(`/api/events?kind=${k}&limit=${MAX}`).then(d => { live[k] = d.events; })),
    ]).then(() => { emit(); return refreshApprovals(); }).catch(err => console.error('load failed', err));
    loading = p;
    p.finally(() => { if (loading === p) loading = null; });
    return p;
}

let attempts = 0;
function connect() {
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`);
    ws.onopen = () => { attempts = 0; live.ws = true; load(); };
    ws.onmessage = async m => {
        let msg;
        try { msg = JSON.parse(m.data); } catch { return; }
        if (msg.stats) { live.stats = msg.stats; live.redis = msg.stats.redis_connected !== false; }
        if (msg.type === 'resync') return load();
        if (msg.type === 'events' && Array.isArray(msg.events)) {
            if (loading) await loading;
            const arrived = [];
            for (const e of msg.events) {
                if (live[e.kind]?.some(x => x.event_id === e.event_id)) continue;
                live[e.kind].unshift(e);
                live[e.kind].length = Math.min(live[e.kind].length, MAX);
                arrived.push(e);
            }
            if (arrived.some(e => e.kind === 'action' && e.decision === 'HUMAN')) refreshApprovals();
            return emit(arrived);
        }
        emit();
    };
    ws.onclose = () => {   // retry forever, capped exponential backoff
        live.ws = false; emit();
        setTimeout(connect, Math.min(1000 * 2 ** attempts++, 30000));
    };
}

export function start() { load(); connect(); }
