import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const [base, approveId, rejectId, outputDir] = process.argv.slice(2);
if (!base || !approveId || !rejectId || !outputDir) throw new Error('usage: node run_f8_controls.mjs <base> <approve-id> <reject-id> <output-dir>');
const mode = execFileSync('kubectl', ['--context', 'k3d-kubeheal', '-n', 'kubeheal', 'get', 'configmap', 'kubeheal-mode', '-o', 'jsonpath={.data.mode}'], { encoding: 'utf8' }).trim();
if (mode !== 'test') throw new Error('F8 UI actions require mode test');
const token = Buffer.from(execFileSync('kubectl', ['--context', 'k3d-kubeheal', '-n', 'kubeheal', 'get', 'secret', 'kubeheal-dashboard-admin', '-o', 'jsonpath={.data.token}'], { encoding: 'utf8' }).trim(), 'base64').toString('utf8');
const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const profile = `${process.env.TEMP}\\kubeheal-f8-controls-${Date.now()}`;
const browser = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-first-run', '--remote-allow-origins=*', '--remote-debugging-port=9225', `--user-data-dir=${profile}`, 'about:blank'], { detached: true, stdio: 'ignore' });
let socket;
try {
  let ready = false;
  for (let i = 0; i < 100; i++) { try { await fetch('http://127.0.0.1:9225/json/version'); ready = true; break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  if (!ready) throw new Error('headless browser did not start');
  const target = (await (await fetch('http://127.0.0.1:9225/json/list')).json()).find(item => item.type === 'page');
  if (!target) throw new Error('headless browser page target missing');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let nextId = 0; const pending = new Map();
  socket.addEventListener('message', event => { const m = JSON.parse(event.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result); } });
  const cdp = (method, params = {}) => new Promise((resolve, reject) => { const id = ++nextId; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params })); });
  await cdp('Page.enable');
  await cdp('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1200, deviceScaleFactor: 1, mobile: false });
  await cdp('Page.addScriptToEvaluateOnNewDocument', { source: `sessionStorage.setItem('kubeheal-admin-token', ${JSON.stringify(token)});` });
  mkdirSync(outputDir, { recursive: true });
  const basePage = `${base}/approvals`;
  const navigate = async () => { await cdp('Page.navigate', { url: basePage }); await new Promise(r => setTimeout(r, 1800)); };
  const navigateIncident = async incident => { await cdp('Page.navigate', { url: `${base}/incidents/${incident}` }); await new Promise(r => setTimeout(r, 1800)); };
  const screenshot = async name => { const result = await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }); writeFileSync(`${outputDir}/${name}.png`, Buffer.from(result.data, 'base64')); };
  await navigate();
  await cdp('Runtime.evaluate', { expression: `sessionStorage.setItem('kubeheal-admin-token', ${JSON.stringify(token)}); const i=document.getElementById('admin-token'); if(i) i.value=${JSON.stringify(token)};`, returnByValue: true });
  const authState = await cdp('Runtime.evaluate', { expression: 'JSON.stringify({hasToken:!!sessionStorage.getItem("kubeheal-admin-token"), inputFilled:!!document.getElementById("admin-token")?.value, approveButtons:document.querySelectorAll("button[data-action=approve]").length})', returnByValue: true });
  process.stdout.write(`UI auth state: ${authState.result.value}\n`);
  await screenshot('approvals-before-actions');
  const click = async (incident, action, expected) => {
    await navigateIncident(incident);
    await screenshot(`${action}-control-before`);
    const install = `if (!window.__f8fetch) { window.__f8fetch=true; const old=window.fetch.bind(window); window.fetch=async (...args)=>{ const r=await old(...args); if(String(args[0]).includes('/api/approvals/')) { const body=await r.clone().json().catch(()=>({})); sessionStorage.setItem('f8-last-response', JSON.stringify({status:r.status,body})); } return r; }; } const b=document.querySelector('button[data-action="${action}"][data-incident="${incident}"]'); if(!b) throw new Error('missing ${action} control for incident'); b.click(); 'clicked';`;
    await cdp('Runtime.evaluate', { expression: install, awaitPromise: true, returnByValue: true });
    await new Promise(r => setTimeout(r, 1200));
    const result = await cdp('Runtime.evaluate', { expression: 'sessionStorage.getItem("f8-last-response")', returnByValue: true });
    const value = JSON.parse(result.result.value || 'null');
    if (!value || value.status < 200 || value.status >= 300 || value.body.status !== expected) throw new Error(`${action} response did not match ${expected}: ${JSON.stringify(value)}`);
    process.stdout.write(`${action} ${incident}: ${value.body.status}\n`);
    await navigateIncident(incident);
    if (action === 'approve') await screenshot('approval-dry-run');
  };
  await click(approveId, 'approve', 'dry_run_approved');
  await click(approveId, 'reject', 'rejected');
  await click(rejectId, 'reject', 'rejected');
  await navigate();
  await screenshot('approvals-resolved');
  process.stdout.write('mode=test; two run-owned approvals resolved; no Kubernetes writes requested\n');
} finally { if (socket) socket.close(); try { browser.kill(); } catch {} }


