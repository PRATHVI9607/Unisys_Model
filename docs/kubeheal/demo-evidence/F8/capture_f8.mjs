import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const [base, incidentId, outputDir] = process.argv.slice(2);
if (!base || !incidentId || !outputDir) throw new Error('usage: node capture_f8.mjs <base> <incident-id> <output-dir>');
const token = Buffer.from(execFileSync('kubectl', [
  '--context', 'k3d-kubeheal', '-n', 'kubeheal', 'get', 'secret', 'kubeheal-dashboard-admin',
  '-o', 'jsonpath={.data.token}',
], { encoding: 'utf8' }).trim(), 'base64').toString('utf8');
const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const profile = `${process.env.TEMP}\\kubeheal-f8-capture-${Date.now()}`;
const browser = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-first-run', '--remote-allow-origins=*',
  '--remote-debugging-port=9224', `--user-data-dir=${profile}`, 'about:blank'], { detached: true, stdio: 'ignore' });
let socket;
try {
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { await fetch('http://127.0.0.1:9224/json/version'); ready = true; break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!ready) throw new Error('headless browser did not start');
  const targets = await (await fetch('http://127.0.0.1:9224/json/list')).json();
  const target = targets.find(item => item.type === 'page');
  if (!target) throw new Error('headless browser page target missing');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id); pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message)); else resolve(message.result);
    }
  });
  const cdp = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
  });
  await cdp('Page.enable');
  await cdp('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1200, deviceScaleFactor: 1, mobile: false });
  await cdp('Page.addScriptToEvaluateOnNewDocument', { source: `sessionStorage.setItem('kubeheal-admin-token', ${JSON.stringify(token)});` });
  mkdirSync(outputDir, { recursive: true });
  const pages = [
    ['approvals', '/approvals'],
    ['baseline-candidates', '/baseline-candidates'],
    ['incident-detail', `/incidents/${encodeURIComponent(incidentId)}`],
  ];
  for (const [name, route] of pages) {
    await cdp('Page.navigate', { url: `${base}${route}` });
    await new Promise(resolve => setTimeout(resolve, 2200));
    const meta = await cdp('Runtime.evaluate', { expression: 'JSON.stringify({title:document.title,path:location.pathname})', returnByValue: true });
    const page = JSON.parse(meta.result.value);
    if (page.path !== route) throw new Error(`dashboard route ${route} redirected to ${page.path}`);
    const shot = await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
    writeFileSync(`${outputDir}/${name}.png`, Buffer.from(shot.data, 'base64'));
    process.stdout.write(`Captured ${name}: ${page.path}\n`);
  }
} finally {
  if (socket) socket.close();
  try { browser.kill(); } catch {}
}
