import { spawn, execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const [base, pageUrl, output] = process.argv.slice(2);
if (!base || !pageUrl || !output) throw new Error('usage: node capture_grafana.mjs <base> <page-url> <output.png>');
const secret = (key) => Buffer.from(execFileSync('kubectl', [
  '--context', 'k3d-kubeheal', '-n', 'monitoring', 'get', 'secret', 'monitoring-grafana',
  '-o', `jsonpath={.data.${key}}`,
], { encoding: 'utf8' }).trim(), 'base64').toString('utf8');
const user = secret('admin-user');
const password = secret('admin-password');
const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const profile = `${process.env.TEMP}\\kubeheal-grafana-capture-${Date.now()}`;
const browser = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-first-run', '--remote-allow-origins=*',
  '--remote-debugging-port=9223', `--user-data-dir=${profile}`, 'about:blank'], { detached: true, stdio: 'ignore' });
let socket;
try {
  let version;
  for (let i = 0; i < 100; i++) {
    try { version = await (await fetch('http://127.0.0.1:9223/json/version')).json(); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!version) throw new Error('headless browser did not start');
  const targets = await (await fetch('http://127.0.0.1:9223/json/list')).json();
  const target = targets.find(item => item.type === 'page');
  if (!target) throw new Error('headless browser page target missing');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message)); else resolve(message.result);
    }
  });
  const cdp = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const response = await fetch(`${base}/login`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user, password }) });
  if (!response.ok) throw new Error(`Grafana login failed with HTTP ${response.status}`);
  const setCookies = response.headers.getSetCookie();
  const cookies = setCookies.map(raw => {
    const [pair] = raw.split(';'); const split = pair.indexOf('=');
    return { name: pair.slice(0, split), value: pair.slice(split + 1), url: base, httpOnly: true, secure: false, sameSite: 'Lax' };
  });
  if (!cookies.length) throw new Error('Grafana login returned no session cookie');
  await cdp('Network.enable');
  await cdp('Page.enable');
  await cdp('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1200, deviceScaleFactor: 1, mobile: false });
  await cdp('Network.setCookies', { cookies });
  await cdp('Page.navigate', { url: pageUrl });
  await new Promise(resolve => setTimeout(resolve, 9000));
  const meta = await cdp('Runtime.evaluate', { expression: 'JSON.stringify({title:document.title,path:location.pathname})', returnByValue: true });
  const page = JSON.parse(meta.result.value);
  if (!page.path.startsWith('/d/')) throw new Error(`Grafana dashboard route did not load (path ${page.path})`);
  const image = await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  writeFileSync(output, Buffer.from(image.data, 'base64'));
  process.stdout.write(`Captured ${page.title} at ${page.path} to ${output}\n`);
} finally {
  if (socket) socket.close();
  try { browser.kill(); } catch {}
}
