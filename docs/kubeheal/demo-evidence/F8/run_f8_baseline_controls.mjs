import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const [base, namespace, deployment, candidateId, outputDir] = process.argv.slice(2);
if (!base || !namespace || !deployment || !candidateId || !outputDir) throw new Error('usage: node run_f8_baseline_controls.mjs <base> <namespace> <deployment> <candidate-id> <output-dir>');
const mode = execFileSync('kubectl', ['--context', 'k3d-kubeheal', '-n', 'kubeheal', 'get', 'configmap', 'kubeheal-mode', '-o', 'jsonpath={.data.mode}'], { encoding: 'utf8' }).trim();
if (mode !== 'test') throw new Error('F8 baseline UI actions require mode test');
const token = Buffer.from(execFileSync('kubectl', ['--context', 'k3d-kubeheal', '-n', 'kubeheal', 'get', 'secret', 'kubeheal-dashboard-admin', '-o', 'jsonpath={.data.token}'], { encoding: 'utf8' }).trim(), 'base64').toString('utf8');
const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const profile = `${process.env.TEMP}\\kubeheal-f8-baseline-${Date.now()}`;
const browser = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-first-run', '--remote-allow-origins=*', '--remote-debugging-port=9226', `--user-data-dir=${profile}`, 'about:blank'], { detached: true, stdio: 'ignore' });
let socket;
try {
  let ready=false; for(let i=0;i<100;i++){try{await fetch('http://127.0.0.1:9226/json/version');ready=true;break}catch{await new Promise(r=>setTimeout(r,100));}}
  if(!ready)throw new Error('headless browser did not start');
  const target=(await(await fetch('http://127.0.0.1:9226/json/list')).json()).find(x=>x.type==='page');
  if(!target)throw new Error('browser page target missing');
  socket=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
  let id=0;const waiting=new Map();
  socket.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id&&waiting.has(m.id)){const p=waiting.get(m.id);waiting.delete(m.id);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});
  const cdp=(method,params={})=>new Promise((resolve,reject)=>{const n=++id;waiting.set(n,{resolve,reject});socket.send(JSON.stringify({id:n,method,params}));});
  await cdp('Page.enable');await cdp('Emulation.setDeviceMetricsOverride',{width:1600,height:1200,deviceScaleFactor:1,mobile:false});
  const page=`${base}/baseline-candidates`;
  const navigate=async()=>{await cdp('Page.navigate',{url:page});await new Promise(r=>setTimeout(r,1800));};
  const screenshot=async name=>{const r=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});writeFileSync(`${outputDir}/${name}.png`,Buffer.from(r.data,'base64'));};
  mkdirSync(outputDir,{recursive:true});await navigate();
  await cdp('Runtime.evaluate',{expression:`sessionStorage.setItem('kubeheal-admin-token',${JSON.stringify(token)});const i=document.getElementById('admin-token');if(i)i.value=${JSON.stringify(token)};`,returnByValue:true});
  const selector=`button[data-namespace="${namespace}"][data-deployment="${deployment}"][data-candidate="${candidateId}"]`;
  const count=await cdp('Runtime.evaluate',{expression:`document.querySelectorAll(${JSON.stringify(selector)}).length`,returnByValue:true});
  if(count.result.value!==2)throw new Error(`expected approve and reject controls, got ${count.result.value}`);
  await screenshot('baseline-candidate-pending');
  const call=async action=>{
    const wrapper=`if(!window.__f8fetch){window.__f8fetch=true;const old=window.fetch.bind(window);window.fetch=async(...args)=>{const r=await old(...args);if(String(args[0]).includes('/api/baseline-candidates/')){const b=await r.clone().json().catch(()=>({}));sessionStorage.setItem('f8-baseline-response',JSON.stringify({status:r.status,body:b}));}return r;};}const b=document.querySelector('button[data-action="baseline-${action}"][data-namespace="${namespace}"][data-deployment="${deployment}"][data-candidate="${candidateId}"]');if(!b)throw new Error('baseline ${action} button missing');b.click();'clicked';`;
    await cdp('Runtime.evaluate',{expression:wrapper,returnByValue:true});await new Promise(r=>setTimeout(r,1200));
    const response=await cdp('Runtime.evaluate',{expression:'sessionStorage.getItem("f8-baseline-response")',returnByValue:true});
    const value=JSON.parse(response.result.value||'null');
    if(!value||value.status<200||value.status>=300)throw new Error(`${action} request failed: ${JSON.stringify(value)}`);
    process.stdout.write(`baseline ${action}: ${value.body.status}; applied=${value.body.applied}\n`);
    await navigate();return value;
  };
  const approved=await call('approve');
  if(approved.body.status!=='dry_run'||approved.body.applied!==false||approved.body.candidate_unchanged!==true)throw new Error('baseline approval was not a no-write dry run');
  await screenshot('baseline-approval-dry-run');
  const rejected=await call('reject');
  if(rejected.body.status!=='rejected')throw new Error('baseline candidate was not rejected');
  await screenshot('baseline-candidate-rejected');
  const remaining=await(await fetch(`${base}/api/baseline-candidates`)).json();
  if(remaining.count!==0)throw new Error(`candidate remains after rejection: ${remaining.count}`);
  writeFileSync(`${outputDir}/baseline-controls-result.json`,JSON.stringify({mode,scripted:true,candidate_id:candidateId,approve_status:approved.body.status,approve_applied:approved.body.applied,reject_status:rejected.body.status,pending_candidates_after:remaining.count,golden_changed:false},null,2)+'\n');
  process.stdout.write('mode=test; candidate approve was dry-run; reject cleared candidate; golden baseline unchanged\n');
}finally{if(socket)socket.close();try{browser.kill();}catch{}}
