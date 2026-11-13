import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const [base, outputDir] = process.argv.slice(2);
if (!base || !outputDir) throw new Error('usage: node run_f8_mode_control.mjs <base> <output-dir>');
const mode = () => execFileSync('kubectl', ['--context','k3d-kubeheal','-n','kubeheal','get','configmap','kubeheal-mode','-o','jsonpath={.data.mode}'],{encoding:'utf8'}).trim();
if (mode() !== 'test') throw new Error('F8 mode walkthrough must begin in test mode');
const token=Buffer.from(execFileSync('kubectl',['--context','k3d-kubeheal','-n','kubeheal','get','secret','kubeheal-dashboard-admin','-o','jsonpath={.data.token}'],{encoding:'utf8'}).trim(),'base64').toString('utf8');
const chrome='C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const profile=`${process.env.TEMP}\\kubeheal-f8-mode-${Date.now()}`;
const browser=spawn(chrome,['--headless=new','--disable-gpu','--no-first-run','--remote-allow-origins=*','--remote-debugging-port=9227',`--user-data-dir=${profile}`,'about:blank'],{detached:true,stdio:'ignore'});
let socket;
try{
 let ready=false;for(let i=0;i<100;i++){try{await fetch('http://127.0.0.1:9227/json/version');ready=true;break}catch{await new Promise(r=>setTimeout(r,100));}}
 if(!ready)throw new Error('headless browser did not start');
 const target=(await(await fetch('http://127.0.0.1:9227/json/list')).json()).find(x=>x.type==='page');if(!target)throw new Error('browser page target missing');
 socket=new WebSocket(target.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
 let next=0;const waiting=new Map();socket.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id&&waiting.has(m.id)){const p=waiting.get(m.id);waiting.delete(m.id);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});
 const cdp=(method,params={})=>new Promise((resolve,reject)=>{const id=++next;waiting.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 await cdp('Page.enable');await cdp('Emulation.setDeviceMetricsOverride',{width:1600,height:1200,deviceScaleFactor:1,mobile:false});mkdirSync(outputDir,{recursive:true});
 const navigate=async()=>{await cdp('Page.navigate',{url:`${base}/approvals`});await new Promise(r=>setTimeout(r,900));await cdp('Runtime.evaluate',{expression:`sessionStorage.setItem('kubeheal-admin-token',${JSON.stringify(token)});const i=document.getElementById('admin-token');if(i)i.value=${JSON.stringify(token)};`,returnByValue:true});};
 const screenshot=async name=>{const s=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});writeFileSync(`${outputDir}/${name}.png`,Buffer.from(s.data,'base64'));};
 const results=[];
 for(const nextMode of ['enforce','test']){
   await navigate();
   const wrapper=`if(!window.__f8fetch){window.__f8fetch=true;const old=window.fetch.bind(window);window.fetch=async(...args)=>{const r=await old(...args);if(String(args[0]).includes('/api/kill-switch')){const b=await r.clone().json().catch(()=>({}));sessionStorage.setItem('f8-mode-response',JSON.stringify({status:r.status,body:b}));}return r;};}const b=document.querySelector('button[data-action="mode"][data-mode="${nextMode}"]');if(!b)throw new Error('mode button missing');b.click();'clicked';`;
   await cdp('Runtime.evaluate',{expression:wrapper,returnByValue:true});await new Promise(r=>setTimeout(r,1200));
   const response=await cdp('Runtime.evaluate',{expression:'sessionStorage.getItem("f8-mode-response")',returnByValue:true});const value=JSON.parse(response.result.value||'null');
   if(!value||value.status<200||value.status>=300||value.body.mode!==nextMode)throw new Error(`dashboard mode change to ${nextMode} failed: ${JSON.stringify(value)}`);
   if(mode()!==nextMode)throw new Error(`ConfigMap mode is not ${nextMode} after dashboard response`);
   results.push({mode:nextMode,ledger_id:value.body.ledger_id,status:value.body.status});
   await navigate();await screenshot(`kill-switch-${nextMode}`);
 }
 if(mode()!=='test')throw new Error('mode was not restored to test');
 writeFileSync(`${outputDir}/mode-control-result.json`,JSON.stringify({before:'test',changes:results,final:'test',scripted_window:true},null,2)+'\n');
 process.stdout.write(`dashboard kill switch test -> enforce -> test; final=${mode()}\n`);
}finally{if(socket)socket.close();try{browser.kill();}catch{}}
