"""Create one reversible, run-owned scripted prod candidate for the F8 dashboard controls."""
import json
import subprocess
import uuid

CONTEXT = "k3d-kubeheal"
REMOTE = r'''
import asyncio, hashlib, json, sys
import redis.asyncio as redis
from kubernetes_asyncio import client, config
from agents.common.ledger import ledger_from_env
from agents.health_agent import baseline

async def main():
    p=json.load(sys.stdin)
    config.load_incluster_config()
    core=client.CoreV1Api()
    apps=client.AppsV1Api()
    cm=await core.read_namespaced_config_map("kubeheal-mode","kubeheal")
    if (cm.data or {}).get("mode") != "test": raise RuntimeError("F8 candidate requires test mode")
    r=redis.from_url(__import__("os").environ["REDIS_URL"],decode_responses=True)
    deployment="f5-scripted-prod-2a87df12"
    live=await apps.read_namespaced_deployment(deployment,"prod")
    labels=live.metadata.labels or {}
    if labels.get("kubeheal.io/run-id") != "2a87df128d8848ceb2f800351f6a3620" or labels.get("kubeheal.io/scripted") != "F5":
        raise RuntimeError("target is not the expected F5 run-owned scripted Deployment")
    held=await baseline.load_baseline_raw(r,"prod",deployment)
    if held is None: raise RuntimeError("F5 golden baseline is missing")
    golden_raw,golden=held
    view=json.loads(json.dumps(golden.get("spec") or {}))
    env=view["template"]["spec"]["containers"][0].setdefault("env",[])
    env[:]=[item for item in env if item.get("name") != "F8_SCRIPTED_CONFIG"]
    env.append({"name":"F8_SCRIPTED_CONFIG","value":"candidate-"+p["run_id"][:12]})
    fields=["/template/spec/containers/0/env/F8_SCRIPTED_CONFIG"]
    spec_hash=hashlib.sha256(json.dumps(view,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    result=await baseline.store_candidate(r,ledger_from_env(),"prod",deployment,new_spec=view,spec_hash=spec_hash,
        golden_raw=golden_raw,tier="prod",changed_fields=fields,
        assessment={"label":"benign","risk":0.01,"prediction_set":["benign"],"model_version":"SCRIPTED-F8","event_id":"scripted-f8-"+p["run_id"]})
    await r.aclose()
    await apps.api_client.close()
    await core.api_client.close()
    print(json.dumps({"run_id":p["run_id"],"scripted":True,"mode":"test","namespace":"prod","deployment":deployment,
        "result":result,"golden_changed":False},sort_keys=True))
asyncio.run(main())
'''

mode=subprocess.run(["kubectl","--context",CONTEXT,"-n","kubeheal","get","configmap","kubeheal-mode","-o","jsonpath={.data.mode}"],capture_output=True,text=True,check=True).stdout.strip()
if mode != "test": raise SystemExit("refusing scripted F8 candidate unless mode is test")
run_id=uuid.uuid4().hex
pod=subprocess.run(["kubectl","--context",CONTEXT,"-n","kubeheal","get","pods","-l","app=health-agent","-o","jsonpath={.items[0].metadata.name}"],capture_output=True,text=True,check=True).stdout.strip()
proc=subprocess.run(["kubectl","--context",CONTEXT,"-n","kubeheal","exec","-i",pod,"--","python","-c",REMOTE],input=json.dumps({"run_id":run_id}),capture_output=True,text=True,timeout=60)
if proc.returncode: raise SystemExit(f"scripted candidate creation failed: {proc.stderr[-1200:]}")
print(proc.stdout.strip().splitlines()[-1])
