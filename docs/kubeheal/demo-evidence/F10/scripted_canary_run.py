"""Run-owned F10 drift canaries with real Prometheus p99 and rollback evidence.

The runner uses only k3d-kubeheal, existing demo app images, PVC-free scratch
Deployments, the Executor request stream, and the shipped Prometheus metric
source. All assessments and requests are explicitly scripted.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
import urllib.request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CONTEXT = "k3d-kubeheal"
REMOTE = r'''
import asyncio, json, os, sys, time
import redis.asyncio as redis
from agents.executor.metrics_source import PrometheusMetricSource
from agents.health_agent import baseline

async def main():
 p=json.load(sys.stdin); r=redis.from_url(os.environ["REDIS_URL"],decode_responses=True)
 if p["phase"]=="seed":
  record,created=await baseline.get_or_set_baseline(r,p["namespace"],p["deployment"],p["spec"])
  print(json.dumps({"phase":"seed","created":created,"golden_digest":baseline.record_digest(record)}))
 elif p["phase"]=="queue":
  f={"incident_id":p["incident_id"],"action":"patch","namespace":p["namespace"],
     "deployment":p["deployment"],"patch_field":"template.spec.containers[0].resources",
     "patch_fields":"[\"template.spec.containers[0].resources\"]","rule_path":"true",
     "rule_reasons":"[\"scripted F10 drift\"]","dry_run":"false","approved_by":"scripted-F10",
     "source":"scripted-F10","timestamp_ms":str(int(time.time()*1000))}
  sid=await r.xadd("kubeheal.exec",f)
  print(json.dumps({"queued":True,"stream_id":sid,"incident_id":p["incident_id"],
                    "namespace":p["namespace"],"deployment":p["deployment"]}))
 elif p["phase"]=="metrics":
  src=PrometheusMetricSource(os.environ["PROMETHEUS_URL"])
  values=await src(p["namespace"],p["deployment"],30)
  print(json.dumps({"namespace":p["namespace"],"deployment":p["deployment"],
                    "window_s":30,"metrics":values},sort_keys=True))
 elif p["phase"]=="wait":
  deadline=time.monotonic()+p.get("timeout_s",300)
  while time.monotonic()<deadline:
   rows=await r.xrevrange("kubeheal.actions",count=100)
   found=next((f for _,f in rows if f.get("incident_id")==p["incident_id"]
               and f.get("action_type")=="executed_patch"),None)
   if found:
    print(json.dumps({"incident_id":p["incident_id"],"outcome":found.get("outcome"),
                      "action_type":found.get("action_type"),"timestamp_ms":found.get("timestamp_ms")},sort_keys=True))
    break
   await asyncio.sleep(2)
  else: raise TimeoutError("Executor result did not arrive before timeout")
 await r.aclose()
asyncio.run(main())
'''

LOAD_CODE = r'''import concurrent.futures,sys,time,urllib.request,threading
url=sys.argv[1]; workers=int(sys.argv[2]); duration=float(sys.argv[3]); end=time.monotonic()+duration
counts=[0,0]; lock=threading.Lock()
def hit(_):
 while time.monotonic()<end:
  try:
   with urllib.request.urlopen(url,timeout=8) as r: r.read()
   with lock: counts[0]+=1
  except Exception:
   with lock: counts[1]+=1
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
 futures=[pool.submit(hit,i) for i in range(workers)]
 while time.monotonic()<end:
  time.sleep(10)
  with lock: print("scripted host load progress",workers,"workers","success",counts[0],"errors",counts[1],flush=True)
 for f in futures: f.result()
print("scripted host load ended",workers,"workers","success",counts[0],"errors",counts[1],flush=True)
'''


def run(args: list[str], *, input_text: str | None = None, timeout: int = 180) -> str:
    p = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}) {' '.join(args[:6])}: {p.stderr[-1800:]}")
    return p.stdout.strip()


def k(*args: str, input_text: str | None = None, timeout: int = 180) -> str:
    return run(["kubectl", "--context", CONTEXT, *args], input_text=input_text, timeout=timeout)


def remote(executor: str, payload: dict, timeout: int = 60) -> dict:
    raw = run(["kubectl", "--context", CONTEXT, "-n", "kubeheal", "exec", "-i", executor,
               "--", "python", "-c", REMOTE], input_text=json.dumps(payload), timeout=timeout)
    return json.loads(raw.splitlines()[-1])


def deployment_spec(namespace: str, name: str) -> dict:
    return json.loads(k("-n", namespace, "get", "deployment", name, "-o", "json"))["spec"]


def resources(namespace: str, name: str) -> dict:
    spec=deployment_spec(namespace,name)
    return spec["template"]["spec"]["containers"][0]["resources"]


def apply_monitor(namespace: str, deployment: str) -> None:
    service={"apiVersion":"v1","kind":"Service","metadata":{"name":deployment,"namespace":namespace,
             "labels":{"app":deployment,"app.kubernetes.io/name":"victim-app",
                       "kubeheal.io/scrape":"true","kubeheal.io/scripted":"F10"}},
             "spec":{"selector":{"app":deployment},"ports":[{"name":"http","port":8000,"targetPort":"http"}]}}
    monitor={"apiVersion":"monitoring.coreos.com/v1","kind":"ServiceMonitor",
             "metadata":{"name":deployment,"namespace":"monitoring","labels":{"release":"monitoring",
             "kubeheal.io/scripted":"F10"}},"spec":{"selector":{"matchLabels":{"app":deployment,
             "kubeheal.io/scrape":"true"}},"namespaceSelector":{"matchNames":[namespace]},
             "endpoints":[{"port":"http","path":"/metrics","interval":"5s","scheme":"http"}]}}
    k("apply","-f","-",input_text=json.dumps(service))
    k("apply","-f","-",input_text=json.dumps(monitor))


def create_scratch(namespace: str, name: str, base_resources: dict) -> dict:
    source=json.loads(k("-n",namespace,"get","deployment","victim-app","-o","json"))
    metadata={"name":name,"namespace":namespace,"labels":{"app":name,"kubeheal.io/scripted":"F10"}}
    spec=source["spec"]
    spec["selector"]={"matchLabels":{"app":name}}
    spec["template"]["metadata"]["labels"]={"app":name,"app.kubernetes.io/name":"victim-app",
                                             "kubeheal.io/scrape":"true","kubeheal.io/scripted":"F10"}
    spec["template"]["spec"]["containers"][0]["resources"]=base_resources
    manifest={"apiVersion":"apps/v1","kind":"Deployment","metadata":metadata,"spec":spec}
    k("apply","-f","-",input_text=json.dumps(manifest))
    k("-n",namespace,"rollout","status",f"deployment/{name}","--timeout=120s")
    created=deployment_spec(namespace,name)
    result=remote(executor_name(),{"phase":"seed","namespace":namespace,"deployment":name,"spec":created})
    if not result.get("created"):
        raise RuntimeError(f"F10 scratch baseline unexpectedly existed for {namespace}/{name}")
    return created


def executor_name() -> str:
    return k("-n","kubeheal","get","pods","-l","app=executor","-o","jsonpath={.items[0].metadata.name}")


def start_port_forward(namespace: str, service: str, port: int, log: Path) -> tuple[subprocess.Popen, object]:
    handle=log.open("a",encoding="utf-8")
    proc=subprocess.Popen(["kubectl","--context",CONTEXT,"-n",namespace,"port-forward",
                           f"service/{service}",f"{port}:8000"],
                          stdout=handle,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    deadline=time.monotonic()+30
    url=f"http://127.0.0.1:{port}/health"
    while time.monotonic()<deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"port-forward exited for {namespace}/{service}; see {log}")
        try:
            with urllib.request.urlopen(url,timeout=2) as r:
                if r.status==200: return proc,handle
        except (URLError,TimeoutError): time.sleep(1)
    raise TimeoutError(f"port-forward did not become ready for {namespace}/{service}")


def start_load(port: int, workers: int, duration: int, log: Path) -> tuple[subprocess.Popen, object]:
    handle=log.open("a",encoding="utf-8")
    url=f"http://127.0.0.1:{port}/cpu?milliseconds=200"
    proc=subprocess.Popen([sys.executable,"-u","-c",LOAD_CODE,url,str(workers),str(duration)],
                          stdout=handle,stderr=subprocess.STDOUT,
                          creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    return proc,handle


def wait_applied(namespace: str, name: str, expected: dict, timeout: int = 60) -> None:
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        try:
            actual=resources(namespace,name)
            if actual==expected:
                return
        except Exception:
            pass
        time.sleep(2)
    raise TimeoutError(f"{namespace}/{name} did not receive the scripted canary patch")


def stop_pair(processes: list, forward_index: int, load_index: int) -> None:
    for index in (forward_index,load_index):
        proc,handle=processes[index]
        if proc.poll() is None: proc.terminate()
        try: proc.wait(timeout=10)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        handle.close()


def restart_load_pair(processes: list, namespace: str, service: str, port: int,
                      forward_index: int, load_index: int, workers: int, duration: int, log: Path) -> None:
    stop_pair(processes,forward_index,load_index)
    processes[forward_index]=start_port_forward(namespace,service,port,log)
    processes[load_index]=start_load(port,workers,duration,log)


def set_mode(value: str) -> None:
    k("-n","kubeheal","patch","configmap","kubeheal-mode","--type","merge","-p",
      json.dumps({"data":{"mode":value}}))
    actual=k("-n","kubeheal","get","configmap","kubeheal-mode","-o","jsonpath={.data.mode}")
    if actual!=value:
        raise RuntimeError(f"mode readback failed: wanted {value}, got {actual}")


def main() -> None:
    run_id=uuid.uuid4().hex
    mode=k("-n","kubeheal","get","configmap","kubeheal-mode","-o","jsonpath={.data.mode}")
    if mode!="test": raise RuntimeError("F10 requires test mode before setup")
    dev_name=f"f10-scripted-dev-{run_id[:8]}"
    prod_name=f"f10-scripted-prod-{run_id[:8]}"
    executor=executor_name()
    dev_base_spec=create_scratch("dev",dev_name,{"requests":{"cpu":"100m","memory":"64Mi"},
                                                   "limits":{"cpu":"500m","memory":"128Mi"}})
    prod_base_spec=create_scratch("prod",prod_name,{"requests":{"cpu":"50m","memory":"64Mi"},
                                                      "limits":{"cpu":"200m","memory":"128Mi"}})
    apply_monitor("dev",dev_name); apply_monitor("prod",prod_name)
    dev_base=resources("dev",dev_name)
    prod_base=resources("prod",prod_name)
    # Keep the dev workload's 5x CPU drift bounded and reversible.
    k("-n","dev","set","resources",f"deployment/{dev_name}","-c","victim-app",
      "--requests=cpu=10m,memory=64Mi","--limits=cpu=50m,memory=128Mi")
    # For the rollback case, the scripted golden baseline is lower than the live spec. It is the change under test.
    k("-n","prod","set","resources",f"deployment/{prod_name}","-c","victim-app",
      "--requests=cpu=100m,memory=64Mi","--limits=cpu=500m,memory=128Mi")
    k("-n","dev","rollout","status",f"deployment/{dev_name}","--timeout=120s")
    k("-n","prod","rollout","status",f"deployment/{prod_name}","--timeout=120s")
    evidence=Path(__file__).with_name(f"F10_scripted_run_{run_id}.txt")
    load_log=Path(__file__).with_name(f"load_{run_id}.txt")
    dev_port=30000+int(run_id[:4],16)%10000
    prod_port=dev_port+1
    processes=[start_port_forward("dev",dev_name,dev_port,load_log),
               start_port_forward("prod",prod_name,prod_port,load_log)]
    processes.extend([start_load(dev_port,4,360,load_log),start_load(prod_port,4,360,load_log)])
    try:
        time.sleep(45)  # allow Prometheus to scrape several real histogram windows
        dev_pre=remote(executor,{"phase":"metrics","namespace":"dev","deployment":dev_name})
        prod_pre=remote(executor,{"phase":"metrics","namespace":"prod","deployment":prod_name})
        print(json.dumps({"scripted":True,"run_id":run_id,"pre_canary_metrics":{"dev":dev_pre,"prod":prod_pre}},sort_keys=True))
        for name,metric in ((dev_name,dev_pre),(prod_name,prod_pre)):
            if metric["metrics"].get("http_p99_latency_ms") is None:
                raise RuntimeError(f"Prometheus has no HTTP p99 series for {name}")

        deadman_log=Path(__file__).with_name(f"deadman_{run_id}.txt")
        deadman_script=Path(__file__).resolve().parents[4]/"demo"/"scripts"/"deadman_test_mode.ps1"
        log_handle=deadman_log.open("w",encoding="utf-8")
        deadman=subprocess.Popen([os.environ.get("F10_POWERSHELL","pwsh"),"-NoProfile","-File",str(deadman_script),
                                  "-RunId",run_id,"-AfterSeconds","600"],stdout=log_handle,
                                 stderr=subprocess.STDOUT,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        start_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
        print(json.dumps({"run_id":run_id,"enforce_window":"START","utc":start_utc,"deadman_timeout_s":600}))
        set_mode("enforce")
        try:
            time.sleep(5)  # let the Executor's ConfigMap watch apply the scripted enforce transition
            good_id=f"f10-good-{run_id[:16]}"
            queued=remote(executor,{"phase":"queue","incident_id":good_id,"namespace":"dev","deployment":dev_name})
            print(json.dumps({"case":"canary_heal","queue":queued,"scripted_drift":"CPU 10m/50m",
                              "target_resources":dev_base},sort_keys=True))
            wait_applied("dev",dev_name,dev_base)
            k("-n","dev","rollout","status",f"deployment/{dev_name}","--timeout=120s")
            restart_load_pair(processes,"dev",dev_name,dev_port,0,2,4,240,load_log)
            good=remote(executor,{"phase":"wait","incident_id":good_id,"timeout_s":300},timeout=320)
            print(json.dumps({"case":"canary_heal","executor_result":good},sort_keys=True))
            if good.get("outcome")!="patched_kept":
                raise RuntimeError(f"F10 good canary did not keep patch: {good.get('outcome')}")
            if resources("dev",dev_name)!=dev_base:
                raise RuntimeError("F10 good canary resource values did not match the golden baseline")

            bad_id=f"f10-bad-{run_id[:16]}"
            bad_live={"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"500m","memory":"128Mi"}}
            wait_applied("prod",prod_name,bad_live)
            queued=remote(executor,{"phase":"queue","incident_id":bad_id,"namespace":"prod","deployment":prod_name})
            print(json.dumps({"case":"bad_p99_rollback","queue":queued,
                              "scripted_drift":"prod live CPU 100m/500m toward golden lower resources"},sort_keys=True))
            wait_applied("prod",prod_name,prod_base)
            k("-n","prod","rollout","status",f"deployment/{prod_name}","--timeout=120s")
            restart_load_pair(processes,"prod",prod_name,prod_port,1,3,24,120,load_log)
            # Add real bounded CPU workload after the canary patch starts to raise the p99 sample.
            bad=remote(executor,{"phase":"wait","incident_id":bad_id,"timeout_s":300},timeout=320)
            print(json.dumps({"case":"bad_p99_rollback","executor_result":bad},sort_keys=True))
            if not str(bad.get("outcome","")).startswith("rolled_back:"):
                raise RuntimeError(f"F10 did not roll back on the scripted bad-p99 canary: {bad.get('outcome')}")
            if resources("prod",prod_name)!=bad_live:
                raise RuntimeError("F10 rollback did not restore the exact pre-patch live resources")
        finally:
            set_mode("test")
            print(json.dumps({"run_id":run_id,"enforce_window":"END","mode":"test",
                              "utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())},sort_keys=True))
            deadman.wait(timeout=30); log_handle.close()
            if deadman.returncode!=0: raise RuntimeError("F10 dead-man exited nonzero")
            print(deadman_log.read_text(encoding="utf-8").strip())
            if k("-n","kubeheal","get","configmap","kubeheal-mode","-o","jsonpath={.data.mode}")!="test":
                raise RuntimeError("mode not test after F10 window")
            print(json.dumps({"mode_after":"test","dev_resources":resources("dev",dev_name),
                              "prod_resources_after_rollback":resources("prod",prod_name),
                              "capture":str(evidence)},sort_keys=True))
    finally:
        for p,handle in processes:
            if p.poll() is None: p.terminate()
            try: p.wait(timeout=15)
            except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
            handle.close()


if __name__ == "__main__": main()
