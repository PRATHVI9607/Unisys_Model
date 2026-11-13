"""Run-owned F7 scripted Fusion inputs on k3d-kubeheal in global test mode."""
from __future__ import annotations

import json
import subprocess
import uuid

CONTEXT = "k3d-kubeheal"
REMOTE = r'''
import asyncio, json, os, sys, time
import redis.asyncio as aioredis
from kubernetes_asyncio import client, config
from agents.common.ledger import ledger_from_env
from agents.fusion_agent.agent import FusionAgentV4, derive_incident_id, EXEC_STREAM
from kubeheal.posture import policy_violations

async def main():
    p=json.load(sys.stdin); rid=p["run_id"]
    config.load_incluster_config()
    core=client.CoreV1Api()
    cm=await core.read_namespaced_config_map("kubeheal-mode","kubeheal")
    nsobj=await core.read_namespace("dev")
    if (cm.data or {}).get("mode") != "test":
        raise RuntimeError("F7 requires global test mode")
    a=FusionAgentV4(ledger=ledger_from_env())
    a.redis=aioredis.from_url(os.environ["REDIS_URL"],decode_responses=True)
    a.mode.apply_configmap(cm); a.mode.apply_namespace(nsobj); a.mode.ns_readable=True
    a.mode.apply_namespace(await core.read_namespace("prod"))
    now=int(time.time()*1000)
    # Reuse the existing F5 run-owned dev Deployment so the dry-run target exists.
    workload="f5-scripted-dev-2a87df12"

    # M2: a model-scored health event with a multi-label conformal set must become HUMAN.
    h={"event_id":"scripted-f7-m2-"+rid,"timestamp_ms":str(now),"namespace":"dev",
       "deployment":workload,"namespace_tier":"dev","model_scored":"true","model_version":"SCRIPTED-F7",
       "health_label":"degraded","health_risk":"0.99","health_prediction_set":"[\"degraded\",\"benign\"]",
       "health_uncertain":"false","spec_changed":"true","has_baseline":"true",
       "changed_fields_json":"[\"/spec/template/spec/containers/0/resources/limits/cpu\"]"}
    await a._decide("dev:"+workload,h,None)
    m2_id=derive_incident_id(h); m2=await a.redis.hgetall(a._ctx_key(m2_id))

    # Q1: rule rollback with no fresh Security Model response is HUMAN_PATCH.
    h0={"event_id":"scripted-f7-rule-stale-"+rid,"timestamp_ms":str(now),"namespace":"dev",
        "deployment":workload,"namespace_tier":"dev","model_scored":"true","model_version":"SCRIPTED-F7",
        "health_label":"benign","health_risk":"0.1","health_prediction_set":"[\"benign\"]",
        "health_uncertain":"false","spec_changed":"true","has_baseline":"true",
        "failure_reasons_json":"[\"policy:cpu_cut_10x\",\"policy:memory_cut_10x\"]",
        "changed_fields_json":"[\"/spec/template/spec/containers/0/resources\"]"}
    s0={"event_id":"scripted-f7-rule-stale-security-"+rid,"timestamp_ms":str(now),"namespace":"dev",
        "deployment":workload,"namespace_tier":"dev","model_scored":"false","model_version":"SCRIPTED-F7",
        "sec_label":"benign","sec_risk":"0.10","sec_prediction_set":"[\"benign\"]",
        "sec_uncertain":"false","syscall_source":"scripted","window_start_ms":str(now-1000),
        "window_end_ms":str(now),"pod_uid":"scripted-f7-stale-uid-"+rid}
    await a._decide("dev:"+workload,h0,s0)
    stale_id=derive_incident_id(s0); stale=await a.redis.hgetall(a._ctx_key(stale_id))

    # Q1: same rollback rule with a fresh, explicitly scripted Security Model response.
    h1={**h0,"event_id":"scripted-f7-rule-fresh-health-"+rid}
    s={"event_id":"scripted-f7-rule-fresh-security-"+rid,"timestamp_ms":str(now),"namespace":"dev",
       "deployment":workload,"namespace_tier":"dev","model_scored":"true","model_version":"SCRIPTED-F7",
       "sec_label":"benign","sec_risk":"0.10","sec_prediction_set":"[\"benign\"]",
       "sec_uncertain":"false","syscall_source":"scripted","window_start_ms":str(now-1000),
       "window_end_ms":str(now),"pod_uid":"scripted-f7-uid-"+rid}
    await a._decide("dev:"+workload,h1,s)
    fresh_id=derive_incident_id(s); fresh=await a.redis.hgetall(a._ctx_key(fresh_id))
    entries=await a.redis.xrevrange(EXEC_STREAM,count=20)
    action=next((f for _,f in entries if f.get("incident_id")==fresh_id),None)

    # D1 inclusive edges, evaluated by the shipped posture policy using CPU and memory requests.
    def spec(cpu,mem):
        return {"template":{"spec":{"containers":[{"name":"app","resources":{"requests":{"cpu":cpu,"memory":mem}}}]}}}
    cpu=policy_violations(spec("500m","320Mi"),spec("50m","320Mi"))
    mem=policy_violations(spec("500m","320Mi"),spec("500m","32Mi"))
    result={"run_id":rid,"scripted":True,"mode":"test",
      "m2":{"decision":m2.get("action_state"),"human_pending":m2.get("action_state")=="human_pending",
            "event_id":h["event_id"],"prediction_set":["degraded","benign"]},
      "rule_without_fresh_security":{"decision":stale.get("action_state"),"human_pending":stale.get("action_state")=="human_pending",
            "event_id":s0["event_id"],"security_model_scored":False},
      "rule_with_fresh_scripted_security":{"decision":fresh.get("action_state"),"security_fresh":True,
            "security_source":"scripted Security Model event","event_id":s["event_id"],
            "exec_request_dry_run":(action or {}).get("dry_run"),"exec_rule_path":(action or {}).get("rule_path")},
      "d1_inclusive_edges":{"cpu_500m_to_50m":cpu,"memory_320Mi_to_32Mi":mem}}
    await a.redis.aclose()
    await a.mode.stop()
    await core.api_client.close()
    print(json.dumps(result,sort_keys=True))
asyncio.run(main())
'''


def main() -> None:
    mode = subprocess.run(["kubectl", "--context", CONTEXT, "-n", "kubeheal", "get", "configmap",
                           "kubeheal-mode", "-o", "jsonpath={.data.mode}"], capture_output=True, text=True, check=True).stdout.strip()
    if mode != "test":
        raise SystemExit("refusing F7 because global mode is not test")
    run_id = uuid.uuid4().hex
    pods = subprocess.run(["kubectl", "--context", CONTEXT, "-n", "kubeheal", "get", "pods", "-l",
                           "app=fusion-agent", "-o", "jsonpath={.items[0].metadata.name}"],
                          capture_output=True, text=True, check=True).stdout.strip()
    proc = subprocess.run(["kubectl", "--context", CONTEXT, "-n", "kubeheal", "exec", "-i", pods,
                           "--", "python", "-c", REMOTE], input=json.dumps({"run_id":run_id}),
                          capture_output=True, text=True, timeout=60)
    if proc.returncode:
        raise SystemExit(f"F7 scripted Fusion run failed: {proc.stderr[-1500:]}")
    print(proc.stdout.strip().splitlines()[-1])


if __name__ == "__main__":
    main()
