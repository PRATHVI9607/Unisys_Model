"""Scripted, run-owned F5 live baseline flow for k3d-kubeheal.

This runner creates two PVC-free Deployments, records their pre-change spec as a
golden baseline, changes one environment field, then calls the deployed Health
Agent baseline implementation with an explicitly scripted benign/certain
assessment. Dev is auto-promoted; prod remains a candidate until the dashboard
approval endpoint is used. The runner never prints Secret data.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


CONTEXT = "k3d-kubeheal"
NAMESPACE = "kubeheal"
DASHBOARD = "http://127.0.0.1:8080"
REMOTE = r'''
import asyncio, hashlib, json, os, sys
import redis.asyncio as redis
from agents.common.ledger import ledger_from_env
from agents.health_agent import baseline

async def main():
    p=json.load(sys.stdin)
    r=redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    ledger=ledger_from_env()
    ns,name=p["namespace"],p["deployment"]
    if p["phase"] == "seed":
        record,created=await baseline.get_or_set_baseline(r,ns,name,p["old_spec"])
        print(json.dumps({"phase":"seed","created":created,"golden_digest":baseline.record_digest(record)}))
    else:
        held=await baseline.load_baseline_raw(r,ns,name)
        if held is None:
            raise RuntimeError("scripted F5 golden baseline disappeared")
        old_raw,golden=held
        view=baseline.drift_view(p["new_spec"])
        h=hashlib.sha256(json.dumps(view,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        if p["namespace"] == "dev":
            result=await baseline.promote_baseline(
                r,ledger,ns,name,new_spec=view,spec_hash=h,golden_raw=old_raw,
                kind="auto",actor=baseline.AUTO_ACTOR,tier="dev",
                changed_fields=["/template/spec/containers/0/env"],
                evidence={"label":"benign","prediction_set":["benign"],"model_version":"SCRIPTED-F5","event_id":p["event_id"]},
            )
            current=await baseline.load_baseline(r,ns,name)
            print(json.dumps({"phase":"promote","result":result.get("status"),
                "ledger_key":result.get("ledger_key"),"ledger_points_from_golden":
                bool(current and current.get("promotion",{}).get("ledger_key")==result.get("ledger_key")),
                "golden_digest":baseline.record_digest(current)}))
        else:
            result=await baseline.store_candidate(
                r,ledger,ns,name,new_spec=view,spec_hash=h,golden_raw=old_raw,tier="prod",
                changed_fields=["/template/spec/containers/0/env"],
                assessment={"label":"benign","risk":0.01,"prediction_set":["benign"],
                            "model_version":"SCRIPTED-F5","event_id":p["event_id"]},
            )
            print(json.dumps({"phase":"candidate","result":result.get("status"),
                "candidate_id":result.get("candidate_id")}))
    await r.aclose()

asyncio.run(main())
'''


def run(args: list[str], *, input_text: str | None = None) -> str:
    p = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=90)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(args[:5])}\n{p.stderr[-1200:]}")
    return p.stdout.strip()


def kubectl(*args: str, **kwargs) -> str:
    return run(["kubectl", "--context", CONTEXT, *args], **kwargs)


def get_json(*args: str) -> dict:
    return json.loads(kubectl(*args, "-o", "json"))


def remote(payload: dict) -> dict:
    pod = kubectl("-n", NAMESPACE, "get", "pods", "-l", "app=health-agent",
                  "-o", "jsonpath={.items[0].metadata.name}")
    out = run(["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "exec", "-i", pod,
               "--", "python", "-c", REMOTE], input_text=json.dumps(payload))
    return json.loads(out.splitlines()[-1])


def admin_token() -> str:
    encoded = kubectl("-n", NAMESPACE, "get", "secret", "kubeheal-dashboard-admin",
                      "-o", "jsonpath={.data.token}")
    return base64.b64decode(encoded).decode("utf-8")


def dashboard(method: str, path: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body or {}).encode() if body is not None else None
    req = urllib.request.Request(DASHBOARD + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"dashboard returned HTTP {exc.code} for {method} {path}") from None


def main() -> None:
    run_id = os.environ.get("KUBEHEAL_F5_RUN_ID", uuid.uuid4().hex)
    if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
        raise RuntimeError("KUBEHEAL_F5_RUN_ID must be 32 lowercase hex characters")
    image = kubectl("-n", "dev", "get", "deployment", "victim-app",
                    "-o", "jsonpath={.spec.template.spec.containers[0].image}")
    expected = "test"
    mode = kubectl("-n", NAMESPACE, "get", "configmap", "kubeheal-mode",
                   "-o", "jsonpath={.data.mode}")
    if mode != expected:
        raise RuntimeError("F5 requires global mode=test before creating scripted targets")

    targets = [("dev", f"f5-scripted-dev-{run_id[:8]}"),
               ("prod", f"f5-scripted-prod-{run_id[:8]}")]
    created: list[tuple[str, str]] = []
    try:
        for ns, name in targets:
            exists = subprocess.run(["kubectl", "--context", CONTEXT, "-n", ns,
                                     "get", "deployment", name], capture_output=True, text=True)
            if exists.returncode == 0:
                # Resume only the exact run-owned target after the earlier selector-only failure.
                kubectl("-n", ns, "set", "env", f"deployment/{name}", "F5_SCRIPTED_CONFIG=before")
                kubectl("-n", ns, "rollout", "status", f"deployment/{name}", "--timeout=120s")
                created.append((ns, name))
            manifest = {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":name,"namespace":ns,
                         "labels":{"kubeheal.io/scripted":"F5","kubeheal.io/run-id":run_id}},
                        "spec":{"replicas":1,"selector":{"matchLabels":{"app":name}},
                               "template":{"metadata":{"labels":{"app":name,"kubeheal.io/scripted":"F5"}},
                               "spec":{"containers":[{"name":"victim-app","image":image,
                                 "imagePullPolicy":"IfNotPresent","env":[{"name":"F5_SCRIPTED_CONFIG","value":"before"}],
                                 "ports":[{"name":"http","containerPort":8000}],
                                 "readinessProbe":{"httpGet":{"path":"/health","port":"http"}},
                                 "resources":{"requests":{"cpu":"50m","memory":"64Mi"},
                                               "limits":{"cpu":"200m","memory":"128Mi"}}}]}}}}
            if exists.returncode != 0:
                kubectl("apply", "-f", "-", input_text=json.dumps(manifest))
                created.append((ns, name))
                kubectl("-n", ns, "rollout", "status", f"deployment/{name}", "--timeout=120s")
            old = get_json("-n", ns, "get", "deployment", name)["spec"]
            seeded = remote({"phase":"seed","namespace":ns,"deployment":name,"old_spec":old})
            if not seeded["created"]:
                raise RuntimeError("unexpected pre-existing scripted baseline")
            kubectl("-n", ns, "set", "env", f"deployment/{name}", "F5_SCRIPTED_CONFIG=after")
            kubectl("-n", ns, "rollout", "status", f"deployment/{name}", "--timeout=120s")
            new = get_json("-n", ns, "get", "deployment", name)["spec"]
            os.environ[f"F5_NEW_SPEC_{ns.upper()}"] = json.dumps(new)

        # The scripted promotion and dashboard approval are the only enforce-mode operations.
        deadman_log = Path(__file__).with_name(f"deadman_{run_id}.txt")
        deadman_script = Path(__file__).resolve().parents[4] / "demo" / "scripts" / "deadman_test_mode.ps1"
        powershell = os.environ.get("F5_POWERSHELL", "pwsh")
        log_handle = deadman_log.open("w", encoding="utf-8")
        deadman = subprocess.Popen(
            [powershell, "-NoProfile", "-File", str(deadman_script), "-RunId", run_id,
             "-AfterSeconds", "60"], stdout=log_handle, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        window_start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        print(json.dumps({"run_id":run_id,"enforce_window":"START","utc":window_start,
                          "deadman_timeout_s":60},sort_keys=True))
        kubectl("-n", NAMESPACE, "patch", "configmap", "kubeheal-mode", "--type", "merge",
                "-p", '{"data":{"mode":"enforce"}}')
        try:
            for ns, name in targets:
                new = json.loads(os.environ[f"F5_NEW_SPEC_{ns.upper()}"])
                changed = remote({"phase":"apply","namespace":ns,"deployment":name,"new_spec":new,
                                  "event_id":f"scripted-f5-{run_id}-{ns}"})
                print(json.dumps({"namespace":ns,"deployment":name,"scripted_input":True,
                                  "config":"before -> after","baseline_flow":changed},sort_keys=True))
                if ns == "dev" and (changed.get("result") != "promoted" or
                                      not changed.get("ledger_points_from_golden")):
                    raise RuntimeError("dev auto-promotion/ledger pointer did not verify")
                if ns == "prod" and changed.get("result") != "stored":
                    raise RuntimeError("prod candidate was not stored")
                if ns == "prod":
                    pending = dashboard("GET", "/api/baseline-candidates", admin_token())
                    row = next((r for r in pending.get("candidates", [])
                                if r.get("namespace") == ns and r.get("deployment") == name
                                and r.get("candidate_id") == changed.get("candidate_id")), None)
                    if row is None or row.get("status") != "pending":
                        raise RuntimeError("prod candidate did not wait in dashboard")
                    print(json.dumps({"namespace":"prod","pending_dashboard_candidate":row},sort_keys=True))
                    approved = dashboard("POST", f"/api/baseline-candidates/prod/{name}/approve", admin_token(),
                                         {"candidate_id":changed["candidate_id"],
                                          "reason":"Scripted F5 run-owned baseline rehearsal"})
                    print(json.dumps({"prod_dashboard_approval":approved},sort_keys=True))
                    if approved.get("status") != "promoted" or not approved.get("applied"):
                        raise RuntimeError("prod dashboard approval did not promote")
        finally:
            kubectl("-n", NAMESPACE, "patch", "configmap", "kubeheal-mode", "--type", "merge",
                    "-p", '{"data":{"mode":"test"}}')
            window_end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            print(json.dumps({"run_id":run_id,"enforce_window":"END","utc":window_end,
                              "mode":"test"},sort_keys=True))
            # Let the independent dead-man read back test and write its END record.
            deadman.wait(timeout=90)
            log_handle.close()
            if deadman.returncode != 0:
                raise RuntimeError(f"dead-man exited {deadman.returncode}; see {deadman_log}")
            if kubectl("-n", NAMESPACE, "get", "configmap", "kubeheal-mode",
                       "-o", "jsonpath={.data.mode}") != "test":
                raise RuntimeError("mode is not test after the F5 window")
            print(deadman_log.read_text(encoding="utf-8").strip())
        print(json.dumps({"run_id":run_id,"targets":created,"status":"passed",
                          "mode_after":kubectl("-n",NAMESPACE,"get","configmap","kubeheal-mode",
                                                "-o","jsonpath={.data.mode}")},sort_keys=True))
    finally:
        # These Deployments are the only run-owned Kubernetes objects. Keep them for evidence/review.
        pass


if __name__ == "__main__":
    main()
