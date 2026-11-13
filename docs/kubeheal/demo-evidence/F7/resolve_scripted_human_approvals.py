"""Reject only the three human approvals opened by the recorded scripted F7 run."""
from __future__ import annotations
import base64, json, subprocess
from urllib.request import Request, urlopen

CONTEXT = "k3d-kubeheal"
API = "http://127.0.0.1:8080"
TARGET = ("dev", "f5-scripted-dev-2a87df12")
REVIEWED = {
    "inc-20261113-130451-48edc975",  # M2 multi-label -> HUMAN
    "inc-20261113-130613-179e8288",  # no fresh Security Model response -> HUMAN
    "inc-20261113-130613-765a3169",  # second run's M2 multi-label -> HUMAN
}

def main():
    raw = subprocess.run(["kubectl", "--context", CONTEXT, "-n", "kubeheal", "get", "secret",
                          "kubeheal-dashboard-admin", "-o", "jsonpath={.data.token}"],
                         capture_output=True, text=True, check=True).stdout.strip()
    token = base64.b64decode(raw).decode()
    headers = {"Authorization":"Bearer "+token,"Content-Type":"application/json"}
    with urlopen(Request(API+"/api/approvals",headers=headers),timeout=15) as r:
        pending=json.loads(r.read()).get("pending",[])
    selected=[r for r in pending if r.get("incident_id") in REVIEWED]
    if {r.get("incident_id") for r in selected} != REVIEWED or any(
        (r.get("namespace"),r.get("deployment")) != TARGET or r.get("decision") != "human_patch"
        for r in selected
    ):
        raise RuntimeError("the exact reviewed F7 approvals are not pending; refusing broader cleanup")
    out=[]
    note="Scripted F7 policy verification completed in test mode; no remediation approved."
    for row in selected:
        req=Request(API+f"/api/approvals/{row['incident_id']}/reject",data=json.dumps({"note":note}).encode(),
                    method="POST",headers=headers)
        with urlopen(req,timeout=15) as r:
            body=json.loads(r.read())
        if body.get("status") not in {"rejected","already_rejected"}:
            raise RuntimeError("F7 test approval was not resolved")
        out.append({"incident_id":row["incident_id"],"status":body["status"]})
    print(json.dumps({"resolved":out,"method":"dashboard rejection; history retained"},sort_keys=True))

if __name__ == "__main__": main()
