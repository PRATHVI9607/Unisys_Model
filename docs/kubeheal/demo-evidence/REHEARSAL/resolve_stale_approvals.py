"""Resolve the reviewed 2026-11-13 stale test approvals without deleting their records."""
from __future__ import annotations

import base64
import json
import subprocess
from urllib.error import HTTPError
from urllib.request import Request, urlopen


CONTEXT = "k3d-kubeheal"
SECRET = "kubeheal-dashboard-admin"
API = "http://127.0.0.1:8080"
NOTE = "Stale prior KubeHeal test escalation; rejected during authorized cleanup. No remediation approved."
REVIEWED_IDS = {
    "inc-20261111-044212-4a9ff674", "inc-20261111-045504-f2b0ea1a",
    "inc-20261111-061333-edf381aa", "inc-20261111-093001-353a4230",
    "inc-20261111-093001-b6696e1f", "inc-20261113-015627-84e51778",
    "inc-20261113-015648-4e345688", "inc-20261113-015708-9a101249",
    "inc-20261113-015730-0dc2271f", "inc-20261113-015752-e353b903",
    "inc-20261113-015812-d7adfae1", "inc-20261113-015833-6f13e4ef",
    "inc-20261113-015855-a8216d8c", "inc-20261113-015916-4adeb29e",
    "inc-20261113-080214-d4b35860", "inc-20261113-080345-43a5bae6",
}


def token() -> str:
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, "-n", "kubeheal", "get", "secret", SECRET,
         "-o", "jsonpath={.data.token}"], capture_output=True, text=True, timeout=15, check=True,
    )
    return base64.b64decode(result.stdout.strip()).decode("utf-8")


def request(method: str, path: str, admin_token: str, body: dict | None = None) -> dict:
    raw = json.dumps(body or {}).encode("utf-8") if method == "POST" else None
    req = Request(API + path, data=raw, method=method, headers={
        "Authorization": "Bearer " + admin_token,
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=10) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        raise RuntimeError(f"dashboard {method} {path} returned HTTP {exc.code}") from None


def run() -> dict:
    admin_token = token()
    before = request("GET", "/api/approvals", admin_token)
    pending = before.get("pending") or []
    observed_ids = {row.get("incident_id") for row in pending}
    if observed_ids != REVIEWED_IDS:
        raise RuntimeError("pending approval set changed since review; refusing to resolve an unreviewed item")
    for row in pending:
        if (row.get("decision") != "human_patch" or
                (row.get("namespace"), row.get("deployment")) not in
                {("prod", "victim-app"), ("dev", "victim-app")}):
            raise RuntimeError("a pending approval does not match the reviewed stale test target set")

    outcomes = []
    for incident_id in sorted(REVIEWED_IDS):
        body = request("POST", f"/api/approvals/{incident_id}/reject", admin_token, {"note": NOTE})
        if body.get("status") not in {"rejected", "already_rejected"}:
            raise RuntimeError(f"approval {incident_id} was not resolved")
        outcomes.append({"incident_id": incident_id, "status": body["status"],
                         "rejected_by": body.get("rejected_by", "dashboard-admin")})
    after = request("GET", "/api/approvals", admin_token)
    remaining = {row.get("incident_id") for row in after.get("pending", [])} & REVIEWED_IDS
    if remaining:
        raise RuntimeError("some reviewed approvals remain pending")
    return {"resolved": outcomes, "remaining_reviewed_pending": sorted(remaining),
            "note": NOTE, "method": "dashboard rejection; stream and ledger history retained"}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
