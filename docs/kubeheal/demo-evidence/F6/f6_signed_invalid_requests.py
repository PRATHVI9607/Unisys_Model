"""F6 signed invalid requests on k3d-kubeheal, test mode only.

Each request is signed inside the node-local Security Agent container using its Secret-backed
containment key. The requests exercise validation only; they must receive authenticated refused
results with frozen=0. The protected-label case temporarily labels the existing dev namespace and
restores its exact previous label in finally. Redis request/result records are run-owned and removed.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CONTEXT = "k3d-kubeheal"
KH_NS = "kubeheal"
TARGET_NS = "dev"
REMOTE = r'''import json, os, sys, time
import redis
from agents.common.containment_auth import sign_fields, verify_fields

spec = json.load(sys.stdin)
r = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=False,
                         socket_connect_timeout=3, socket_timeout=3)
key = os.environ.get("CONTAIN_HMAC_KEY", "")
if not key:
    raise RuntimeError("containment signing key unavailable")
stream = "kubeheal.contain.req:" + spec["node"]
queued = []
results = {}
expected = {
    "bad_namespace": "bad_namespace",
    "protected_label": "namespace_protected: the namespace carries kubeheal/protected or is unknown",
    "unknown_action": "bad_action: 'wipe'",
    "missing_field": "bad_pod_uid",
}
try:
    for case in spec["cases"]:
        rid = spec["request_ids"][case]
        fields = {
            "request_id": rid,
            "incident_id": "f6-" + spec["run_id"][:24] + "-" + case.replace("_", "-"),
            "namespace": spec["namespace"], "pod": spec["pod"], "pod_uid": spec["pod_uid"],
            "node": spec["node"], "action": "freeze", "label": "ransomware",
            "requested_by": "executor", "timestamp_ms": str(int(time.time() * 1000)),
        }
        if case == "bad_namespace":
            fields["namespace"] = "bad_namespace"
        elif case == "unknown_action":
            fields["action"] = "wipe"
        elif case == "missing_field":
            fields.pop("pod_uid")
        signed = sign_fields(fields, key)
        msg_id = r.xadd(stream, signed).decode("utf-8")
        queued.append((case, rid, msg_id))

    deadline = time.monotonic() + spec["wait_s"]
    while len(results) < len(queued) and time.monotonic() < deadline:
        for case, rid, _msg_id in queued:
            if case in results:
                continue
            raw = r.hgetall("kubeheal:contain:result:" + rid) or {}
            if raw:
                row = {(k.decode() if isinstance(k, bytes) else str(k)):
                       (v.decode() if isinstance(v, bytes) else str(v)) for k, v in raw.items()}
                results[case] = row
        if len(results) < len(queued):
            time.sleep(0.1)

    if len(results) != len(queued):
        raise RuntimeError("timed out waiting for signed validation responses")
    output = []
    for case, _rid, _msg_id in queued:
        row = results[case]
        if not verify_fields(row, key):
            raise RuntimeError(case + " response HMAC was invalid")
        if row.get("status") != "refused" or row.get("reason") != expected[case] or row.get("frozen") != "0":
            raise RuntimeError(case + " was not refused before a freeze write: " +
                               row.get("status", "") + " " + row.get("reason", ""))
        output.append({"case": case, "request_id": row["request_id"], "status": row["status"],
                       "reason": row["reason"], "frozen": row["frozen"], "response_hmac": "valid"})
finally:
    if queued:
        cleanup = """
        local n = #ARGV - 1
        for i=1,n do
          redis.pcall('XACK', KEYS[1], ARGV[1], ARGV[i + 1])
          redis.call('XDEL', KEYS[1], ARGV[i + 1])
          redis.call('DEL', KEYS[i + 1])
        end
        for i=1,n do
          if #redis.call('XRANGE', KEYS[1], ARGV[i + 1], ARGV[i + 1]) > 0 or
             redis.call('EXISTS', KEYS[i + 1]) ~= 0 then
            return redis.error_reply('run-owned cleanup incomplete')
          end
        end
        return 'clean'
        """
        keys = ["kubeheal:contain:result:" + rid for _case, rid, _msg in queued]
        ids = [msg for _case, _rid, msg in queued]
        cleaned = r.eval(cleanup, 1 + len(keys), stream, *keys, "security-agent", *ids)
        if cleaned.decode("utf-8") != "clean":
            raise RuntimeError("run-owned request/result cleanup failed")
print(json.dumps({"cases": output, "cleanup": "run-owned request/results removed"}, separators=(",", ":")))
'''


def kubectl(*args: str, input_text: str | None = None, timeout: int = 30) -> str:
    result = subprocess.run(["kubectl", "--context", CONTEXT, *args], input=input_text, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"kubectl {args[0] if args else 'command'} failed ({result.returncode})")
    return result.stdout.strip()


def mode() -> str:
    return kubectl("-n", KH_NS, "get", "configmap", "kubeheal-mode", "-o", "jsonpath={.data.mode}")


def run() -> dict:
    if mode() != "test":
        raise RuntimeError("refusing F6 validation unless global mode is test")
    ns = json.loads(kubectl("get", "namespace", TARGET_NS, "-o", "json"))
    old_label = (ns.get("metadata", {}).get("labels") or {}).get("kubeheal/protected")
    victims = json.loads(kubectl("-n", TARGET_NS, "get", "pods", "-l", "app.kubernetes.io/name=victim-app", "-o", "json"))
    agents = json.loads(kubectl("-n", KH_NS, "get", "pods", "-l", "app=security-agent", "-o", "json"))
    pair = None
    for victim in victims.get("items", []):
        node = (victim.get("spec") or {}).get("nodeName")
        if (victim.get("status") or {}).get("phase") != "Running":
            continue
        agent = next((p for p in agents.get("items", []) if (p.get("spec") or {}).get("nodeName") == node
                      and (p.get("status") or {}).get("phase") == "Running"), None)
        if agent:
            pair = victim, agent
            break
    if not pair:
        raise RuntimeError("no running dev victim and node-local Security Agent pair")
    victim, agent = pair
    pod_meta, pod_spec = victim["metadata"], victim["spec"]
    run_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    request_ids = {name: uuid.uuid4().hex for name in ("bad_namespace", "protected_label", "unknown_action", "missing_field")}
    payload = {"run_id": run_id, "namespace": TARGET_NS, "pod": pod_meta["name"],
               "pod_uid": pod_meta["uid"], "node": pod_spec["nodeName"],
               "request_ids": request_ids, "wait_s": 15}
    label_changed = old_label != "true"
    if mode() != "test":
        raise RuntimeError("mode changed before F6 request publication")
    try:
        # Ordinary validation cases first, with the namespace's prior protection state intact.
        ordinary = {k: v for k, v in payload.items() if k != "request_ids"}
        ordinary["request_ids"] = {k: request_ids[k] for k in ("bad_namespace", "unknown_action", "missing_field")}
        ordinary["cases"] = ["bad_namespace", "unknown_action", "missing_field"]
        # The remote runner is invoked in two groups so the protected-label case is evaluated only
        # after the watcher has observed the temporary label.
        first = _send(agent["metadata"]["name"], ordinary)
        if label_changed:
            kubectl("label", "namespace", TARGET_NS, "kubeheal/protected=true", "--overwrite")
            time.sleep(2)
        label_deadline = time.monotonic() + 15
        while time.monotonic() < label_deadline:
            seen = json.loads(kubectl("get", "namespace", TARGET_NS, "-o", "json"))
            if (seen.get("metadata", {}).get("labels") or {}).get("kubeheal/protected") == "true":
                break
            time.sleep(0.25)
        second = _send(agent["metadata"]["name"], {**payload,
                       "request_ids": {"protected_label": request_ids["protected_label"]},
                       "cases": ["protected_label"]})
        evidence = {"run_id": run_id, "scripted": True, "mode": "test", "target": f"{TARGET_NS}/{pod_meta['name']}",
                    "node": pod_spec["nodeName"], "cases": first["cases"] + second["cases"],
                    "security_agent_log": _filtered_logs(agent["metadata"]["name"], started_at),
                    "protected_label_restored": True, "cleanup": "run-owned Redis messages/results removed"}
        if len(evidence["cases"]) != 4:
            raise RuntimeError("incomplete F6 result set")
        if mode() != "test":
            raise RuntimeError("global mode changed during F6 validation")
    finally:
        if label_changed:
            if old_label is None:
                kubectl("label", "namespace", TARGET_NS, "kubeheal/protected-")
            else:
                kubectl("label", "namespace", TARGET_NS, f"kubeheal/protected={old_label}", "--overwrite")
        if mode() != "test":
            raise RuntimeError("global mode is not test after F6 validation")
    restored = json.loads(kubectl("get", "namespace", TARGET_NS, "-o", "json"))
    restored_label = (restored.get("metadata", {}).get("labels") or {}).get("kubeheal/protected")
    if restored_label != old_label:
        raise RuntimeError("dev namespace protected label did not return to its exact prior value")
    evidence["protected_label_restored"] = True
    return evidence


def _send(agent: str, payload: dict) -> dict:
    stdout = kubectl("-n", KH_NS, "exec", "-i", agent, "-c", "agent", "--", "python", "-c", REMOTE,
                     input_text=json.dumps(payload, separators=(",", ":")), timeout=40)
    return json.loads(stdout)


def _filtered_logs(agent: str, since_time: str) -> list[str]:
    raw = kubectl("-n", KH_NS, "logs", agent, "-c", "agent", "--since-time=" + since_time)
    reasons = ("bad_namespace", "namespace_protected", "bad_action", "bad_pod_uid")
    return [line for line in raw.splitlines() if "containment" in line and "-> refused" in line
            and any(reason in line for reason in reasons)]


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
