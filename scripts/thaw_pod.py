"""Operator tool: thaw a pod that the cgroup freeze (V5-S5) left frozen.

A contained pod stays frozen until an operator releases it: nothing thaws automatically. This script publishes a
`thaw` request for the pod on the stream of its node (`kubeheal.contain.req:<node>`) and waits for the verified
answer of the node-local Security Agent (hash `kubeheal:contain:result:<request_id>`).

A thaw is the safe direction, so it is accepted in every kill-switch mode (including `test`), but only from
requested_by `operator`, and the Security Agent still validates everything else (namespace guard, pod UID, node,
request age). The script writes ONLY to Redis. It reads nothing from Kubernetes: give it the facts, for example from
`kubectl --context k3d-kubeheal -n <ns> get pod <pod> -o jsonpath='{.metadata.uid} {.spec.nodeName}'`.

Usage:
  REDIS_URL=redis://:<password>@127.0.0.1:6379 CONTAIN_HMAC_KEY=<secret-value> python scripts/thaw_pod.py \\
      --namespace prod --pod web-abc-1 --pod-uid <uid> --node <node> --incident-id <incident>

`CONTAIN_HMAC_KEY` is read from the same Kubernetes Secret key as the Redis password; do not put it in a command
history or commit it. The script rejects missing or invalid result signatures.

Exit codes: 0 only when the answer says status `thawed` with frozen 0; 1 when it does not (refused, failed, no
answer in time; the reason is printed); 2 when REDIS_URL is not set; 3 when Redis cannot be reached.
The Security Agent refuses a request whose timestamp is more than CONTAIN_REQUEST_TTL_S (30 s, chosen) away from
its own clock: a reason `expired` or `bad_timestamp` usually means the clocks differ (a Docker Desktop VM can
drift); fix the clock and retry.
"""
import argparse
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.common.containment_auth import sign_fields, verify_fields

STREAM_PREFIX = "kubeheal.contain.req"      # keep in step with agents/executor/freeze.py
RESULT_PREFIX = "kubeheal:contain:result"


def build_request(namespace, pod, pod_uid, node, incident_id, now_ms=None, request_id=None, hmac_key=None):
    key = os.environ.get("CONTAIN_HMAC_KEY", "") if hmac_key is None else hmac_key
    return sign_fields({
        "request_id": request_id or uuid.uuid4().hex, "incident_id": incident_id, "namespace": namespace,
        "pod": pod, "pod_uid": pod_uid, "node": node, "action": "thaw", "label": "",
        "requested_by": "operator", "timestamp_ms": str(int(now_ms if now_ms is not None else time.time() * 1000)),
    }, key)


def thaw(redis, request, wait_s=15.0, poll_s=0.5, sleep=time.sleep, clock=time.monotonic):
    """Publish the request and wait for the answer. Returns (ok, message, result dict)."""
    redis.xadd(f"{STREAM_PREFIX}:{request['node']}", request)
    hmac_key = os.environ.get("CONTAIN_HMAC_KEY", "")
    key = f"{RESULT_PREFIX}:{request['request_id']}"
    deadline = clock() + wait_s
    while True:
        raw = redis.hgetall(key) or {}
        result = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                  for k, v in raw.items()}
        if result:
            authenticated = verify_fields(result, hmac_key)
            ok = authenticated and result.get("status") == "thawed" and result.get("frozen") == "0"
            why = result.get("reason", "")
            if not authenticated:
                why = "invalid_hmac"
            hint = ""
            if why.startswith(("expired", "bad_timestamp")):
                hint = " (the clocks of this machine and the node probably differ by more than the request window)"
            return ok, (f"status={result.get('status')!r} frozen={result.get('frozen')!r}"
                        + (f" reason={why!r}" if why else "") + hint), result
        if clock() >= deadline:
            return False, "no answer in time (is the Security Agent on that node running with the freeze consumer?)", {}
        sleep(poll_s)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--pod", required=True)
    ap.add_argument("--pod-uid", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--incident-id", required=True)
    ap.add_argument("--wait-s", type=float, default=15.0)
    args = ap.parse_args(argv)
    url = os.environ.get("REDIS_URL")
    if not url:
        print("REDIS_URL is not set", file=sys.stderr)
        return 2
    if not os.environ.get("CONTAIN_HMAC_KEY"):
        print("CONTAIN_HMAC_KEY is not set", file=sys.stderr)
        return 2
    import redis as redis_lib
    client = redis_lib.from_url(url, decode_responses=True)
    request = build_request(args.namespace, args.pod, args.pod_uid, args.node, args.incident_id)
    try:
        ok, message, _result = thaw(client, request, wait_s=args.wait_s)
    except redis_lib.exceptions.RedisError as e:
        print(f"NOT THAWED: redis unreachable or failing ({type(e).__name__})", file=sys.stderr)
        return 3
    print(("THAWED: " if ok else "NOT THAWED: ") + message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
