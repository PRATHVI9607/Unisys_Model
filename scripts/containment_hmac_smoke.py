"""Mode-test-only smoke check for signed and rejected node-local containment messages.

The runner never reads the HMAC key into the local process or prints it. It execs a short Python
program in the matching Security Agent container, where the existing Secret-backed environment is
available, and sends only three unique requests to that node's existing Redis stream. In mode test,
the valid freeze request must receive a signed dry-run result and cannot write cgroup state.
"""

import argparse
import json
import re
import subprocess
import sys
import time
import uuid
from typing import Callable, Dict, Iterable, Optional

CONTEXT = "k3d-kubeheal"
KUBEHEAL_NAMESPACE = "kubeheal"
VICTIM_NAMESPACE = "dev"
AGENT_CONTAINER = "agent"
GROUP = "security-agent"
REQUEST_STREAM_PREFIX = "kubeheal.contain.req:"
RESULT_KEY_PREFIX = "kubeheal:contain:result:"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


REMOTE_SMOKE = r'''import json, os, sys, time
import redis
from agents.common.containment_auth import sign_fields, verify_fields

spec = json.load(sys.stdin)
queued = []
checks = []
r = None
stream = "kubeheal.contain.req:" + spec["node"]
group = "security-agent"
def text(v):
    return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
try:
    key = os.environ.get("CONTAIN_HMAC_KEY", "")
    if not key:
        raise RuntimeError("containment key unavailable")
    r = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=False,
                             socket_connect_timeout=2, socket_timeout=2)
    for kind in ("signed", "unsigned", "tampered"):
        fields = {
            "request_id": spec["request_ids"][kind],
            "incident_id": spec["incident_ids"][kind],
            "namespace": spec["namespace"], "pod": spec["pod"], "pod_uid": spec["pod_uid"],
            "node": spec["node"], "action": "freeze", "label": "ransomware",
            "requested_by": "executor", "timestamp_ms": str(int(time.time() * 1000)),
        }
        signed = sign_fields(fields, key)
        if kind == "signed":
            message = signed
        elif kind == "unsigned":
            message = dict(fields)
        else:
            message = dict(signed)
            # A one millisecond timestamp change remains within TTL if signature verification were skipped.
            message["timestamp_ms"] = str(int(message["timestamp_ms"]) + 1)
        message_id = text(r.xadd(stream, message))
        queued.append((kind, message_id, spec["request_ids"][kind]))

    deadline = time.monotonic() + spec["wait_s"]
    results = {}
    while len(results) < 3 and time.monotonic() < deadline:
        for kind, _message_id, request_id in queued:
            if kind in results:
                continue
            raw = r.hgetall("kubeheal:contain:result:" + request_id) or {}
            if raw:
                result = {text(k): text(v) for k, v in raw.items()}
                results[kind] = result
        if len(results) < 3:
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    if len(results) != 3:
        raise RuntimeError("containment responses timed out")

    for kind in ("signed", "unsigned", "tampered"):
        result = results[kind]
        valid_hmac = verify_fields(result, key)
        if not valid_hmac:
            raise RuntimeError("a containment result had an invalid HMAC")
        if kind == "signed":
            ok = (result.get("status") == "dry_run" and result.get("mode_seen") == "test"
                  and result.get("reason", "").startswith("mode_test"))
        else:
            ok = result.get("status") == "refused" and result.get("reason") == "invalid_hmac"
        if not ok:
            raise RuntimeError("a containment request did not receive its required result")
        checks.append({"case": kind, "status": result["status"], "reason": result.get("reason", ""),
                       "mode_seen": result.get("mode_seen", ""), "result_hmac": "valid"})
finally:
    if r is not None and queued:
        cleanup_script = """
        local n = #ARGV - 1
        for i=1,n do
          redis.pcall('XACK', KEYS[1], ARGV[1], ARGV[i + 1])
          redis.call('XDEL', KEYS[1], ARGV[i + 1])
          redis.call('DEL', KEYS[i + 1])
        end
        for i=1,n do
          if #redis.call('XRANGE', KEYS[1], ARGV[i + 1], ARGV[i + 1]) > 0 or
             redis.call('EXISTS', KEYS[i + 1]) ~= 0 then
            return redis.error_reply('run-owned containment cleanup incomplete')
          end
        end
        return 'clean'
        """
        result_keys = ["kubeheal:contain:result:" + request_id for _kind, _mid, request_id in queued]
        message_ids = [message_id for _kind, message_id, _request_id in queued]
        cleanup = r.eval(cleanup_script, 1 + len(result_keys), stream, *result_keys, group, *message_ids)
        if text(cleanup) != "clean":
            raise RuntimeError("could not clean up all run-owned containment messages and results")
print(json.dumps({"checks": checks, "cleanup": "run-owned messages and results removed"},
                 separators=(",", ":")))
'''


def _kubectl(*args: str, input_text: Optional[str] = None, timeout_s: float = 30.0) -> str:
    """Run kubectl with the sole permitted context and a caller-supplied hard subprocess timeout."""
    proc = subprocess.run(["kubectl", "--context", CONTEXT, *args], input=input_text, text=True,
                          capture_output=True, check=False, timeout=max(0.1, timeout_s))
    if proc.returncode:
        raise RuntimeError(f"kubectl failed ({proc.returncode}) for {args[0] if args else 'command'}")
    return proc.stdout


class BoundedKubectl:
    def __init__(self, kubectl: Callable, clock: Callable[[], float], deadline: float):
        self.kubectl, self.clock, self.deadline = kubectl, clock, deadline

    def remaining(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("HMAC smoke deadline reached")
        return remaining

    def __call__(self, *args: str, input_text: Optional[str] = None) -> str:
        return self.kubectl(*args, input_text=input_text, timeout_s=self.remaining())


def _json(call: Callable, *args: str) -> Dict:
    return json.loads(call(*args))


def _mode(call: Callable) -> str:
    config = _json(call, "-n", KUBEHEAL_NAMESPACE, "get", "configmap", "kubeheal-mode", "-o", "json")
    return (config.get("data") or {}).get("mode", "")


def _running_pod(row: Dict) -> bool:
    return (row.get("status") or {}).get("phase") == "Running" and \
        bool((row.get("metadata") or {}).get("uid")) and bool((row.get("spec") or {}).get("nodeName"))


def _select_pair(victims: Iterable[Dict], agents: Iterable[Dict]):
    candidates = []
    for pod in victims:
        metadata = pod.get("metadata") or {}
        labels = metadata.get("labels") or {}
        if not _running_pod(pod) or (labels.get("app.kubernetes.io/name") != "victim-app"
                                      and labels.get("app") != "victim-app"):
            continue
        candidates.append(pod)
    for victim in sorted(candidates, key=lambda p: p["metadata"]["name"]):
        victim_node = victim["spec"]["nodeName"]
        matching = [pod for pod in agents if _running_pod(pod)
                    and (pod.get("metadata") or {}).get("labels", {}).get("app") == "security-agent"
                    and (pod.get("spec") or {}).get("nodeName") == victim_node]
        if len(matching) == 1:
            return victim, matching[0]
        if len(matching) > 1:
            raise RuntimeError(f"expected one Security Agent on victim node {victim_node}, found {len(matching)}")
    raise RuntimeError("no Running dev victim-app pod has exactly one Running Security Agent on its node")


def run(kubectl: Callable = _kubectl, clock: Callable[[], float] = time.monotonic,
        timeout_s: int = 60) -> Dict:
    """Send and verify three test-mode-only protocol cases; the remote code removes only its unique Redis records."""
    if timeout_s < 20:
        raise ValueError("--timeout-s must be at least 20 seconds to reserve bounded response cleanup")
    start = clock()
    deadline = start + timeout_s
    cleanup_reserve = min(10.0, max(5.0, timeout_s * 0.2))
    call = BoundedKubectl(kubectl, clock, deadline - cleanup_reserve)
    if _mode(call) != "test":
        raise RuntimeError("refusing HMAC smoke unless kubeheal-mode is already test")

    victim_list = _json(call, "-n", VICTIM_NAMESPACE, "get", "pods",
                        "-l", "app.kubernetes.io/name=victim-app", "-o", "json")
    agent_list = _json(call, "-n", KUBEHEAL_NAMESPACE, "get", "pods", "-l", "app=security-agent", "-o", "json")
    victim, agent = _select_pair(victim_list.get("items", []), agent_list.get("items", []))
    metadata, spec = victim["metadata"], victim["spec"]
    namespace, pod, pod_uid, node = VICTIM_NAMESPACE, metadata["name"], metadata["uid"], spec["nodeName"]
    if not _UUID.fullmatch(pod_uid):
        raise RuntimeError("victim pod UID is not a canonical Kubernetes UUID")
    if _mode(call) != "test":
        raise RuntimeError("refusing HMAC smoke because kubeheal-mode changed before requests were sent")

    run_id = uuid.uuid4().hex
    request_ids = {kind: uuid.uuid4().hex for kind in ("signed", "unsigned", "tampered")}
    incident_ids = {kind: f"hmac-{run_id}-{kind}" for kind in request_ids}
    wait_s = min(25, max(1, int(call.remaining()) - 5))
    payload = {"namespace": namespace, "pod": pod, "pod_uid": pod_uid, "node": node,
               "request_ids": request_ids, "incident_ids": incident_ids, "wait_s": wait_s}
    output = call("-n", KUBEHEAL_NAMESPACE, "exec", "-i", agent["metadata"]["name"],
                  "-c", AGENT_CONTAINER, "--", "python", "-c", REMOTE_SMOKE,
                  input_text=json.dumps(payload, separators=(",", ":")))
    try:
        evidence = json.loads(output)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Security Agent smoke runner returned no valid summary") from exc
    if _mode(BoundedKubectl(kubectl, clock, deadline)) != "test":
        raise RuntimeError("kubeheal-mode changed during HMAC smoke; expected test")
    checks = evidence.get("checks") or []
    if [row.get("case") for row in checks] != ["signed", "unsigned", "tampered"] or \
            evidence.get("cleanup") != "run-owned messages and results removed":
        raise RuntimeError("HMAC smoke returned incomplete checks or cleanup evidence")
    print(f"HMAC smoke target: {namespace}/{pod} on {node}; mode=test")
    for row in checks:
        print(f"{row['case']}: status={row['status']} reason={row['reason']} "
              f"mode_seen={row['mode_seen'] or 'not applicable'} result_hmac={row['result_hmac']}")
    print("Cleanup verified: run-owned Redis messages/results removed; mode remains test")
    return evidence


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--timeout-s", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        run(timeout_s=args.timeout_s)
    except Exception as exc:
        print(f"HMAC smoke failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
