"""Mode-test-only runner for a one-shot D-5 Falco replay through Security Agent and Fusion.

The source trace is a hand-written fixture, not a captured Falco log. The runner reads the current prod victim Pod,
rewrites its namespace/name/UID/node identity into a temporary ConfigMap, temporarily mounts that trace on the
Security Agent node that hosts the victim, and restores the original DaemonSet settings in `finally`.
Every kubectl invocation is pinned to `k3d-kubeheal`; the kill switch is only read and must already be `test`.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = "k3d-kubeheal"
NAMESPACE = "kubeheal"
DAEMONSET = "security-agent"
CONTAINER = "agent"
VOLUME = "d5-replay-trace"
MOUNT_PATH = "/var/run/kubeheal-replay"
TRACE_PATH = MOUNT_PATH + "/trace.jsonl"
FIXTURE = ROOT / "tests" / "fixtures" / "falco" / "ransomware_pv_encrypt_new_rules.jsonl"

_READ_REDIS = (
    "import json,os,redis; r=redis.Redis.from_url(os.environ['REDIS_URL']); "
    "d=lambda x: x.decode() if isinstance(x,bytes) else str(x); "
    "read=lambda s:[{d(k):d(v) for k,v in row.items()} for _,row in r.xrevrange(s,count=500)]; "
    "print(json.dumps({'security':read('kubeheal.security.events'),'actions':read('kubeheal.actions')}))"
)


def _kubectl(*args: str, input_text: Optional[str] = None) -> str:
    """Run a context-pinned kubectl command and return stdout."""
    proc = subprocess.run(["kubectl", "--context", CONTEXT, *args], input=input_text, text=True,
                          capture_output=True, check=False, timeout=180)
    if proc.returncode:
        raise RuntimeError(f"kubectl {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def adapt_trace(raw: str, namespace: str, pod: str, pod_uid: str, node: str,
                container_id: str = "") -> str:
    """Adapt target identity only; preserve the hand-written event sequence and its original times/PID."""
    lines = []
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            lines.append(line)
            continue
        event = json.loads(line)
        fields = event.setdefault("output_fields", {})
        fields["k8s.ns.name"] = namespace
        fields["k8s.pod.name"] = pod
        fields["k8s.pod.uid"] = pod_uid
        if container_id:
            fields["container.id"] = container_id
        event["hostname"] = node
        lines.append(json.dumps(event, separators=(",", ":"), sort_keys=True))
    return "\n".join(lines) + "\n"


def _json(kubectl: Callable, *args: str) -> Dict:
    return json.loads(kubectl(*args))


def _env_map(ds: Dict) -> Dict[str, Dict]:
    containers = ds["spec"]["template"]["spec"]["containers"]
    agent = next((c for c in containers if c.get("name") == CONTAINER), None)
    if agent is None:
        raise RuntimeError("Security Agent DaemonSet has no 'agent' container")
    return {e["name"]: e for e in agent.get("env", [])}


def _restore_patch(original_env: Dict[str, Dict]) -> Dict:
    env = []
    for name in ("FALCO_MODE", "FALCO_REPLAY_PATH", "FALCO_REPLAY_NODE"):
        env.append(dict(original_env[name]) if name in original_env else {"name": name, "$patch": "delete"})
    return {"spec": {"template": {"spec": {
        "volumes": [{"name": VOLUME, "$patch": "delete"}],
        "containers": [{"name": CONTAINER, "env": env,
                        "volumeMounts": [{"name": VOLUME, "$patch": "delete"}]}],
    }}}}


def _replay_patch(configmap: str, node: str) -> Dict:
    return {"spec": {"template": {"spec": {
        "volumes": [{"name": VOLUME, "configMap": {"name": configmap}}],
        "containers": [{"name": CONTAINER,
                        "env": [{"name": "FALCO_MODE", "value": "replay"},
                                {"name": "FALCO_REPLAY_PATH", "value": TRACE_PATH},
                                {"name": "FALCO_REPLAY_NODE", "value": node}],
                        "volumeMounts": [{"name": VOLUME, "mountPath": MOUNT_PATH, "readOnly": True}]}],
    }}}}


def _event_rows(raw: str) -> Tuple[list, list]:
    data = json.loads(raw)
    return data.get("security", []), data.get("actions", [])


def _targets_action(row: Dict, namespace: str, pod: str) -> bool:
    try:
        target = json.loads(row.get("target", "{}"))
    except (TypeError, json.JSONDecodeError):
        return False
    return target.get("namespace") == namespace and target.get("pod") == pod


def run(kubectl: Callable = _kubectl, sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic, timeout_s: int = 120,
        fixture: Path = FIXTURE) -> Dict:
    """Run one replay and return its Security event and Fusion action; always restore the DaemonSet and ConfigMap."""
    mode = _json(kubectl, "-n", NAMESPACE, "get", "configmap", "kubeheal-mode", "-o", "json")
    if (mode.get("data") or {}).get("mode") != "test":
        raise RuntimeError("refusing D-5 replay unless kubeheal-mode is already test")

    target_list = _json(kubectl, "-n", "prod", "get", "pods", "-l", "app.kubernetes.io/name=victim-app", "-o", "json")
    candidates = [p for p in target_list.get("items", []) if (p.get("status") or {}).get("phase") == "Running"]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one Running prod victim-app pod, found {len(candidates)}")
    target = candidates[0]
    meta, spec = target.get("metadata") or {}, target.get("spec") or {}
    namespace, pod, pod_uid, node = meta.get("namespace"), meta.get("name"), meta.get("uid"), spec.get("nodeName")
    if namespace != "prod" or not all((pod, pod_uid, node)):
        raise RuntimeError("prod victim pod is missing namespace, name, UID, or node")
    statuses = target.get("status", {}).get("containerStatuses") or []
    container_id = (statuses[0].get("containerID", "").split("//", 1)[-1] if statuses else "")

    ds = _json(kubectl, "-n", NAMESPACE, "get", "daemonset", DAEMONSET, "-o", "json")
    original_env = _env_map(ds)
    if original_env.get("FALCO_MODE", {}).get("value") != "auto":
        raise RuntimeError("refusing replay unless the Security Agent FALCO_MODE is auto")
    template_spec = ds["spec"]["template"]["spec"]
    names = {v.get("name") for v in template_spec.get("volumes", [])}
    agent = next(c for c in template_spec["containers"] if c.get("name") == CONTAINER)
    mounts = {v.get("name") for v in agent.get("volumeMounts", [])}
    if VOLUME in names or VOLUME in mounts:
        raise RuntimeError(f"temporary replay volume name already exists: {VOLUME}")

    configmap = f"kubeheal-d5-replay-{uuid.uuid4().hex[:8]}"
    temp_path = None
    configmap_attempted = False
    patch_attempted = False
    started_ms = int(time.time() * 1000)
    result = None
    cleanup_errors = []
    try:
        raw_fixture = fixture.read_text(encoding="utf-8")
        adapted = adapt_trace(raw_fixture, namespace, pod, pod_uid, node, container_id)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False) as f:
            f.write(adapted)
            temp_path = f.name
        yaml = kubectl("-n", NAMESPACE, "create", "configmap", configmap,
                       "--from-file=trace.jsonl=" + temp_path, "--dry-run=client", "-o", "yaml")
        configmap_attempted = True
        kubectl("-n", NAMESPACE, "apply", "-f", "-", input_text=yaml)
        patch_attempted = True
        kubectl("-n", NAMESPACE, "patch", "daemonset", DAEMONSET, "--type=strategic",
                "-p", json.dumps(_replay_patch(configmap, node), separators=(",", ":")))
        kubectl("-n", NAMESPACE, "rollout", "status", "daemonset/" + DAEMONSET, "--timeout=180s")

        deadline = clock() + timeout_s
        while clock() < deadline:
            pods = _json(kubectl, "-n", NAMESPACE, "get", "pods", "-l", "app=security-agent", "-o", "json")
            agent_pod = next((p for p in pods.get("items", [])
                              if (p.get("spec") or {}).get("nodeName") == node
                              and (p.get("status") or {}).get("phase") == "Running"), None)
            if agent_pod:
                read = kubectl("-n", NAMESPACE, "exec", agent_pod["metadata"]["name"], "-c", CONTAINER,
                               "--", "python", "-c", _READ_REDIS)
                security, actions = _event_rows(read)
                security = [r for r in security if r.get("namespace") == namespace and r.get("pod_name") == pod
                            and r.get("syscall_source") == "replay" and int(r.get("timestamp_ms", "0") or 0) >= started_ms]
                actions = [r for r in actions if _targets_action(r, namespace, pod)
                           and int(r.get("timestamp_ms", "0") or 0) >= started_ms]
                event = security[-1] if security else None
                action = actions[-1] if actions else None
                if event and action:
                    if action.get("dry_run") != "true":
                        raise RuntimeError("Fusion action for replay event was not marked dry_run=true")
                    result = {"target": {"namespace": namespace, "pod": pod, "pod_uid": pod_uid, "node": node},
                              "security_event": event, "fusion_action": action}
                    break
            sleep(2)
        if result is None:
            raise TimeoutError("timed out waiting for a replay Security event and matching Fusion action")
    finally:
        if patch_attempted:
            try:
                kubectl("-n", NAMESPACE, "patch", "daemonset", DAEMONSET, "--type=strategic",
                        "-p", json.dumps(_restore_patch(original_env), separators=(",", ":")))
                kubectl("-n", NAMESPACE, "rollout", "status", "daemonset/" + DAEMONSET, "--timeout=180s")
            except Exception as e:
                cleanup_errors.append(f"restore DaemonSet: {e}")
        if configmap_attempted:
            try:
                kubectl("-n", NAMESPACE, "delete", "configmap", configmap, "--ignore-not-found=true")
            except Exception as e:
                cleanup_errors.append(f"delete temporary ConfigMap: {e}")
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        if cleanup_errors:
            raise RuntimeError("D-5 cleanup failed: " + "; ".join(cleanup_errors))

    final_mode = _json(kubectl, "-n", NAMESPACE, "get", "configmap", "kubeheal-mode", "-o", "json")
    if (final_mode.get("data") or {}).get("mode") != "test":
        raise RuntimeError("kubeheal-mode changed during replay; expected test")
    final_ds = _json(kubectl, "-n", NAMESPACE, "get", "daemonset", DAEMONSET, "-o", "json")
    final_env = _env_map(final_ds)
    if final_env.get("FALCO_MODE", {}).get("value") != "auto" or any(
            final_env.get(name) != original_env.get(name)
            for name in ("FALCO_MODE", "FALCO_REPLAY_PATH", "FALCO_REPLAY_NODE")):
        raise RuntimeError("Security Agent replay configuration was not fully restored")
    final_spec = final_ds["spec"]["template"]["spec"]
    final_agent = next(c for c in final_spec["containers"] if c.get("name") == CONTAINER)
    if VOLUME in {v.get("name") for v in final_spec.get("volumes", [])} \
            or VOLUME in {v.get("name") for v in final_agent.get("volumeMounts", [])}:
        raise RuntimeError("temporary replay volume was not removed")
    leftover = kubectl("-n", NAMESPACE, "get", "configmap", configmap, "--ignore-not-found=true", "-o", "name")
    if leftover.strip():
        raise RuntimeError("temporary replay ConfigMap was not deleted")
    if result is None:
        raise RuntimeError("D-5 replay completed without event evidence")
    print("Security event: " + json.dumps(result["security_event"], sort_keys=True))
    print("Fusion action: " + json.dumps(result["fusion_action"], sort_keys=True))
    print("Cleanup verified: FALCO_MODE=auto, replay mount removed, kill switch remains test")
    return result


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--timeout-s", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        run(timeout_s=args.timeout_s)
    except Exception as e:
        print(f"D-5 replay failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
