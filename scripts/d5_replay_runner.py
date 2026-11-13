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


def _kubectl(*args: str, input_text: Optional[str] = None, timeout_s: float = 30.0) -> str:
    """Run a context-pinned kubectl command and return stdout."""
    proc = subprocess.run(["kubectl", "--context", CONTEXT, *args], input=input_text, text=True,
                          capture_output=True, check=False, timeout=max(0.1, timeout_s))
    if proc.returncode:
        raise RuntimeError(f"kubectl {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


class BoundedKubectl:
    """Every subprocess shares one deadline; tests can inject the transport and monotonic clock."""

    def __init__(self, kubectl: Callable, clock: Callable[[], float], deadline: float):
        self.kubectl, self.clock, self.deadline = kubectl, clock, deadline

    def remaining(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("D-5 replay deadline reached")
        return remaining

    def __call__(self, *args: str, input_text: Optional[str] = None) -> str:
        return self.kubectl(*args, input_text=input_text, timeout_s=self.remaining())


def _rollout(call: BoundedKubectl) -> None:
    remaining = call.remaining()
    rollout_s = max(1, int(remaining) - 1)
    call("-n", NAMESPACE, "rollout", "status", "daemonset/" + DAEMONSET,
         "--timeout=" + str(rollout_s) + "s")


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
                        # Strategic-merge deletion of volumeMounts requires its Kubernetes merge key,
                        # mountPath. Omitting it makes cleanup fail and leaves the DaemonSet mounted.
                        "volumeMounts": [{"name": VOLUME, "mountPath": MOUNT_PATH,
                                          "$patch": "delete"}]}],
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
    """Run one replay under a total deadline, reserving time for guaranteed cleanup attempts."""
    if timeout_s < 12:
        raise ValueError("--timeout-s must be at least 12 seconds (includes cleanup reserve)")
    start = clock()
    deadline = start + timeout_s
    cleanup_reserve = min(30.0, max(5.0, timeout_s * 0.25))
    call = BoundedKubectl(kubectl, clock, deadline - cleanup_reserve)

    mode = _json(call, "-n", NAMESPACE, "get", "configmap", "kubeheal-mode", "-o", "json")
    if (mode.get("data") or {}).get("mode") != "test":
        raise RuntimeError("refusing D-5 replay unless kubeheal-mode is already test")

    # Select only the explicitly watched demo victim. Scripted F5/F10 Deployments
    # use the same image/name label but must never be targets for D-5 replay.
    target_list = _json(call, "-n", "prod", "get", "pods", "-l",
                        "app.kubernetes.io/name=victim-app,kubeheal.io/scripted!=F10", "-o", "json")
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

    ds = _json(call, "-n", NAMESPACE, "get", "daemonset", DAEMONSET, "-o", "json")
    original_env = _env_map(ds)
    if original_env.get("FALCO_MODE", {}).get("value") != "auto":
        raise RuntimeError("refusing replay unless the Security Agent FALCO_MODE is auto")
    template_spec = ds["spec"]["template"]["spec"]
    names = {v.get("name") for v in template_spec.get("volumes", [])}
    agent = next(c for c in template_spec["containers"] if c.get("name") == CONTAINER)
    mounts = {v.get("name") for v in agent.get("volumeMounts", [])}
    if VOLUME in names or VOLUME in mounts:
        raise RuntimeError(f"temporary replay volume name already exists: {VOLUME}")

    run_id = uuid.uuid4().hex
    configmap = f"kubeheal-d5-replay-{run_id}"
    temp_path = None
    configmap_created = False
    configmap_create_attempted = False
    patch_attempted = False
    started_ms = int(time.time() * 1000)
    result = None
    cleanup_errors = []
    restore_ok = False
    try:
        raw_fixture = fixture.read_text(encoding="utf-8")
        adapted = adapt_trace(raw_fixture, namespace, pod, pod_uid, node, container_id)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False) as f:
            f.write(adapted)
            temp_path = f.name
        generated = json.loads(call("-n", NAMESPACE, "create", "configmap", configmap,
                                    "--from-file=trace.jsonl=" + temp_path, "--dry-run=client", "-o", "json"))
        generated.setdefault("metadata", {}).setdefault("labels", {}).update({
            "app.kubernetes.io/managed-by": "kubeheal-d5-replay", "kubeheal.io/d5-replay-id": run_id,
        })
        configmap_create_attempted = True
        call("-n", NAMESPACE, "create", "-f", "-", input_text=json.dumps(generated, separators=(",", ":")))
        configmap_created = True

        # Re-read immediately before enabling replay. The first read is only an early refusal; this one closes
        # the time gap while the unique ConfigMap was created.
        mode = _json(call, "-n", NAMESPACE, "get", "configmap", "kubeheal-mode", "-o", "json")
        if (mode.get("data") or {}).get("mode") != "test":
            raise RuntimeError("refusing to enable replay because kubeheal-mode is no longer test")

        patch_attempted = True
        call("-n", NAMESPACE, "patch", "daemonset", DAEMONSET, "--type=strategic",
             "-p", json.dumps(_replay_patch(configmap, node), separators=(",", ":")))
        _rollout(call)

        while clock() < call.deadline:
            pods = _json(call, "-n", NAMESPACE, "get", "pods", "-l", "app=security-agent", "-o", "json")
            agent_pod = next((p for p in pods.get("items", [])
                              if (p.get("spec") or {}).get("nodeName") == node
                              and (p.get("status") or {}).get("phase") == "Running"), None)
            if agent_pod:
                read = call("-n", NAMESPACE, "exec", agent_pod["metadata"]["name"], "-c", CONTAINER,
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
            sleep(min(2.0, max(0.0, call.deadline - clock())))
        if result is None:
            raise TimeoutError("timed out waiting for a replay Security event and matching Fusion action")
    finally:
        call.deadline = deadline
        if patch_attempted:
            try:
                call("-n", NAMESPACE, "patch", "daemonset", DAEMONSET, "--type=strategic",
                     "-p", json.dumps(_restore_patch(original_env), separators=(",", ":")))
                _rollout(call)
                restored_ds = _json(call, "-n", NAMESPACE, "get", "daemonset", DAEMONSET, "-o", "json")
                restored_env = _env_map(restored_ds)
                restored_spec = restored_ds["spec"]["template"]["spec"]
                restored_agent = next(c for c in restored_spec["containers"] if c.get("name") == CONTAINER)
                if any(restored_env.get(name) != original_env.get(name)
                       for name in ("FALCO_MODE", "FALCO_REPLAY_PATH", "FALCO_REPLAY_NODE")) \
                        or VOLUME in {v.get("name") for v in restored_spec.get("volumes", [])} \
                        or VOLUME in {v.get("name") for v in restored_agent.get("volumeMounts", [])}:
                    raise RuntimeError("DaemonSet configuration does not match the captured original")
                restore_ok = True
            except Exception as e:
                cleanup_errors.append(f"restore DaemonSet: {e}")
        if configmap_create_attempted and not configmap_created:
            # A client-side timeout can happen after the API server accepted create. Recover only an object
            # carrying this invocation's random ownership label; never delete a same-name collision.
            try:
                raw_cm = call("-n", NAMESPACE, "get", "configmap", configmap,
                              "--ignore-not-found=true", "-o", "json")
                if raw_cm.strip():
                    existing_cm = json.loads(raw_cm)
                    labels = (existing_cm.get("metadata") or {}).get("labels") or {}
                    configmap_created = labels.get("kubeheal.io/d5-replay-id") == run_id
            except Exception as e:
                cleanup_errors.append(f"check ownership of possibly created ConfigMap: {e}")
        if configmap_created and (not patch_attempted or restore_ok):
            try:
                call("-n", NAMESPACE, "delete", "configmap", configmap)
            except Exception as e:
                cleanup_errors.append(f"delete temporary ConfigMap: {e}")
        elif configmap_created and patch_attempted and not restore_ok:
            cleanup_errors.append(f"preserved mounted ConfigMap {configmap} because DaemonSet restore did not complete")
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        if cleanup_errors:
            restore_json = json.dumps(_restore_patch(original_env), separators=(",", ":"))
            recovery = (f"Manual recovery for context {CONTEXT}: restore `FALCO_MODE=auto`, remove replay env/volume "
                        f"from daemonset/{DAEMONSET} with this strategic patch: {restore_json}; then wait for "
                        f"`kubectl --context {CONTEXT} -n {NAMESPACE} rollout status daemonset/{DAEMONSET}`. "
                        f"Only after restoration succeeds, delete ConfigMap {configmap}.")
            raise RuntimeError("D-5 cleanup failed: " + "; ".join(cleanup_errors) + ". " + recovery)

    final_mode = _json(call, "-n", NAMESPACE, "get", "configmap", "kubeheal-mode", "-o", "json")
    if (final_mode.get("data") or {}).get("mode") != "test":
        raise RuntimeError("kubeheal-mode changed during replay; expected test")
    final_ds = _json(call, "-n", NAMESPACE, "get", "daemonset", DAEMONSET, "-o", "json")
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
    leftover = call("-n", NAMESPACE, "get", "configmap", configmap, "--ignore-not-found=true", "-o", "name")
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
