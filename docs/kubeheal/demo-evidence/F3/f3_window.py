"""F3 scripted containment window on a scratch Deployment (context k3d-kubeheal only).

    python docs/kubeheal/demo-evidence/F3/f3_window.py prep       # test mode: scratch objects, clean files, pre-T0 snapshot
    python docs/kubeheal/demo-evidence/F3/f3_window.py rehearse   # test mode: inject the alert, expect "would have" entries
    python docs/kubeheal/demo-evidence/F3/f3_window.py window     # ONE enforce window, mode forced back to test in `finally`
    python docs/kubeheal/demo-evidence/F3/f3_window.py cleanup    # delete the scratch objects (staging, f3-scratch*)

What is real and what is scripted (read before trusting the output):
  * The alert is NOT a Falco capture and NOT produced by the Security Agent in this window. Falco is not installed
    and the /proc-only path cannot produce a model score (no syscall window), so no real non-replay alert exists on
    this cluster. The script publishes ONE Security event on kubeheal.security.events whose model fields (label,
    risk, prediction set, top factors, model version) are copied from the event the real Security Agent published
    for the hand-written D-5 fixture scored by the real inference service. Identity (namespace, pod, uid, owner),
    timestamps and T0 are those of the scratch pod. `syscall_source` is `scripted_window`, never `replay`.
  * Everything after that is the real chain: Fusion decision, kubeheal.exec, Executor intake and every step.
  * The scratch Deployment is in `staging`: the dev tier multiplier (0.70) cannot reach the 0.85 auto-contain
    threshold with a 0.95 risk, staging (1.00) can.
  * The rolling snapshot taken before T0 is created by this script with the manifest the Executor's scheduler uses
    (agents.executor.snapshots.volume_snapshot), because the scheduler only writes in enforce mode.
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from agents.executor.snapshots import KIND_ROLLING, volume_snapshot   # noqa: E402

CTX, KH = "k3d-kubeheal", "kubeheal"
NS = "staging"
NAME = os.environ.get("F3_NAME", "f3-scratch")      # a new name per attempt: stale SnapshotFreeze keys are per PVC
PVC = f"{NAME}-data"
RUN_LABEL = "kubeheal.io/f3-run"
SNAP_CLASS = "csi-hostpath-snapclass"
IMAGE_SRC = ("dev", "victim-app")                 # reuse the image already pulled from the cluster registry
SOURCE_EVENT = "sec-20261112-135158-892771-victim-app-b4b79986f-rcfvq"     # real, model-scored, D-5 rerun
STREAM_SEC, STREAM_ACTIONS, STREAM_EXEC, STREAM_ESC = ("kubeheal.security.events", "kubeheal.actions",
                                                       "kubeheal.exec", "kubeheal.escalations")
WINDOW_MAX_S = 300           # hard bound on how long the chain is waited for inside the window


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def say(msg):
    print(f"[{ts()}] {msg}", flush=True)


def kc(*args, ns=None, inp=None, check=True):
    cmd = ["kubectl", "--context", CTX] + (["-n", ns] if ns else []) + list(args)
    r = subprocess.run(cmd, input=inp, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd[:6])}... failed: {r.stderr.strip()[:400]}")
    return r.stdout.strip()


def redis(*args):
    return kc("exec", "redis-0", "--", "redis-cli", *args, ns=KH)


def mode():
    return kc("get", "cm", "kubeheal-mode", "-o", "jsonpath={.data.mode}", ns=KH)


def set_mode(value):
    kc("patch", "cm", "kubeheal-mode", "--type", "merge", "-p", json.dumps({"data": {"mode": value}}), ns=KH)
    say(f"kubeheal-mode patched to {value}; read back: {mode()}")


def scratch_pod():
    out = kc("get", "pod", "-l", f"app={NAME}", "-o", "json", ns=NS)
    items = [p for p in json.loads(out)["items"] if p["status"].get("phase") == "Running"
             and not p["metadata"].get("deletionTimestamp")]
    if len(items) != 1:
        raise RuntimeError(f"expected one running scratch pod, found {len(items)}")
    return items[0]["metadata"]["name"], items[0]["metadata"]["uid"]


def prep():
    assert mode() == "test", "prep runs in test mode"
    image = kc("get", "deploy", IMAGE_SRC[1], "-o", "jsonpath={.spec.template.spec.containers[0].image}", ns=IMAGE_SRC[0])
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": PVC, "namespace": NS, "labels": {"app": NAME, RUN_LABEL: NAME}},
           "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "csi-hostpath-sc",
                    "resources": {"requests": {"storage": "64Mi"}}}}
    dep = {"apiVersion": "apps/v1", "kind": "Deployment",
           "metadata": {"name": NAME, "namespace": NS, "labels": {"app": NAME, RUN_LABEL: NAME}},
           "spec": {"replicas": 1, "selector": {"matchLabels": {"app": NAME}},
                    "template": {"metadata": {"labels": {"app": NAME, RUN_LABEL: NAME}},
                                 "spec": {"securityContext": {"runAsUser": 10001, "runAsGroup": 10001,
                                                              "fsGroup": 10001, "runAsNonRoot": True},
                                          "containers": [{
                                              "name": "app", "image": image,
                                              "command": ["sh", "-c", "sleep 100000"],
                                              "securityContext": {"allowPrivilegeEscalation": False,
                                                                  "capabilities": {"drop": ["ALL"]},
                                                                  "readOnlyRootFilesystem": True},
                                              "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                            "limits": {"cpu": "100m", "memory": "64Mi"}},
                                              "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                                          "volumes": [{"name": "data",
                                                       "persistentVolumeClaim": {"claimName": PVC}}]}}}}
    for obj in (pvc, dep):
        say(kc("apply", "-f", "-", inp=json.dumps(obj)))
    kc("rollout", "status", f"deploy/{NAME}", "--timeout=180s", ns=NS)
    pod, uid = scratch_pod()
    say(f"scratch pod {pod} uid {uid}")
    kc("exec", pod, "--", "sh", "-c",
       "for i in 1 2 3 4 5; do echo \"clean file $i\" > /data/clean_$i.txt; done; sync; ls -l /data", ns=NS)
    snap = f"kubeheal-roll-{PVC}-{int(time.time())}"
    say(kc("apply", "-f", "-", inp=json.dumps(volume_snapshot(
        snap, NS, PVC, SNAP_CLASS, KIND_ROLLING, {RUN_LABEL: NAME}))))
    for _ in range(60):
        if kc("get", "volumesnapshot", snap, "-o", "jsonpath={.status.readyToUse}", ns=NS, check=False) == "true":
            break
        time.sleep(2)
    else:
        raise RuntimeError("snapshot never became ready")
    say(f"snapshot {snap} readyToUse; creationTime "
        f"{kc('get', 'volumesnapshot', snap, '-o', 'jsonpath={.status.creationTime}', ns=NS)}")
    say(kc("get", "deploy,pod,pvc,volumesnapshot", "-o", "wide", ns=NS))


def inject(t0_ms, pid_target):
    pod, uid = scratch_pod()
    raw = redis("HGETALL", f"kubeheal:security:{SOURCE_EVENT}").splitlines()
    ev = dict(zip(raw[0::2], raw[1::2]))
    assert ev.get("model_scored") == "true" and ev.get("sec_label") == "ransomware", "source event not usable"
    now_ms = int(time.time() * 1000)
    ev.update({
        "event_id": f"sec-f3-{now_ms}-{NAME}", "namespace": NS, "namespace_tier": "staging", "pod_name": pod,
        "deployment": NAME, "workload_kind": "Deployment", "owner_resolved": "true", "pod_uid": uid,
        "pid_target": str(pid_target), "timestamp_ms": str(now_ms), "t0_ms": str(t0_ms),
        "window_start_ms": str(t0_ms), "window_end_ms": str(now_ms), "syscall_source": "scripted_window",
        "injected_by": f"f3_window.py; model fields copied from {SOURCE_EVENT} (hand-written fixture, not Falco)"})
    ev.pop("dry_run", None)
    args = ["XADD", STREAM_SEC, "*"]
    for k, v in ev.items():
        args += [k, v]
    say(f"publishing scripted alert {ev['event_id']} for {NS}/{pod} (T0 {t0_ms}, "
        f"risk {ev['sec_risk']}, set {ev['sec_prediction_set']}, source model {ev['model_version']})")
    say(f"XADD id {redis(*args)}")
    return ev["event_id"], pod


def incident_entries(event_id, since_ms):
    """Entries of kubeheal.actions newer than since_ms that target the scratch workload."""
    rows = json.loads(redis("--json", "XRANGE", STREAM_ACTIONS, str(since_ms), "+") or "[]")
    entries = []
    for entry_id, flat in rows:
        e = dict(zip(flat[0::2], flat[1::2]))
        e["_id"] = entry_id
        if NAME in e.get("target", "") or NAME in e.get("incident_id", ""):
            entries.append(e)
    return entries


def escalations_since(since_ms):
    rows = json.loads(redis("--json", "XRANGE", STREAM_ESC, str(since_ms), "+") or "[]")
    out = []
    for _id, flat in rows:
        e = dict(zip(flat[0::2], flat[1::2]))
        if NAME in json.dumps(e):
            out.append(e)
    return out


def wait_for_chain(since_ms, stop_actions, timeout_s):
    """Poll the action and escalation streams. Returns (seen, reason). Stops on the first of: a stop action
    (executed_restore, or executed_contain with an outcome other than exactly `contained`), an escalation for the
    scratch workload, or the timeout."""
    seen, reported_esc = {}, set()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for e in incident_entries(None, since_ms):
            key = (e.get("action_type"), e.get("outcome", "")[:60])
            if key not in seen:
                seen[key] = ts()
                say(f"action stream: {e.get('action_type')} incident={e.get('incident_id')} "
                    f"outcome={e.get('outcome', '')[:200]} dry_run={e.get('dry_run', '')}")
            kind, outcome = e.get("action_type"), e.get("outcome", "")
            if kind == "executed_restore":
                return seen, f"executed_restore: {outcome[:120]}"
            if kind == "executed_contain" and outcome != "contained" and not outcome.startswith("DRY RUN"):
                return seen, f"executed_contain ended with {outcome[:120]}"
            if kind == "executed_contain" and outcome.startswith("DRY RUN") and "executed_contain" in stop_actions:
                return seen, "executed_contain dry run"
        for esc in escalations_since(since_ms):
            if json.dumps(esc) not in reported_esc:
                reported_esc.add(json.dumps(esc))
                say(f"ESCALATION: {esc.get('reason', '')[:300]}")
                return seen, "escalation"
        time.sleep(4)
    return seen, "timeout"


def rehearse():
    assert mode() == "test"
    t0 = int(time.time() * 1000)
    since = t0 - 1000
    ev_id, pod = inject(t0, 4242)
    _, why = wait_for_chain(since, ("executed_contain",), 90)
    say(f"rehearsal ended: {why}")
    say(f"mode after rehearsal: {mode()}")


def pods_of(selector, ns=KH):
    return json.loads(kc("get", "pod", "-l", selector, "-o", "json", ns=ns))["items"]


def mode_seen_everywhere(since_s=40, timeout_s=20):
    """True when both Fusion pods, the Executor and the node Security Agent of the scratch pod log the switch."""
    node = kc("get", "pod", scratch_pod()[0], "-o", "jsonpath={.spec.nodeName}", ns=NS)
    targets = [p["metadata"]["name"] for sel in ("app=fusion-agent", "app=executor") for p in pods_of(sel)]
    targets += [p["metadata"]["name"] for p in pods_of("app=security-agent") if p["spec"]["nodeName"] == node]
    pending = set(targets)
    deadline = time.time() + timeout_s
    while pending and time.time() < deadline:
        for name in sorted(pending):
            logs = kc("logs", name, f"--since={since_s}s", ns=KH, check=False)
            if "-> enforce" in logs:
                say(f"mode switch seen in {name}")
                pending.discard(name)
        time.sleep(2)
    if pending:
        say(f"mode switch NOT seen in: {sorted(pending)}")
    return not pending


def window():
    assert mode() == "test", "the window must start from test"
    pod, uid = scratch_pod()
    start = ts()
    start_ms = int(time.time() * 1000)
    say(f"=== ENFORCE WINDOW START {start} ===")
    try:
        set_mode("enforce")
        if not mode_seen_everywhere():
            say("ABORT: a component did not pick up enforce; returning to test without sending the alert")
            return
        t0 = int(time.time() * 1000)
        say(f"T0 (attack onset) {t0}: writing high-entropy .locked files into /data of {pod}")
        say(kc("exec", pod, "--", "sh", "-c",
               "for i in 1 2 3 4 5 6 7 8; do head -c 32768 /dev/urandom > /data/doc_$i.locked; done; "
               "echo 'your files are encrypted' > /data/README_RANSOM.txt; sync; ls -l /data", ns=NS))
        ev_id, pod_now = inject(t0, 4243)
        seen, why = wait_for_chain(start_ms, ("executed_restore",), WINDOW_MAX_S)
        say(f"chain wait ended: {why}")
        time.sleep(5)            # let the last ledger writes land
    finally:
        set_mode("test")
        end = ts()
        say(f"=== ENFORCE WINDOW END {end}; mode now {mode()} ===")
    say(f"WINDOW {start} -> {end}")


def cleanup():
    """Delete only this run's labelled objects and resources owned by its incident IDs.

    Every selected object is inspected for its unique run or incident label before deletion. No namespace-wide
    prefix cleanup is allowed; resources with unrelated labels or names are left alone.
    """
    assert mode() == "test"
    rows = json.loads(redis("--json", "XRANGE", STREAM_ACTIONS, "-", "+") or "[]")
    incident_ids = set()
    for _stream_id, flat in rows:
        fields = dict(zip(flat[0::2], flat[1::2]))
        if NAME in fields.get("target", "") or NAME in fields.get("incident_id", ""):
            if fields.get("incident_id"):
                incident_ids.add(fields["incident_id"])
    rows = json.loads(redis("--json", "XRANGE", STREAM_ESC, "-", "+") or "[]")
    for _stream_id, flat in rows:
        fields = dict(zip(flat[0::2], flat[1::2]))
        if fields.get("deployment") == NAME and fields.get("namespace") == NS and fields.get("incident_id"):
            incident_ids.add(fields["incident_id"])

    def labelled_names(kind, selector):
        raw = kc("get", kind, "-l", selector, "-o", "json", ns=NS)
        items = json.loads(raw).get("items", [])
        names = []
        for item in items:
            meta = item.get("metadata") or {}
            labels = meta.get("labels") or {}
            if labels.get(RUN_LABEL) == NAME or labels.get("kubeheal/incident") in incident_ids:
                names.append(meta["name"])
        return names

    targets = []
    for kind in ("deployment", "pvc", "volumesnapshot"):
        targets.extend((kind, name) for name in labelled_names(kind, f"{RUN_LABEL}={NAME}"))
    for incident_id in sorted(incident_ids):
        selector = f"kubeheal/incident={incident_id}"
        for kind in ("job", "networkpolicy", "pvc", "volumesnapshot"):
            targets.extend((kind, name) for name in labelled_names(kind, selector))
    targets = sorted(set(targets))
    if not targets:
        raise SystemExit(f"ABORT: no resources carry this run's ownership labels ({RUN_LABEL}={NAME})")
    say("verified run-owned cleanup targets: " + json.dumps(targets))
    for kind, name in targets:
        say(kc("delete", kind, name, "--ignore-not-found", ns=NS))
    say("after cleanup: " + kc("get", "deployment,pod,job,pvc,volumesnapshot,networkpolicy", "-o", "wide", ns=NS))


if __name__ == "__main__":
    {"prep": prep, "rehearse": rehearse, "window": window, "cleanup": cleanup}[sys.argv[1]]()
