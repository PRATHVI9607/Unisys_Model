#!/usr/bin/env python3
"""Helpers shared by deploy/scripts/realworld/*.sh and scale.py/soak.py. Every object lives in a khe-rw-* namespace.

Reuses deploy/scripts/evaluate.py (benign tool pods, attack pods, stream parsing, percentiles).
kubectl is pinned to the guard-verified context: KH_CTX from lib.sh, else this runs deploy/scripts/lib/guard.sh itself.
RW_DRY=1 (or --dry-run): nothing talks to a cluster; every kubectl call is printed and answers "".

CLI (JSON on stdout):
  benign --workload TOOL --ns SUFFIX   start one real benign tool pod (evaluate.py WORKLOADS)
  attack --ns SUFFIX --name POD [--node NODE] [--args "--num-files 400 ..."] [--deadline S]
  probe-loop --stop-file F --interval S --out FILE [--tag T]     one attack every S seconds until F exists
  snapshot --out FILE        state that must survive an upgrade;  diff A B  -> problems, exit 1 if any
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "deploy/scripts"))
import evaluate as ev  # noqa: E402

PREFIX = "khe-rw-"
KH = "kubeheal"
DRY = os.environ.get("RW_DRY") == "1"
SECRETS = ("kubeheal-redis", "kubeheal-admin", "kubeheal-contain-hmac", "kubeheal-approval-hmac")


def pin(force_context: str = "") -> str:
    ctx = os.environ.get("KH_CTX", "")
    if not ctx and not DRY:
        g = subprocess.run([str(ROOT / "deploy/scripts/lib/guard.sh"), *(["--force-context", force_context] if force_context else [])],
                           stdout=subprocess.PIPE, text=True)
        if g.returncode:
            sys.exit(2)
        ctx = g.stdout.strip()
    ev.KUBECTL[:] = ["kubectl", "--context", ctx]
    if DRY:
        def fake(*a, **kw):   # the same names evaluate.py uses (k, rc) now only print
            print("[dry-run] kubectl", *a[:8], file=sys.stderr)
            return ""
        ev.k = fake
    return ctx


def ns_ok(ns: str) -> str:
    if not ns.startswith(PREFIX):
        raise SystemExit(f"refusing namespace {ns!r}: must start with {PREFIX}")
    return ns


def mkns(ns: str) -> None:
    ev.mkns(ns_ok(ns))


def delete_ns(ns: str) -> None:
    ev.k("delete", "ns", ns_ok(ns), "--wait=false", check=False)


def cleanup_all() -> None:
    for ns in ev.k("get", "ns", "-o", "name", check=False).split():
        if ns.startswith(f"namespace/{PREFIX}"):
            ev.k("delete", ns, "--wait=false", check=False)
    ev.clear_keys(PREFIX)


def attack(ns: str, name: str, args: list[str] | None = None, node: str | None = None, deadline: float = 150) -> dict:
    """One sandboxed detection-test attack pod (deploy/chaos/): was it killed, how fast, did containment freeze it."""
    ns_ok(ns)
    mkns(ns)
    pod = ev.attack_pod(name, ns, args or ev.BENCH_ARGS)
    if node:
        pod["spec"]["nodeName"] = node
    t0 = ev.now_ms()
    out = {"ns": ns, "pod": name, "node": node, "t0": t0, "killed": False, "latency_s": None, "outcome": None, "containment": None}
    if DRY:
        return out
    ev.apply(pod)
    w = ev.watch_attack(ns, name, deadline)
    time.sleep(2)   # the action may land just after the pod disappears
    k = ev.kill_of(ev.actions(t0), ns, name, w["op"])
    out["op_ms"], out["gone"] = w["op"], w["gone"]
    if k:
        out.update(killed=True, outcome=k.get("outcome"), containment=k.get("containment"),
                   latency_s=(k["id"] - (w["op"] or t0)) / 1000, decision=k.get("decision"))
    out["node_actual"] = ev.k("get", "pod", name, "-n", ns, "-o", "jsonpath={.spec.nodeName}", check=False).strip() or node
    return out


def benign_start(workload: str, ns: str) -> None:
    mkns(ns)
    ev.apply(ev.work_pod(workload, ns_ok(ns)))


def used_memory() -> tuple[int, int]:
    """(used_memory, maxmemory) bytes of the KubeHeal Redis."""
    used = re.search(r"used_memory:(\d+)", ev.rc("INFO", "memory"))
    mx = ev.rc("CONFIG", "GET", "maxmemory").split()
    return (int(used.group(1)) if used else 0), (int(mx[1]) if len(mx) > 1 else 0)


def group_state(stream: str) -> dict[str, dict]:
    """XINFO GROUPS: {group: {pending, lag}} (lag is None when Redis cannot tell)."""
    out, cur = {}, None
    lines = ev.rc("XINFO", "GROUPS", stream).split("\n")
    for key, val in zip(lines[::2], lines[1::2], strict=False):
        if key == "name":
            cur = out.setdefault(val, {})
        elif cur is not None and key in ("pending", "lag"):
            cur[key] = int(val) if val.lstrip("-").isdigit() else None
    return out


def scrape(pod: str, port: int = 8080) -> str:
    return ev.k("get", "--raw", f"/api/v1/namespaces/{KH}/pods/{pod}:{port}/proxy/metrics", check=False)


def metric(text: str, name: str) -> float | None:
    vals = [float(m.group(1)) for m in re.finditer(rf"^{re.escape(name)}(?:{{[^}}]*}})? (\S+)$", text, re.M)]
    return sum(vals) if vals else None


def probe_loop(stop_file: str, interval: float, out: str, tag: str) -> None:
    """One attack every `interval` seconds (each in its own namespace and thread) until stop_file exists."""
    lock, threads, i = threading.Lock(), [], 0

    def one(n: int) -> None:
        r = attack(f"{PREFIX}{tag}-{n}", f"probe-{n}")
        with lock, open(out, "a") as f:
            f.write(json.dumps(r) + "\n")
        delete_ns(f"{PREFIX}{tag}-{n}")
    while not Path(stop_file).exists():
        i += 1
        t = threading.Thread(target=one, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        for _ in range(int(interval)):
            if Path(stop_file).exists():
                break
            time.sleep(1)
    for t in threads:
        t.join(timeout=200)


# ── upgrade state ────────────────────────────────────────────────────────────────────────────────
def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def snapshot(marker: str | None = None) -> dict:
    snap: dict = {"secrets": {}, "baselines": {}, "ts": ev.now_ms()}
    for s in SECRETS:
        raw = ev.k("get", "secret", s, "-n", KH, "-o", "json", check=False)
        if raw:
            j = json.loads(raw)
            snap["secrets"][s] = {"uid": j["metadata"]["uid"], "data": sha(json.dumps(j.get("data"), sort_keys=True))}
    pvc = ev.k("get", "pvc", "redis-data", "-n", KH, "-o", "jsonpath={.metadata.uid}", check=False)
    snap["pvc_uid"] = pvc.strip()
    for key in ev.rc("--scan", "--pattern", f"kubeheal:baseline:{PREFIX}*").split():
        snap["baselines"][key] = sha(ev.rc("GET", key))
    snap["mode"] = ev.rc("GET", "kubeheal:mode").strip()
    snap["pending_approvals"] = sorted(ev.rc("ZRANGE", "kubeheal:approvals:pending", "0", "-1").split())
    snap["marker"] = marker
    if marker:
        ev.rc("SET", f"kubeheal:rw-marker:{marker}", marker)
        ev.rc("XADD", "kubeheal.ledger", "*", "kind", "rw-marker", "actor", "rw-upgrade", "detail", marker)
    return snap


def diff(before: dict, after: dict) -> list[str]:
    bad = []
    for s, v in before["secrets"].items():
        if after["secrets"].get(s) != v:
            bad.append(f"secret {s} changed or vanished (must be reused, never regenerated)")
    if before["pvc_uid"] != after["pvc_uid"]:
        bad.append("redis PVC was replaced")
    for key, h in before["baselines"].items():
        if after["baselines"].get(key) != h:
            bad.append(f"baseline {key} lost or changed")
    if before["mode"] != after["mode"]:
        bad.append(f"runtime mode {before['mode']!r} -> {after['mode']!r}")
    m = before.get("marker")
    if m:
        if ev.rc("GET", f"kubeheal:rw-marker:{m}").strip() != m:
            bad.append("redis marker key lost (persistence broken)")
        if m not in ev.rc("XREVRANGE", "kubeheal.ledger", "+", "-", "COUNT", "5000"):
            bad.append("ledger marker entry lost")
    gone = set(before["pending_approvals"]) - set(after["pending_approvals"])
    if gone and ev.now_ms() - before["ts"] < 3_000_000:   # approvals expire after 1 h
        bad.append(f"pending approvals disappeared: {sorted(gone)[:5]}")
    return bad


def main() -> None:
    global DRY
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("attack")
    a.add_argument("--ns", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--node")
    a.add_argument("--args", default="")
    a.add_argument("--deadline", type=float, default=150)
    b = sub.add_parser("benign")
    b.add_argument("--workload", required=True)
    b.add_argument("--ns", required=True, help="suffix: the namespace becomes khe-rw-<ns>")
    p = sub.add_parser("probe-loop")
    p.add_argument("--stop-file", required=True)
    p.add_argument("--interval", type=float, default=20)
    p.add_argument("--out", required=True)
    p.add_argument("--tag", default="probe")
    s = sub.add_parser("snapshot")
    s.add_argument("--out", required=True)
    s.add_argument("--marker", default=None)
    d = sub.add_parser("diff")
    d.add_argument("before")
    d.add_argument("after", nargs="?", help="ignored: the after state is read live")
    sub.add_parser("cleanup")
    sub.add_parser("mem")
    ap.add_argument("--dry-run", action="store_true")
    n = ap.parse_args()
    DRY = DRY or n.dry_run
    pin()
    if n.cmd == "attack":
        print(json.dumps(attack(f"{PREFIX}{n.ns}", n.name, n.args.split() or None, n.node, n.deadline)))
    elif n.cmd == "benign":
        ev.DUR = 3600 * 6   # long-running: the script's trap deletes the namespace
        benign_start(n.workload, f"{PREFIX}{n.ns}")
    elif n.cmd == "probe-loop":
        probe_loop(n.stop_file, n.interval, n.out, n.tag)
    elif n.cmd == "snapshot":
        Path(n.out).write_text(json.dumps(snapshot(n.marker)))
    elif n.cmd == "diff":
        # the "after" state is read live; before is the saved snapshot
        bad = diff(json.loads(Path(n.before).read_text()), snapshot())
        print("\n".join(bad) or "state preserved")
        sys.exit(1 if bad else 0)
    elif n.cmd == "cleanup":
        cleanup_all()
    elif n.cmd == "mem":
        print(json.dumps(dict(zip(("used", "max"), used_memory(), strict=True))))


if __name__ == "__main__":
    random.seed()
    main()
