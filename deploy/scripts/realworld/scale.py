#!/usr/bin/env python3
"""Scale and churn test: 200+ Deployments / 300+ pods over 20 namespaces of pause containers, then a rollout every
few seconds. Measures health-agent memory/CPU, Redis memory, fusion lag and end-to-end event lag, and asserts that
no limit is hit. Needs metrics-server (`kubectl top`).

  python3 deploy/scripts/realworld/scale.py [--namespaces 20] [--deployments 200] [--pods 300] [--churn-seconds 300]
        [--churn-interval 3] [--image registry.k8s.io/pause:3.10] [--out DIR] [--dry-run] [--force-context NAME]

Cluster guard: runs deploy/scripts/lib/guard.sh (minikube / k3d-kubeheal). Everything lives in khe-rw-scale-NN
namespaces; the finally block deletes them and their Redis keys. Duration: ~5 min create + --churn-seconds + ~2 min settle.
These pods are benign: any AUTO_KILL / AUTO_PATCH on them fails the run.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path

import rwlib
from rwlib import PREFIX, ev

NS = PREFIX + "scale-"


def deployment(ns: str, name: str, replicas: int, image: str) -> dict:
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": ns, "labels": {"rw-scale": "1"}},
            "spec": {"replicas": replicas, "selector": {"matchLabels": {"app": name}},
                     "template": {"metadata": {"labels": {"app": name, "rw-scale": "1"}},
                                  "spec": {"terminationGracePeriodSeconds": 0,
                                           "containers": [{"name": "c", "image": image, "imagePullPolicy": "IfNotPresent",
                                                           "env": [{"name": "CHURN", "value": "0"}],
                                                           "resources": {"requests": {"cpu": "1m", "memory": "2Mi"},
                                                                         "limits": {"cpu": "50m", "memory": "16Mi"}}}]}}}}


def top_of(prefix: str, ns: str = "kubeheal") -> tuple[float, float]:
    """(cpu millicores, memory MiB) summed over pods whose name starts with prefix."""
    cpu = mem = 0.0
    for ln in ev.k("top", "pod", "-n", ns, "--no-headers", check=False).splitlines():
        p = ln.split()
        if len(p) >= 3 and p[0].startswith(prefix):
            cpu += float(p[1].rstrip("m")) if p[1].endswith("m") else float(p[1]) * 1000
            mem += float(p[2][:-2]) * {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024}.get(p[2][-2:], 0)
    return cpu, mem


def limit_mib(deploy: str) -> float:
    raw = ev.k("-n", "kubeheal", "get", "deploy", deploy, "-o", "jsonpath={.spec.template.spec.containers[0].resources.limits.memory}", check=False).strip()
    m = re.fullmatch(r"(\d+)(Mi|Gi)", raw)
    return float(m.group(1)) * (1024 if m and m.group(2) == "Gi" else 1) if m else 0.0


def restarts() -> dict[str, int]:
    out = ev.k("-n", "kubeheal", "get", "pods", "--no-headers", "-o", "custom-columns=N:.metadata.name,R:.status.containerStatuses[*].restartCount", check=False)
    return {ln.split()[0]: sum(int(x) for x in ln.split()[1].split(",") if x.isdigit()) for ln in out.splitlines() if len(ln.split()) > 1}


def ready_scale_pods() -> int:
    out = ev.k("get", "pods", "-A", "-l", "rw-scale=1", "--field-selector=status.phase=Running", "--no-headers", check=False)
    return sum(1 for ln in out.splitlines() if ln.split()[0].startswith(PREFIX))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--namespaces", type=int, default=20)
    ap.add_argument("--deployments", type=int, default=200)
    ap.add_argument("--pods", type=int, default=300)
    ap.add_argument("--churn-seconds", type=int, default=300)
    ap.add_argument("--churn-interval", type=float, default=3.0)
    ap.add_argument("--image", default="registry.k8s.io/pause:3.10")
    ap.add_argument("--max-lag-s", type=float, default=30, help="p95 budget for event lag and fusion lag")
    ap.add_argument("--max-redis-frac", type=float, default=0.8, help="used_memory / maxmemory")
    ap.add_argument("--max-mem-frac", type=float, default=0.9, help="peak memory / limit of the health agent and fusion")
    ap.add_argument("--out", default=".")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force-context", default="")
    a = ap.parse_args()
    if a.namespaces > 25 or a.deployments > 1000 or a.pods > 3000:
        sys.exit("refusing: that is more than a lab cluster should be asked to hold")
    rwlib.DRY = rwlib.DRY or a.dry_run
    rwlib.pin(a.force_context)
    per = max(1, a.pods // a.deployments)
    extra = a.pods - per * a.deployments   # first `extra` deployments get one more replica
    print(f"scale: {a.deployments} deployments / {a.pods} pods over {a.namespaces} namespaces, churn {a.churn_seconds}s every {a.churn_interval}s")
    if rwlib.DRY:
        print("dry-run: no cluster calls made")
        return 0
    out, rnd, bad = Path(a.out), random.Random(1), []
    spaces = [f"{NS}{i:02d}" for i in range(a.namespaces)]
    t0 = ev.now_ms()
    try:
        for ns in spaces:
            rwlib.mkns(ns)
        objs = [deployment(spaces[i % len(spaces)], f"app-{i:03d}", per + (1 if i < extra else 0), a.image) for i in range(a.deployments)]
        for j in range(0, len(objs), 50):
            ev.apply({"apiVersion": "v1", "kind": "List", "items": objs[j:j + 50]})
        for _ in range(100):   # up to ~5 min
            if ready_scale_pods() >= a.pods:
                break
            time.sleep(3)
        created = ready_scale_pods()
        print(f"{created}/{a.pods} pods Running after create")
        if created < a.pods * 0.98:
            bad.append(f"only {created}/{a.pods} pods Running (cluster out of capacity?)")
        time.sleep(60)   # let the health agent take its baselines
        r0 = restarts()
        dl0 = int(ev.rc("XLEN", "kubeheal.deadletter").strip() or 0)

        samples: list[dict] = []
        patched: list[tuple[str, str, int]] = []   # (namespace, workload, ms)

        def sample() -> None:
            used, mx = rwlib.used_memory()
            h, f, inf = top_of("kubeheal-health"), top_of("kubeheal-fusion"), top_of("kubeheal-inference")
            lag = rwlib.group_state("kubeheal.health.events").get("fusion", {})
            samples.append({"t": time.time(), "health_cpu_m": h[0], "health_mem_mi": h[1], "fusion_cpu_m": f[0], "fusion_mem_mi": f[1],
                            "inference_cpu_m": inf[0], "redis_used": used, "redis_max": mx,
                            "fusion_pending": lag.get("pending"), "fusion_lag": lag.get("lag")})
        sample()
        end, nxt, n = time.time() + a.churn_seconds, 0.0, 0
        while time.time() < end:
            i = rnd.randrange(a.deployments)
            ns, name = spaces[i % len(spaces)], f"app-{i:03d}"
            n += 1
            ev.k("set", "env", f"deploy/{name}", "-n", ns, f"CHURN={n}", check=False)   # a real spec change = one rollout
            patched.append((ns, name, ev.now_ms()))
            if time.time() >= nxt:
                sample()
                nxt = time.time() + 15
            time.sleep(a.churn_interval)
        time.sleep(90)   # settle: the agents drain the backlog
        sample()

        # end-to-end event lag: spec change -> first health event of that workload after it; fusion lag: event -> action
        events: dict[tuple[str, str], list[tuple[int, str]]] = {}
        for e in ev.stream("kubeheal.health.events", t0):
            events.setdefault((e.get("namespace", ""), e.get("workload", "")), []).append((int(e.get("timestamp_ms", 0)), e.get("event_id", "")))
        ev_lag = []
        for ns, name, ts in patched:
            nxt_ev = next((x for x, _ in sorted(events.get((ns, name), [])) if x >= ts), None)
            if nxt_ev is not None:
                ev_lag.append((nxt_ev - ts) / 1000)
        by_id = {eid: ts for lst in events.values() for ts, eid in lst}
        acts = [x for x in ev.actions(t0) if x.get("namespace", "").startswith(PREFIX)]
        fus_lag = [(int(x["timestamp_ms"]) - by_id[x["health_event_id"]]) / 1000 for x in acts if x.get("health_event_id") in by_id]
        harmful = [x for x in acts if x.get("decision") in ("AUTO_KILL", "AUTO_PATCH") or x.get("outcome") == "pod_killed"]

        r1 = restarts()
        dl1 = int(ev.rc("XLEN", "kubeheal.deadletter").strip() or 0)
        peak = lambda key: max((s[key] for s in samples if s[key] is not None), default=0)  # noqa: E731
        lim_h, lim_f = limit_mib("kubeheal-health-agent"), limit_mib("kubeheal-fusion-agent")
        report = {
            "pods_running": created, "rollouts": n, "health_events": sum(len(v) for v in events.values()), "actions": len(acts),
            "health_agent": {"cpu_m_max": peak("health_cpu_m"), "mem_mi_max": peak("health_mem_mi"), "mem_limit_mi": lim_h},
            "fusion": {"cpu_m_max": peak("fusion_cpu_m"), "mem_mi_max": peak("fusion_mem_mi"), "mem_limit_mi": lim_f,
                       "stream_lag_max": peak("fusion_lag"), "pending_max": peak("fusion_pending")},
            "redis": {"used_mb_max": round(peak("redis_used") / 2**20, 1), "maxmemory_mb": round(peak("redis_max") / 2**20, 1)},
            "event_lag_s": {p: ev.pct(ev_lag, p) for p in (50, 95, 99, 100)}, "event_lag_missing": len(patched) - len(ev_lag),
            "fusion_lag_s": {p: ev.pct(fus_lag, p) for p in (50, 95, 99, 100)}, "restarts_delta": {k: r1.get(k, 0) - v for k, v in r0.items() if r1.get(k, 0) != v},
            "deadletter_delta": dl1 - dl0, "harmful_actions": len(harmful), "samples": samples,
        }
        (out / "scale-report.json").write_text(json.dumps(report, indent=2, default=str))
        print(json.dumps({k: v for k, v in report.items() if k != "samples"}, indent=1, default=str))

        if lim_h and report["health_agent"]["mem_mi_max"] > a.max_mem_frac * lim_h:
            bad.append(f"health agent memory {report['health_agent']['mem_mi_max']:.0f}Mi > {a.max_mem_frac:.0%} of {lim_h:.0f}Mi")
        if lim_f and report["fusion"]["mem_mi_max"] > a.max_mem_frac * lim_f:
            bad.append("fusion memory near its limit")
        if peak("redis_max") and peak("redis_used") > a.max_redis_frac * peak("redis_max"):
            bad.append("redis near maxmemory (noeviction: writes would start failing)")
        if report["restarts_delta"]:
            bad.append(f"KubeHeal pods restarted (OOM or crash): {report['restarts_delta']}")
        if report["deadletter_delta"]:
            bad.append(f"{report['deadletter_delta']} events dead-lettered")
        if harmful:
            bad.append(f"{len(harmful)} AUTO_KILL/AUTO_PATCH on benign churn")
        for name, vals in (("event lag", ev_lag), ("fusion lag", fus_lag)):
            if vals and ev.pct(vals, 95) > a.max_lag_s:
                bad.append(f"{name} p95 {ev.pct(vals, 95):.1f}s > {a.max_lag_s}s")
        if len(ev_lag) < 0.5 * len(patched):
            bad.append(f"only {len(ev_lag)}/{len(patched)} rollouts produced a health event (agent dropped or never saw them)")
    finally:
        rwlib.cleanup_all()
    print("SCALE FAIL: " + "; ".join(bad) if bad else "SCALE PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
