#!/usr/bin/env python3
"""Soak engine behind soak.sh: N hours of real benign tools plus a random attack every ~10 minutes (enforce mode).

Asserts 0 benign kills and every attack killed; reports kill latency percentiles, the benign false-alert rate
(HUMAN/OBSERVE decisions on benign pods) and component CPU/memory percentiles. Exit 1 when an assertion fails.
Run it through soak.sh (guard, trap, --dry-run); everything lives in khe-rw-soak-* namespaces.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import threading
import time
from pathlib import Path

import rwlib
from rwlib import PREFIX, ev

BENIGN_NS = PREFIX + "soak-b-"
ATTACK_NS = PREFIX + "soak-a-"
PROFILES = [(n, a) for n, a, per_ns in ev.ROWS_C if per_ns == 1]   # the section-C attack variants (rate, size, rename style, delay)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hours", type=float, default=1.0)
    ap.add_argument("--attack-every", type=float, default=600, help="seconds between attacks (jittered +-30%%)")
    ap.add_argument("--cycle", type=int, default=600, help="seconds each benign tool runs before it is restarted")
    ap.add_argument("--workloads", default="", help="comma list (default: every tool in evaluate.py WORKLOADS)")
    ap.add_argument("--max-kill-s", type=float, default=30, help="an attack must be killed this long after its first write")
    ap.add_argument("--max-false-alerts-per-hour", type=float, default=2.0, help="HUMAN/OBSERVE per benign workload-hour")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out", default=".")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    rwlib.DRY = rwlib.DRY or a.dry_run
    rwlib.pin()
    rnd = random.Random(a.seed)
    names = [w for w in (a.workloads.split(",") if a.workloads else ev.WORKLOADS) if w in ev.WORKLOADS]
    ev.DUR = a.cycle
    t_end = time.time() + a.hours * 3600
    n_attacks = max(1, int(a.hours * 3600 / a.attack_every))
    print(f"soak: {a.hours} h, benign tools {names}, ~{n_attacks} attacks over {len(PROFILES)} profiles, kill budget {a.max_kill_s}s")
    if rwlib.DRY:
        print("dry-run: no cluster calls made")
        return 0
    out = Path(a.out)
    t0 = ev.now_ms()
    top = ev.Top()
    top.start()
    results: list[dict] = []
    lock = threading.Lock()
    restarts = dict.fromkeys(names, 0)
    errors: list[str] = []

    def attack_once(i: int, profile: tuple[str, list[str]]) -> None:
        try:
            r = rwlib.attack(f"{ATTACK_NS}{i}", f"atk-{i}", profile[1])
            r["profile"] = profile[0]
            with lock:
                results.append(r)
            print(f"attack {i} {profile[0]}: killed={r['killed']} latency={r['latency_s']} outcome={r['outcome']}", flush=True)
            rwlib.delete_ns(f"{ATTACK_NS}{i}")
        except ev.KubectlError as e:
            with lock:
                errors.append(f"attack {i}: {e}")

    for w in names:
        rwlib.benign_start(w, BENIGN_NS + w)
    threads: list[threading.Thread] = []
    next_attack, i = time.time() + a.attack_every * rnd.uniform(0.2, 0.6), 0   # first attack early: fail fast
    try:
        while time.time() < t_end:
            now = time.time()
            if now >= next_attack:
                i += 1
                t = threading.Thread(target=attack_once, args=(i, rnd.choice(PROFILES)), daemon=True)
                t.start()
                threads.append(t)
                next_attack = now + a.attack_every * rnd.uniform(0.7, 1.3)
            for w in names:   # a tool that finished is restarted; a vanished pod is counted (possible benign kill)
                ph = ev.k("get", "pod", w, "-n", BENIGN_NS + w, "-o", "jsonpath={.status.phase}", check=False).strip()
                if ph in ("", "Succeeded", "Failed"):
                    restarts[w] += 1
                    ev.k("delete", "pod", w, "-n", BENIGN_NS + w, "--ignore-not-found", "--wait=true", check=False, timeout=120)
                    ev.apply(ev.work_pod(w, BENIGN_NS + w))
            time.sleep(15)
    except ev.KubectlError as e:
        errors.append(str(e))
    finally:
        for t in threads:
            t.join(timeout=240)
        top.stop.set()

    acts, secs = ev.actions(t0), ev.sec(t0)
    benign = {w: ev.summarise_ns(BENIGN_NS + w, acts, secs) for w in names}
    kills = sum(b["killed"] + b["kill"] for b in benign.values())
    alerts = sum(b["human"] + b["observe"] for b in benign.values())
    hours = max(1e-9, (time.time() - t0 / 1000) / 3600)
    lat = [r["latency_s"] for r in results if r["latency_s"] is not None]
    missed = [r for r in results if not r["killed"]]
    report = {
        "hours": round(hours, 2), "attacks": len(results), "attacks_killed": len(results) - len(missed),
        "kill_latency_s": {p: ev.pct(lat, p) for p in (50, 90, 95, 99, 100)},
        "benign_kills": kills, "benign_alerts": alerts, "benign_workloads": len(names),
        "false_alerts_per_workload_hour": round(alerts / hours / max(1, len(names)), 3),
        "benign_cycles": sum(restarts.values()) + len(names), "benign": benign, "benign_pod_restarts": restarts,
        "resources": {c: {"cpu_m": {p: ev.pct([x[0] for x in v], p) for p in (50, 95, 99, 100)},
                          "mem_mi": {p: ev.pct([x[1] for x in v], p) for p in (50, 95, 99, 100)}} for c, v in top.s.items() if v},
        "errors": errors,
    }
    (out / "soak-report.json").write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps({k: v for k, v in report.items() if k not in ("benign", "resources")}, indent=1, default=str))
    for c, v in report["resources"].items():
        print(f"  {c:15s} cpu_m p50/p95/p99/max {v['cpu_m']}   mem_mi {v['mem_mi']}")
    bad = []
    if kills:
        bad.append(f"{kills} benign pods killed")
    if missed:
        bad.append(f"{len(missed)} attacks not killed: {[m['profile'] for m in missed]}")
    if lat and max(lat) > a.max_kill_s:
        bad.append(f"slowest kill {max(lat):.1f}s > {a.max_kill_s}s")
    if report["false_alerts_per_workload_hour"] > a.max_false_alerts_per_hour:
        bad.append(f"false-alert rate {report['false_alerts_per_workload_hour']}/workload-hour")
    if errors:
        bad.append(f"{len(errors)} kubectl errors")
    print("SOAK FAIL: " + "; ".join(bad) if bad else "SOAK PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
