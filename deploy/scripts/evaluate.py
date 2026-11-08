#!/usr/bin/env python3
"""Live evaluation of the DEPLOYED KubeHeal stack (enforce mode). Prints a compact TSV.

  uv run --all-extras python deploy/scripts/evaluate.py [--sections A,F,B,C,E,D] [--out DIR] [--dur 200] [--repeat N]

A automated checks | F resources (idle, then under the B load) | B false-kill soak with real tools
C detection sweep (deploy/chaos/detection-test-workload.py, other parameters) | E health/drift | D resilience
--repeat N runs B, C and E N times (namespaces khe-b-r<i>-*, ...) and adds AGG rows (n/min/median/max).
A kubectl or redis-cli failure is an ERROR row for that section, never a silent "no kill".
Safety: attacks use only the sandbox-gated detection workload (kubeheal.invalid/chaos:v5). Everything runs in
throwaway `khe-*` prod-tier namespaces, deleted at the end. Only section D restarts KubeHeal's own pods
(inference, fusion, redis, health agent) and Falco, and restores them. Needs kubectl, a pulled
kubeheal.invalid/chaos:v5 image, and network access from the cluster (apk, pip, npm, git).
"""
from __future__ import annotations

import argparse
import json
import re
import statistics as st
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KH = "kubeheal"
CHAOS = "kubeheal.invalid/chaos:v5"
OUT: Path
ROWS: list[str] = []
REP = ""   # "-r<i>" with --repeat > 1: makes namespace names unique per repetition
AGG: dict[tuple[str, str, str], list[float]] = {}   # (section, row, metric) -> one value per repetition/pod
REDIS_ERR = re.compile(r"(ERR|NOAUTH|NOPERM|WRONGPASS|WRONGTYPE|LOADING|NOGROUP|BUSY)\b")


class KubectlError(RuntimeError):
    pass


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def k(*a: str, inp: str | None = None, timeout: int = 300, check: bool = True) -> str:
    """kubectl stdout. check=True raises KubectlError on a non-zero exit or timeout; check=False is for polls
    where failure is an answer (pod gone, logs not ready) and returns whatever stdout there was."""
    try:
        r = subprocess.run(["kubectl", *a], input=inp, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        if check:
            raise KubectlError(f"kubectl {' '.join(a[:6])}: timeout after {timeout}s") from e
        return ""
    if r.returncode and check:
        raise KubectlError(f"kubectl {' '.join(a[:6])}: rc={r.returncode}: {r.stderr.strip()[-300:]}")
    return r.stdout


def note(sec: str, key: str, metric: str, v: float | None) -> None:
    if v is not None:
        AGG.setdefault((sec, key, metric), []).append(float(v))


def row(*cols) -> None:
    line = "\t".join("" if c is None else (f"{c:.2f}" if isinstance(c, float) else str(c)) for c in cols)
    ROWS.append(line)
    print(line, flush=True)
    with open(OUT / "results.tsv", "a") as f:
        f.write(line + "\n")


def apply(obj: dict) -> None:
    k("apply", "-f", "-", inp=json.dumps(obj))


def mkns(ns: str) -> None:
    k("create", "ns", ns, check=False)   # may exist already; the label below must succeed
    k("label", "ns", ns, "kubeheal.io/namespace-tier=prod", "--overwrite")


def rc(*a: str) -> str:
    """redis-cli in the Redis pod (admin user via its REDISCLI_AUTH). redis-cli exits 0 on error replies."""
    out = k("-n", KH, "exec", "deploy/redis", "--", "redis-cli", *a)
    if REDIS_ERR.match(out):
        raise KubectlError(f"redis-cli {' '.join(a[:3])}: {out.strip()[:200]}")
    return out


def stream(name: str, t0: int) -> list[dict]:
    """XRANGE parsed from raw redis-cli output (id line, then field/value lines; empty value = blank line)."""
    recs: list[dict] = []
    for ln in rc("XRANGE", name, str(t0), "+", "COUNT", "20000").split("\n"):
        if re.fullmatch(r"\d+-\d+", ln):
            recs.append({"id": int(ln.split("-")[0]), "f": []})
        elif recs:
            recs[-1]["f"].append(ln)
    return [{"id": r["id"], **dict(zip(r["f"][::2], r["f"][1::2], strict=False))} for r in recs]


def actions(t0: int) -> list[dict]:
    return stream("kubeheal.actions", t0)


def sec(t0: int) -> list[dict]:
    return stream("kubeheal.security.events", t0)


def clear_keys(pat: str, kinds: tuple[str, ...] = ("cb:", "lock:")) -> None:
    for kind in kinds:
        keys = rc("--scan", "--pattern", f"kubeheal:{kind}*{pat}*").split()
        for i in range(0, len(keys), 500):
            rc("DEL", *keys[i:i + 500])


def pct(v: list[float], p: float):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))] if v else None


# ------------------------------------------------------------------ A
def section_a() -> None:
    def run(name: str, cmd: list[str], cwd: Path = ROOT, timeout: int = 1500) -> subprocess.CompletedProcess:
        try:
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            row("A", name, "timeout", "", "")
            return subprocess.CompletedProcess(cmd, 124, "", "")
        (OUT / f"A-{name}.log").write_text(r.stdout + r.stderr)
        return r

    junit = OUT / "junit.xml"
    r = run("pytest", ["uv", "run", "--all-extras", "pytest", "-q", f"--junitxml={junit}"])
    try:
        ts = ET.parse(junit).getroot()
        ts = ts if ts.tag == "testsuite" else ts[0]
        n, f, e, s = (int(ts.get(x, 0)) for x in ("tests", "failures", "errors", "skipped"))
        row("A", "pytest", f"rc={r.returncode}", f"passed={n - f - e - s}", f"failed={f + e} skipped={s} total={n}")
    except Exception as ex:  # noqa: BLE001
        row("A", "pytest", f"rc={r.returncode}", f"no junit: {ex}", "")
    r = run("ruff", ["uv", "run", "--all-extras", "ruff", "check", "."])
    row("A", "ruff", f"rc={r.returncode}", r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "", "")
    r = run("cargo", ["cargo", "test"], ROOT / "sensor")
    m = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", r.stdout)
    row("A", "cargo test", f"rc={r.returncode}", f"passed={sum(int(x[1]) for x in m)}", f"failed={sum(int(x[2]) for x in m)}")
    for p in ("deploy/k8s", "deploy/k8s/overlays/production"):
        r = run("kustomize", ["kubectl", "kustomize", p])
        row("A", f"kustomize {p}", f"rc={r.returncode}", f"docs={r.stdout.count(chr(10) + '---')+1}", "")
    bad = [str(p) for p in sorted(ROOT.glob("deploy/**/*.sh")) + sorted(ROOT.glob("training/**/*.sh"))
           if subprocess.run(["bash", "-n", str(p)]).returncode]
    row("A", "bash -n", f"rc={1 if bad else 0}", f"bad={bad}", "")


# ------------------------------------------------------------------ pods
def base_pod(name: str, ns: str, image: str, script: str, env: dict | None = None, mem: str = "1Gi") -> dict:
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": {"khe": "1"}},
            "spec": {"restartPolicy": "Never",
                     "containers": [{"name": "w", "image": image, "imagePullPolicy": "IfNotPresent",
                                     "command": ["sh", "-c", script],
                                     "env": [{"name": a, "value": b} for a, b in (env or {}).items()],
                                     "resources": {"limits": {"memory": mem}},
                                     "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                     "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "2Gi"}}]}}


def attack_pod(name: str, ns: str, args: list[str]) -> dict:
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": {"kubeheal.io/chaos": "true", "khe": "1"}},
            "spec": {"restartPolicy": "Never",
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "initContainers": [{"name": "mark-sandbox", "image": CHAOS, "imagePullPolicy": "IfNotPresent",
                                         "command": ["sh", "-c", "touch /data/.kubeheal-sandbox"],
                                         "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                     "containers": [{"name": "workload", "image": CHAOS, "imagePullPolicy": "IfNotPresent",
                                     "args": ["--sandbox", "/data", *args],
                                     "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "capabilities": {"drop": ["ALL"]}}}],
                     "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "1Gi"}}]}}


BENCH_ARGS = ["--num-files", "400", "--rate", "180", "--duration", "60"]


def watch_attack(ns: str, name: str, deadline_s: float, after_finish_s: float = 45) -> dict:
    """Poll one attack pod: first malicious op time, completion, disappearance (kill)."""
    t_end = time.time() + deadline_s
    r = {"op": None, "done": None, "gone": False, "files": None}
    fin = None
    while time.time() < t_end:
        if "NotFound" in subprocess.run(["kubectl", "get", "pod", name, "-n", ns], capture_output=True, text=True).stderr:
            r["gone"] = True
            break
        if r["done"] is None:
            log = k("logs", name, "-n", ns, "-c", "workload", check=False)
            m = re.search(r"overwrite_start_ms=(\d+)", log)
            r["op"] = int(m.group(1)) if m else r["op"]
            m = re.search(r"overwrote\S* (\d+) self-created", log)
            if m:
                r["done"], r["files"], fin = now_ms(), int(m.group(1)), time.time()
        elif fin and time.time() - fin > after_finish_s:
            break
        time.sleep(1)
    return r


def kill_of(acts: list[dict], ns: str, pod: str, op: int | None) -> dict | None:
    return next((a for a in acts if a.get("namespace") == ns and a.get("pod") == pod
                 and a.get("outcome") == "pod_killed" and (op is None or a["id"] >= op)), None)


# ------------------------------------------------------------------ B
DUR = 200
FIND = ("apk add --no-cache %s >/dev/null 2>&1 || { echo SETUP_FAIL; exit 1; }; ")
LEFT = 'END=$(( $(date +%s) + @DUR@ )); left() { [ $(date +%s) -lt $END ]; }; '
WORKLOADS: dict[str, tuple[str, dict, str, str]] = {  # name -> image, env, script, mem
    "postgres": ("postgres:16", {"POSTGRES_PASSWORD": "x", "PGPASSWORD": "x", "PGDATA": "/data/pg"},
                 LEFT + "docker-entrypoint.sh postgres >/tmp/pg.log 2>&1 & "
                 "for i in $(seq 1 90); do pg_isready -q -h localhost -U postgres && break; sleep 1; done; "
                 "pgbench -h localhost -U postgres -i -s 20 postgres; pgbench -h localhost -U postgres -T 120 -c 4 postgres; "
                 "echo WORK_DONE; while left; do sleep 2; done", "2Gi"),
    "redis-bgsave": ("redis:7", {}, LEFT + "redis-server --dir /data --save '1 1' >/tmp/r.log 2>&1 & sleep 2; "
                     "(while :; do redis-cli bgsave >/dev/null; sleep 1; done) & "
                     "while left; do redis-benchmark -q -n 300000 -t set -d 2048 -r 200000 -c 20 >/dev/null; done; echo WORK_DONE", "1Gi"),
    "logrotate": ("alpine:3.22", {}, FIND % "logrotate" + LEFT + "mkdir -p /data/logs; "
                  "printf '/data/logs/app.log {\\n compress\\n rotate 5\\n missingok\\n copytruncate\\n}\\n' > /data/lr.conf; "
                  "(while :; do seq 1 3000 | sed 's/^/2026-11-07 app event id=/' >> /data/logs/app.log; sleep 0.2; done) & "
                  "while left; do logrotate -f -s /data/lr.state /data/lr.conf; sleep 2; done; echo WORK_DONE", "512Mi"),
    "tar-gzip-zstd": ("alpine:3.22", {}, FIND % "zstd tar gzip" + LEFT + "mkdir -p /data/src; i=0; "
                      "while [ $i -lt 200 ]; do d=/data/src/d$((i%10)); mkdir -p $d; seq 1 3000 | sed \"s/^/line$i /\" > $d/f$i.c; i=$((i+1)); done; "
                      "while left; do tar czf /data/a.tgz -C /data src; rm -rf /data/src2; cp -r /data/src /data/src2; gzip -rq /data/src2; "
                      "rm -rf /data/src2; tar cf - -C /data src | zstd -q -3 -f -o /data/a.zst; done; echo WORK_DONE", "512Mi"),
    "git": ("alpine/git:latest", {}, LEFT + "cd /data; git clone -q https://github.com/stefanprodan/podinfo.git repo || { echo SETUP_FAIL; exit 1; }; "
            "cd repo; while left; do for t in $(git tag | tail -8); do git checkout -q -f $t; done; git gc -q; "
            "rm -rf /data/c2; git clone -q /data/repo /data/c2; done; echo WORK_DONE", "1Gi"),
    "pip": ("python:3.13-slim", {"HOME": "/data/home", "PIP_CACHE_DIR": "/data/pipcache"},
            LEFT + "while left; do rm -rf /data/venv; python -m venv /data/venv && /data/venv/bin/pip install -q requests numpy flask rich "
            "|| echo SETUP_FAIL; done; echo WORK_DONE", "1Gi"),
    "npm": ("node:22-alpine", {"HOME": "/data/home", "npm_config_cache": "/data/npmcache"},
            LEFT + "mkdir -p /data/app; cd /data/app; npm init -y >/dev/null; "
            "while left; do rm -rf node_modules; npm install --no-audit --no-fund express lodash axios >/dev/null 2>&1 || echo SETUP_FAIL; done; echo WORK_DONE", "1Gi"),
    "sqlite": ("python:3.13-slim", {}, "python - <<'PY'\nimport sqlite3,time,os\nend=time.time()+@DUR@-5\n"
               "for mode in ('WAL','DELETE'):\n c=sqlite3.connect(f'/data/db_{mode}.sqlite'); c.execute(f'pragma journal_mode={mode}')\n"
               " c.execute('create table t(id integer primary key,a text,b blob)'); n=0; stop=time.time()+(end-time.time())/(2 if mode=='WAL' else 1)\n"
               " while time.time()<stop:\n  c.execute('insert into t(a,b) values(?,?)',('row%d'%n,os.urandom(200))); c.commit(); n+=1\n print(mode,n)\nPY\necho WORK_DONE", "512Mi"),
    "rsync": ("alpine:3.22", {}, FIND % "rsync" + LEFT + "mkdir -p /data/src /data/d1 /data/d2; i=0; "
              "while [ $i -lt 400 ]; do seq 1 800 | sed \"s/^/f$i /\" > /data/src/f$i.txt; i=$((i+1)); done; n=0; "
              "while left; do n=$((n+1)); for f in $(ls /data/src | head -100); do echo $n >> /data/src/$f; done; "
              "rsync -a /data/src/ /data/d1/; rsync -a --inplace /data/src/ /data/d2/; done; echo WORK_DONE", "512Mi"),
    "nginx-logs": ("nginx:1.27-alpine", {}, LEFT + "mkdir -p /data/logs; printf 'worker_processes 1;\\npid /tmp/nginx.pid;\\nerror_log /data/logs/error.log warn;\\n"
                   "events { worker_connections 256; }\\nhttp { access_log /data/logs/access.log; client_body_temp_path /tmp/c; proxy_temp_path /tmp/p; "
                   "fastcgi_temp_path /tmp/f; uwsgi_temp_path /tmp/u; scgi_temp_path /tmp/s;\\n server { listen 8080; location / { root /usr/share/nginx/html; } } }\\n' "
                   "> /etc/nginx/nginx.conf; nginx; sleep 1; while left; do for i in $(seq 1 50); do wget -q -O /dev/null http://localhost:8080/; done; "
                   "seq 1 500 | sed 's/^/app log line /' >> /data/logs/app.log; done; echo WORK_DONE", "512Mi"),
    "restic": ("alpine:3.22", {"RESTIC_PASSWORD": "kubeheal-eval", "RESTIC_REPOSITORY": "/data/repo", "RESTIC_CACHE_DIR": "/data/cache"},
               FIND % "restic" + LEFT + "mkdir -p /data/src; i=0; while [ $i -lt 150 ]; do seq 1 4000 | sed \"s/^/f$i /\" > /data/src/f$i.txt; "
               "head -c 20000 /dev/urandom > /data/src/r$i.bin; i=$((i+1)); done; restic init -q || { echo SETUP_FAIL; exit 1; }; n=0; "
               "while left; do n=$((n+1)); date +%s%N >> /data/src/f$((n%150)).txt; restic backup -q /data/src; "
               "[ $((n%3)) = 0 ] && restic forget --keep-last 3 --prune -q; done; echo WORK_DONE", "1Gi"),
}


def work_pod(w: str, ns: str, name: str | None = None) -> dict:
    image, env, script, mem = WORKLOADS[w]
    return base_pod(name or w, ns, image, script.replace("@DUR@", str(DUR)), env, mem)


class Top(threading.Thread):
    """Samples `kubectl top` every 15 s into per-component CPU (m) and memory (Mi) lists."""
    COMP = {"falco": lambda ns, n: ns == "falco", "security-agent": lambda ns, n: "kubeheal-security" in n,
            "inference": lambda ns, n: "kubeheal-inference" in n, "fusion": lambda ns, n: "kubeheal-fusion" in n,
            "health-agent": lambda ns, n: "kubeheal-health" in n, "redis": lambda ns, n: ns == KH and n.startswith("redis")}

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.s: dict[str, list[tuple[float, float]]] = {c: [] for c in self.COMP}

    def run(self) -> None:
        while not self.stop.is_set():
            acc = {c: [0.0, 0.0] for c in self.COMP}
            for ln in k("top", "pod", "-A", "--no-headers", check=False).splitlines():
                p = ln.split()
                if len(p) < 4:
                    continue
                cpu = float(p[2].rstrip("m")) if p[2].endswith("m") else float(p[2]) * 1000
                mem = float(p[3][:-2]) * {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024}.get(p[3][-2:], 0)
                for c, f in self.COMP.items():
                    if f(p[0], p[1]):
                        acc[c][0] += cpu
                        acc[c][1] += mem
            for c, v in acc.items():
                self.s[c].append((v[0], v[1]))
            self.stop.wait(15)

    def report(self, label: str) -> None:
        for c, v in self.s.items():
            if v:
                row("F", label, c, f"cpu_m_p50={pct([x[0] for x in v], 50):.0f}", f"cpu_m_max={max(x[0] for x in v):.0f}",
                    f"mem_mi_p50={pct([x[1] for x in v], 50):.0f}", f"mem_mi_max={max(x[1] for x in v):.0f}", f"n={len(v)}")


def summarise_ns(ns: str, acts: list[dict], secs: list[dict]) -> dict:
    a = [x for x in acts if x.get("namespace") == ns]
    s = [x for x in secs if x.get("namespace") == ns]
    d = lambda name: sum(1 for x in a if x.get("decision") == name)  # noqa: E731
    return {"kill": sum(1 for x in a if x.get("decision") == "AUTO_KILL"), "killed": sum(1 for x in a if x.get("outcome") == "pod_killed"),
            "human": d("HUMAN"), "observe": d("OBSERVE"), "other": len(a) - d("AUTO_KILL") - d("HUMAN") - d("OBSERVE"),
            "max_risk": max((float(x.get("risk", 0)) for x in s), default=0.0), "n_sec": len(s),
            "labels": {lab: sum(1 for x in s if x.get("label") == lab) for lab in {x.get("label") for x in s}}}


def section_b(top: Top | None) -> None:
    t0 = now_ms()
    names = list(WORKLOADS)
    for w in names:
        mkns(f"khe-b{REP}-{w}")
        apply(work_pod(w, f"khe-b{REP}-{w}"))
    seen: dict[str, str] = {}
    tails: dict[str, str] = {}
    t_end = time.time() + DUR + 360
    while time.time() < t_end:
        time.sleep(10)
        alive = 0
        for w in names:
            ns = f"khe-b{REP}-{w}"
            ph = k("get", "pod", w, "-n", ns, "-o", "jsonpath={.status.phase}", check=False)
            if ph:
                seen[w] = ph
                tails[w] = k("logs", w, "-n", ns, "--tail=3", check=False).strip().replace("\n", " | ")[-120:]
                alive += ph in ("Pending", "Running")
            else:
                seen.setdefault(w, "")
                seen[w] = seen[w] if seen[w].startswith("GONE") else "GONE(" + seen[w] + ")"
        if not alive:
            break
    if top:
        top.report("B-load")
    acts, secs = actions(t0), sec(t0)
    for w in names:
        s = summarise_ns(f"khe-b{REP}-{w}", acts, secs)
        note("B", w, "AUTO_KILL", s["kill"])
        note("B", w, "killed", s["killed"])
        note("B", w, "max_risk", s["max_risk"])
        ok = "WORK_DONE" in tails.get(w, "") or "SETUP_FAIL" not in tails.get(w, "")
        row("B", w, f"AUTO_KILL={s['kill']}", f"killed={s['killed']}", f"HUMAN={s['human']}", f"OBSERVE={s['observe']}",
            f"max_risk={s['max_risk']:.2f}", f"sec_events={s['n_sec']}", f"labels={s['labels']}",
            f"survived={seen[w]}", f"log={tails.get(w, '')[-70:]}", "ok" if ok else "SETUP_FAIL")
    for w in names:
        k("delete", "ns", f"khe-b{REP}-{w}", "--wait=false")
    clear_keys("khe-b-")


# ------------------------------------------------------------------ C
ROWS_C: list[tuple[str, list[str], int]] = [  # (row, extra args, pods per ns)
    ("default-400@180", BENCH_ARGS, 1),
    ("rate2", ["--num-files", "100", "--rate", "2", "--duration", "60"], 1),
    ("rate1000", ["--num-files", "500", "--rate", "1000", "--duration", "60"], 1),
    ("files2000", ["--num-files", "2000", "--max-files", "2000", "--rate", "180", "--duration", "60"], 1),
    ("tiny128B", ["--num-files", "400", "--rate", "180", "--file-size", "128", "--duration", "60"], 1),
    ("large8MiB", ["--num-files", "12", "--rate", "4", "--file-size", "8388608", "--duration", "60"], 1),
    ("partial0.05", ["--num-files", "400", "--rate", "180", "--partial", "0.05", "--duration", "60"], 1),
    ("no-rename", ["--num-files", "400", "--rate", "180", "--no-rename", "--duration", "60"], 1),
    ("swap-ext", ["--num-files", "400", "--rate", "180", "--swap-ext", "--duration", "60"], 1),
    ("delay10", [*BENCH_ARGS, "--delay", "10"], 1),
    ("delay60", [*BENCH_ARGS, "--delay", "60"], 1),
    ("2-concurrent", BENCH_ARGS, 2),
]


def section_c(only: str = "") -> list[float]:
    all_lat: list[float] = []
    for rname, args, per in ROWS_C:
        if only and only not in rname:
            continue
        t0 = now_ms()
        delay = int(args[args.index("--delay") + 1]) if "--delay" in args else 0
        rate = float(args[args.index("--rate") + 1])
        n = min(int(args[args.index("--num-files") + 1]), int(args[args.index("--max-files") + 1]) if "--max-files" in args else 500)
        pods = []
        for t in range(1, 4):
            ns = f"khe-c{REP}-{re.sub('[^a-z0-9]', '', rname.lower())}-{t}"
            mkns(ns)
            for p in range(per):
                nm = f"atk-{t}-{p}"
                apply(attack_pod(nm, ns, args))
                pods.append((ns, nm))
        with ThreadPoolExecutor(len(pods)) as ex:
            res = list(ex.map(lambda x, dl=150 + delay + n / rate: watch_attack(x[0], x[1], dl), pods))
        time.sleep(3)
        acts = actions(t0)
        # Containment (fusion freezes the pod via STREAM_CONTAIN before the API delete): measured only when
        # the stream has entries / ActionEvent carries `containment`, so older builds just leave it blank.
        contain = stream("kubeheal.contain", t0)
        lats, files = [], []
        for (ns, nm), r in zip(pods, res, strict=True):
            kl = kill_of(acts, ns, nm, r["op"])
            lat = (kl["id"] - r["op"]) / 1000 if kl and r["op"] else None
            cn = next((c for c in contain if c.get("namespace") == ns and c.get("pod") == nm), None)
            clat = (cn["id"] - r["op"]) / 1000 if cn and r["op"] else None
            note("C", rname, "latency_s", lat)
            note("C", rname, "contain_s", clat)
            est = (r["files"] if r["files"] is not None else min(n, int(rate * lat))) if lat is not None else None
            if lat is not None:
                lats.append(lat)
                all_lat.append(lat)
            files.append(est)
            row("C", rname, f"{ns}/{nm}", f"killed={'y' if kl else 'n'}", f"latency_s={lat:.2f}" if lat is not None else "latency_s=",
                f"files_total={n}", f"files_overwritten={'all(done)' if r['files'] is not None else '~' + str(est) if est is not None else ''}",
                f"contain_s={clat:.2f}" if clat is not None else "contain_s=", f"containment={(kl or {}).get('containment', '')}")
        note("C", rname, "recall", len(lats) / len(pods))
        row("C-sum", rname, f"recall={len(lats)}/{len(pods)}", f"med_s={st.median(lats):.2f}" if lats else "med_s=",
            f"p90_s={pct(lats, 90):.2f}" if lats else "p90_s=")
        for ns, _ in pods:
            k("delete", "ns", ns, "--wait=false")
        clear_keys("khe-c-")
    row("C-sum", "ALL", f"killed={len(all_lat)}", f"med_s={st.median(all_lat):.2f}" if all_lat else "", f"p90_s={pct(all_lat, 90):.2f}" if all_lat else "")
    return all_lat


# ------------------------------------------------------------------ E
IMG = "ghcr.io/stefanprodan/podinfo"


def podinfo(name: str, ns: str, replicas: int = 2, image: str = f"{IMG}:6.14.1") -> dict:
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": ns},
            "spec": {"replicas": replicas, "progressDeadlineSeconds": 120, "selector": {"matchLabels": {"app": name}},
                     "template": {"metadata": {"labels": {"app": name, "kubeheal.io/scrape": "true"}},
                                  "spec": {"securityContext": {"runAsNonRoot": True, "runAsUser": 100, "seccompProfile": {"type": "RuntimeDefault"}},
                                           "containers": [{"name": "app", "image": image, "command": ["./podinfo", "--port=9898", "--level=info"],
                                                           "ports": [{"containerPort": 9898, "name": "http"}],
                                                           "resources": {"requests": {"cpu": "25m", "memory": "32Mi"}, "limits": {"cpu": "500m", "memory": "128Mi"}},
                                                           "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                                           "livenessProbe": {"httpGet": {"path": "/healthz", "port": 9898}, "periodSeconds": 10},
                                                           "readinessProbe": {"httpGet": {"path": "/readyz", "port": 9898}, "periodSeconds": 3}}]}}}}


def cpatch(c: dict) -> dict:
    return {"spec": {"template": {"spec": {"containers": [{"name": "app", **c}]}}}}


CHANGES: dict[str, tuple[dict, dict, int]] = {  # name -> (strategic-merge patch, deployment overrides, base replicas)
    "image-upgrade(benign)": (cpatch({"image": f"{IMG}:6.14.1"}), {"image": f"{IMG}:6.12.0"}, 2),
    "replicas-2to4(benign)": ({"spec": {"replicas": 4}}, {}, 2),
    "env-var(benign)": (cpatch({"env": [{"name": "FEATURE_X", "value": "on"}]}), {}, 2),
    "bad-image-tag": (cpatch({"image": f"{IMG}:0.0.0-missing"}), {}, 2),
    "privileged": (cpatch({"securityContext": {"privileged": True, "allowPrivilegeEscalation": True}}), {}, 2),
    "hostNetwork": ({"spec": {"template": {"spec": {"hostNetwork": True}}}}, {}, 1),
    "hostPath": ({"spec": {"template": {"spec": {"volumes": [{"name": "hp", "hostPath": {"path": "/var/log"}}]}}}}, {}, 2),
    "memory-8Mi-oom": (cpatch({"resources": {"requests": {"memory": "8Mi"}, "limits": {"memory": "8Mi"}}}), {}, 2),
    "readiness-wrong-path": (cpatch({"readinessProbe": {"httpGet": {"path": "/nope", "port": 9898}}}), {}, 2),
    "cpu-limit-5m": (cpatch({"resources": {"requests": {"cpu": "5m"}, "limits": {"cpu": "5m"}}}), {}, 2),
    "wrong-command": (cpatch({"command": ["/bin/false"]}), {}, 2),
}
BENIGN = {"image-upgrade(benign)", "replicas-2to4(benign)", "env-var(benign)"}


def section_e(window: int = 480) -> None:
    ns = f"khe-e{REP}"
    mkns(ns)
    for nm, (_, ov, rep) in CHANGES.items():
        apply(podinfo(re.sub("[^a-z0-9]+", "-", nm).strip("-"), ns, rep, ov.get("image", f"{IMG}:6.14.1")))
    dn = {nm: re.sub("[^a-z0-9]+", "-", nm).strip("-") for nm in CHANGES}
    for d in dn.values():
        k("-n", ns, "rollout", "status", f"deploy/{d}", "--timeout=180s")
    time.sleep(120)  # baseline learned on first sight; give the agent time and a quiet window

    def snap(d: str) -> str:
        o = json.loads(k("-n", ns, "get", "deploy", d, "-o", "json") or "{}")
        return json.dumps([o.get("spec", {}).get("replicas"), o.get("spec", {}).get("template", {}).get("spec")], sort_keys=True)
    init = {d: snap(d) for d in dn.values()}
    t0 = now_ms()
    for nm, (patch, _, _) in CHANGES.items():
        k("-n", ns, "patch", f"deploy/{dn[nm]}", "--type", "strategic", "-p", json.dumps(patch))
    t_chg = time.time()
    restored: dict[str, float] = {}
    t_end = t_chg + window
    while time.time() < t_end:
        for nm, d in dn.items():
            if nm not in restored and snap(d) == init[d]:
                restored[nm] = time.time() - t_chg
        time.sleep(5)
    acts = [a for a in actions(t0) if a.get("namespace") == ns]
    health = [h for h in stream("kubeheal.health.events", t0) if h.get("namespace") == ns]
    for nm, d in dn.items():
        a = sorted((x for x in acts if x.get("workload") == d), key=lambda x: x["id"])
        h = sorted((x for x in health if x.get("workload") == d), key=lambda x: x["id"])
        o = json.loads(k("-n", ns, "get", "deploy", d, "-o", "json") or "{}")
        ready = f"{o.get('status', {}).get('readyReplicas', 0)}/{o.get('spec', {}).get('replicas')}"
        note("E", nm, "restored", nm in restored)
        note("E", nm, "restored_s", restored.get(nm))
        note("E", nm, "false_patch", nm in BENIGN and any("patch" in x.get("outcome", "") for x in a))
        row("E", nm, "decisions=" + (",".join(f"{x['decision']}:{x['outcome']}@{(x['id'] - t0) / 1000:.0f}s" for x in a[:4]) or "none"),
            "health=" + ",".join(f"{x.get('label')}/{float(x.get('risk', 0)):.2f}{'?' if x.get('uncertain') == '1' else ''}"
                                 f"{('/' + x['failure_reasons']) if x.get('failure_reasons') not in (None, '', '[]') else ''}" for x in h[:3]),
            f"restored_s={restored[nm]:.0f}" if nm in restored else "restored=no", f"ready={ready}",
            "FALSE_PATCH" if nm in BENIGN and any(x.get("outcome") == "patched" or "patch" in x.get("outcome", "") for x in a) else "")
    k("delete", "ns", ns, "--wait=false")
    clear_keys(ns, ("",))   # every kubeheal:* key of the namespace, baselines included


# ------------------------------------------------------------------ D
def restarts() -> dict[str, int]:
    o = json.loads(k("-n", KH, "get", "pods", "-o", "json") or '{"items":[]}')
    return {p["metadata"]["name"]: sum(c.get("restartCount", 0) for c in p["status"].get("containerStatuses", [])) for p in o["items"]}


def wait_rollout(kind: str, ns: str, name: str) -> None:
    k("-n", ns, "rollout", "status", f"{kind}/{name}", "--timeout=240s")


def scale(dep: str, n: int) -> None:
    k("-n", KH, "scale", f"deploy/{dep}", f"--replicas={n}")
    if n == 0:
        for _ in range(60):
            if dep not in k("-n", KH, "get", "pods", "--no-headers", "-o", "custom-columns=N:.metadata.name"):
                break
            time.sleep(2)
    else:
        wait_rollout("deploy", KH, dep)


def start_attack(ns: str, name: str, args: list[str]) -> tuple[threading.Thread, dict]:
    mkns(ns)
    apply(attack_pod(name, ns, args))
    out: dict = {}
    th = threading.Thread(target=lambda: out.update(watch_attack(ns, name, 240)), daemon=True)
    th.start()
    return th, out


def exists(ns: str, name: str) -> bool:
    return "NotFound" not in subprocess.run(["kubectl", "get", "pod", name, "-n", ns], capture_output=True, text=True).stderr


def result(t0: int, ns: str, name: str, out: dict, since: float | None = None) -> str:
    kl = kill_of(actions(t0), ns, name, out.get("op"))
    if not kl:
        return "killed=n"
    return f"killed=y latency_s={(kl['id'] - out['op']) / 1000:.1f}" + (f" since_restore_s={(kl['id'] - since) / 1000:.1f}" if since else "")


SLOW = ["--num-files", "240", "--rate", "4", "--duration", "60"]


def groups() -> str:
    return " ".join(f"{s.split('.', 1)[1]}:{rc('XINFO', 'GROUPS', s).count('name')}" for s in ("kubeheal.health.events", "kubeheal.security.events", "kubeheal.actions"))


def section_d() -> None:
    r0 = restarts()
    # D1 inference down during an attack
    t0 = now_ms()
    orig = int(k("-n", KH, "get", "deploy", "kubeheal-inference", "-o", "jsonpath={.spec.replicas}") or 1)
    try:
        scale("kubeheal-inference", 0)
        th, out = start_attack("khe-d1", "atk1", SLOW)
        time.sleep(40)
        alive_down = exists("khe-d1", "atk1")
        scale("kubeheal-inference", orig)
        t_up = now_ms()
        th.join(timeout=200)
        row("D", "inference-down", f"pod_alive_while_down={alive_down}", "after_recovery:" + result(t0, "khe-d1", "atk1", out, t_up))
    finally:
        scale("kubeheal-inference", orig)
    t1 = now_ms()
    th, out = start_attack("khe-d1b", "atk2", BENCH_ARGS)
    th.join(timeout=200)
    row("D", "inference-after-recovery", "new attack:" + result(t1, "khe-d1b", "atk2", out))
    # D2 fusion down during an attack
    t0 = now_ms()
    try:
        scale("kubeheal-fusion-agent", 0)
        th, out = start_attack("khe-d2", "atk1", SLOW)
        time.sleep(30)
        alive_down = exists("khe-d2", "atk1")
        scale("kubeheal-fusion-agent", 1)
        t_up = now_ms()
        th.join(timeout=200)
        row("D", "fusion-down", f"pod_alive_while_down={alive_down}", "after_restart:" + result(t0, "khe-d2", "atk1", out, t_up))
    finally:
        scale("kubeheal-fusion-agent", 1)
    # D3 redis restart: AOF on a PVC, so consumer groups and baselines must survive without any agent restart
    g0 = groups()
    b0 = rc("EXISTS", "kubeheal:baseline:demo:victim-app").strip()
    k("-n", KH, "rollout", "restart", "deploy/redis")
    wait_rollout("deploy", KH, "redis")
    time.sleep(45)
    g1 = groups()
    t0 = now_ms()
    th, out = start_attack("khe-d3", "atk1", BENCH_ARGS)
    th.join(timeout=200)
    row("D", "redis-restart", f"groups_before={g0}", f"groups_45s_after={g1}", f"groups_after_attack={groups()}", "attack:" + result(t0, "khe-d3", "atk1", out))
    row("D", "redis-restart-baseline-persisted", f"demo/victim-app baseline exists before={b0}",
        "after=" + rc("EXISTS", "kubeheal:baseline:demo:victim-app").strip())
    # D4 falco restart during benign load
    t0 = now_ms()
    mkns("khe-d4")
    for w in ("logrotate", "tar-gzip-zstd", "sqlite", "rsync"):
        apply(work_pod(w, "khe-d4"))
    time.sleep(45)
    t_r = now_ms()
    k("-n", "falco", "rollout", "restart", "ds/falco")
    wait_rollout("ds", "falco", "falco")
    t_back = now_ms()
    time.sleep(90)
    secs = [s for s in sec(t0) if s.get("namespace") == "khe-d4"]
    acts = [a for a in actions(t0) if a.get("namespace") == "khe-d4"]
    row("D", "falco-restart-benign", f"restart_took_s={(t_back - t_r) / 1000:.0f}", f"sec_events_before={sum(1 for s in secs if s['id'] < t_r)}",
        f"sec_events_after_ready={sum(1 for s in secs if s['id'] >= t_back)}", f"AUTO_KILL={sum(1 for a in acts if a.get('decision') == 'AUTO_KILL')}",
        f"actions={len(acts)}", f"pods={k('get', 'pods', '-n', 'khe-d4', '--no-headers', '-o', 'custom-columns=N:.metadata.name,P:.status.phase').split()}")
    k("delete", "ns", "khe-d4", "--wait=false")
    # D5 load: 20 benign pods + 1 attack
    t0 = now_ms()
    mkns("khe-d5")
    light = ["logrotate", "tar-gzip-zstd", "sqlite", "rsync", "nginx-logs", "git", "redis-bgsave"]
    names = []
    for i, w in enumerate(["postgres", "restic", "pip", "npm", *light * 2][:20]):
        n = f"{w}-{i}"
        apply(work_pod(w, "khe-d5", n))
        names.append(n)
    time.sleep(75)
    th, out = start_attack("khe-d5a", "atk1", BENCH_ARGS)
    th.join(timeout=200)
    atk = result(t0, "khe-d5a", "atk1", out)
    time.sleep(60)
    acts = [a for a in actions(t0) if a.get("namespace") == "khe-d5"]
    phases = k("get", "pods", "-n", "khe-d5", "--no-headers", "-o", "custom-columns=P:.status.phase").split()
    row("D", "load-20-benign+1-attack", "attack:" + atk, f"benign_AUTO_KILL={sum(1 for a in acts if a.get('decision') == 'AUTO_KILL')}",
        f"benign_actions={len(acts)}", f"benign_phases={ {p: phases.count(p) for p in set(phases)} }")
    k("delete", "ns", "khe-d5", "--wait=false")
    r1 = restarts()
    row("D", "agent-restarts", "delta(by pod, excluding deliberate)=" + str({p: r1[p] - r0.get(p, 0) for p in r1 if r1[p] != r0.get(p, 0)}))


# ------------------------------------------------------------------ cleanup / verify
def cleanup() -> None:
    for ns in k("get", "ns", "-o", "name", check=False).split():
        if ns.startswith("namespace/khe-"):
            k("delete", ns, "--wait=false", check=False)
    for _ in range(90):
        if "khe-" not in k("get", "ns", "--no-headers", check=False):
            break
        time.sleep(3)
    clear_keys("khe-")
    left = rc("--scan", "--pattern", "kubeheal:*khe-*").split()
    cap = k("-n", KH, "get", "ds", "kubeheal-security-agent", "-o", "jsonpath={.spec.template.spec.containers[0].env}")
    mode = k("-n", KH, "get", "deploy", "kubeheal-fusion-agent", "-o", "jsonpath={.spec.template.spec.containers[0].env}")
    pods = k("-n", KH, "get", "pods", "--no-headers")
    row("CLEAN", f"khe_ns_left={'khe-' in k('get', 'ns', '--no-headers')}", f"redis_khe_keys_left={len(left)}",
        f"capture0={'KUBEHEAL_CAPTURE' not in cap or '\"KUBEHEAL_CAPTURE\",\"value\":\"0\"' in cap.replace(' ', '')}",
        f"enforce={'enforce' in mode}", f"not_ready={[ln.split()[0] for ln in pods.splitlines() if ln.split()[2] != 'Completed' and ln.split()[1].split('/')[0] != ln.split()[1].split('/')[1]]}")


def main() -> None:
    global OUT, DUR
    ap = argparse.ArgumentParser()
    ap.add_argument("--sections", default="A,F,B,C,E,D")
    ap.add_argument("--out", default=str(ROOT / "training/data/collected/eval"))
    ap.add_argument("--dur", type=int, default=200)
    ap.add_argument("--c-rows", default="", help="only section C rows whose name contains this")
    ap.add_argument("--repeat", type=int, default=1, help="run sections B, C, E this many times (not D)")
    a = ap.parse_args()
    OUT, DUR = Path(a.out), a.dur
    OUT.mkdir(parents=True, exist_ok=True)
    secs = a.sections.split(",")
    row("META", time.strftime("%Y-%m-%d %H:%M"), k("-n", KH, "get", "deploy", "kubeheal-inference", "-o", "jsonpath={.spec.template.spec.containers[0].image}"),
        rc("XREVRANGE", "kubeheal.security.events", "+", "-", "COUNT", "1").split("model_version")[-1].split()[0:1])
    def guarded(name: str, fn, *args) -> None:
        try:
            fn(*args)
        except KubectlError as e:   # reported, not swallowed: the scorecard shows which section broke
            row("ERROR", name + REP, str(e)[:300])

    global REP
    try:
        if "A" in secs:
            section_a()
        if "F" in secs:
            top = Top()
            top.start()
            time.sleep(120)
            top.stop.set()
            top.join()
            top.report("idle-2min")
        for i in range(1, a.repeat + 1):
            REP = f"-r{i}" if a.repeat > 1 else ""
            if "B" in secs:
                top = Top()
                top.start()
                try:
                    guarded("B", section_b, top)
                finally:
                    top.stop.set()
            if "C" in secs:
                if "B" in secs:
                    time.sleep(150)  # let Falco and the agent drain the soak backlog, or detection latency measures the backlog
                guarded("C", section_c, a.c_rows)
            if "E" in secs:
                guarded("E", section_e)
        REP = ""
        if a.repeat > 1:
            for (sec_, key, metric), v in sorted(AGG.items()):
                row("AGG", sec_, key, metric, f"n={len(v)}", f"min={min(v):.2f}", f"median={st.median(v):.2f}", f"max={max(v):.2f}")
        if "D" in secs:
            guarded("D", section_d)
    finally:
        k("-n", KH, "scale", "deploy/kubeheal-fusion-agent", "--replicas=1", check=False)
        k("-n", KH, "scale", "deploy/kubeheal-inference", "--replicas=1", check=False)
        cleanup()

if __name__ == "__main__":
    main()
    sys.exit(0)
