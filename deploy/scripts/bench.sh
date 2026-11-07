#!/usr/bin/env bash
# Reproducible resource + kill-latency benchmark against the DEPLOYED stack (enforce mode).
#   ./deploy/scripts/bench.sh [--duration 300] [--runs 5] [--out training/data/collected/bench-<ts>.json]
# Phase 1: benign heavy-I/O pod (protected) loads Falco; every 15 s sample kubectl top (falco,
#   security agent, inference) and the Falco events file size. Phase 2: run the detection workload
#   --runs times sequentially (unprotected) and time the first malicious op (the workload logs it) -> kill (actions-stream entry).
# Cleans up the kubeheal-bench namespace and its circuit breakers on exit.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
NS=kubeheal-bench; KH=kubeheal; DURATION=300; RUNS=5; OUT="training/data/collected/bench-$(date +%s).json"
while [ $# -gt 0 ]; do case $1 in
  --duration) DURATION=$2; shift 2;; --runs) RUNS=$2; shift 2;; --out) OUT=$2; shift 2;;
  *) echo "usage: $0 [--duration S] [--runs N] [--out FILE]"; exit 1;; esac; done
command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }
mkdir -p "$(dirname "$OUT")"; TMP=$(mktemp -d)

reset_cb() {  # per-workload circuit breakers would trip after MAX_KILLS_PER_HOUR
  kubectl -n $KH exec deploy/redis -- sh -c \
    "redis-cli --scan --pattern 'kubeheal:cb:*kubeheal-bench*' | xargs -r redis-cli DEL >/dev/null" || true
}
cleanup() { kubectl delete ns $NS --ignore-not-found --wait=false >/dev/null 2>&1 || true; reset_cb; rm -rf "$TMP"; }
trap cleanup EXIT

kubectl delete ns $NS --ignore-not-found --wait=true >/dev/null
kubectl create ns $NS >/dev/null
kubectl label ns $NS kubeheal.io/namespace-tier=prod >/dev/null
reset_cb
kubectl apply -n $NS -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Pod
metadata: {name: io-load, labels: {kubeheal.io/protected: "true"}}
spec:
  containers:
    - name: load
      image: busybox:1.36
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "while true; do dd if=/dev/urandom of=/data/a bs=1M count=64 2>/dev/null; cp /data/a /data/b; md5sum /data/a /data/b >/dev/null; rm -f /data/a /data/b; done"]
      volumeMounts: [{name: data, mountPath: /data}]
  volumes: [{name: data, emptyDir: {}}]
YAML
kubectl wait -n $NS --for=condition=Ready pod/io-load --timeout=120s >/dev/null

# stat only (apparent bytes, allocated blocks, block size): the events file is sparse, never read it.
# Exec into Falco (has coreutils; the agent image has no stat) so the agent's memory cgroup is untouched.
fsize() { kubectl exec -n falco ds/falco -c falco -- stat -c '%s %b %B' /var/run/falco/events.jsonl; }
echo ">> sampling every 15 s for ${DURATION} s"
T0=$(date +%s); S0=$(fsize)
while :; do  # always at least one sample, even when --duration < 15
  # one line per tick, only when falco, a security agent and inference were all seen: falco cpu/mem,
  # security-agent cpu/mem, inference cpu. Summed over pods; cpu in millicores, memory in Mi.
  kubectl top pod -A --no-headers 2>/dev/null | awk '
    function cpu(v) { return v ~ /m$/ ? v + 0 : v * 1000 }
    function mem(v) { return v ~ /Gi$/ ? v * 1024 : v ~ /Ki$/ ? v / 1024 : v + 0 }
    $1=="falco"{f+=cpu($3);fm+=mem($4);nf++} $2~/kubeheal-security/{s+=cpu($3);sm+=mem($4);ns++}
    $2~/kubeheal-inference/{i+=cpu($3);ni++}
    END{if(nf&&ns&&ni) printf "%d %d %d %d %d\n", f,fm,s,sm,i}' >> "$TMP/top.txt" || true
  REM=$(( DURATION - ($(date +%s) - T0) )); [ "$REM" -gt 0 ] || break
  sleep $(( REM < 15 ? REM : 15 ))
done
S1=$(fsize); T1=$(date +%s); echo "$S0 $S1 $((T1-T0))" > "$TMP/events.txt"

for i in $(seq 1 "$RUNS"); do
  echo ">> detection run $i/$RUNS"; reset_cb
  kubectl apply -n $NS -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: chaos-$i, labels: {kubeheal.io/chaos: "true"}}
spec:
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 10001, fsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  initContainers:
    - {name: mark-sandbox, image: "kubeheal/chaos:v5", imagePullPolicy: IfNotPresent, command: ["sh","-c","touch /data/.kubeheal-sandbox"], volumeMounts: [{name: data, mountPath: /data}]}
  containers:
    - name: workload
      image: kubeheal/chaos:v5
      imagePullPolicy: IfNotPresent
      args: ["--sandbox", "/data", "--num-files", "400", "--rate", "20", "--duration", "60"]
      volumeMounts: [{name: data, mountPath: /data}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
  volumes: [{name: data, emptyDir: {}}]
YAML
  OPMS=""; END=$((SECONDS+240))
  while [ $SECONDS -lt $END ]; do   # until the pod is gone (killed) or the deadline
    kubectl get pod chaos-$i -n $NS >/dev/null 2>&1 || break
    # the workload prints the epoch ms of its first overwrite (the first malicious op) in its log
    [ -n "$OPMS" ] || OPMS=$(kubectl logs chaos-$i -n $NS -c workload 2>/dev/null | sed -n 's/^overwrite_start_ms=//p' | head -1) || true
    sleep 0.5
  done
  kubectl delete pod chaos-$i -n $NS --ignore-not-found --wait=false >/dev/null
  kubectl -n $KH exec deploy/redis -- redis-cli XREVRANGE kubeheal.actions + - COUNT 200 > "$TMP/actions-$i.txt" || true
  kubectl -n $KH exec deploy/redis -- redis-cli XREVRANGE kubeheal.security.events + - COUNT 300 > "$TMP/sec-$i.txt" || true
  echo "chaos-$i ${OPMS:-none}" >> "$TMP/kills.txt"
done

python3 - "$TMP" "$NS" "$OUT" "$DURATION" <<'PY'
import sys, re, json, statistics as st
from datetime import datetime
tmp, ns, out, dur = sys.argv[1:]
def pct(v, p): v = sorted(v); return v[min(len(v)-1, int(round(p/100*(len(v)-1))))] if v else None
warnings = []
def rd(name):  # file text, "" if the shell never wrote it
    try: return open(f"{tmp}/{name}").read()
    except OSError: return ""
mx = lambda v: max(v) if v else None
rows = [list(map(int, l.split())) for l in rd("top.txt").splitlines() if len(l.split()) == 5]
if not rows: warnings.append("no resource samples: duration shorter than the sampling interval, or falco/security-agent/inference never all reported in kubectl top (metrics-server lag)")
col = lambda k: [r[k] for r in rows]
fc, fm, sc, sm, ic = (col(k) for k in range(5))
ev = rd("events.txt").split()
if len(ev) == 7: a0, b0, z0, a1, b1, z1, el = map(int, ev)
else: a0 = a1 = b1 = z1 = el = None; warnings.append("no events-file stats: stat on the falco events file failed")
backlog = b1 * z1 if ev and a1 is not None else None  # allocated bytes: the sparse file's unread backlog (hole punching), not the output rate
def entries(path):  # raw redis-cli XREVRANGE: id line, then field/value lines per entry
    recs = []
    for l in rd(path.rsplit("/", 1)[1]).split("\n"):
        if re.fullmatch(r"\d+-\d+", l): recs.append({"id": int(l.split("-")[0]), "f": []})
        elif recs: recs[-1]["f"].append(l)
    return [{"id": r["id"], **dict(zip(r["f"][::2], r["f"][1::2]))} for r in recs]
kills = []
for ln in rd("kills.txt").splitlines():
    pod, op = ln.split(); i = pod.split("-")[1]; op = None if op == "none" else int(op)
    mine = lambda e: e.get("namespace") == ns and e.get("pod") == pod and op is not None and e["id"] >= op
    acts = sorted((e for e in entries(f"{tmp}/actions-{i}.txt") if mine(e)), key=lambda e: e["id"])
    secs = sorted((e for e in entries(f"{tmp}/sec-{i}.txt") if mine(e)), key=lambda e: e["id"])
    kill = next((e for e in acts if e.get("outcome") == "pod_killed"), None)
    first = secs[0] if secs else None
    certain = next((e for e in secs if e.get("uncertain") == "0"), None)
    k = lambda e: e["id"] - op if e else None   # ms from the first malicious op to the stream entry
    if op is None: warnings.append(f"{pod}: workload never logged overwrite_start_ms, no latency")
    elif not acts: warnings.append(f"{pod}: no actions-stream entry after the first malicious op (not killed, or stream read failed)")
    elif kill is None: warnings.append(f"{pod}: actions seen but none with outcome pod_killed")
    kills.append({"pod": pod, "first_op_ms": op, "first_security_event_ms": k(first), "first_certain_event_ms": k(certain),
                  "kill_ms_action": k(kill),   # action entry is written after the pod delete returned
                  "actions": [(e["decision"], e["outcome"], k(e)) for e in acts[:3]]})
ka = [k["kill_ms_action"] for k in kills if k["kill_ms_action"] is not None]
if not kills: warnings.append("no detection runs (--runs 0)")
json.dump({"duration_s": int(dur), "samples": len(rows),
  "falco_cpu_m": {"p50": pct(fc, 50), "p95": pct(fc, 95), "max": mx(fc)},
  "falco_mem_mi": {"p50": pct(fm, 50), "max": mx(fm)},
  "sec_agent_cpu_m": {"p50": pct(sc, 50), "p95": pct(sc, 95), "max": mx(sc)},
  "sec_agent_mem_mi": {"p50": pct(sm, 50), "max": mx(sm)},
  "inference_cpu_m_total": {"p50": pct(ic, 50), "p95": pct(ic, 95), "max": mx(ic)},
  "events_bytes_per_s": round((a1 - a0) / max(el, 1), 1) if el is not None else None, "events_backlog_bytes": backlog,
  "kill_ms": ka, "kill_ms_median": st.median(ka) if ka else None, "kills": kills, "warnings": warnings},
  open(out, "w"), indent=2)
print(open(out).read())
PY
