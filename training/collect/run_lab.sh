#!/usr/bin/env bash
# Lab data collection run (minikube or any lab cluster kubectl points at; never production).
#
#   training/collect/run_lab.sh --hours 12 [--health-slots 12] [--security-slots 5]   (0 slots = skip that collector)
#   mkdir -p training/data/collected && nohup training/collect/run_lab.sh --hours 12 >> training/data/collected/run_lab.out 2>&1 &
#
# Builds the agents + chaos images, applies deploy/k8s/, port-forwards Redis (localhost:16379) and
# Prometheus (localhost:19090) for the collectors, turns the security agent's capture mode on, and
# runs training/collect/drift_lab.py and security_lab.py concurrently. On any exit (normal, error,
# INT, TERM) it stops the collectors, deletes the lab namespace, restores KUBEHEAL_CAPTURE=0 and
# kills the port-forwards. Resumable: the collectors append to training/data/collected/*.jsonl.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

HOURS="" HEALTH_SLOTS=12 SECURITY_SLOTS=5   # measured on 8 CPU / 8 GB minikube: Falco caps security at ~5-6
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours) HOURS="$2"; shift 2 ;;
    --health-slots) HEALTH_SLOTS="$2"; shift 2 ;;
    --security-slots) SECURITY_SLOTS="$2"; shift 2 ;;
    *) echo "usage: $0 --hours N [--health-slots N] [--security-slots N]" >&2; exit 2 ;;
  esac
done
[[ -n "$HOURS" ]] || { echo "--hours is required" >&2; exit 2; }

OUT="$ROOT/training/data/collected"
mkdir -p "$OUT"
LAB_NS=kubeheal-lab
DS=ds/kubeheal-security-agent
log() { echo "$(date -Is) run_lab: $*"; }

PIDS=() PF=() CLEANED=0
cleanup() {
  [[ $CLEANED == 1 ]] && return
  CLEANED=1
  set +e
  log "cleanup: stopping collectors, restoring capture=0"
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  wait "${PIDS[@]}" 2>/dev/null
  kubectl delete namespace "$LAB_NS" --wait=false --ignore-not-found
  kubectl -n kubeheal set env "$DS" KUBEHEAL_CAPTURE=0 && kubectl -n kubeheal rollout status "$DS" --timeout=300s
  [[ "$(kubectl -n kubeheal get "$DS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="KUBEHEAL_CAPTURE")].value}')" == 0 ]] \
    && log "capture is OFF" || log "ERROR: could not restore KUBEHEAL_CAPTURE=0 — run: kubectl -n kubeheal set env $DS KUBEHEAL_CAPTURE=0"
  for p in "${PF[@]}"; do pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done   # kubectl child first, then its loop
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap '' HUP     # survive a closed terminal even without nohup

log "build images"
minikube image build -t kubeheal/agents:v5 -f deploy/docker/Dockerfile.agents .
minikube image build -t kubeheal/chaos:v5 -f deploy/docker/Dockerfile.chaos .
log "pre-pull lab images"
for img in ghcr.io/stefanprodan/podinfo:{6.9.0,6.10.0,6.12.0,6.13.0,6.14.1} busybox:1.37 busybox:1.37.0 \
           python:3.13-slim redis:7-alpine; do
  minikube image pull "$img"
done

log "apply manifests (capture=0 in the manifest), restart agents on the new image"
kubectl wait --for=delete "namespace/$LAB_NS" --timeout=300s 2>/dev/null || true   # an earlier run's lab may be terminating
kubectl apply -k deploy/k8s/
kubectl -n kubeheal rollout restart deploy/kubeheal-health-agent deploy/kubeheal-fusion-agent
for d in redis kubeheal-inference kubeheal-health-agent kubeheal-fusion-agent; do
  kubectl -n kubeheal rollout status "deploy/$d" --timeout=300s
done

log "capture ON"
kubectl -n kubeheal set env "$DS" KUBEHEAL_CAPTURE=1     # a change vs the manifest: always rolls the DS
kubectl -n kubeheal rollout status "$DS" --timeout=300s

forward() {  # restart on drop (pod restarts, idle timeouts) for the whole run
  while true; do kubectl -n "$1" port-forward "svc/$2" "$3" >>"$OUT/port-forward.log" 2>&1 || true; sleep 2; done
}
forward kubeheal redis-master 16379:6379 & PF+=($!)
forward monitoring prometheus-operated 19090:9090 & PF+=($!)
for _ in $(seq 30); do
  curl -sf localhost:19090/-/ready >/dev/null && (exec 3<>/dev/tcp/127.0.0.1/16379) 2>/dev/null && break
  sleep 1
done

log "collect for ${HOURS}h: health slots $HEALTH_SLOTS, security slots $SECURITY_SLOTS -> $OUT"
# 0 slots skips that collector (e.g. security-only after the health target is reached)
if [[ $HEALTH_SLOTS -gt 0 ]]; then
  uv run --all-extras python -m training.collect.drift_lab --hours "$HOURS" --slots "$HEALTH_SLOTS" >>"$OUT/health.log" 2>&1 & PIDS+=($!)
fi
if [[ $SECURITY_SLOTS -gt 0 ]]; then
  uv run --all-extras python -m training.collect.security_lab --hours "$HOURS" --slots "$SECURITY_SLOTS" >>"$OUT/security.log" 2>&1 & PIDS+=($!)
fi
[[ ${#PIDS[@]} -gt 0 ]] || { echo "nothing to collect: both slot counts are 0" >&2; exit 2; }

# Resource log (node, Prometheus, Redis, Falco events file + queue drops) once a minute while collecting.
resources() {
  set +e   # best-effort log: a failed kubectl top / exec must not end the loop
  while true; do
    { echo "--- $(date -Is)"
      kubectl top node --no-headers
      kubectl -n monitoring top pod -l app.kubernetes.io/name=prometheus --no-headers
      kubectl -n kubeheal exec deploy/redis -- redis-cli info memory | grep '^used_memory_human'
      kubectl -n kubeheal exec "$DS" -- python -c \
        "import os; s=os.stat('/var/run/falco/events.jsonl'); print('falco_events size', s.st_size, 'allocated', s.st_blocks*512)"
      # Falco over capacity drops alerts (deploy/k8s/helm/falco-values.yaml outputs_queue): fewer security slots if > 0
      echo "falco_queue_drop_logs_last_min $(kubectl -n falco logs ds/falco -c falco --since=60s | grep -c 'queue out of memory')"
    } >>"$OUT/resources.log" 2>&1
    sleep 60
  done
}
resources & PF+=($!)

rc=0
for p in "${PIDS[@]}"; do wait "$p" || rc=$?; done
log "collectors finished (rc=$rc)"
exit "$rc"
