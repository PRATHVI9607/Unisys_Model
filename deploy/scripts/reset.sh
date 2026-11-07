#!/usr/bin/env bash
# Return the demo to a clean baseline: drop chaos pods + quarantine policies,
# recreate demo/victim-app from its manifest, clear the KubeHeal Redis streams
# and keys (events, baselines, circuit breakers, locks), and restart the agents
# so their in-memory state matches (fusion recreates its consumer group, the
# health agent re-learns the restored spec as the baseline on first sight).
set -euo pipefail
NS=demo; KH=kubeheal
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }

echo "Removing chaos workloads + quarantine network policies..."
kubectl delete deploy,pod -l kubeheal.io/chaos=true -n "$NS" --ignore-not-found --grace-period=0 --force 2>/dev/null
# Quarantine policies are owned by their pod and GC'd with it; delete any leftovers.
kubectl get networkpolicy -n "$NS" -o name | { grep '/kubeheal-quarantine-' || true; } \
  | xargs -r kubectl delete -n "$NS" --ignore-not-found

echo "Recreating demo/victim-app from deploy/demo/victim-app.yaml..."
# delete + apply: `apply` alone would keep fields set imperatively (kubectl set/patch/scale).
kubectl delete deploy victim-app -n "$NS" --ignore-not-found --wait=true
kubectl apply -f deploy/demo/victim-app.yaml
kubectl rollout status deploy/victim-app -n "$NS" --timeout=180s

echo "Clearing Redis streams + KubeHeal keys..."
kubectl exec -n "$KH" deploy/redis -- sh -c '
  redis-cli DEL kubeheal.health.events kubeheal.security.events kubeheal.actions kubeheal.deadletter >/dev/null
  redis-cli --scan --pattern "kubeheal:*" | while read -r k; do redis-cli DEL "$k" >/dev/null; done
'

echo "Restarting agents..."
kubectl rollout restart deploy/kubeheal-health-agent deploy/kubeheal-fusion-agent ds/kubeheal-security-agent -n "$KH"
kubectl rollout status deploy/kubeheal-fusion-agent -n "$KH" --timeout=180s
kubectl rollout status deploy/kubeheal-health-agent -n "$KH" --timeout=180s
kubectl rollout status ds/kubeheal-security-agent -n "$KH" --timeout=180s
DELAY=$(kubectl get deploy kubeheal-health-agent -n "$KH" \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ASSESS_DELAY_S")].value}')
echo "Reset complete. The health agent stores baselines ${DELAY:-60}s after start; wait that long before"
echo "./deploy/scripts/demo.sh. (Leftover khtest_* files on the PVC are harmless test artifacts.)"
