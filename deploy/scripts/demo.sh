#!/usr/bin/env bash
# KubeHeal v5 demo, enforce mode (fusion really patches Deployments and
# quarantines + kills pods; safety rails: confidence gates, protected
# namespaces / kubeheal.io/protected, per-workload circuit breakers).
#   A) config drift on demo/victim-app (podinfo under load): CPU limit 500m -> 20m.
#      The health agent scores it ASSESS_DELAY_S (60 s; sooner on a failed rollout or posture violation) after the change on the
#      post-change metric window; fusion decides (AUTO_PATCH restores the
#      baseline template; HUMAN/OBSERVE leave it for a person).
#   B) ransomware-like detection workload (deploy/chaos/) -> Falco -> security model ->
#      AUTO_KILL: pod labelled kubeheal.io/quarantined, deny-all NetworkPolicy,
#      pod deleted (the policy is garbage-collected with it).
# Prompts between steps when run from a terminal; runs straight through otherwise.
#   ./deploy/scripts/demo.sh            # A then B
#   ./deploy/scripts/demo.sh --seed     # also seed sample (fake) actions first; nothing is written to the health/security streams
# Run ./deploy/scripts/reset.sh first for a clean slate (it also resets circuit breakers).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
NS=demo; KH=kubeheal

command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }
kubectl get ns "$KH" >/dev/null 2>&1 || { echo "run ./deploy/scripts/install.sh first"; exit 1; }
kubectl get deploy victim-app -n "$NS" >/dev/null 2>&1 || { echo "demo/victim-app missing — run install.sh"; exit 1; }
DELAY=$(kubectl get deploy kubeheal-health-agent -n "$KH" \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ASSESS_DELAY_S")].value}')
DELAY=${DELAY:-60}
[ "${1:-}" = "--seed" ] && ./deploy/scripts/seed_demo.sh

pause() { if [ -t 0 ]; then read -rp "$1 [ENTER] "; else echo ">> $1"; fi; }
template() { kubectl get deploy victim-app -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].resources}'; echo; }
# Wait until fusion logs a decision for $1 (namespace/workload) after time $2 (RFC 3339).
await_decision() {
  local deadline=$((SECONDS + $3))
  until kubectl logs deploy/kubeheal-fusion-agent -n "$KH" --since-time="$2" | grep " $1 " >/dev/null; do
    [ $SECONDS -ge $deadline ] && { echo "!! no decision for $1 within $3 s"; return 1; }
    sleep 2
  done
  kubectl logs deploy/kubeheal-fusion-agent -n "$KH" --since-time="$2" | grep " $1 "
}

# Dashboard port-forward (background; cleaned up on exit).
if ! curl -sf -m1 http://localhost:8080/healthz >/dev/null 2>&1; then
  kubectl port-forward -n "$KH" svc/kubeheal-dashboard 8080:8080 >/tmp/kh-dash-pf.log 2>&1 &
  PF=$!; trap 'kill $PF 2>/dev/null || true' EXIT
  for _ in $(seq 1 15); do curl -sf -m1 http://localhost:8080/healthz >/dev/null 2>&1 && break; sleep 1; done
  kill -0 "$PF" 2>/dev/null || { echo "port-forward failed:"; cat /tmp/kh-dash-pf.log; exit 1; }
fi
echo ">> Dashboard: http://localhost:8080"

pause "Demo A — config drift: CPU limit 500m -> 20m on demo/victim-app"
echo "before: $(template)"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Strategic merge patches the container by name; request must stay <= limit.
kubectl patch deployment victim-app -n "$NS" --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"20m"},"requests":{"cpu":"20m"}}}]}}}}'
echo "drifted: $(template)"
echo "Health agent assesses in ${DELAY}s (metrics window = [change, change + ${DELAY}s])..."
await_decision "demo/victim-app" "$T0" $((DELAY + 90))
sleep 3
echo "after:  $(template)"
echo "(AUTO_PATCH restores the baseline template; HUMAN/OBSERVE leave the drift for a person —"
echo " ./deploy/scripts/reset.sh puts it back.)"

pause "Demo B — ransomware-like detection workload in demo"
kubectl delete pod detection-test-workload -n "$NS" --ignore-not-found --wait=true >/dev/null
T1=$(date -u +%Y-%m-%dT%H:%M:%SZ); S1=$SECONDS
kubectl apply -f deploy/chaos/chaos-pods.yaml
await_decision "demo/detection-test-workload" "$T1" 90
echo "decision $((SECONDS - S1))s after kubectl apply"
sleep 2
echo "pod: $(kubectl get pod detection-test-workload -n "$NS" --no-headers 2>&1 || true)"
echo "quarantine policies: $(kubectl get networkpolicy -n "$NS" -o name 2>&1 | grep -c kubeheal-quarantine || true) (GC'd with the pod)"
echo "Demo complete. Click any event row on the dashboard for the full analysis."
[ -n "${PF:-}" ] && [ -t 0 ] && { echo "(Ctrl-C stops the port-forward.)"; wait "$PF"; } || true
