#!/usr/bin/env bash
# Deploy smoke test, run after install.sh (enforce mode: it really kills and patches, but only objects in its
# own khe-smoke-* namespaces, which it deletes on exit together with their Redis keys).
#   1 pods      every pod in kubeheal is Ready (Completed Job pods excepted)
#   2 acl       each Redis user authenticates, and ACL DRYRUN allows/denies the expected commands
#   3 inference /readyz through the API-server service proxy
#   4 dashboard /api/stats through a port-forward, with a Host header the app accepts
#   5 kill      detection-test workload (deploy/chaos/) in a sandbox PVC namespace -> AUTO_KILL, pod gone
#   6 patch     failed rollout (bad image) on a Deployment with a baseline -> AUTO_PATCH restores the image
# Cluster guard: minikube or k3d-kubeheal (deploy/scripts/lib/guard.sh). Exits non-zero on the first failure.
#   ./deploy/scripts/smoke.sh [--force-context NAME] [--skip-dashboard]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
source deploy/scripts/lib/guard.sh; kh_guard "$@" || exit 1; set -- "${KH_REST[@]}"
DASH=1; [[ ${1:-} == --skip-dashboard ]] && { DASH=0; shift; }   # the dashboard is not deployed with --production
[[ $# -eq 0 ]] || { echo "usage: $0 [--force-context NAME] [--skip-dashboard]"; exit 1; }
KH=kubeheal; SEC_NS=khe-smoke-sec; HEALTH_NS=khe-smoke-health
declare -a TIMES=(); PF=""; T0=$SECONDS
rc() { kubectl exec -i -n "$KH" deploy/redis -- redis-cli --raw "$@" 2>&1; }   # admin user via REDISCLI_AUTH
step() { STEP="$1"; S=$SECONDS; echo "== $1"; }
ok() { TIMES+=("$(printf '%-10s %4ss  PASS' "$STEP" $((SECONDS - S)))"); echo "   ok ($((SECONDS - S))s)"; }
fail() {
  echo "!! FAIL [$STEP]: $*" >&2
  TIMES+=("$(printf '%-10s %4ss  FAIL  %s' "$STEP" $((SECONDS - S)) "$*")"); exit 1
}
cleanup() {
  local rc_=$?; set +e
  [[ -n $PF ]] && kill "$PF" 2>/dev/null
  kubectl delete ns "$SEC_NS" "$HEALTH_NS" --wait=false --ignore-not-found >/dev/null 2>&1
  kubectl exec -n "$KH" deploy/redis -- sh -c "redis-cli --scan --pattern 'kubeheal:*khe-smoke*' | xargs -r -n50 redis-cli DEL >/dev/null" 2>/dev/null
  echo; printf '%s\n' "${TIMES[@]}"; echo "total $((SECONDS - T0))s  exit $rc_"
}
trap cleanup EXIT

step pods
for _ in $(seq 100); do
  bad="$(kubectl get pods -n "$KH" --no-headers 2>&1 | awk '$3=="Completed"{next} {split($2,r,"/"); if ($3!="Running" || r[1]!=r[2]) print $1" "$2" "$3}')"
  [[ -z $bad ]] && break; sleep 3
done
[[ -z $bad ]] || fail "not ready: $bad"
[[ $(kubectl get pods -n "$KH" --no-headers | wc -l) -ge 6 ]] || fail "fewer than 6 pods in $KH"
ok

step acl
pw() { kubectl get secret kubeheal-redis -n "$KH" -o jsonpath="{.data.$1-password}" | base64 -d; }
for u in health security fusion dashboard; do
  out="$(kubectl exec -n "$KH" deploy/redis -- redis-cli --user "$u" --pass "$(pw $u)" --no-auth-warning ping 2>&1)"
  [[ $out == PONG ]] || fail "user $u cannot authenticate: $out"
done
[[ $(kubectl exec -n "$KH" deploy/redis -- redis-cli --user dashboard --pass wrong --no-auth-warning ping 2>&1) != PONG ]] || fail "wrong password accepted"
# user | OK or NO | command (ACL DRYRUN: nothing is executed)
while IFS='|' read -r u want cmd; do
  [[ -z $u ]] && continue
  got="$(rc ACL DRYRUN "$u" $cmd)"; [[ $got == OK ]] && got=OK || got=NO
  [[ $got == "$want" ]] || fail "ACL: $u '$cmd' expected $want, got $got"
done <<'ACL'
health|OK|SET kubeheal:baseline:ns:w v
health|NO|SET kubeheal:mode observe
health|NO|EVAL x 0
security|OK|XADD kubeheal.security.events * a b
security|NO|SET kubeheal:baseline:ns:w v
fusion|OK|XREADGROUP GROUP fusion c1 STREAMS kubeheal.approvals >
fusion|OK|XACK kubeheal.approvals fusion 1-1
fusion|OK|XAUTOCLAIM kubeheal.approvals fusion c1 60000 0
fusion|OK|XGROUP CREATE kubeheal.approvals fusion $ MKSTREAM
fusion|OK|XGROUP DELCONSUMER kubeheal.approvals fusion c1
fusion|OK|XINFO CONSUMERS kubeheal.approvals fusion
fusion|OK|XPENDING kubeheal.approvals fusion
fusion|OK|XADD kubeheal.ledger MINID ~ 1 * a b
fusion|OK|GET kubeheal:mode
fusion|OK|SET kubeheal:approval:x v
fusion|OK|EVAL x 0
dashboard|OK|GET kubeheal:baseline:ns:w
dashboard|OK|XREVRANGE kubeheal.ledger + - COUNT 5
dashboard|OK|XRANGE kubeheal.ledger - +
dashboard|OK|XREAD COUNT 1 STREAMS kubeheal.actions 0
dashboard|OK|HGETALL kubeheal:action:a1
dashboard|OK|MGET kubeheal:approval:a kubeheal:approval:b
dashboard|OK|XADD kubeheal.approvals * a b
dashboard|OK|XADD kubeheal.ledger * a b
dashboard|OK|SET kubeheal:mode observe
dashboard|OK|SET kubeheal:approval:x v
dashboard|OK|GET kubeheal:approval:x
dashboard|OK|WATCH kubeheal:approval:x
dashboard|OK|MULTI
dashboard|OK|EXEC
dashboard|NO|SET kubeheal:baseline:ns:w v
dashboard|NO|SET kubeheal:spec:ns:w v
dashboard|NO|SET kubeheal:lock:ns:Deployment/w v
dashboard|NO|SET kubeheal:cb:kill:ns:Deployment/w v
dashboard|NO|SET kubeheal:done:e v
dashboard|NO|DEL kubeheal:approval:x
dashboard|NO|XADD kubeheal.actions * a b
dashboard|NO|XADD kubeheal.health.events * a b
dashboard|NO|EVAL x 0
dashboard|NO|FLUSHALL
ACL
ok

# port-forward svc/$1 port $2 to localhost:$3 (not subject to NetworkPolicy, unlike the API-server service proxy)
forward() {
  kubectl port-forward -n "$KH" "svc/$1" "$3:$2" >/dev/null 2>&1 & PF=$!
  for _ in $(seq 20); do (exec 3<>"/dev/tcp/127.0.0.1/$3") 2>/dev/null && return 0; sleep 1; done
  fail "port-forward svc/$1 failed"
}

step inference
forward kubeheal-inference 8000 18000
out="$(curl -s -m5 -w ' http=%{http_code}' http://127.0.0.1:18000/readyz)"; echo "   $out" | cut -c1-120
[[ $out == *"http=200" ]] || fail "readyz: $out"
kill "$PF"; PF=""; ok

if [[ $DASH == 1 ]]; then
  step dashboard
  forward kubeheal-dashboard 8080 18080
  curl -sf -m5 -H 'Host: localhost' http://127.0.0.1:18080/api/stats | head -c 200; echo
  [[ ${PIPESTATUS[0]} == 0 ]] || fail "/api/stats not reachable"
  [[ $(curl -s -m5 -o /dev/null -w '%{http_code}' -H 'Host: evil.example' http://127.0.0.1:18080/api/stats) == 400 ]] || fail "foreign Host header not rejected"
  kill "$PF"; PF=""; ok
fi

# decision $1 (AUTO_KILL|AUTO_PATCH) for namespace $2 in the actions stream?
acted() {
  rc XREVRANGE kubeheal.actions + - COUNT 300 | awk -v ns="$2" -v d="$1" '
    /^[0-9]+-[0-9]+$/ {a=0; b=0} $0=="namespace" {getline v; if (v==ns) a=1} $0=="decision" {getline v; if (v==d) b=1}
    a && b {print "HIT"; exit}' | grep -q HIT
}
tier_ns() { kubectl create ns "$1" >/dev/null && kubectl label ns "$1" kubeheal.io/namespace-tier=prod >/dev/null; }

step kill
tier_ns "$SEC_NS"
kubectl apply -n "$SEC_NS" -f - >/dev/null <<YAML || fail "pvc"
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: victim-data}
spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}
YAML
sed "s/namespace: demo/namespace: $SEC_NS/" deploy/chaos/chaos-pods.yaml | kubectl apply -f - >/dev/null || fail "chaos pod"
for _ in $(seq 60); do acted AUTO_KILL "$SEC_NS" && break; sleep 3; done
acted AUTO_KILL "$SEC_NS" || fail "no AUTO_KILL for $SEC_NS in 180s"
for _ in $(seq 20); do kubectl get pod detection-test-workload -n "$SEC_NS" >/dev/null 2>&1 || break; sleep 2; done
kubectl get pod detection-test-workload -n "$SEC_NS" >/dev/null 2>&1 && fail "pod still exists after AUTO_KILL"
ok

step patch
tier_ns "$HEALTH_NS"
GOOD=kubeheal.invalid/chaos:v5
kubectl create deploy web -n "$HEALTH_NS" --image="$GOOD" -- sleep 86400 >/dev/null || fail "create deploy"
kubectl patch deploy web -n "$HEALTH_NS" -p '{"spec":{"template":{"spec":{"containers":[{"name":"chaos","imagePullPolicy":"IfNotPresent"}]}}}}' >/dev/null
kubectl rollout status deploy/web -n "$HEALTH_NS" --timeout=120s >/dev/null || fail "deploy not ready"
for _ in $(seq 60); do [[ $(rc EXISTS "kubeheal:baseline:$HEALTH_NS:web") == 1 ]] && break; sleep 2; done
[[ $(rc EXISTS "kubeheal:baseline:$HEALTH_NS:web") == 1 ]] || fail "health agent stored no baseline in 120s"
kubectl set image deploy/web -n "$HEALTH_NS" "*=kubeheal.invalid/chaos:broken" >/dev/null || fail "drift"
for _ in $(seq 90); do acted AUTO_PATCH "$HEALTH_NS" && break; sleep 3; done
acted AUTO_PATCH "$HEALTH_NS" || fail "no AUTO_PATCH for $HEALTH_NS in 270s"
for _ in $(seq 20); do
  img="$(kubectl get deploy web -n "$HEALTH_NS" -o jsonpath='{.spec.template.spec.containers[0].image}')"
  [[ $img == "$GOOD" ]] && break; sleep 2
done
[[ $img == "$GOOD" ]] || fail "image is $img, expected $GOOD"
ok
echo "SMOKE PASS"
