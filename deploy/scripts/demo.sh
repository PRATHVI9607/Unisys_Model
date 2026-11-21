#!/usr/bin/env bash
# KubeHeal v5 one-command demo, enforce mode (really kills pods and patches Deployments, but only objects in its
# own khe-demo-* namespaces, which it deletes on exit together with their Redis keys unless --keep).
#   ./deploy/scripts/demo.sh [--target k3d|minikube] [--keep] [--dry-run] [--force-context NAME]
# Timeline, each line stamped [HH:MM:SS +elapsed]:
#   cluster   (k3d: create `kubeheal` if missing) -> install if KubeHeal is not deployed -> wait Ready
#   benign    a quiet workload runs, nothing happens
#   kill      ransomware-like detection workload (deploy/chaos/) -> AUTO_KILL; detection -> freeze -> action in ms
#   patch     bad image on a Deployment with a baseline -> AUTO_PATCH restores it
#   human     moderate resource drift; if the model is unsure it lands in HUMAN -> approve via the admin API -> executed
#   switch    kill switch to observe -> the same attack only gives would_kill -> back to enforce
#   finish    dashboard port-forward + admin token commands; cleanup
# Cluster guard (deploy/scripts/lib/guard.sh): minikube or k3d-kubeheal only. --dry-run prints the plan, touches nothing.
# The human step depends on the health model finding the drift uncertain: if it decides otherwise the script says so and goes on.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
source deploy/scripts/lib/redis.sh
KH=kubeheal; PFX=khe-demo
NS_BENIGN=$PFX-benign NS_KILL=$PFX-kill NS_PATCH=$PFX-patch NS_HUMAN=$PFX-human NS_OBS=$PFX-observe
CHAOS=kubeheal.invalid/chaos:v5
DASH_PORT=18080
declare -a CREATED=(); PF=""; TOKEN=""; MODE_BEFORE="" MODE_TOUCHED=0; T0=$SECONDS

say() { printf '[%s +%3ss] %s\n' "$(date +%T)" $((SECONDS - T0)) "$*"; }
die() { say "FAIL: $*" >&2; exit 1; }
rc() { kubectl exec -i -n "$KH" $(kh_redis_target) -- redis-cli --raw "$@" 2>&1; }   # admin user via REDISCLI_AUTH

# Redis stream output (--raw) -> one line per entry: "<id> k=v k=v ..." for the keys in $1 (space separated).
# Values lose their spaces; entries come newest first, as XREVRANGE returns them.
parse_stream() {
  awk -v want="$1" 'BEGIN {n = split(want, w, " "); for (i = 1; i <= n; i++) ok[w[i]] = 1}
    cnt % 2 == 0 && /^[0-9]+-[0-9]+$/ {if (line != "") print line; line = $0; cnt = 0; next}
    {cnt++; if (cnt % 2) key = $0; else if (key in ok) {v = $0; gsub(/ /, "_", v); line = line " " key "=" v}}
    END {if (line != "") print line}'
}
field() { local f; for f in $1; do [[ $f == "$2="* ]] && { echo "${f#*=}"; return; }; done; }   # field "<line>" key
actions() { rc XREVRANGE kubeheal.actions + - COUNT 300 | parse_stream "namespace decision outcome timestamp_ms security_event_id pod"; }
# newest action line of namespace $1 whose text matches regex $2
action_of() { actions | grep -E " namespace=$1( |$)" | grep -E -- "${2:-.}" | head -1; }
wait_action() {  # wait_action <ns> <regex> <timeout_s> -> line on stdout
  local end=$((SECONDS + $3)) l
  while ((SECONDS < end)); do l="$(action_of "$1" "$2")"; [[ -n $l ]] && { echo "$l"; return 0; }; sleep 2; done
  return 1
}
now_ms() { date +%s%3N; }

tier_ns() {
  kubectl create ns "$1" >/dev/null && kubectl label ns "$1" kubeheal.io/namespace-tier=prod >/dev/null || die "namespace $1"
  CREATED+=("$1")
}
api() {  # api METHOD PATH [json] -> body on stdout; non-2xx fails
  local out
  out="$(curl -s -m10 -w '\n%{http_code}' -X "$1" -H "Host: localhost" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "http://127.0.0.1:$DASH_PORT$2")" || return 1
  [[ ${out##*$'\n'} == 2* ]] || { echo "${out%$'\n'*}" >&2; return 1; }
  echo "${out%$'\n'*}"
}
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d.get(k) if isinstance(d, dict) else None
print("" if d is None else d)' "$1"; }

cleanup() {
  local rc_=$?; set +e; trap - EXIT INT TERM
  if [[ $MODE_TOUCHED == 1 ]]; then
    if [[ -n $MODE_BEFORE ]]; then rc SET kubeheal:mode "$MODE_BEFORE" >/dev/null; else rc DEL kubeheal:mode >/dev/null; fi
    say "kill switch restored to '${MODE_BEFORE:-<unset>}'"
  fi
  [[ -n $PF ]] && kill "$PF" 2>/dev/null
  if [[ ${#CREATED[@]} -gt 0 && ${KEEP:-0} == 0 ]]; then
    say "cleanup: deleting ${CREATED[*]}"
    kubectl delete ns "${CREATED[@]}" --wait=false --ignore-not-found >/dev/null 2>&1
    kubectl exec -n "$KH" $(kh_redis_target) -- sh -c "redis-cli --scan --pattern 'kubeheal:*$PFX*' | xargs -r -n50 redis-cli DEL >/dev/null" 2>/dev/null
  elif [[ ${#CREATED[@]} -gt 0 ]]; then
    say "--keep: left ${CREATED[*]} (delete: kubectl delete ns ${CREATED[*]})"
  fi
  say "done (exit $rc_)"; exit "$rc_"
}

# ── steps ────────────────────────────────────────────────────────────────────────────────────────

s_cluster() {
  if [[ $TARGET == k3d ]]; then
    command -v k3d >/dev/null || die "need k3d (docs/operations.md)"
    k3d cluster list kubeheal >/dev/null 2>&1 || { say "creating k3d cluster kubeheal"; ./deploy/k3d/create.sh || die "k3d create"; }
    source deploy/k3d/lib.sh   # exports KUBECONFIG=<kubeheal kubeconfig>
    k3d kubeconfig merge kubeheal -o "$KCFG" --kubeconfig-switch-context >/dev/null || die "kubeconfig"
  elif [[ $TARGET == minikube ]]; then
    command -v minikube >/dev/null && minikube status >/dev/null 2>&1 || die "minikube is not running (minikube start)"
  fi
  source deploy/scripts/lib/guard.sh; kh_guard "${GUARD_ARGS[@]}" || exit 1
  [[ $TARGET != k3d || $KH_CTX == k3d-kubeheal ]] || die "--target k3d needs context k3d-kubeheal, have $KH_CTX"
  [[ $TARGET != minikube || $KH_CTX == minikube ]] || die "--target minikube needs context minikube, have $KH_CTX"
  say "cluster: $KH_CTX"
}
s_install() {
  if kubectl get deploy kubeheal-fusion-agent -n "$KH" >/dev/null 2>&1 && kubectl get deploy victim-app -n demo >/dev/null 2>&1; then
    say "KubeHeal already installed"
  else
    say "installing KubeHeal (image builds take a few minutes)"
    ./deploy/scripts/install.sh ${TARGET:+--target "$TARGET"} ${FORCE:+--force-context "$FORCE"} || die "install.sh failed"
  fi
}
s_ready() {
  local d
  for d in redis kubeheal-inference kubeheal-health-agent kubeheal-fusion-agent kubeheal-dashboard; do
    kubectl rollout status deploy/$d -n "$KH" --timeout=300s >/dev/null || die "deploy/$d not ready"
  done
  kubectl rollout status ds/kubeheal-security-agent -n "$KH" --timeout=300s >/dev/null || die "security agent not ready"
  [[ $(rc PING) == PONG ]] || die "redis does not answer"
  MODE_BEFORE="$(rc GET kubeheal:mode)"
  TOKEN="$(kubectl get secret kubeheal-admin -n "$KH" -o jsonpath='{.data.token}' | base64 -d)"; [[ -n $TOKEN ]] || die "no admin token"
  kubectl port-forward -n "$KH" svc/kubeheal-dashboard "$DASH_PORT:8080" >/dev/null 2>&1 & PF=$!
  local _; for _ in $(seq 20); do (exec 3<>"/dev/tcp/127.0.0.1/$DASH_PORT") 2>/dev/null && break; sleep 1; done
  api GET /api/admin/session >/dev/null || die "admin API unreachable or token rejected"
  say "KubeHeal Ready, mode $(api GET /api/mode | jget effective), admin API ok"
  # a fresh install: demo/victim-app's baseline is stored ASSESS_DELAY_S after the health agent starts
}

s_benign() {
  tier_ns $NS_BENIGN
  kubectl apply -n $NS_BENIGN -f - >/dev/null <<YAML || die "benign pod"
apiVersion: v1
kind: Pod
metadata: {name: quiet-writer}
spec:
  securityContext: {runAsNonRoot: true, runAsUser: 10001, fsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: w
      image: $CHAOS
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "i=0; while true; do echo ok \$i > /data/state.txt; i=\$((i+1)); sleep 2; done"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: data, mountPath: /data}]
  volumes: [{name: data, emptyDir: {}}]
YAML
  kubectl wait --for=condition=Ready pod/quiet-writer -n $NS_BENIGN --timeout=120s >/dev/null || die "quiet-writer not ready"
  say "benign workload running (low-rate plain writes); watching 40 s"
  sleep 40
  local l; l="$(action_of $NS_BENIGN 'decision=(AUTO_|HUMAN)')"
  [[ -z $l ]] || die "benign workload got an action: $l"
  kubectl get pod quiet-writer -n $NS_BENIGN >/dev/null 2>&1 || die "benign pod was killed"
  say "benign: no action taken, pod still running"
}

# detection workload in namespace $1 (PVC + deploy/chaos/chaos-pods.yaml); echoes the apply time in ms
attack() {
  kubectl apply -n "$1" -f - >/dev/null <<YAML || die "pvc"
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: victim-data}
spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}
YAML
  local t; t=$(now_ms)
  sed "s/namespace: demo/namespace: $1/" deploy/chaos/chaos-pods.yaml | kubectl apply -f - >/dev/null || die "chaos pod"
  echo "$t"
}
timeline() {  # timeline <ns> <apply_ms> <action line>
  local sid ts det frz act pod
  act=$(field "$3" timestamp_ms); sid=$(field "$3" security_event_id); pod=$(field "$3" pod)
  det=$(rc HGET "kubeheal:security:$sid" timestamp_ms)
  frz=$(rc XREVRANGE kubeheal.contain + - COUNT 100 | parse_stream "namespace pod ts_ms" | grep -E " namespace=$1( |$)" | head -1)
  frz=$(field "$frz" ts_ms)
  [[ $det =~ ^[0-9]+$ ]] || det=""; [[ $frz =~ ^[0-9]+$ ]] || frz=""
  say "  apply -> decision: $((act - $2)) ms"
  [[ -n $det ]] && say "  detection (window end): +$((det - $2)) ms after apply"
  [[ -n $det && -n $frz ]] && say "  detection -> freeze command: $((frz - det)) ms"
  [[ -n $frz ]] && say "  freeze command -> action published (after delete): $((act - frz)) ms"
  [[ -n $det ]] && say "  detection -> action: $((act - det)) ms"
}
s_kill() {
  tier_ns $NS_KILL
  say "starting the ransomware-like detection workload in $NS_KILL"
  local t l; t=$(attack $NS_KILL)
  l="$(wait_action $NS_KILL 'decision=AUTO_KILL' 180)" || die "no AUTO_KILL for $NS_KILL in 180 s"
  say "AUTO_KILL: $(field "$l" outcome)"
  timeline $NS_KILL "$t" "$l"
  local _; for _ in $(seq 20); do kubectl get pod detection-test-workload -n $NS_KILL >/dev/null 2>&1 || break; sleep 2; done
  kubectl get pod detection-test-workload -n $NS_KILL >/dev/null 2>&1 && die "pod still exists after AUTO_KILL"
  say "pod deleted"
}

# Deployment web in $1 with a stored baseline
baselined() {
  kubectl create deploy "$2" -n "$1" --image="$CHAOS" -- sleep 86400 >/dev/null || die "deploy $2"
  kubectl patch deploy "$2" -n "$1" -p '{"spec":{"template":{"spec":{"containers":[{"name":"chaos","imagePullPolicy":"IfNotPresent","resources":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"500m","memory":"128Mi"}}}]}}}}' >/dev/null
  kubectl rollout status deploy/"$2" -n "$1" --timeout=120s >/dev/null || die "deploy $2 not ready"
  local _; for _ in $(seq 70); do [[ $(rc EXISTS "kubeheal:baseline:$1:$2") == 1 ]] && return 0; sleep 2; done
  die "health agent stored no baseline for $1/$2 in 140 s"
}
s_patch() {
  tier_ns $NS_PATCH
  baselined $NS_PATCH web
  say "baseline stored; deploying a bad image (config drift)"
  kubectl set image deploy/web -n $NS_PATCH "*=kubeheal.invalid/chaos:broken" >/dev/null || die "drift"
  local l; l="$(wait_action $NS_PATCH 'decision=AUTO_PATCH' 270)" || die "no AUTO_PATCH for $NS_PATCH in 270 s"
  say "AUTO_PATCH: $(field "$l" outcome)"
  local img _; for _ in $(seq 20); do
    img="$(kubectl get deploy web -n $NS_PATCH -o jsonpath='{.spec.template.spec.containers[0].image}')"; [[ $img == "$CHAOS" ]] && break; sleep 2
  done
  [[ $img == "$CHAOS" ]] || die "image is $img, expected $CHAOS"
  say "image restored to $CHAOS"
}

s_human() {
  tier_ns $NS_HUMAN
  baselined $NS_HUMAN api
  say "applying a moderate resource drift (cpu limit 500m -> 150m, memory 128Mi -> 96Mi)"
  kubectl patch deploy api -n $NS_HUMAN -p '{"spec":{"template":{"spec":{"containers":[{"name":"chaos","resources":{"limits":{"cpu":"150m","memory":"96Mi"}}}]}}}}' >/dev/null || die "drift"
  local end=$((SECONDS + 240)) id="" l=""
  while ((SECONDS < end)); do
    id="$(api GET /api/approvals | NS=$NS_HUMAN python3 -c 'import json,os,sys
print(next((i["action_event_id"] for i in json.load(sys.stdin)["items"] if i["namespace"] == os.environ["NS"] and i["state"] == "pending"), ""))')"
    [[ -n $id ]] && break
    l="$(action_of $NS_HUMAN 'decision=(AUTO_|BENIGN)')"; [[ -n $l ]] && break   # the model was sure either way: no approval will come
    sleep 3
  done
  if [[ -z $id ]]; then
    say "human: the model decided '$(field "${l:-x}" decision)' ($(field "${l:-x}" outcome)), not HUMAN: nothing to approve. Skipping."
    return 0
  fi
  say "HUMAN decision pending (action $id): approving through the admin API"
  api POST "/api/approvals/$id/approve" '{"reason":"demo"}' >/dev/null || die "approve failed"
  local st _; for _ in $(seq 60); do
    st="$(api GET "/api/approvals/$id" | jget state)"; [[ $st == executed || $st == failed || $st == expired ]] && break; sleep 2
  done
  [[ $st == executed ]] || die "approval ended in state '${st:-?}'"
  say "approval executed ($(kubectl get deploy api -n $NS_HUMAN -o jsonpath='{.spec.template.spec.containers[0].resources.limits}'))"
}

set_mode() {
  MODE_TOUCHED=1
  api POST /api/mode "{\"mode\":\"$1\",\"reason\":\"demo\"}" >/dev/null || die "mode $1 rejected"
  local _; for _ in $(seq 20); do [[ $(api GET /api/mode | jget effective) == "$1" ]] && { say "kill switch: effective mode is $1"; return 0; }; sleep 1; done
  die "fusion did not switch to $1"
}
s_switch() {
  set_mode observe
  tier_ns $NS_OBS
  say "same attack in $NS_OBS, mode observe"
  local t l; t=$(attack $NS_OBS)
  l="$(wait_action $NS_OBS 'outcome=would_kill' 180)" || die "no would_kill for $NS_OBS in 180 s"
  say "$(field "$l" decision) -> $(field "$l" outcome): dry-run, nothing was killed"
  kubectl get pod detection-test-workload -n $NS_OBS >/dev/null 2>&1 || die "pod was killed in observe mode"
  say "pod still running"
  set_mode enforce   # cleanup puts back whatever kubeheal:mode held before the demo
}
s_finish() {
  say "dashboard:    kubectl --context $KH_CTX port-forward -n $KH svc/kubeheal-dashboard 8080:8080   then http://localhost:8080"
  say "admin token:  kubectl --context $KH_CTX get secret kubeheal-admin -n $KH -o jsonpath='{.data.token}' | base64 -d"
}

STEPS=(
  "s_cluster|cluster guard (k3d: create if missing), context check"
  "s_install|install KubeHeal unless already deployed"
  "s_ready|wait Ready, admin API + dashboard port-forward"
  "s_benign|benign workload runs: no action"
  "s_kill|ransomware detection workload: AUTO_KILL, detection -> freeze -> kill timeline"
  "s_patch|bad image: AUTO_PATCH restores it"
  "s_human|moderate drift: HUMAN -> approve via admin API -> executed"
  "s_switch|kill switch to observe: would_kill, then back to enforce"
  "s_finish|print dashboard + admin token commands, cleanup"
)

main() {
  TARGET="" KEEP=0 DRY=0 FORCE="" GUARD_ARGS=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target) TARGET="${2:-}"; [[ $TARGET == k3d || $TARGET == minikube ]] || { echo "--target must be k3d or minikube"; exit 1; }; shift 2 ;;
      --keep) KEEP=1; shift ;;
      --dry-run) DRY=1; shift ;;
      --force-context) FORCE="${2:-}"; GUARD_ARGS=(--force-context "$FORCE"); shift 2 ;;
      *) echo "usage: $0 [--target k3d|minikube] [--keep] [--dry-run] [--force-context NAME]"; exit 1 ;;
    esac
  done
  if [[ $DRY == 1 ]]; then
    local s; for s in "${STEPS[@]}"; do echo "plan: ${s%%|*}: ${s#*|}"; done; echo "plan: namespaces ${NS_BENIGN} ${NS_KILL} ${NS_PATCH} ${NS_HUMAN} ${NS_OBS} (deleted at the end unless --keep)"
    exit 0
  fi
  trap cleanup EXIT; trap 'exit 130' INT TERM
  local s; for s in "${STEPS[@]}"; do say "== ${s#*|}"; "${s%%|*}"; done
}
[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"
