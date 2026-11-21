#!/usr/bin/env bash
# Shared by the real-world cluster scripts (source it; do not run). Provides:
#   - the cluster guard (deploy/scripts/lib/guard.sh): minikube / k3d-kubeheal only, context pinned
#   - --dry-run: kubectl/helm/docker/k3d/git only print what they would do, polls return at once, nothing is touched
#   - namespace hygiene: every object lives in a khe-rw-* namespace; the EXIT trap deletes them and their Redis keys
#   - rw_undo: register a command that restores a fault injection (run in reverse order on exit, also on Ctrl-C)
#   - check: record one PASS/FAIL assertion; the script exits non-zero when any failed
# Usage:  source lib.sh; RW_NAME=soak; rw_init "$@"; set -- "${RW_REST[@]}"
set -uo pipefail
RW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$RW_DIR/../../.." && pwd)"
source "$ROOT/deploy/scripts/lib/guard.sh"
KH=kubeheal; RW_PREFIX=khe-rw-; RW_DRY=0; RW_UNDO=(); RW_FAILS=0; RW_T0=$SECONDS; RW_T0_MS=$(date +%s%3N); RW_NAME="${RW_NAME:-rw}"

say() { echo "[$(date +%H:%M:%S)] $*" >&2; }
die() { say "FATAL: $*"; exit 1; }
rw_undo() { RW_UNDO+=("$*"); }
rw_sleep() { (( RW_DRY )) || sleep "$1"; }

rw_init() {
  RW_REST=(); local a
  for a in "$@"; do if [[ $a == --dry-run ]]; then RW_DRY=1; else RW_REST+=("$a"); fi; done
  export RW_DRY
  if (( RW_DRY )); then
    for t in kubectl helm docker k3d git; do eval "$t() { echo \"[dry-run] $t \$*\" >&2; return 0; }"; done
    export KH_CTX=dry-run
  else
    kh_guard "${RW_REST[@]}" || exit 2
    RW_REST=("${KH_REST[@]}")
  fi
  RW_OUT="${RW_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/kubeheal-rw-XXXXXX")}"; export RW_OUT
  : > "$RW_OUT/results.tsv"
  trap rw_cleanup EXIT; trap 'exit 130' INT TERM
  say "$RW_NAME: context $KH_CTX, results in $RW_OUT$( (( RW_DRY )) && echo ' (DRY RUN)')"
}

rw_ns() { [[ $1 =~ ^[a-z0-9-]+$ ]] || die "bad namespace suffix '$1'"; echo "${RW_PREFIX}$1"; }
rw_mkns() {   # only khe-rw-* namespaces are ever created or deleted by these scripts
  [[ $1 == ${RW_PREFIX}* ]] || die "refusing namespace '$1' (must start with $RW_PREFIX)"
  kubectl create ns "$1" >/dev/null 2>&1; kubectl label ns "$1" kubeheal.io/namespace-tier=prod --overwrite >/dev/null
}
rc() { kubectl exec -i -n "$KH" deploy/redis -- redis-cli --raw "$@" 2>&1; }   # admin user via the pod's REDISCLI_AUTH
rwpy() { RW_DRY=$RW_DRY KH_CTX=$KH_CTX python3 "$RW_DIR/rwlib.py" "$@"; }

rw_delete_namespaces() {
  local n
  kubectl get ns -o name 2>/dev/null | grep "^namespace/${RW_PREFIX}" | while read -r n; do kubectl delete "$n" --wait=false >/dev/null 2>&1; done
  rc --scan --pattern "kubeheal:*${RW_PREFIX}*" | while read -r n; do [[ $n == kubeheal:* ]] && rc DEL "$n" >/dev/null; done
}
rw_cleanup() {
  local rc_=$? i; set +e; trap - EXIT
  (( RW_FAILS )) && [[ $rc_ == 0 ]] && rc_=1
  jobs -p | while read -r p; do kill "$p" 2>/dev/null; done
  for ((i = ${#RW_UNDO[@]} - 1; i >= 0; i--)); do say "undo: ${RW_UNDO[i]}"; eval "${RW_UNDO[i]}" >/dev/null 2>&1; done
  declare -F extra_cleanup >/dev/null && extra_cleanup
  rw_delete_namespaces
  echo; column -t -s$'\t' "$RW_OUT/results.tsv" 2>/dev/null
  say "$RW_NAME finished: exit $rc_, $RW_FAILS failed checks, $((SECONDS - RW_T0))s; results in $RW_OUT"
  (( RW_DRY )) && rm -rf "$RW_OUT"
  exit $rc_
}

check() {   # check "description" command...   (PASS when the command succeeds)
  local d=$1; shift
  if (( RW_DRY )) || "$@"; then printf 'PASS\t%s\n' "$d" >> "$RW_OUT/results.tsv"; say "PASS $d"
  else printf 'FAIL\t%s\n' "$d" >> "$RW_OUT/results.tsv"; say "FAIL $d"; RW_FAILS=$((RW_FAILS + 1)); fi
  return 0
}
rw_until() {   # rw_until TIMEOUT_S command...   poll every 3 s
  local t=$1 end; shift; end=$((SECONDS + t))
  (( RW_DRY )) && return 0
  until "$@"; do (( SECONDS < end )) || return 1; sleep 3; done
}
pods_ready() {   # every pod in kubeheal Ready (Completed Job pods excepted)
  local bad; bad="$(kubectl get pods -n "$KH" --no-headers 2>&1 | awk '$3=="Completed"{next} {split($2,r,"/"); if ($3!="Running" || r[1]!=r[2]) print $1}')"
  [[ -z $bad && $(kubectl get pods -n "$KH" --no-headers | wc -l) -ge 6 ]]
}
kh_restarts() { kubectl get pods -n "$KH" --no-headers -o custom-columns=N:.metadata.name,R:.status.containerStatuses[*].restartCount | tr -s ' ' | sort; }

# ── helpers for the fault-injection scripts ──────────────────────────────────────────────────────
jget() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]))' "$1"; }
attack() {   # attack SUFFIX [NODE]  -> JSON of one sandboxed attack (killed, latency_s, node_actual, ...) on stdout
  rwpy attack --ns "$1" --name "atk-$1" ${2:+--node "$2"} --deadline "${ATTACK_DEADLINE:-150}"
}
killed_within() {   # killed_within JSON MAX_SECONDS
  python3 -c 'import json,sys; r=json.loads(sys.argv[1]); sys.exit(0 if r.get("killed") and r["latency_s"] is not None and r["latency_s"]<=float(sys.argv[2]) else 1)' "$1" "$2"
}
sec_pod_on() { kubectl get pods -n "$KH" -l app=kubeheal-security-agent --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}'; }
frozen_count() {   # pods this security-agent pod froze (kubeheal_security_contain_total{outcome="frozen"})
  kubectl get --raw "/api/v1/namespaces/$KH/pods/$1:8080/proxy/metrics" 2>/dev/null | awk '/^kubeheal_security_contain_total\{outcome="frozen"\}/{print int($2); f=1} END{if(!f) print 0}'
}
worker_nodes() { kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[*].metadata.name}'; }
benign_kills() {   # AUTO_KILL / pod_killed decisions in the namespaces matching $1 (a khe-rw- prefix), since the run started (RW_T0_MS)
  rc XRANGE kubeheal.actions "$RW_T0_MS" + COUNT 20000 | awk -v p="$1" '
    /^[0-9]+-[0-9]+$/ {ns=0; k=0} $0=="namespace" {getline v; ns=(index(v,p)==1)} $0=="outcome" {getline v; k=(v=="pod_killed")}
    ns && k && !seen[NR]++ {n++} END {print n+0}'
}
