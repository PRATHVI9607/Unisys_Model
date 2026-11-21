#!/usr/bin/env bash
# Fault injection while attacks and benign tools keep running. For each fault: inject, attack during it, undo, measure
# the recovery time, attack again. Global assertions: 0 benign kills, no kill storm (kills <= attacks launched), nothing
# outside khe-rw-* ever killed, every attack launched while healthy is killed, KubeHeal recovers to all-Ready.
#
# Expected (fail-safe) behaviour per fault - the checks below enforce the "must" part, the rest is reported:
#  pods     kill random kubeheal pods (agents, fusion, inference, dashboard; never redis here)
#           must: attack after the restart is killed; no duplicate kill (idempotency markers); benign untouched.
#  redis    restart Redis (AOF + PVC)       must: baselines survive; agents reconnect, no crash loop; attack after recovery
#           killed. An attack DURING the outage is not required to be killed (events cannot be written; stale ones
#           are skipped) - but nothing benign may be killed and no stale replay may kill after recovery.
#  inference  NetworkPolicy blocks inference  must: security agent (embedded scoring) still kills; health agent degrades
#           (skips scoring) without AUTO_PATCH of healthy specs; after the undo a bad-image drift is patched again.
#  redisfull  Redis filled to --fill-pct of maxmemory (noeviction)   must: no pod restarts/OOM, nothing benign killed,
#           attack killed at 90%; at 99% only fail-safe (no crash) is required; keys removed -> attack killed again.
#  drain    cordon + drain a worker without Redis   must: attacks on other nodes killed meanwhile; after uncordon all Ready.
#  sensor   security-agent pod on one node deleted every 12 s for 90 s (sensor+agent crash loop)   must: no false kill
#           when it returns (no replay of old events), no kill storm; an attack after stabilisation killed on that node.
# Touches: khe-rw-* namespaces, plus in namespace kubeheal only objects named khe-rw-* (a temporary NetworkPolicy, Redis
# filler keys kubeheal:khe-rw-fill:*), a backed-up-and-restored kubeheal-inference-clients policy, cordon state of one node.
# Everything is undone by the EXIT trap, also on Ctrl-C.
#   ./deploy/scripts/realworld/chaos.sh [--only pods,redis,inference,redisfull,drain,sensor] [--fill-pct 90] [--max-kill-s 40] [--max-recovery-s 240] [--dry-run]
# Duration: ~35 min on k3d (drain needs a multi-node cluster: deploy/k3d/create.sh with KUBEHEAL_K3D_AGENTS=3), ~25 min on minikube (drain skipped).
RW_NAME=chaos
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ONLY=pods,redis,inference,redisfull,drain,sensor; FILL=90; MAX_KILL=40; MAX_REC=240
rw_init "$@"; set -- "${RW_REST[@]}"
while [[ $# -gt 0 ]]; do case $1 in
  --only) ONLY=$2; shift 2 ;; --fill-pct) FILL=$2; shift 2 ;; --max-kill-s) MAX_KILL=$2; shift 2 ;; --max-recovery-s) MAX_REC=$2; shift 2 ;;
  *) die "usage: $0 [--only a,b] [--fill-pct N] [--max-kill-s N] [--max-recovery-s N] [--dry-run] [--force-context NAME]" ;;
esac; done
want() { [[ ,$ONLY, == *,"$1",* ]]; }
(( RW_DRY )) || pods_ready || die "KubeHeal is not healthy before the run"
[[ $(rc GET kubeheal:mode) == observe ]] && die "runtime mode switch is observe: kills would not happen"
N=0; ATTACKS=0
chaos_attack() {   # chaos_attack LABEL [NODE]: run an attack, return its JSON in $R
  N=$((N + 1)); ATTACKS=$((ATTACKS + 1)); say "attack $N ($1)"
  R="$(attack "chaos-atk-$N" ${2:-})"; echo "$1 $R" >> "$RW_OUT/attacks.jsonl"
}
recover() {   # recover LABEL: seconds until every KubeHeal pod is Ready again
  local t=$SECONDS; rw_until "$MAX_REC" pods_ready; local ok=$?; local d=$((SECONDS - t))
  printf 'INFO\t%s recovery %ss\n' "$1" "$d" >> "$RW_OUT/results.tsv"
  check "$1: KubeHeal back to all-Ready within ${MAX_REC}s (took ${d}s)" test $ok -eq 0
}

# background load: three light real tools that must never be touched
for w in sqlite logrotate nginx-logs; do rwpy benign --workload "$w" --ns "chaos-benign-$w" 2>/dev/null || true; done
RESTARTS0="$(kh_restarts)"
chaos_attack "baseline"; check "baseline attack killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"

if want pods; then
  say "FAULT pods"
  for d in kubeheal-fusion-agent kubeheal-health-agent kubeheal-inference; do
    victim="$(kubectl get pods -n "$KH" -l app="$d" -o jsonpath='{.items[0].metadata.name}')"
    kubectl delete pod -n "$KH" "$victim" --wait=false >/dev/null
  done
  kubectl delete pod -n "$KH" -l app=kubeheal-security-agent --field-selector "spec.nodeName=$(worker_nodes | awk '{print $1}')" --wait=false >/dev/null
  chaos_attack "pods-during"; check "pods: attack during the restarts is killed (late is fine, within $((MAX_KILL + MAX_REC))s)" killed_within "$R" $((MAX_KILL + MAX_REC))
  recover pods
  chaos_attack "pods-after"; check "pods: attack after recovery killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
fi

if want redis; then
  say "FAULT redis restart"
  base_before="$(rc --scan --pattern 'kubeheal:baseline:*' | sort | md5sum)"
  kubectl rollout restart deploy/redis -n "$KH" >/dev/null
  chaos_attack "redis-during"     # no kill requirement
  recover redis
  check "redis: baselines identical after the restart (AOF + PVC)" test "$base_before" == "$(rc --scan --pattern 'kubeheal:baseline:*' | sort | md5sum)"
  chaos_attack "redis-after"; check "redis: attack after recovery killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
fi

if want inference; then
  say "FAULT inference blocked by NetworkPolicy"
  kubectl get netpol kubeheal-inference-clients -n "$KH" -o yaml > "$RW_OUT/inference-netpol.yaml"
  rw_undo "kubectl delete netpol khe-rw-deny-inference -n $KH --ignore-not-found; kubectl apply -f $RW_OUT/inference-netpol.yaml"
  # NetworkPolicies only add allows: the allow-list must go for the deny to bite; the EXIT trap puts it back
  kubectl delete netpol kubeheal-inference-clients -n "$KH" >/dev/null
  kubectl apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: khe-rw-deny-inference, namespace: $KH}
spec: {podSelector: {matchLabels: {app: kubeheal-inference}}, policyTypes: [Ingress], ingress: []}
YAML
  rw_sleep 20
  chaos_attack "inference-blocked"; check "inference blocked: security agent (embedded scoring) still kills within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
  check "inference blocked: no benign pod killed" test "$(benign_kills khe-rw-chaos-benign)" == 0
  kubectl delete netpol khe-rw-deny-inference -n "$KH" >/dev/null; kubectl apply -f "$RW_OUT/inference-netpol.yaml" >/dev/null
  recover inference
  # drift must be repaired again: bad image on a Deployment with a baseline
  HN="$(rw_ns chaos-health)"; rw_mkns "$HN"
  kubectl create deploy web -n "$HN" --image=kubeheal.invalid/chaos:v5 -- sleep 86400 >/dev/null
  kubectl patch deploy web -n "$HN" -p '{"spec":{"template":{"spec":{"containers":[{"name":"chaos","imagePullPolicy":"IfNotPresent"}]}}}}' >/dev/null
  has_baseline() { [[ $(rc EXISTS "kubeheal:baseline:$HN:web") == 1 ]]; }
  rw_until 150 has_baseline
  kubectl set image deploy/web -n "$HN" '*=kubeheal.invalid/chaos:broken' >/dev/null
  patched() { [[ $(kubectl get deploy web -n "$HN" -o jsonpath='{.spec.template.spec.containers[0].image}') == kubeheal.invalid/chaos:v5 ]]; }
  rw_until 240 patched; check "inference restored: bad-image drift is AUTO_PATCHed again" patched
fi

if want redisfull; then
  say "FAULT redis memory fill"
  rw_undo "for k in \$(kubectl exec -n $KH deploy/redis -- redis-cli --raw --scan --pattern 'kubeheal:khe-rw-fill:*'); do kubectl exec -n $KH deploy/redis -- redis-cli DEL \$k >/dev/null; done"
  fill() {   # fill PERCENT: pipe 32 KiB values into Redis until used_memory >= PERCENT of maxmemory
    local pct=$1 i used max n val
    val="$(head -c 32768 /dev/zero | tr '\0' x)"
    for i in 1 2 3 4 5 6; do
      read -r used max < <(rwpy mem | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["used"], d["max"])')
      n=$(( (max * pct / 100 - used) / 33000 )); (( n > 0 )) || return 0
      awk -v n="$n" -v s="$RANDOM" -v v="$val" 'BEGIN{for(i=1;i<=n;i++) printf "SET kubeheal:khe-rw-fill:%d-%d %s\r\n", s, i, v}' \
        | kubectl exec -i -n "$KH" deploy/redis -- redis-cli --pipe >/dev/null   # OOM replies near 99% are expected
    done
  }
  R0="$(kh_restarts)"
  fill "$FILL" >/dev/null; say "redis at ${FILL}%: $(rwpy mem)"
  chaos_attack "redisfull-$FILL"; check "redis at ${FILL}%: attack still killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
  fill 99 >/dev/null; say "redis at 99%: $(rwpy mem)"
  chaos_attack "redisfull-99"   # only fail-safe required: writes may be refused (OOM) so detection can be late
  check "redis full: no benign pod killed" test "$(benign_kills khe-rw-chaos-benign)" == 0
  for k in $(rc --scan --pattern 'kubeheal:khe-rw-fill:*'); do rc DEL "$k" >/dev/null; done
  recover redisfull
  check "redis full: no KubeHeal pod restarted (no OOM / crash loop)" test "$R0" == "$(kh_restarts)"
  chaos_attack "redisfull-after"; check "redis emptied: attack killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
fi

if want drain; then
  say "FAULT cordon + drain"
  redis_node="$(kubectl get pod -n "$KH" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].spec.nodeName}')"
  victim="$(for n in $(worker_nodes); do [[ $n != "$redis_node" ]] && echo "$n"; done | head -1)"
  other="$(for n in $(worker_nodes); do [[ $n != "$victim" ]] && echo "$n"; done | head -1)"
  if [[ -z $victim || -z $other ]] && (( ! RW_DRY )); then say "SKIP drain: needs >= 2 worker nodes, one without Redis (k3d with KUBEHEAL_K3D_AGENTS=3)"; else
    rw_undo "kubectl uncordon $victim"
    kubectl drain "$victim" --ignore-daemonsets --delete-emptydir-data --force --timeout=120s >/dev/null
    chaos_attack "drain-other-node" "$other"; check "drain: attack on another node killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
    kubectl uncordon "$victim" >/dev/null; recover drain
    chaos_attack "drain-after" "$victim"; check "drain: attack on the returned node killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
  fi
fi

if want sensor; then
  say "FAULT sensor / security-agent crash loop"
  node="$(worker_nodes | awk '{print $1}')"
  for _ in 1 2 3 4 5 6 7; do kubectl delete pod -n "$KH" -l app=kubeheal-security-agent --field-selector "spec.nodeName=$node" --wait=false >/dev/null; rw_sleep 12; done
  recover sensor
  rw_sleep 30
  chaos_attack "sensor-after" "$node"; check "sensor: attack on the recovered node killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
fi

# ── global invariants ────────────────────────────────────────────────────────────────────────────
rw_sleep 20
KILLS="$(rc XRANGE kubeheal.actions "$RW_T0_MS" + COUNT 20000 | awk '/^[0-9]+-[0-9]+$/{ns="";o=""} $0=="namespace"{getline ns} $0=="outcome"{getline o; if(o=="pod_killed" && index(ns,"khe-rw-")==1) n++} END{print n+0}')"
OUTSIDE="$(rc XRANGE kubeheal.actions "$RW_T0_MS" + COUNT 20000 | awk '/^[0-9]+-[0-9]+$/{ns="";o=""} $0=="namespace"{getline ns} $0=="outcome"{getline o; if(o=="pod_killed" && index(ns,"khe-rw-")!=1) n++} END{print n+0}')"
check "no benign tool pod killed" test "$(benign_kills khe-rw-chaos-benign)" == 0
check "no kill storm: pods killed ($KILLS) <= attacks launched ($ATTACKS)" test "$KILLS" -le "$ATTACKS"
check "KubeHeal killed nothing outside khe-rw-* during this run" test "$OUTSIDE" == 0
recover final
exit 0
