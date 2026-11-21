#!/usr/bin/env bash
# Redis HA failover under attack (needs the HA install: production overlay or Helm redis.ha.enabled; guarded; k3d with
# KUBEHEAL_K3D_AGENTS=3 spreads the pods across nodes). An attack loop runs while the Redis PRIMARY pod is killed
# (force, grace 0 = a crash). Measured: seconds until Sentinel has promoted a replica AND a write succeeds on it.
# Asserted: failover within --max-failover-s; the old primary rejoins as a replica; the primary has 2 replicas again;
# attacks keep being detected and killed during and after (at most one in-flight attack may be lost: async replication
# can drop the last writes of the old primary, docs/operations.md "Redis high availability"); an attack after recovery is
# killed within --max-kill-s; no duplicate action (at most one pod_killed per attack namespace, kills <= attacks);
# nothing outside khe-rw-* killed; fusion has no stuck pending entries.
# Touches: khe-rw-fo* namespaces, Redis key kubeheal:khe-rw-fo-probe; the killed pod is restarted by its StatefulSet.
#   ./deploy/scripts/realworld/redis_failover.sh [--max-failover-s 45] [--max-kill-s 40] [--max-recovery-s 240] [--dry-run] [--force-context NAME]
# Duration: ~8 min.
RW_NAME=redis_failover
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
MAX_FO=45; MAX_KILL=40; MAX_REC=240
rw_init "$@"; set -- "${RW_REST[@]}"
while [[ $# -gt 0 ]]; do case $1 in
  --max-failover-s) MAX_FO=$2; shift 2 ;; --max-kill-s) MAX_KILL=$2; shift 2 ;; --max-recovery-s) MAX_REC=$2; shift 2 ;;
  *) die "usage: $0 [--max-failover-s N] [--max-kill-s N] [--max-recovery-s N] [--dry-run] [--force-context NAME]" ;;
esac; done

# Sentinel's view of the primary: its pod name (the Sentinels report the pod IP).
primary_pod() {
  (( RW_DRY )) && { echo redis-0; return; }
  local ip; ip="$(kubectl exec -n "$KH" "${1:-redis-sentinel-0}" -- redis-cli -p 26379 sentinel get-master-addr-by-name kubeheal 2>/dev/null | sed -n 1p)"
  [[ -n $ip ]] && kubectl get pods -n "$KH" -l app.kubernetes.io/name=redis -o jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' | awk -v ip="$ip" '$2==ip{print $1}'
}
(( RW_DRY )) || kubectl get sts -n "$KH" redis redis-sentinel >/dev/null 2>&1 || die "Redis HA is not installed (StatefulSets redis and redis-sentinel): use the production overlay or redis.ha.enabled"
(( RW_DRY )) || pods_ready || die "KubeHeal is not healthy before the run"
[[ $(rc GET kubeheal:mode) == observe ]] && die "runtime mode switch is observe: kills would not happen"

R="$(attack fo-base)"; echo "base $R" >> "$RW_OUT/attacks.jsonl"
check "baseline attack killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"

# attack loop in the background; each line of loop.jsonl is one attack's result
if (( RW_DRY )); then printf '{"killed":true,"latency_s":1}\n%.0s' 1 2 > "$RW_OUT/loop.jsonl"; LOOP=""
else
  : > "$RW_OUT/loop.jsonl"
  ( i=0; while [[ ! -e $RW_OUT/stop ]]; do i=$((i + 1)); echo "$(attack "fo-$i")" >> "$RW_OUT/loop.jsonl"; done ) &
  LOOP=$!
fi
rw_until 150 test -s "$RW_OUT/loop.jsonl"

OLD="$(primary_pod)"; OLD_IP="$(kubectl get pod -n "$KH" "$OLD" -o jsonpath='{.status.podIP}' 2>/dev/null)"
say "killing the primary $OLD ($OLD_IP)"
T0=$(date +%s%3N)
kubectl delete pod -n "$KH" "$OLD" --grace-period=0 --force >/dev/null 2>&1
promoted() {   # Sentinel names another node AND that node accepts a write
  local p; p="$(primary_pod redis-sentinel-1)"; [[ -n $p && $p != "$OLD" ]] || return 1
  [[ $(kubectl exec -n "$KH" "$p" -c redis -- redis-cli --raw SET kubeheal:khe-rw-fo-probe 1 EX 60 2>&1) == OK ]]
}
rw_until "$MAX_REC" promoted; ok=$?
FO_S=$(( ($(date +%s%3N) - T0) / 1000 ))
printf 'INFO\tfailover (primary killed -> new primary writable) %ss\n' "$FO_S" >> "$RW_OUT/results.tsv"
check "a replica was promoted and accepts writes within ${MAX_FO}s (took ${FO_S}s)" test "$ok" -eq 0 -a "$FO_S" -le "$MAX_FO"

rw_until "$MAX_REC" pods_ready; ok=$?
check "KubeHeal back to all-Ready within ${MAX_REC}s" test "$ok" -eq 0
check "the old primary $OLD rejoined as a replica" test "$(kubectl exec -n "$KH" "$OLD" -c redis -- redis-cli role 2>/dev/null | sed -n 1p)" == slave
check "the new primary has 2 connected replicas" test "$(rc INFO replication | tr -d '\r' | sed -n 's/^connected_slaves://p')" == 2

touch "$RW_OUT/stop"; [[ -z $LOOP ]] || wait "$LOOP" 2>/dev/null
N=$(wc -l < "$RW_OUT/loop.jsonl"); LOST="$(python3 -c '
import json, sys
bound = float(sys.argv[2]) + float(sys.argv[3])
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print(sum(not (r.get("killed") and r["latency_s"] is not None and r["latency_s"] <= bound) for r in rows))' "$RW_OUT/loop.jsonl" "$MAX_KILL" "$MAX_FO")"
printf 'INFO\tloop attacks %s, not killed in time %s\n' "$N" "$LOST" >> "$RW_OUT/results.tsv"
check "attacks kept being killed during and after the failover (loop: $N attacks, $LOST not killed in $((MAX_KILL + MAX_FO))s; at most 1 in flight may be lost)" test "$LOST" -le 1 -a "$N" -ge 2

R="$(attack fo-after)"; echo "after $R" >> "$RW_OUT/attacks.jsonl"
check "attack after recovery killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"

# duplicate actions: the idempotency markers (kubeheal:done:*) and the pod-UID precondition must hold across the switch
rw_sleep 20
ATTACKS=$((N + 2))
ACTIONS="$(rc XRANGE kubeheal.actions "$RW_T0_MS" + COUNT 20000)"
DUP="$(echo "$ACTIONS" | awk '/^[0-9]+-[0-9]+$/{ns="";o=""} $0=="namespace"{getline ns} $0=="outcome"{getline o; if(o=="pod_killed") c[ns]++} END{for(k in c) if(c[k]>1) n++; print n+0}')"
KILLS="$(echo "$ACTIONS" | awk '/^[0-9]+-[0-9]+$/{ns="";o=""} $0=="namespace"{getline ns} $0=="outcome"{getline o; if(o=="pod_killed" && index(ns,"khe-rw-")==1) n++} END{print n+0}')"
OUTSIDE="$(echo "$ACTIONS" | awk '/^[0-9]+-[0-9]+$/{ns="";o=""} $0=="namespace"{getline ns} $0=="outcome"{getline o; if(o=="pod_killed" && index(ns,"khe-rw-")!=1) n++} END{print n+0}')"
check "no duplicate kill: namespaces with more than one pod_killed = $DUP" test "$DUP" -eq 0
check "no kill storm: pods killed ($KILLS) <= attacks launched ($ATTACKS)" test "$KILLS" -le "$ATTACKS"
check "KubeHeal killed nothing outside khe-rw-* during this run" test "$OUTSIDE" -eq 0
check "fusion has no stuck pending entries on the security stream" test "$(rc XPENDING kubeheal.security.events fusion | sed -n 1p)" == 0
exit 0
