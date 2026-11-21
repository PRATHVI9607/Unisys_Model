#!/usr/bin/env bash
# Where to run redis-cli, single Redis (Deployment redis) or HA (StatefulSet redis + Sentinels). Source it, or run it
# (prints the target; honours KH_CTX). The one place that knows the topology; every script that execs into Redis uses it:
#   kubectl exec -i -n "$KH" $(kh_redis_target) -- redis-cli ...      # target is unquoted on purpose: "pod -c redis"
# HA: the primary the Sentinels name (the pod with that IP); a Sentinel that does not answer falls back to the pod
# whose `role` is master. Single: deploy/redis.
_kh_k() { if declare -F kubectl >/dev/null; then kubectl "$@"; else command kubectl ${KH_CTX:+--context "$KH_CTX"} "$@"; fi; }
kh_redis_target() {
  local ns="${KH:-kubeheal}" ip pod i
  [[ ${KH_CTX:-} == dry-run ]] && { echo deploy/redis; return; }   # --dry-run touches no cluster
  _kh_k get sts redis -n "$ns" >/dev/null 2>&1 || { echo deploy/redis; return; }
  for i in 0 1 2; do
    ip="$(_kh_k exec -n "$ns" "redis-sentinel-$i" -- redis-cli -p 26379 sentinel get-master-addr-by-name kubeheal 2>/dev/null | sed -n 1p)"
    [[ -n $ip ]] && break
  done
  if [[ -n $ip ]]; then
    pod="$(_kh_k get pods -n "$ns" -l app.kubernetes.io/name=redis -o jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' | awk -v ip="$ip" '$2==ip{print $1}')"
  fi
  if [[ -z ${pod:-} ]]; then
    for i in 0 1 2; do
      [[ $(_kh_k exec -n "$ns" "redis-$i" -c redis -- redis-cli role 2>/dev/null | sed -n 1p) == master ]] && { pod="redis-$i"; break; }
    done
  fi
  echo "${pod:-redis-0} -c redis"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then kh_redis_target; fi
