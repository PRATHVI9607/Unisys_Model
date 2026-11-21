#!/usr/bin/env bash
# Soak: N hours of real benign tools (restic, npm, pip, git, postgres+pgbench, redis bgsave, nginx+logs, logrotate,
# tar/gzip/zstd, sqlite, rsync) with a random sandboxed attack about every 10 minutes, fusion in enforce mode.
# PASS = 0 benign pods killed, every attack killed within --max-kill-s, false-alert rate under the budget.
# Reports kill-latency percentiles, false alerts per workload-hour, CPU/memory percentiles (soak-report.json in the
# results dir). Needs: images pulled by the cluster (alpine, node, postgres, redis, nginx, restic via apk, github),
# metrics-server for `kubectl top`, and the kubeheal.invalid/chaos:v5 image. Duration: --hours (default 1).
#   ./deploy/scripts/realworld/soak.sh [--hours 4] [--attack-every 600] [--cycle 600] [--workloads a,b] [--seed N] [--dry-run]
# Only khe-rw-soak-* namespaces are touched; the EXIT trap deletes them and their Redis keys.
RW_NAME=soak
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"; rw_init "$@"; set -- "${RW_REST[@]}"
[[ $(kubectl get deploy kubeheal-fusion-agent -n "$KH" -o jsonpath='{.spec.template.spec.containers[0].env}' 2>/dev/null) == *enforce* ]] \
  || (( RW_DRY )) || die "fusion is not in enforce mode: a soak in observe mode proves nothing (kill checks need real kills)"
(( RW_DRY )) || pods_ready || die "KubeHeal pods in $KH are not all Ready"
[[ $(rc GET kubeheal:mode) == observe ]] && die "runtime mode switch is on observe (kubeheal:mode): set it back to enforce first"
rc XLEN kubeheal.deadletter > "$RW_OUT/deadletter.before"
before_restarts="$(kh_restarts)"
dry=(); (( RW_DRY )) && dry=(--dry-run)
python3 "$RW_DIR/soak.py" --out "$RW_OUT" "$@" "${dry[@]}"
rc=$?
check "soak engine passed (benign kills, missed attacks, kill latency, false-alert budget)" test $rc -eq 0
check "no KubeHeal pod restarted during the soak" test "$before_restarts" == "$(kh_restarts)"
check "no new dead-letter entries" test "$(rc XLEN kubeheal.deadletter)" == "$(cat "$RW_OUT/deadletter.before")"
