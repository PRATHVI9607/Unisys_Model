#!/usr/bin/env bash
# Multi-node correctness on the k3d cluster with 3 agents (KUBEHEAL_K3D_AGENTS=3 ./deploy/k3d/create.sh, then install.sh
# --target k3d): an attack pinned to each worker is killed, and the containment freeze lands on that node's
# security agent only (kubeheal_security_contain_total{outcome="frozen"} grows on exactly one agent), never elsewhere.
# Also: one security-agent pod per node, each Ready; the victim pod's own node matches the one it was pinned to.
# Rounds: each node is attacked --rounds times (default 2), nodes visited in a shuffled order.
#   ./deploy/scripts/realworld/multinode.sh [--rounds 2] [--max-kill-s 40] [--dry-run] [--force-context k3d-kubeheal]
# Duration: ~1.5 min per attack (3 nodes x 2 rounds = ~8 min). Cleans up khe-rw-mn-* namespaces on exit.
RW_NAME=multinode
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROUNDS=2; MAX_KILL=40
rw_init "$@"; set -- "${RW_REST[@]}"
while [[ $# -gt 0 ]]; do case $1 in
  --rounds) ROUNDS=$2; shift 2 ;; --max-kill-s) MAX_KILL=$2; shift 2 ;;
  *) die "usage: $0 [--rounds N] [--max-kill-s N] [--dry-run] [--force-context NAME]" ;;
esac; done
read -r -a NODES <<< "$(worker_nodes)"
(( RW_DRY )) && NODES=(node-a node-b node-c)
(( ${#NODES[@]} >= 2 )) || die "need >= 2 worker nodes (found ${#NODES[@]}): KUBEHEAL_K3D_AGENTS=3 ./deploy/k3d/create.sh"
check "one Ready security-agent pod on each of ${#NODES[@]} nodes" bash -c \
  "[[ \$(kubectl get pods -n $KH -l app=kubeheal-security-agent --no-headers | awk '\$2==\"2/2\" || \$2==\"1/1\"' | wc -l) -eq ${#NODES[@]} ]]"
declare -A POD; for n in "${NODES[@]}"; do POD[$n]="$(sec_pod_on "$n")"; done
frozen_all() { local n; for n in "${NODES[@]}"; do echo "$n=$(frozen_count "${POD[$n]}")"; done; }

i=0
for ((r = 1; r <= ROUNDS; r++)); do
  for n in $(printf '%s\n' "${NODES[@]}" | shuf); do
    i=$((i + 1)); say "round $r: attack pinned to $n"
    before="$(frozen_all)"
    R="$(attack "mn-$i" "$n")"
    after="$(frozen_all)"
    check "$n round $r: attack killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
    check "$n round $r: victim really ran on $n" test "$(echo "$R" | jget node_actual)" == "$n"
    check "$n round $r: containment requested by fusion" test "$(echo "$R" | jget containment)" == requested
    # the freeze counter must grow on $n's agent and on no other agent
    grew="$(join -t= <(echo "$before" | sort) <(echo "$after" | sort) | awk -F= '$3>$2{print $1}' | tr '\n' ' ')"
    check "$n round $r: freeze landed on $n only (agents whose counter grew: '${grew% }')" test "${grew% }" == "$n"
  done
done
check "no other pod was killed (kills in khe-rw-mn-* == attacks)" test "$(benign_kills khe-rw-mn-)" -eq "$i"
exit 0
