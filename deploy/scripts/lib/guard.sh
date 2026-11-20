#!/usr/bin/env bash
# Cluster guard shared by install/demo/reset/seed_demo/smoke/run_lab (source it) and evaluate.py (runs it).
# These scripts rewrite Deployments, delete namespaces and pods: refuse unless kubectl points at the
# local lab cluster (minikube or k3d-kubeheal), or the caller names the current context with
# --force-context NAME (must equal `kubectl config current-context`). Always prints the context.
# The verified context is pinned (KH_CTX): after the check, `kubectl` and `helm` in this shell and in child bash
# scripts are functions that add --context "$KH_CTX", so a `kubectl config use-context` made later (another
# terminal) cannot redirect them. Anything not going through those functions (xargs, python) must pass --context itself.
#   source guard.sh; kh_guard "$@"; set -- "${KH_REST[@]}"     # strips --force-context NAME from the args
#   guard.sh [--force-context NAME]                            # check only (exit 0 ok, 2 refused); prints the context on stdout
KH_ALLOWED_CONTEXTS=(minikube k3d-kubeheal)
kh_pin() {
  export KH_CTX="$1"
  kubectl() { command kubectl --context "$KH_CTX" "$@"; }
  helm() { command helm --kube-context "$KH_CTX" "$@"; }
  export -f kubectl helm
}
kh_guard() {
  local force="${KUBEHEAL_FORCE_CONTEXT:-}" ctx a
  KH_REST=()
  while [[ $# -gt 0 ]]; do
    if [[ $1 == --force-context ]]; then force="${2:-}"; shift $(($# > 1 ? 2 : 1)); else KH_REST+=("$1"); shift; fi
  done
  export KUBEHEAL_FORCE_CONTEXT="$force"   # child scripts (demo.sh -> seed_demo.sh) inherit the decision
  command -v kubectl >/dev/null || { echo "need kubectl" >&2; return 2; }
  ctx="$(kubectl config current-context 2>/dev/null)" || { echo "refusing: no current kubectl context" >&2; return 2; }
  echo "kubectl context: $ctx" >&2
  for a in "${KH_ALLOWED_CONTEXTS[@]}"; do [[ $ctx == "$a" ]] && { kh_pin "$ctx"; return 0; }; done
  [[ -n $force && $force == "$ctx" ]] && { echo "context '$ctx' forced" >&2; kh_pin "$ctx"; return 0; }
  echo "refusing: context '$ctx' is not one of: ${KH_ALLOWED_CONTEXTS[*]} (use --force-context $ctx to override)" >&2
  return 2
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then kh_guard "$@" || exit 2; echo "$KH_CTX"; fi
