#!/usr/bin/env bash
# Create the throwaway k3d lab cluster `kubeheal` (context k3d-kubeheal; see cluster.yaml).
# It never touches your default kubeconfig or current context: the kubeconfig goes to
#   $KUBEHEAL_K3D_KUBECONFIG, else $KUBECONFIG if it is a single file, else ~/.kube/kubeheal-k3d.yaml
# Use it with:  export KUBECONFIG=<that file>
# KUBEHEAL_K3D_AGENTS=N overrides the number of agent nodes (default 2).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/deploy/k3d/lib.sh"
command -v k3d >/dev/null || { echo "need k3d (https://k3d.io; docs/operations.md lists the pinned release)"; exit 1; }
command -v docker >/dev/null || { echo "need docker"; exit 1; }
if k3d cluster list kubeheal >/dev/null 2>&1; then echo "cluster kubeheal exists"; else
  k3d cluster create --config "$ROOT/deploy/k3d/cluster.yaml" --agents "${KUBEHEAL_K3D_AGENTS:-2}" \
    --kubeconfig-update-default=false --kubeconfig-switch-context=false --wait --timeout 180s
fi
k3d kubeconfig merge kubeheal -o "$KCFG" --kubeconfig-switch-context >/dev/null
echo "kubeconfig: $KCFG   (export KUBECONFIG=$KCFG)"
KUBECONFIG="$KCFG" kubectl config current-context
KUBECONFIG="$KCFG" kubectl wait --for=condition=Ready nodes --all --timeout=120s
