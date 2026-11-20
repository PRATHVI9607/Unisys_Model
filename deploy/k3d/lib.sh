# Shared by create.sh / delete.sh: pick the kubeconfig file and export it, so k3d never writes anywhere else.
KCFG="${KUBEHEAL_K3D_KUBECONFIG:-}"
[[ -n $KCFG ]] || { [[ -n ${KUBECONFIG:-} && $KUBECONFIG != *:* ]] && KCFG="$KUBECONFIG" || KCFG="$HOME/.kube/kubeheal-k3d.yaml"; }
mkdir -p "$(dirname "$KCFG")"
export KUBECONFIG="$KCFG"
