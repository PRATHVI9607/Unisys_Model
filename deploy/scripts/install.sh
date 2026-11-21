#!/usr/bin/env bash
# KubeHeal v5 install: build the images, install Prometheus (Helm, values in deploy/k8s/helm/),
# deploy the control plane (kustomize, incl. Redis and the eBPF event sensor) and the
# demo app. Works on minikube (images built straight into the node) or any
# cluster your kubectl points at (local docker build; push them yourself), or a k3d cluster (--target k3d:
# docker build + `k3d image import`; create it with deploy/k3d/create.sh).
# Cluster guard (deploy/scripts/lib/guard.sh): refuses unless the context is minikube or k3d-kubeheal
# (or --force-context NAME equal to the current context). The context is always printed.
# Idempotent; fails loudly — no `|| true` on real steps.
# Usage: install.sh                                   dev/lab install from deploy/k8s (minikube or local cluster)
#        install.sh --target k3d                       same on the k3d cluster `kubeheal` (images imported, not built in-node)
#        install.sh --helm [...]                       deploy the control plane with deploy/helm/kubeheal instead of kustomize
#        install.sh --production --registry HOST/PATH [--tag TAG]
#   --production applies deploy/k8s/overlays/production (no dashboard, inference HPA/PDB,
#   PriorityClass), with images HOST/PATH/{inference,agents}:TAG (TAG defaults to the git short SHA).
#   It builds and pushes them with docker, and skips the demo app and the chaos image.
#   --platform P   target platform(s) of the images (docker buildx syntax). Production default: linux/amd64,linux/arm64
#                  (one multi-arch buildx build + push per image; needs QEMU binfmt on an amd64 builder for the Python
#                  images: `docker run --privileged --rm tonistiigi/binfmt --install arm64`). Dev (minikube, k3d, local):
#                  the host arch unless you pass one platform (e.g. linux/arm64 for an arm64 k3d on Apple silicon).
# EVENT_SOURCE=sensor (default): the eBPF sensor (sensor/) runs in the security-agent DaemonSet.
# EVENT_SOURCE=falco: Falco (Helm, deploy/k8s/helm/falco-values.yaml) feeds the agent instead
#   (deploy/k8s/components/falco-source). Falco caps at ~1900 alerts/s per node: sensor/README.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
source deploy/scripts/lib/guard.sh; kh_guard "$@" || exit 1; set -- "${KH_REST[@]}"
EVENT_SOURCE="${EVENT_SOURCE:-sensor}"
[[ $EVENT_SOURCE == sensor || $EVENT_SOURCE == falco ]] || { echo "EVENT_SOURCE must be sensor or falco"; exit 1; }
KUSTOMIZE=deploy/k8s/; WAIT_DEPLOYS="redis kubeheal-inference kubeheal-health-agent kubeheal-fusion-agent kubeheal-dashboard"
PROD=0 REGISTRY="" TAG="" TARGET="" HELM=0 PLATFORM=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --production) PROD=1; KUSTOMIZE=deploy/k8s/overlays/production; WAIT_DEPLOYS="${WAIT_DEPLOYS#redis }"; WAIT_DEPLOYS="${WAIT_DEPLOYS% kubeheal-dashboard}"; shift ;;
    --registry) REGISTRY="${2%/}"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --platform) PLATFORM="${2:-}"; [[ -n $PLATFORM ]] || { echo "--platform needs a value"; exit 1; }; shift 2 ;;
    --target) TARGET="${2:-}"; [[ $TARGET == minikube || $TARGET == k3d ]] || { echo "--target must be minikube or k3d"; exit 1; }; shift 2 ;;
    --helm) HELM=1; shift ;;
    *) echo "usage: $0 [--target minikube|k3d] [--helm] [--force-context NAME] | $0 --production --registry HOST/PATH [--tag TAG] [--platform P]"; exit 1 ;;
  esac
done
[[ $PROD == 1 || -z "$REGISTRY$TAG" ]] || { echo "--registry/--tag only apply with --production"; exit 1; }
[[ $PROD == 0 || -n "$REGISTRY" ]] || { echo "--production needs --registry HOST/PATH (the overlay's images fail closed)"; exit 1; }
[[ $TARGET != k3d || $(kubectl config current-context) == k3d-kubeheal ]] || { echo "--target k3d needs context k3d-kubeheal (deploy/k3d/create.sh)"; exit 1; }
if [[ $TARGET == k3d && $EVENT_SOURCE == sensor ]] && { [[ ! -e /sys/kernel/btf/vmlinux ]] || ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; }; then
  echo "note: this host has no BTF or no bpf LSM (the k3d nodes share its kernel): using EVENT_SOURCE=falco"; EVENT_SOURCE=falco
fi

need() { command -v "$1" >/dev/null || { echo "need $1 on PATH"; exit 1; }; }
need kubectl; need helm

# --- Images -----------------------------------------------------------------
IMPORT=()
[[ $PROD == 1 || $PLATFORM != *,* ]] || { echo "dev builds load one platform into the local engine: pass a single --platform"; exit 1; }
DPLAT=(); [[ -z $PLATFORM ]] || DPLAT=(--platform "$PLATFORM")
build() {  # build <tag> <dockerfile> [context]
  if [[ $TARGET == k3d ]]; then
    need docker; docker build "${DPLAT[@]}" -t "$1" -f "$2" "${3:-.}"; IMPORT+=("$1")
  elif command -v minikube >/dev/null && minikube status >/dev/null 2>&1; then
    # minikube reads -f relative to the context and exits 0 on failure: pass it relative, then verify
    minikube image build -t "$1" -f "$(realpath --relative-to="${3:-.}" "$2")" "${3:-.}"
    minikube image ls | grep -qF "$1" || { echo "image build failed: $1"; exit 1; }
  else
    need docker; docker build "${DPLAT[@]}" -t "$1" -f "$2" "${3:-.}"
  fi
}
echo "[1/5] Build images"
if [[ $PROD == 1 ]]; then
  need docker; docker buildx version >/dev/null || { echo "need docker buildx"; exit 1; }
  TAG="${TAG:-$(git rev-parse --short HEAD)}"; PLATFORM="${PLATFORM:-linux/amd64,linux/arm64}"
  push() {  # push <name> <dockerfile> <context>: one multi-arch build, pushed straight to the registry
    docker buildx build --platform "$PLATFORM" --push -t "$REGISTRY/$1:$TAG" -f "$2" "$3"
  }
  for n in inference agents; do push "$n" "deploy/docker/Dockerfile.$n" .; done
  [[ $EVENT_SOURCE != sensor ]] || push sensor sensor/Dockerfile sensor
else
  build kubeheal.invalid/inference:v5 deploy/docker/Dockerfile.inference
  build kubeheal.invalid/agents:v5    deploy/docker/Dockerfile.agents
  build kubeheal.invalid/dashboard:v5 deploy/docker/Dockerfile.dashboard
  build kubeheal.invalid/chaos:v5     deploy/docker/Dockerfile.chaos
  [[ $EVENT_SOURCE == falco ]] || build kubeheal.invalid/sensor:v5 sensor/Dockerfile sensor
  [[ $TARGET != k3d ]] || { need k3d; k3d image import -c kubeheal "${IMPORT[@]}"; }
fi

# --- Dependencies -------------------------------------------------------------
echo "[2/5] Helm repos"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
[[ $EVENT_SOURCE == sensor ]] || helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
helm repo update >/dev/null

echo "[3/5] Prometheus (trimmed kube-prometheus-stack)$([[ $EVENT_SOURCE == sensor ]] || echo ' + Falco (modern eBPF)')"
# PROMETHEUS_URL in deploy/k8s/base/health-agent-deployment.yaml is the operator's
# prometheus-operated service in this namespace.
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack --version 92.10.1 \
  -n monitoring --create-namespace -f deploy/k8s/helm/monitoring-values.yaml --wait --timeout 10m
if [[ $EVENT_SOURCE == falco ]]; then
  # JSON events to /var/run/falco/events.jsonl on each node (security agent tails it).
  helm upgrade --install falco falcosecurity/falco --version 9.2.0 \
    -n falco --create-namespace -f deploy/k8s/helm/falco-values.yaml \
    --set-file 'customRules.kubeheal_rules\.yaml=deploy/k8s/falco-kubeheal-rules.yaml' \
    --wait --timeout 5m
elif helm status falco -n falco >/dev/null 2>&1; then
  echo "note: a Falco release is installed but unused with EVENT_SOURCE=sensor (helm uninstall falco -n falco)"
fi

# --- Control plane ----------------------------------------------------------
echo "[4/5] Deploy KubeHeal ($([[ $HELM == 1 ]] && echo helm || echo kustomize))$([[ $PROD == 1 ]] || echo ' + demo workload')"
if [[ $HELM == 1 ]]; then
  # Same objects as kustomize (tests/test_helm.py); profile values in deploy/helm/kubeheal/values-*.yaml.
  HV=(--set namespace.create=false --set eventSource="$EVENT_SOURCE")
  [[ $TARGET != k3d ]] || HV+=(-f deploy/helm/kubeheal/values-k3d.yaml)
  if [[ $PROD == 0 ]]; then HV=(-f deploy/helm/kubeheal/values-dev.yaml "${HV[@]}"); fi   # values.yaml defaults to the published GHCR images
  if [[ $PROD == 1 ]]; then
    HV+=(-f deploy/helm/kubeheal/values-production.yaml --set images.inference="$REGISTRY/inference:$TAG"
         --set images.agents="$REGISTRY/agents:$TAG" --set images.sensor="$REGISTRY/sensor:$TAG")
  else
    kubectl -n kubeheal delete netpol redis-kubeheal-only --ignore-not-found
  fi
  helm upgrade --install kubeheal deploy/helm/kubeheal -n kubeheal --create-namespace "${HV[@]}"
elif [[ $PROD == 1 || $EVENT_SOURCE == falco ]]; then
  # Production: the overlay's images are registry.invalid placeholders; a temp kustomization on top points them
  # at $REGISTRY. Falco: the same temp kustomization adds the falco-source component.
  # (A kustomize base must be a relative path, so the temp dir lives next to the overlay.)
  TMP="$(mktemp -d -p deploy/k8s/overlays .tmp.XXXXXX)"; trap 'rm -rf "$TMP"' EXIT
  {
    if [[ $PROD == 1 ]]; then echo "resources: [../production]"; else echo "resources: [../../base]"; fi
    [[ $EVENT_SOURCE == sensor ]] || echo "components: [../../components/falco-source]"
    if [[ $PROD == 1 ]]; then
      echo "images:"
      echo "  - {name: registry.invalid/kubeheal/inference, newName: $REGISTRY/inference, newTag: \"$TAG\"}"
      echo "  - {name: registry.invalid/kubeheal/agents, newName: $REGISTRY/agents, newTag: \"$TAG\"}"
      echo "  - {name: registry.invalid/kubeheal/sensor, newName: $REGISTRY/sensor, newTag: \"$TAG\"}"
    fi
  } >"$TMP/kustomization.yaml"
  kubectl apply -k "$TMP"
else
  kubectl -n kubeheal delete netpol redis-kubeheal-only --ignore-not-found   # pre-ACL policy; NetworkPolicies add up
  kubectl apply -k "$KUSTOMIZE"
fi
if [[ $PROD == 0 ]]; then
  kubectl apply -f deploy/demo/victim-app.yaml
  # the :v5 tags are rebuilt in place (IfNotPresent), so apply alone never restarts pods on a new image
  # (not redis: it restarts on its own spec changes; its PVC keeps the streams and workload baselines)
  RESTART=(daemonset/kubeheal-security-agent); for d in ${WAIT_DEPLOYS#redis }; do RESTART+=("deploy/$d"); done
  kubectl -n kubeheal rollout restart "${RESTART[@]}"
fi

echo "[5/5] Wait for rollout"
for d in $WAIT_DEPLOYS; do
  kubectl rollout status deploy/"$d" -n kubeheal --timeout=300s
done
[[ $PROD == 1 ]] && for d in redis redis-sentinel; do kubectl rollout status sts/"$d" -n kubeheal --timeout=300s; done   # production = Redis HA
kubectl rollout status daemonset/kubeheal-security-agent -n kubeheal --timeout=300s
[[ $PROD == 1 ]] || kubectl rollout status deploy/victim-app -n demo --timeout=300s

echo
[ $PROD = 0 ] && echo "Done. Dashboard:  kubectl port-forward svc/kubeheal-dashboard 8080:8080 -n kubeheal" || echo "Done (production: no dashboard)."
echo "Demo:       ./deploy/scripts/demo.sh   (fusion runs KUBEHEAL_MODE=enforce: it really patches and kills)"
