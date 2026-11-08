#!/usr/bin/env bash
# KubeHeal v5 install: build the images, install Prometheus (Helm, values in deploy/k8s/helm/),
# deploy the control plane (kustomize, incl. Redis and the eBPF event sensor) and the
# demo app. Works on minikube (images built straight into the node) or any
# cluster your kubectl points at (local docker build; push them yourself).
# Idempotent; fails loudly — no `|| true` on real steps.
# Usage: install.sh                                   dev/lab install from deploy/k8s (minikube or local cluster)
#        install.sh --production --registry HOST/PATH [--tag TAG]
#   --production applies deploy/k8s/overlays/production (no dashboard, inference HPA/PDB,
#   PriorityClass), with images HOST/PATH/{inference,agents}:TAG (TAG defaults to the git short SHA).
#   It builds and pushes them with docker, and skips the demo app and the chaos image.
# EVENT_SOURCE=sensor (default): the eBPF sensor (sensor/) runs in the security-agent DaemonSet.
# EVENT_SOURCE=falco: Falco (Helm, deploy/k8s/helm/falco-values.yaml) feeds the agent instead
#   (deploy/k8s/components/falco-source). Falco caps at ~1900 alerts/s per node: sensor/README.md.
set -euo pipefail
EVENT_SOURCE="${EVENT_SOURCE:-sensor}"
[[ $EVENT_SOURCE == sensor || $EVENT_SOURCE == falco ]] || { echo "EVENT_SOURCE must be sensor or falco"; exit 1; }
KUSTOMIZE=deploy/k8s/; WAIT_DEPLOYS="redis kubeheal-inference kubeheal-health-agent kubeheal-fusion-agent kubeheal-dashboard"
PROD=0 REGISTRY="" TAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --production) PROD=1; KUSTOMIZE=deploy/k8s/overlays/production; WAIT_DEPLOYS="${WAIT_DEPLOYS% kubeheal-dashboard}"; shift ;;
    --registry) REGISTRY="${2%/}"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    *) echo "usage: $0 | $0 --production --registry HOST/PATH [--tag TAG]"; exit 1 ;;
  esac
done
[[ $PROD == 1 || -z "$REGISTRY$TAG" ]] || { echo "--registry/--tag only apply with --production"; exit 1; }
[[ $PROD == 0 || -n "$REGISTRY" ]] || { echo "--production needs --registry HOST/PATH (the overlay's images fail closed)"; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

need() { command -v "$1" >/dev/null || { echo "need $1 on PATH"; exit 1; }; }
need kubectl; need helm

# --- Images -----------------------------------------------------------------
build() {  # build <tag> <dockerfile> [context]
  if command -v minikube >/dev/null && minikube status >/dev/null 2>&1; then
    # minikube reads -f relative to the context and exits 0 on failure: pass it relative, then verify
    minikube image build -t "$1" -f "$(realpath --relative-to="${3:-.}" "$2")" "${3:-.}"
    minikube image ls | grep -qF "$1" || { echo "image build failed: $1"; exit 1; }
  else
    need docker; docker build -t "$1" -f "$2" "${3:-.}"
  fi
}
echo "[1/5] Build images"
if [[ $PROD == 1 ]]; then
  need docker
  TAG="${TAG:-$(git rev-parse --short HEAD)}"
  for n in inference agents; do
    docker build -t "$REGISTRY/$n:$TAG" -f "deploy/docker/Dockerfile.$n" .
    docker push "$REGISTRY/$n:$TAG"
  done
  if [[ $EVENT_SOURCE == sensor ]]; then
    docker build -t "$REGISTRY/sensor:$TAG" sensor/
    docker push "$REGISTRY/sensor:$TAG"
  fi
else
  build kubeheal.invalid/inference:v5 deploy/docker/Dockerfile.inference
  build kubeheal.invalid/agents:v5    deploy/docker/Dockerfile.agents
  build kubeheal.invalid/dashboard:v5 deploy/docker/Dockerfile.dashboard
  build kubeheal.invalid/chaos:v5     deploy/docker/Dockerfile.chaos
  [[ $EVENT_SOURCE == falco ]] || build kubeheal.invalid/sensor:v5 sensor/Dockerfile sensor
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
echo "[4/5] Deploy KubeHeal (kustomize)$([[ $PROD == 1 ]] || echo ' + demo workload')"
if [[ $PROD == 1 || $EVENT_SOURCE == falco ]]; then
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
kubectl rollout status daemonset/kubeheal-security-agent -n kubeheal --timeout=300s
[[ $PROD == 1 ]] || kubectl rollout status deploy/victim-app -n demo --timeout=300s

echo
[ $PROD = 0 ] && echo "Done. Dashboard:  kubectl port-forward svc/kubeheal-dashboard 8080:8080 -n kubeheal" || echo "Done (production: no dashboard)."
echo "Demo:       ./deploy/scripts/demo.sh   (fusion runs KUBEHEAL_MODE=enforce: it really patches and kills)"
