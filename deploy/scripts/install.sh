#!/usr/bin/env bash
# KubeHeal v5 install: build the 4 images, install Prometheus + Falco (Helm,
# values in deploy/k8s/helm/), deploy the control plane (kustomize, incl. Redis) and the
# demo app. Works on minikube (images built straight into the node) or any
# cluster your kubectl points at (local docker build; push them yourself).
# Idempotent; fails loudly — no `|| true` on real steps.
# Usage: install.sh [--production]   (default: dev/lab install from deploy/k8s; --production
# applies deploy/k8s/overlays/production: no dashboard, inference HPA/PDB, PriorityClass)
set -euo pipefail
KUSTOMIZE=deploy/k8s/; WAIT_DEPLOYS="redis kubeheal-inference kubeheal-health-agent kubeheal-fusion-agent kubeheal-dashboard"
case "${1:-}" in
  "") ;;
  --production) KUSTOMIZE=deploy/k8s/overlays/production; WAIT_DEPLOYS="${WAIT_DEPLOYS% kubeheal-dashboard}" ;;
  *) echo "usage: $0 [--production]"; exit 1 ;;
esac
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

need() { command -v "$1" >/dev/null || { echo "need $1 on PATH"; exit 1; }; }
need kubectl; need helm

# --- Images -----------------------------------------------------------------
build() {  # build <tag> <dockerfile>
  if command -v minikube >/dev/null && minikube status >/dev/null 2>&1; then
    minikube image build -t "$1" -f "$2" .
  else
    need docker; docker build -t "$1" -f "$2" .
  fi
}
echo "[1/5] Build images"
build kubeheal/inference:v5 deploy/docker/Dockerfile.inference
build kubeheal/agents:v5    deploy/docker/Dockerfile.agents
build kubeheal/dashboard:v5 deploy/docker/Dockerfile.dashboard
build kubeheal/chaos:v5     deploy/docker/Dockerfile.chaos

# --- Dependencies -------------------------------------------------------------
echo "[2/5] Helm repos"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
helm repo update >/dev/null

echo "[3/5] Prometheus (trimmed kube-prometheus-stack) + Falco (modern eBPF)"
# PROMETHEUS_URL in deploy/k8s/base/health-agent-deployment.yaml is the operator's
# prometheus-operated service in this namespace.
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack --version 92.10.1 \
  -n monitoring --create-namespace -f deploy/k8s/helm/monitoring-values.yaml --wait --timeout 10m
# JSON events to /var/run/falco/events.jsonl on each node (security agent tails it).
helm upgrade --install falco falcosecurity/falco --version 9.2.0 \
  -n falco --create-namespace -f deploy/k8s/helm/falco-values.yaml \
  --set-file 'customRules.kubeheal_rules\.yaml=deploy/k8s/falco-kubeheal-rules.yaml' \
  --wait --timeout 5m

# --- Control plane ----------------------------------------------------------
echo "[4/5] Deploy KubeHeal (kustomize) + demo workload"
kubectl apply -k "$KUSTOMIZE"
kubectl apply -f deploy/demo/victim-app.yaml

echo "[5/5] Wait for rollout"
for d in $WAIT_DEPLOYS; do
  kubectl rollout status deploy/"$d" -n kubeheal --timeout=300s
done
kubectl rollout status daemonset/kubeheal-security-agent -n kubeheal --timeout=300s
kubectl rollout status deploy/victim-app -n demo --timeout=300s

echo
[ "$KUSTOMIZE" = deploy/k8s/ ] && echo "Done. Dashboard:  kubectl port-forward svc/kubeheal-dashboard 8080:8080 -n kubeheal" || echo "Done (production: no dashboard)."
echo "Demo:       ./deploy/scripts/demo.sh   (fusion runs KUBEHEAL_MODE=enforce: it really patches and kills)"
