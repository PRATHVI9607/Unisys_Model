#!/bin/bash
set -e
echo "========================================"
echo " KubeHeal v4 Installation"
echo "========================================"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$(dirname "$SCRIPT_DIR")"

command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }
command -v minikube >/dev/null || { echo "need minikube"; exit 1; }
command -v helm >/dev/null || { echo "need helm"; exit 1; }

echo "[1/6] Minikube..."
minikube status >/dev/null 2>&1 || minikube start --driver=docker --cpus=4 --memory=7g \
  --addons=ingress,metrics-server,csi-hostpath-driver,volumesnapshots
eval "$(minikube docker-env)"

echo "[2/6] Dependencies (Redis Sentinel + Prometheus)..."
helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1 || true
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update >/dev/null
kubectl create namespace kubeheal  >/dev/null 2>&1 || true
kubectl create namespace demo      >/dev/null 2>&1 || true
kubectl create namespace monitoring>/dev/null 2>&1 || true
helm install redis bitnami/redis --set architecture=replication --set sentinel.enabled=true \
  --set sentinel.masterSet=mymaster -n kubeheal 2>/dev/null || true
helm install monitoring prometheus-community/kube-prometheus-stack -n monitoring 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n kubeheal --timeout=120s || true

echo "[3/6] Build images (v4: 2 models + DCM + 3 agents + dashboard)..."
docker build -t kubeheal/health-model-server:v4   -f dockerfiles/Dockerfile.health_model .
docker build -t kubeheal/security-model-server:v4 -f dockerfiles/Dockerfile.security_model .
docker build -t kubeheal/dcm-server:v4            -f dockerfiles/Dockerfile.dcm .
docker build -t kubeheal/health-agent:v4   -f dockerfiles/Dockerfile.health .
docker build -t kubeheal/security-agent:v4 -f dockerfiles/Dockerfile.security .
docker build -t kubeheal/fusion-agent:v4   -f dockerfiles/Dockerfile.fusion .
docker build -t kubeheal/dashboard:v4      -f dockerfiles/Dockerfile.dashboard .
docker build -t kubeheal/ransomware-simulator:v4 -f dockerfiles/Dockerfile.ransomware .

echo "[4/6] RBAC + CRDs..."
kubectl apply -f k8s/rbac/
kubectl apply -f k8s/crds/
# (NL summaries are generated locally — no external API key required)

echo "[5/6] Deploy model servers + agents..."
kubectl apply -f k8s/health-model-deployment.yaml
kubectl apply -f k8s/security-model-deployment.yaml
kubectl apply -f k8s/dcm-deployment.yaml
kubectl apply -f k8s/health-agent-deployment.yaml
kubectl apply -f k8s/security-agent-daemonset.yaml
kubectl apply -f k8s/fusion-agent-deployment.yaml
kubectl apply -f k8s/dashboard-deployment.yaml
kubectl apply -f demo/victim-app.yaml

echo "[6/6] Wait for rollout..."
for app in kubeheal-health-model kubeheal-security-model kubeheal-dcm health-agent fusion-agent kubeheal-dashboard; do
  kubectl wait --for=condition=ready pod -l app=$app -n kubeheal --timeout=90s || true
done

echo ""
echo "Done. Dashboard:  kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n kubeheal"
echo "Demo:       ./scripts/demo.sh"
