#!/bin/bash
set -e

echo "========================================"
echo "KubeHeal Installation Script"
echo "========================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "[0/5] Checking prerequisites..."

if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found. Please install kubectl first."
    exit 1
fi

if ! command -v minikube &> /dev/null; then
    echo "Error: minikube not found. Please install minikube first."
    exit 1
fi

if ! command -v helm &> /dev/null; then
    echo "Error: helm not found. Please install helm first."
    exit 1
fi

echo "Prerequisites OK"

echo "[1/5] Setting up Minikube..."

minikube status || minikube start \
    --driver=docker \
    --cpus=4 \
    --memory=7g \
    --addons=ingress,metrics-server,csi-hostpath-driver,volumesnapshots

eval $(minikube docker-env)

echo "[2/5] Installing dependencies..."

helm repo add bitnami https://charts.bitnami.com/bitnami || true
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || true
helm repo update

kubectl create namespace kubeheal || true
kubectl create namespace demo || true
kubectl create namespace monitoring || true

echo "  Installing Redis..."
helm install redis bitnami/redis \
    --set architecture=replication \
    --set sentinel.enabled=true \
    --set sentinel.masterSet=mymaster \
    -n kubeheal

echo "  Installing Prometheus..."
helm install monitoring prometheus-community/kube-prometheus-stack \
    -n monitoring

echo "  Waiting for Redis..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n kubeheal --timeout=120s || true

echo "[3/5] Building Docker images..."

docker build -t kubeheal/dit-sec-server:v3 -f dockerfiles/Dockerfile.model .
docker build -t kubeheal/health-agent:v3 -f dockerfiles/Dockerfile.health .
docker build -t kubeheal/security-agent:v3 -f dockerfiles/Dockerfile.security .
docker build -t kubeheal/fusion-agent:v3 -f dockerfiles/Dockerfile.fusion .
docker build -t kubeheal/dashboard:v3 -f dockerfiles/Dockerfile.dashboard .
docker build -t kubeheal/ransomware-simulator:v3 -f dockerfiles/Dockerfile.chaos .

echo "[4/5] Deploying K8s resources..."

echo "  Applying RBAC..."
kubectl apply -f k8s/rbac/

echo "  Applying CRDs..."
kubectl apply -f k8s/crds/

echo "  Deploying DIT-Sec model server..."
kubectl apply -f k8s/dit-sec-deployment.yaml

echo "  Deploying Health Agent..."
kubectl apply -f k8s/health-agent-deployment.yaml

echo "  Deploying Security Agent..."
kubectl apply -f k8s/security-agent-daemonset.yaml

echo "  Deploying Fusion Agent..."
kubectl apply -f k8s/fusion-agent-deployment.yaml

echo "  Deploying Dashboard..."
kubectl apply -f k8s/dashboard-deployment.yaml

echo "  Deploying demo app..."
kubectl apply -f demo/victim-app.yaml

echo "[5/5] Verifying deployment..."

kubectl wait --for=condition=ready pod -l app=dit-sec-server -n kubeheal --timeout=60s || true
kubectl wait --for=condition=ready pod -l app=health-agent -n kubeheal --timeout=60s || true
kubectl wait --for=condition=ready pod -l app=fusion-agent -n kubeheal --timeout=60s || true
kubectl wait --for=condition=ready pod -l app=kubeheal-dashboard -n kubeheal --timeout=60s || true

echo ""
echo "========================================"
echo "Installation complete!"
echo "========================================"
echo ""
echo "Access the dashboard:"
echo "  kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n kubeheal"
echo "  Then open http://localhost:5000"
echo ""
echo "Access Grafana:"
echo "  kubectl port-forward svc/monitoring-grafana 3000:80 -n monitoring"
echo "  Then open http://localhost:3000"
echo ""
echo "Run a demo:"
echo "  ./scripts/demo.sh"