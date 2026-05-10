#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "========================================"
echo "KubeHeal Installation Script"
echo "========================================"

echo "[0/5] Checking prerequisites..."

for cmd in kubectl minikube helm docker; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found."
        exit 1
    fi
done
echo "Prerequisites OK"

echo "[1/5] Setting up Minikube..."

if minikube status | grep -q "Running"; then
    echo "Minikube already running, skipping start."
else
    minikube start \
        --driver=docker \
        --cpus=2 \
        --memory=4096m \
        --addons=ingress,metrics-server
fi

eval "$(minikube docker-env)"

echo "[2/5] Installing dependencies..."

helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
helm repo update || true

kubectl create namespace kubeheal 2>/dev/null || true
kubectl create namespace demo 2>/dev/null || true

echo "  Installing Redis (standalone)..."
helm upgrade --install redis bitnami/redis \
    --set architecture=standalone \
    --set auth.enabled=false \
    -n kubeheal

echo "  Waiting for Redis..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n kubeheal --timeout=120s || \
    echo "WARNING: Redis not ready yet, continuing..."

echo "[3/5] Building Docker images..."

images=(
    "kubeheal/dit-sec-server:v3|dockerfiles/Dockerfile.model"
    "kubeheal/health-agent:v3|dockerfiles/Dockerfile.health"
    "kubeheal/security-agent:v3|dockerfiles/Dockerfile.security"
    "kubeheal/fusion-agent:v3|dockerfiles/Dockerfile.fusion"
    "kubeheal/dashboard:v3|dockerfiles/Dockerfile.dashboard"
)

for entry in "${images[@]}"; do
    tag="${entry%%|*}"
    dockerfile="${entry##*|}"
    if [ ! -f "$dockerfile" ]; then
        echo "WARNING: $dockerfile not found, skipping."
        continue
    fi
    echo "  Building $tag..."
    if ! docker build -t "$tag" -f "$dockerfile" .; then
        echo "ERROR: Failed to build $tag"
        exit 1
    fi
done

echo "[4/5] Deploying K8s resources..."

kubectl apply -f k8s/rbac/rbac.yaml
kubectl apply -f k8s/crds/crds.yaml
kubectl apply -f k8s/dit-sec-deployment.yaml
kubectl apply -f k8s/health-agent-deployment.yaml
kubectl apply -f k8s/security-agent-daemonset.yaml
kubectl apply -f k8s/fusion-agent-deployment.yaml
kubectl apply -f k8s/dashboard-deployment.yaml
kubectl apply -f demo/victim-app.yaml

echo "[5/5] Verifying deployment..."

for label in "app=dit-sec-server" "app=health-agent" "app=fusion-agent" "app=kubeheal-dashboard"; do
    kubectl wait --for=condition=ready pod -l "$label" -n kubeheal --timeout=90s || \
        echo "WARNING: $label not ready in 90s"
done

echo ""
echo "========================================"
echo "Installation complete!"
echo "========================================"
echo ""
echo "Access the dashboard:"
echo "  kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n kubeheal"
echo "  Then open http://localhost:5000"
echo ""
echo "Run a demo:"
echo "  bash scripts/demo.sh"
