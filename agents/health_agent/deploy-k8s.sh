#!/bin/bash
# Deployment script for Health Agent to Kubernetes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-kubeheal}"
IMAGE_NAME="${IMAGE_NAME:-health-agent}"
IMAGE_TAG="${IMAGE_TAG:-v3.0}"
REGISTRY="${REGISTRY:-}"

# Construct full image name
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
else
    FULL_IMAGE_NAME="$IMAGE_NAME:$IMAGE_TAG"
fi

echo "======================================"
echo "Health Agent Kubernetes Deployment"
echo "======================================"
echo "Namespace: $NAMESPACE"
echo "Image: $FULL_IMAGE_NAME"
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "✗ kubectl not found. Please install kubectl."
    exit 1
fi

# Check cluster connectivity
echo "Checking cluster connectivity..."
if ! kubectl cluster-info &> /dev/null; then
    echo "✗ Cannot connect to Kubernetes cluster"
    exit 1
fi
echo "✓ Cluster is accessible"

# Create namespace if it doesn't exist
echo ""
echo "Creating namespace if needed..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Namespace '$NAMESPACE' ready"

# Apply the deployment manifest
echo ""
echo "Applying Health Agent deployment..."
kubectl apply -f "$SCRIPT_DIR/k8s-deployment.yaml"
echo "✓ Deployment manifest applied"

# Update image if specified
echo ""
echo "Updating container image to: $FULL_IMAGE_NAME"
kubectl set image deployment/health-agent \
    health-agent="$FULL_IMAGE_NAME" \
    -n "$NAMESPACE" \
    --record
echo "✓ Image updated"

# Wait for rollout
echo ""
echo "Waiting for deployment to be ready (timeout: 5 minutes)..."
if kubectl rollout status deployment/health-agent -n "$NAMESPACE" --timeout=5m; then
    echo "✓ Deployment ready"
else
    echo "✗ Deployment failed to become ready"
    echo ""
    echo "Pod status:"
    kubectl get pods -n "$NAMESPACE" -l app=health-agent
    echo ""
    echo "Recent events:"
    kubectl describe deployment health-agent -n "$NAMESPACE" | tail -20
    exit 1
fi

# Show deployment info
echo ""
echo "======================================"
echo "Deployment Successful!"
echo "======================================"
echo ""
echo "Deployment info:"
kubectl get deployment health-agent -n "$NAMESPACE"
echo ""
echo "Pods:"
kubectl get pods -n "$NAMESPACE" -l app=health-agent
echo ""
echo "Service:"
kubectl get svc health-agent -n "$NAMESPACE"
echo ""
echo "View logs:"
echo "  kubectl logs -n $NAMESPACE -l app=health-agent -f"
echo ""
echo "Delete deployment:"
echo "  kubectl delete ns $NAMESPACE"
