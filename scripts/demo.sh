#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

NAMESPACE=demo

# Pre-flight checks
if ! kubectl cluster-info &>/dev/null; then
    echo "ERROR: Kubernetes cluster not reachable. Run: minikube start"
    exit 1
fi

if ! redis-cli ping &>/dev/null; then
    echo "WARNING: Local redis-cli not reachable. Incident clearing will be skipped."
fi

echo "========================================"
echo "KubeHeal Demo Script"
echo "========================================"

echo "Preparing for demo..."
echo ""

# Ensure namespace exists
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - &>/dev/null

echo "Resetting victim app to baseline..."
if ! kubectl apply -f demo/victim-app.yaml -n "$NAMESPACE"; then
    echo "ERROR: Could not apply demo/victim-app.yaml"
    exit 1
fi

echo "Waiting for victim pod to be ready..."
kubectl wait --for=condition=ready pod -l app=victim -n "$NAMESPACE" --timeout=60s || {
    echo "WARNING: Victim pod not ready within 60s, continuing anyway..."
}

echo "Clearing incidents..."
redis-cli DEL kubeheal.incidents 2>/dev/null || true

echo ""
echo "Ready for demo!"
echo ""

echo "Press ENTER to start Demo A (Config Drift)..."
read -r

echo ""
echo "========================================"
echo "DEMO A: Configuration Drift"
echo "========================================"
echo ""
echo "Injecting CPU drift (500m -> 50m)..."
echo ""

if ! kubectl patch deployment victim-app -n "$NAMESPACE" \
    --type=merge \
    -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"50m"}}}]}}}}'; then
    echo "ERROR: Could not patch deployment victim-app in namespace $NAMESPACE"
    exit 1
fi

echo "Watching events (100s)..."
echo ""

for i in {1..20}; do
    echo -n "."
    sleep 5
done

echo ""
echo ""
echo "Check the dashboard for the auto-patch result."
echo "Expected: Risk score climbs to ~0.79, AUTO-PATCH applied in ~80s"
echo ""

echo "Press ENTER to start Demo B (Ransomware)..."
read -r

echo ""
echo "========================================"
echo "DEMO B: Ransomware Attack"
echo "========================================"
echo ""
echo "Deploying ransomware simulator..."
echo ""

if ! kubectl apply -f chaos/chaos-pods.yaml -n "$NAMESPACE"; then
    echo "ERROR: Could not apply chaos/chaos-pods.yaml"
    exit 1
fi

echo "Watch for:"
echo "  T+2.3s: First rename burst"
echo "  T+3.5s: NetworkPolicy blocks egress"
echo "  T+8s: AUTO-KILL triggered"
echo ""

echo "Demo complete!"
echo ""
echo "View incidents:"
echo "  redis-cli XREVRANGE kubeheal.incidents + - COUNT 10"
