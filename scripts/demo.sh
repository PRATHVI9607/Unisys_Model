#!/bin/bash
set -e

echo "========================================"
echo "KubeHeal Demo Script"
echo "========================================"

NAMESPACE=demo

echo "Preparing for demo..."
echo ""

echo "Resetting victim app to baseline..."
kubectl apply -f demo/victim-app.yaml -n $NAMESPACE

kubectl wait --for=condition=ready pod -l app=victim -n $NAMESPACE --timeout=60s

echo "Clearing incidents..."
redis-cli DEL kubeheal.incidents 2>/dev/null || true

echo ""
echo "Ready for demo!"
echo ""

echo "Press ENTER to start Demo A (Config Drift)..."
read

echo ""
echo "========================================"
echo "DEMO A: Configuration Drift"
echo "========================================"
echo ""
echo "Injecting CPU drift (500m -> 50m)..."
echo ""

kubectl patch deployment victim-app -n $NAMESPACE \
    --type=merge \
    -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"50m"}}}]}}}}'

echo "Watching events..."
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
read

echo ""
echo "========================================"
echo "DEMO B: Ransomware Attack"
echo "========================================"
echo ""
echo "Deploying ransomware simulator..."
echo ""

kubectl apply -f chaos/chaos-pods.yaml -n $NAMESPACE

echo "Watch for:"
echo "  T+2.3s: First rename burst"
echo "  T+3.5s: NetworkPolicy blocks egress"
echo "  T+8s: AUTO-KILL triggered"
echo ""

echo "Demo complete!"
echo ""
echo "View incidents:"
echo "  redis-cli XREVRANGE kubeheal.incidents 0 + COUNT 10"