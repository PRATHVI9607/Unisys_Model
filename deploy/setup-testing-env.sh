#!/bin/bash
set -e

# Setup script for DIT-Sec v3.0 live cluster testing
# Phase 1: Infrastructure deployment (1-2 hours expected total with baseline)

echo "===================================================="
echo "DIT-Sec v3.0 Live Cluster Testing - Setup Phase"
echo "===================================================="
echo ""
echo "Timeline:"
echo "  1. Build Docker image (2-3 min)"
echo "  2. Deploy namespaces and RBAC (1 min)"
echo "  3. Deploy Redis (2 min + startup)"
echo "  4. Deploy Health Agent (2 min + startup)"
echo "  5. Verify pipeline (3-5 min)"
echo "  6. Ready for 30-min baseline collection"
echo ""
echo "Total setup time: ~10-15 minutes"
echo ""
echo "===================================================="
echo ""

PROJECT_ROOT="/home/ryan/Desktop/Unisys_Model"
MANIFESTS_DIR="/tmp/dit-sec-testing"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# STEP 1: Build Docker image
# ============================================================================
log_info "STEP 1: Building health-agent:v3-ditsec-embedded Docker image..."
echo ""

if ! bash "$MANIFESTS_DIR/build-docker-image.sh"; then
    log_error "Failed to build Docker image"
    exit 1
fi

echo ""
log_info "✓ Docker image built successfully"
echo ""

# ============================================================================
# STEP 2: Deploy namespaces and RBAC
# ============================================================================
log_info "STEP 2: Creating namespaces and RBAC..."
echo ""

kubectl apply -f "$MANIFESTS_DIR/01-namespace.yaml"

echo ""
log_info "✓ Namespaces and RBAC configured"
echo ""

# Verify namespace creation
kubectl get ns demo-kubeheal || log_warn "demo-kubeheal namespace not ready yet"
sleep 2

# ============================================================================
# STEP 3: Deploy Redis
# ============================================================================
log_info "STEP 3: Deploying Redis to demo-kubeheal namespace..."
echo ""

kubectl apply -f "$MANIFESTS_DIR/02-redis.yaml"

echo ""
log_info "Waiting for Redis to be ready (max 30s)..."
kubectl wait --for=condition=ready pod -l app=redis -n demo-kubeheal --timeout=30s 2>/dev/null || true

# Check Redis status
REDIS_POD=$(kubectl get pods -n demo-kubeheal -l app=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$REDIS_POD" ]; then
    log_warn "Redis pod not found yet, waiting..."
    sleep 5
    REDIS_POD=$(kubectl get pods -n demo-kubeheal -l app=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
fi

if [ -n "$REDIS_POD" ]; then
    log_info "✓ Redis pod: $REDIS_POD"
    kubectl get pods -n demo-kubeheal -l app=redis
else
    log_warn "Redis pod status not visible yet"
fi

echo ""

# ============================================================================
# STEP 4: Deploy Health Agent
# ============================================================================
log_info "STEP 4: Deploying Health Agent with embedded DIT-Sec model..."
echo ""

kubectl apply -f "$MANIFESTS_DIR/03-health-agent.yaml"

echo ""
log_info "Waiting for Health Agent to be ready (max 60s)..."
kubectl wait --for=condition=ready pod -l app=health-agent -n demo --timeout=60s 2>/dev/null || true

# Check Health Agent status
HA_POD=$(kubectl get pods -n demo -l app=health-agent -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$HA_POD" ]; then
    log_warn "Health Agent pod not found yet, waiting..."
    sleep 5
    HA_POD=$(kubectl get pods -n demo -l app=health-agent -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
fi

if [ -n "$HA_POD" ]; then
    log_info "✓ Health Agent pod: $HA_POD"
    kubectl get pods -n demo -l app=health-agent
else
    log_warn "Health Agent pod status not visible yet"
fi

echo ""

# ============================================================================
# STEP 5: Deploy ServiceMonitor (optional, for Prometheus metrics)
# ============================================================================
log_info "STEP 5: Deploying ServiceMonitor for Prometheus integration..."
echo ""

# Check if ServiceMonitor CRD exists
if kubectl get crd servicemonitors.monitoring.coreos.com >/dev/null 2>&1; then
    kubectl apply -f "$MANIFESTS_DIR/04-servicemonitor.yaml"
    log_info "✓ ServiceMonitor deployed"
else
    log_warn "ServiceMonitor CRD not found - skipping Prometheus integration"
fi

echo ""

# ============================================================================
# STEP 6: Verification
# ============================================================================
log_info "STEP 6: Verifying deployment..."
echo ""

echo "Redis status:"
kubectl get pods -n demo-kubeheal -l app=redis
echo ""

echo "Health Agent status:"
kubectl get pods -n demo -l app=health-agent
echo ""

echo "Services:"
kubectl get svc -n demo health-agent
kubectl get svc -n demo-kubeheal redis-master
echo ""

# Test Redis connectivity from Health Agent
if [ -n "$HA_POD" ]; then
    log_info "Testing Redis connectivity from Health Agent pod..."
    kubectl exec -n demo "$HA_POD" -- python -c "import redis; r = redis.Redis(host='redis-master.demo-kubeheal', port=6379); print('Redis connection:', r.ping())" 2>/dev/null || log_warn "Could not test Redis connectivity yet"
fi

echo ""
log_info "Testing DIT-Sec model loading in Health Agent..."
if [ -n "$HA_POD" ]; then
    kubectl logs -n demo "$HA_POD" | grep -E "DIT-Sec|Loaded|loaded" || log_warn "Checking pod logs..."
    kubectl logs -n demo "$HA_POD" | tail -20
fi

echo ""
echo "===================================================="
echo "Setup phase complete!"
echo "===================================================="
echo ""
echo "Next steps:"
echo "  1. Verify Health Agent is running: kubectl logs -n demo health-agent-* -f"
echo "  2. Ready to start baseline collection (30 minutes)"
echo "  3. Then execute 5 threat scenarios"
echo ""
echo "To continue testing:"
echo "  bash $MANIFESTS_DIR/run-baseline-collection.sh"
echo ""
