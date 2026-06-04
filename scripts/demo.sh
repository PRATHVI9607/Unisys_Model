#!/bin/bash
# KubeHeal v4 — 15-minute demo driver (config drift + ransomware).
set -e
NS=demo
echo "==== KubeHeal v4 Demo ===="
echo "Dashboard: http://localhost:5000  (kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n kubeheal)"
read -rp "ENTER for Demo A — Config Drift..."
echo "Injecting CPU drift 500m -> 50m on victim-app..."
kubectl patch deployment victim-app -n $NS --type=merge \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"50m"}}}]}}}}'
echo "Watch the dashboard: health_risk should rise, field attribution = containers[0].resources.limits.cpu,"
echo "sec_risk stays low, DCM correlation low -> AUTO-PATCH (canary)."
read -rp "ENTER for Demo B — Ransomware..."
kubectl apply -f chaos/chaos-pods.yaml -n $NS
echo "Watch: rename burst -> NetworkPolicy egress block -> entropy 7.7 bits -> sec_risk high"
echo "DCM correlation high (CPU thrash looks like drift) -> compound AUTO-KILL <8s. See causal chain panel."
