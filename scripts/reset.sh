#!/bin/bash
# Return the demo to a clean baseline in <30s.
set -e
NS=demo
echo "Resetting KubeHeal demo..."
kubectl delete pod -l kubeheal.io/chaos=true -n $NS --ignore-not-found --grace-period=0 --force 2>/dev/null || true
kubectl delete networkpolicy kubeheal-quarantine -n $NS --ignore-not-found 2>/dev/null || true
kubectl apply -f demo/victim-app.yaml >/dev/null
kubectl rollout restart deployment victim-app -n $NS 2>/dev/null || true
REDIS=$(kubectl get svc redis-master -n kubeheal -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
for s in health.events security.events dcm.events actions incidents; do
  kubectl exec -n kubeheal deploy/kubeheal-dcm -- sh -c "true" 2>/dev/null || true
done
echo "Clearing Redis streams (best-effort)..."
kubectl run redis-reset --rm -i --restart=Never -n kubeheal --image=redis:7-alpine -- \
  sh -c "for s in kubeheal.health.events kubeheal.security.events kubeheal.dcm.events kubeheal.actions kubeheal.incidents; do redis-cli -h redis-master DEL \$s; done" 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=victim -n $NS --timeout=60s || true
echo "Reset complete."
