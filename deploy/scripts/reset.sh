#!/usr/bin/env bash
# Return the demo to a clean baseline: drop chaos pods + quarantine policies, recreate demo/victim-app
# from its manifest, delete the KubeHeal Redis state that belongs to namespace demo only (stream
# entries, event copies, baselines/specs, circuit breakers, locks, idempotency markers), and restart the
# agents so their in-memory state matches (the health agent re-learns the restored spec as the baseline
# on first sight). Other namespaces' baselines and history are never touched.
# Refuses to run unless kubectl points at minikube, or you name the current context explicitly:
#   ./deploy/scripts/reset.sh                       # minikube only
#   ./deploy/scripts/reset.sh --force-context NAME  # NAME must equal `kubectl config current-context`
set -euo pipefail
NS=demo; KH=kubeheal
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }
CTX="$(kubectl config current-context)"
case "${1:-}" in
  "") [[ $CTX == minikube ]] || { echo "refusing: context is '$CTX', not minikube (use --force-context $CTX)"; exit 1; } ;;
  --force-context) [[ "${2:-}" == "$CTX" ]] || { echo "refusing: --force-context '${2:-}' != current context '$CTX'"; exit 1; } ;;
  *) echo "usage: $0 [--force-context CONTEXT]"; exit 1 ;;
esac

echo "Removing chaos workloads + quarantine network policies..."
kubectl delete deploy,pod -l kubeheal.io/chaos=true -n "$NS" --ignore-not-found --grace-period=0 --force 2>/dev/null
# Quarantine policies are owned by their pod and GC'd with it; delete any leftovers.
kubectl get networkpolicy -n "$NS" -o name | { grep '/kubeheal-quarantine-' || true; } \
  | xargs -r kubectl delete -n "$NS" --ignore-not-found

echo "Recreating demo/victim-app from deploy/demo/victim-app.yaml..."
# delete + apply: `apply` alone would keep fields set imperatively (kubectl set/patch/scale).
kubectl delete deploy victim-app -n "$NS" --ignore-not-found --wait=true
kubectl apply -f deploy/demo/victim-app.yaml
kubectl rollout status deploy/victim-app -n "$NS" --timeout=180s

echo "Deleting KubeHeal Redis state of namespace $NS..."
# One Lua script (admin user via the container's REDISCLI_AUTH): stream entries and event hashes whose
# `namespace` field is $NS, keys kubeheal:{spec,baseline,lock}:$NS:* and kubeheal:cb:*:$NS:*, and
# kubeheal:done:* markers whose ActionEvent JSON names $NS. Streams and consumer groups stay.
OUT="$(kubectl exec -i -n "$KH" deploy/redis -- sh -c 'redis-cli EVAL "$(cat)" 0 "$1"' _ "$NS" <<'LUA'
local ns, n, cursor = ARGV[1], 0, "0"
repeat
  local page = redis.call("SCAN", cursor, "MATCH", "kubeheal*", "COUNT", 1000)
  cursor = page[1]
  for _, key in ipairs(page[2]) do
    local t, seg = redis.call("TYPE", key).ok, {}
    for s in string.gmatch(key, "[^:]+") do seg[#seg + 1] = s end
    if t == "stream" then
      for _, e in ipairs(redis.call("XRANGE", key, "-", "+")) do
        local f = e[2]
        for i = 1, #f, 2 do
          if f[i] == "namespace" and f[i + 1] == ns then redis.call("XDEL", key, e[1]); n = n + 1 end
        end
      end
    elseif t == "hash" then
      if redis.call("HGET", key, "namespace") == ns then
        redis.call("DEL", key); redis.call("LREM", "kubeheal:index:" .. seg[2], 0, key); n = n + 1
      end
    elseif t == "string" then
      local hit = ((seg[2] == "spec" or seg[2] == "baseline" or seg[2] == "lock") and seg[3] == ns)
        or (seg[2] == "cb" and seg[4] == ns)
      if not hit and seg[2] == "done" then
        local ok, v = pcall(cjson.decode, redis.call("GET", key))
        hit = ok and type(v) == "table" and v.namespace == ns
      end
      if hit then redis.call("DEL", key); n = n + 1 end
    end
  end
until cursor == "0"
return n
LUA
)"
[[ $OUT =~ ^[0-9]+$ ]] || { echo "redis cleanup failed: $OUT"; exit 1; }   # redis-cli exits 0 on error replies
echo "  deleted $OUT entries/keys"

echo "Restarting agents..."
kubectl rollout restart deploy/kubeheal-health-agent deploy/kubeheal-fusion-agent ds/kubeheal-security-agent -n "$KH"
kubectl rollout status deploy/kubeheal-fusion-agent -n "$KH" --timeout=180s
kubectl rollout status deploy/kubeheal-health-agent -n "$KH" --timeout=180s
kubectl rollout status ds/kubeheal-security-agent -n "$KH" --timeout=180s
DELAY=$(kubectl get deploy kubeheal-health-agent -n "$KH" \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ASSESS_DELAY_S")].value}')
echo "Reset complete. The health agent stores baselines ${DELAY:-60}s after start; wait that long before"
echo "./deploy/scripts/demo.sh. (Leftover khtest_* files on the PVC are harmless test artifacts.)"
