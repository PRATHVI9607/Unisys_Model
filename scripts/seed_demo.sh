#!/bin/bash
# =============================================================================
# KubeHeal v4 — demo seed.
# Injects a realistic set of health + security events straight into the Redis
# streams the dashboard reads (kubeheal.health.events / kubeheal.security.events)
# plus the per-event detail hashes the modal reads. Use this so the dashboard is
# never empty during a demo, independent of the live agents / cluster timing.
#
#   ./scripts/seed_demo.sh            # seed the standard story (6 events)
#   ./scripts/seed_demo.sh --clear    # wipe seeded streams first, then seed
#
# Runs Python inside the dashboard pod (already has redis + REDIS_URL), so it
# needs no host packages and no port-forward.
# =============================================================================
set -e
NS=kubeheal
POD_SEL="deploy/kubeheal-dashboard"
CLEAR=""
[ "$1" = "--clear" ] && CLEAR="1"

command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }
kubectl get $POD_SEL -n $NS >/dev/null 2>&1 || { echo "dashboard not deployed in ns/$NS"; exit 1; }

echo "Seeding demo events into Redis streams (ns/$NS)..."

CLEAR="$CLEAR" kubectl exec -i -n $NS $POD_SEL -- env CLEAR="$CLEAR" python - <<'PY'
import os, json, time, redis

r = redis.from_url(os.environ.get("REDIS_URL", "redis://redis-master:6379"), decode_responses=True)

if os.environ.get("CLEAR"):
    for s in ("kubeheal.health.events", "kubeheal.security.events"):
        r.delete(s)
    for k in r.scan_iter("kubeheal:health:*"):   r.delete(k)
    for k in r.scan_iter("kubeheal:security:*"): r.delete(k)
    print("  cleared existing seeded streams + hashes")

now = lambda off=0: str(int((time.time() + off) * 1000))

# ---- Health assessments (drift / degradation / config error) ---------------
health = [
    dict(event_id="hlth-demo-0001", namespace="demo", pod_name="victim-app",
         namespace_tier="dev", health_risk="0.1180", health_label="benign",
         health_ci_width="0.0900", top_field="-", top_metric="cpu_usage_millicores",
         field_attribution_json=json.dumps({"cpu_usage_millicores": 0.31, "http_p99_latency_ms": 0.22}),
         patch_proposal_json="{}", blast_radius="single-pod",
         inference_method="health_model_v4", off=-95),
    dict(event_id="hlth-demo-0002", namespace="demo", pod_name="payment-api",
         namespace_tier="prod", health_risk="0.7720", health_label="harmful_performance_degradation",
         top_field="containers[0].resources.limits.cpu", top_metric="cpu_throttle_percent",
         health_ci_width="0.1400",
         field_attribution_json=json.dumps({"cpu_throttle_percent": 0.74, "http_p99_latency_ms": 0.61, "http_error_rate": 0.40}),
         patch_proposal_json=json.dumps({"action": "restore_cpu_limit", "from": "50m", "to": "500m", "mode": "canary"}),
         blast_radius="service", inference_method="health_model_v4", off=-60),
    dict(event_id="hlth-demo-0003", namespace="demo", pod_name="victim-app",
         namespace_tier="dev", health_risk="0.9120", health_label="critical_config_error",
         top_field="containers[0].resources.limits.cpu", top_metric="cpu_throttle_percent",
         health_ci_width="0.0800",
         field_attribution_json=json.dumps({"cpu_throttle_percent": 0.91, "pod_restarts_total": 0.55}),
         patch_proposal_json=json.dumps({"action": "rollback_deployment", "revision": "previous"}),
         blast_radius="single-pod", inference_method="health_model_v4", off=-20),
]
for h in health:
    off = h.pop("off"); h["timestamp_ms"] = now(off)
    r.xadd("kubeheal.health.events", h)
    r.hset(f"kubeheal:health:{h['event_id']}", mapping=h)
    r.expire(f"kubeheal:health:{h['event_id']}", 86400)

# ---- Security events (suspicious / staging / active ransomware) -------------
security = [
    dict(event_id="sec-demo-0001", namespace="demo", pod_name="victim-app",
         namespace_tier="dev", sec_risk="0.3400", sec_label="suspicious",
         sec_ci_width="0.2200", top_syscall="openat",
         syscall_attribution_json=json.dumps({"openat": 0.30, "read": 0.18}),
         entropy_spike_json=json.dumps({"timestep": 4, "value": 5.9}),
         early_signals_json=json.dumps({"rename_burst": False, "high_entropy": False}),
         pid_target="20144", entropy="5.9000", action="observe", off=-80),
    dict(event_id="sec-demo-0002", namespace="demo", pod_name="victim-app",
         namespace_tier="dev", sec_risk="0.6800", sec_label="ransomware_staging",
         sec_ci_width="0.1700", top_syscall="rename",
         syscall_attribution_json=json.dumps({"rename": 0.52, "write": 0.31, "openat": 0.22}),
         entropy_spike_json=json.dumps({"timestep": 11, "value": 7.1}),
         early_signals_json=json.dumps({"rename_burst": True, "high_entropy": True}),
         pid_target="20144", entropy="7.1000", action="alert", off=-35),
    dict(event_id="sec-demo-0003", namespace="demo", pod_name="victim-app",
         namespace_tier="dev", sec_risk="0.9410", sec_label="ransomware_active",
         sec_ci_width="0.0600", top_syscall="write",
         syscall_attribution_json=json.dumps({"write": 0.61, "rename": 0.55, "ftruncate": 0.40}),
         entropy_spike_json=json.dumps({"timestep": 18, "value": 7.7}),
         early_signals_json=json.dumps({"rename_burst": True, "high_entropy": True, "mass_write": True}),
         pid_target="20144", entropy="7.7000", action="quarantine_and_kill", off=-8),
]
for s in security:
    off = s.pop("off"); s["timestamp_ms"] = now(off)
    r.xadd("kubeheal.security.events", s)
    r.hset(f"kubeheal:security:{s['event_id']}", mapping=s)
    r.expire(f"kubeheal:security:{s['event_id']}", 86400)

hl = r.xlen("kubeheal.health.events"); sl = r.xlen("kubeheal.security.events")
print(f"  seeded {len(health)} health + {len(security)} security events")
print(f"  stream lengths now: health={hl}, security={sl}")
PY

# On --clear, restart the dashboard so its in-memory event list reloads from the
# freshly-seeded stream (it reads the stream from the beginning on startup).
if [ -n "$CLEAR" ]; then
  echo "Restarting dashboard to reload the clean stream..."
  kubectl rollout restart deploy/kubeheal-dashboard -n $NS >/dev/null 2>&1 || true
  kubectl rollout status deploy/kubeheal-dashboard -n $NS --timeout=90s >/dev/null 2>&1 || true
  echo "  dashboard restarted"
fi

echo ""
echo "Done. The dashboard should now show data within ~1s."
echo "If not already forwarding:  kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n $NS"
echo "Open: http://localhost:5000"
