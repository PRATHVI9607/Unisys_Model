#!/usr/bin/env bash
# Seed the dashboard with a handful of contract-valid events so it is never
# blank in a demo. Publishes ActionEvents (built from kubeheal.contracts) onto
# kubeheal.actions and writes the Health/Security detail hashes they link to.
# It never writes kubeheal.health.events / kubeheal.security.events: fusion
# consumes those, and in enforce mode fake events there could patch or kill.
# Runs on the host via `uv run` against a port-forwarded Redis.
#   ./deploy/scripts/seed_demo.sh            # seed the standard story
#   ./deploy/scripts/seed_demo.sh --clear    # wipe the actions stream + action details first, then seed
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
command -v kubectl >/dev/null || { echo "need kubectl"; exit 1; }

PORT=16379   # not 6379: never hit a local Redis by accident
kubectl port-forward -n kubeheal svc/redis-master "$PORT:6379" >/tmp/kh-redis-pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.5; done
kill -0 "$PF" 2>/dev/null || { echo "port-forward failed:"; cat /tmp/kh-redis-pf.log; exit 1; }

# Redis requires auth (deploy/k8s/base/redis.yaml): the admin (`default`) password from Secret kubeheal-redis.
PW="$(kubectl get secret kubeheal-redis -n kubeheal -o jsonpath='{.data.default-password}' | base64 -d)"
[[ -n $PW ]] || { echo "no Secret kubeheal/kubeheal-redis (default-password)"; exit 1; }
REDIS_URL="redis://default:$PW@127.0.0.1:$PORT/0" CLEAR="${1:-}" uv run --extra dashboard python - <<'PY'
import os, redis
from kubeheal import contracts as c

r = redis.from_url(os.environ["REDIS_URL"])
if os.environ.get("CLEAR") == "--clear":
    r.delete(c.STREAM_ACTIONS)
    for k in r.scan_iter("kubeheal:action:*"): r.delete(k)
    print("cleared actions stream + action detail hashes")

now = c.now_ms()
def detail(kind, ev):  # detail hash only: no stream entry, so fusion never sees it
    fields = ev.to_fields()
    r.hset(c.key_event(kind, ev.event_id), mapping=fields)
    r.expire(c.key_event(kind, ev.event_id), 86400)

h_benign = c.HealthEvent(event_id=c.new_event_id("hlth"), namespace="demo", workload="victim-app",
    timestamp_ms=now-95000, model_version="health-demo", label="benign", risk=0.08,
    probabilities={"benign":0.9,"degradation":0.07,"critical":0.03}, spec_changed=True,
    changed_fields=["template.spec.containers[0].image"], has_baseline=True)
h_degr = c.HealthEvent(event_id=c.new_event_id("hlth"), namespace="demo", workload="victim-app",
    timestamp_ms=now-40000, model_version="health-demo", label="degradation", risk=0.78,
    probabilities={"benign":0.1,"degradation":0.75,"critical":0.15},
    changed_fields=["template.spec.containers[0].resources.limits.cpu"], has_baseline=True)
s_ransom = c.SecurityEvent(event_id=c.new_event_id("sec"), namespace="demo", workload="victim-app",
    pod="victim-app-7d9", timestamp_ms=now-10000, model_version="security-demo", label="ransomware",
    risk=0.94, probabilities={"benign":0.02,"suspicious":0.04,"ransomware":0.9,"exfiltration":0.04},
    window_start_ms=now-20000, window_end_ms=now-10000, n_events=640)

detail("health", h_benign)
detail("health", h_degr)
detail("security", s_ransom)

a1 = c.ActionEvent(event_id=c.new_event_id("act"), namespace="demo", workload="victim-app",
    decision=c.Decision.OBSERVE, mode="observe", outcome="would_patch", score=0.78, compound_score=0.0,
    rationale="CPU limit cut drove a degradation assessment; no security signal.",
    summary="Config drift on victim-app degraded performance; patch would restore the baseline.",
    health_event_id=h_degr.event_id)
a2 = c.ActionEvent(event_id=c.new_event_id("act"), namespace="demo", workload="victim-app",
    pod="victim-app-7d9", decision=c.Decision.AUTO_KILL, mode="observe", outcome="would_kill",
    score=0.94, compound_score=0.71,
    rationale="High-entropy write+rename burst classified ransomware; correlated with the drift.",
    summary="Ransomware behaviour detected on victim-app; the pod would be quarantined and killed.",
    health_event_id=h_degr.event_id, security_event_id=s_ransom.event_id)
for a in (a1, a2):
    f = a.to_fields()
    r.xadd(c.STREAM_ACTIONS, f, maxlen=c.STREAM_MAXLEN, approximate=True)
    r.hset(c.key_event("action", a.event_id), mapping=f); r.expire(c.key_event("action", a.event_id), 86400)

print(f"seeded: actions={r.xlen(c.STREAM_ACTIONS)}")
PY

echo "Done. If the dashboard caches the stream at startup, restart it:"
echo "  kubectl rollout restart deploy/kubeheal-dashboard -n kubeheal"
