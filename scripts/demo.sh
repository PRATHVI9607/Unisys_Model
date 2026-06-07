#!/bin/bash
# =============================================================================
# KubeHeal v4 — guided demo driver.
# Two scenarios: (A) config drift -> AUTO-PATCH, (B) ransomware -> AUTO-KILL.
# The visible action happens on the DASHBOARD, so this script also brings up the
# port-forward and (optionally) seeds baseline events so the screen is never blank.
#
#   ./scripts/demo.sh             # preflight + port-forward + guided scenarios
#   ./scripts/demo.sh --seed      # also seed baseline events before starting
#   ./scripts/demo.sh --seed-only # just seed + port-forward, no live scenarios
# =============================================================================
set -e
NS=demo
KH=kubeheal
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED=""; SEED_ONLY=""
for a in "$@"; do
  [ "$a" = "--seed" ] && SEED=1
  [ "$a" = "--seed-only" ] && { SEED=1; SEED_ONLY=1; }
done

c_b="\033[1m"; c_g="\033[32m"; c_y="\033[33m"; c_r="\033[31m"; c_0="\033[0m"
say()  { echo -e "${c_b}$*${c_0}"; }
ok()   { echo -e "  ${c_g}OK${c_0}  $*"; }
warn() { echo -e "  ${c_y}!!${c_0}  $*"; }
die()  { echo -e "  ${c_r}XX${c_0}  $*"; exit 1; }

echo "============================================"
say  " KubeHeal v4 Demo"
echo "============================================"

# ---- Preflight --------------------------------------------------------------
say "[preflight]"
command -v kubectl >/dev/null || die "kubectl not found"
minikube status >/dev/null 2>&1 || die "minikube is not running — run: minikube start"
ok "minikube up"

kubectl get ns $KH >/dev/null 2>&1 || die "namespace/$KH missing — run ./scripts/install.sh first"
notready=$(kubectl get pods -n $KH --no-headers 2>/dev/null | grep -vc "1/1" || true)
[ "$notready" = "0" ] && ok "all $KH pods ready" || warn "$notready $KH pod(s) not ready (demo may lag)"

kubectl get deploy victim-app -n $NS >/dev/null 2>&1 || die "demo/victim-app missing — run ./scripts/install.sh"
lbl=$(kubectl get deploy victim-app -n $NS -o jsonpath='{.metadata.labels.kubeheal\.io/watch}' 2>/dev/null)
[ "$lbl" = "true" ] && ok "victim-app is watched (kubeheal.io/watch=true)" || warn "victim-app missing watch label — health agent will ignore it"
[ -f "$ROOT/chaos/chaos-pods.yaml" ] && ok "chaos manifest present" || warn "chaos/chaos-pods.yaml missing — Demo B will skip"

# ---- Dashboard port-forward -------------------------------------------------
say "[dashboard]"
if curl -s -o /dev/null -m 1 http://localhost:5000/health 2>/dev/null; then
  ok "dashboard already reachable at http://localhost:5000"
else
  kubectl port-forward -n $KH svc/kubeheal-dashboard 5000:5000 >/tmp/kh-portfwd.log 2>&1 &
  PF_PID=$!
  trap '[ -n "$PF_PID" ] && kill $PF_PID 2>/dev/null || true' EXIT
  for i in $(seq 1 15); do curl -s -o /dev/null -m 1 http://localhost:5000/health 2>/dev/null && break; sleep 1; done
  curl -s -o /dev/null -m 1 http://localhost:5000/health 2>/dev/null \
    && ok "port-forward up -> http://localhost:5000" \
    || warn "could not confirm dashboard; check /tmp/kh-portfwd.log"
fi

# ---- Optional seed ----------------------------------------------------------
if [ -n "$SEED" ]; then
  say "[seed] injecting baseline events so the dashboard is populated"
  bash "$ROOT/scripts/seed_demo.sh" || warn "seed failed (continuing)"
fi
echo -e "\n${c_b}>> Open http://localhost:5000 on the projector now.${c_0}\n"
[ -n "$SEED_ONLY" ] && { say "Seed-only mode. Dashboard populated. Leaving port-forward running (Ctrl-C to stop)."; wait; }

# ---- Demo A: config drift ---------------------------------------------------
read -rp "ENTER to run Demo A — config drift (CPU limit 500m -> 50m on victim-app)..."
say "Injecting CPU drift on demo/victim-app ..."
kubectl patch deployment victim-app -n $NS --type=merge \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"50m"}}}]}}}}'
ok "patched. Watch the dashboard:"
echo "   - Health assessment for demo/victim-app, risk rises"
echo "   - top field = containers[0].resources.limits.cpu"
echo "   - security stays low, DCM correlation low  ->  AUTO-PATCH (canary)"

# ---- Demo B: ransomware -----------------------------------------------------
if [ -f "$ROOT/chaos/chaos-pods.yaml" ]; then
  read -rp "ENTER to run Demo B — ransomware scenario..."
  say "Launching ransomware chaos pod ..."
  kubectl apply -f "$ROOT/chaos/chaos-pods.yaml" -n $NS
  ok "applied. Watch the dashboard:"
  echo "   - rename burst -> entropy climbs to ~7.7 bits -> sec_risk high"
  echo "   - DCM correlation high (CPU thrash looks like drift) = compound incident"
  echo "   - compound  ->  AUTO-KILL in <8s, see the causal chain in the event detail"
fi

echo ""
say "Demo complete. Click any event row on the dashboard for the full model analysis."
echo "(Port-forward stays up until you Ctrl-C.)"
[ -n "$PF_PID" ] && wait
