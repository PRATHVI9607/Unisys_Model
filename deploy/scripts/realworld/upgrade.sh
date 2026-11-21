#!/usr/bin/env bash
# Upgrade and rollback test: install the PREVIOUS release (a git worktree of --from-ref, using its own install.sh), create
# state (baselines, a Redis marker key, a ledger entry, the approval queue, runtime mode), upgrade to HEAD with HEAD's
# install.sh, then roll back, asserting at every step:
#   - state preserved: Secrets reused (same uid and data, never regenerated), Redis PVC not replaced, every baseline
#     byte-identical, marker key + ledger entry present, runtime mode unchanged, pending approvals not lost
#   - detection never down for long: an attack is launched every 20 s during the upgrade; the worst time-to-kill of
#     the attacks launched during it must stay under --max-gap-s (default 180), none may be missed, and attacks launched
#     after the rollout are killed within --max-kill-s
#   - rollback: kustomize = the previous release's install.sh again; Helm = `helm rollback` to the previous revision.
#     State is checked again and the cluster ends on HEAD (reinstalled), so the lab is left as it was found.
# Paths: --path kustomize|helm (default: what the cluster uses now, `helm status kubeheal` decides). `--path both`
# needs --wipe, which DELETES the whole kustomize install (namespace kubeheal, Redis state, cluster RBAC) between the two
# paths - Helm cannot adopt kustomize objects.
# Touches: namespace kubeheal (that is the point), khe-rw-up-* namespaces. Images are rebuilt by install.sh under the
# same :v5 tag, so the old and new release never run side by side from different registries.
#   ./deploy/scripts/realworld/upgrade.sh --from-ref v5.0.0 [--path kustomize|helm|both] [--wipe] [--target minikube|k3d]
#                                         [--max-gap-s 180] [--max-kill-s 40] [--dry-run] [--force-context NAME]
# Duration: 3 installs of ~5 min each per path (+ probes): ~25 min per path.
RW_NAME=upgrade
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
REF=""; PATHS=auto; WIPE=0; TARGET=""; MAX_GAP=180; MAX_KILL=40
rw_init "$@"; set -- "${RW_REST[@]}"
while [[ $# -gt 0 ]]; do case $1 in
  --from-ref) REF=$2; shift 2 ;; --path) PATHS=$2; shift 2 ;; --wipe) WIPE=1; shift ;; --target) TARGET=$2; shift 2 ;;
  --max-gap-s) MAX_GAP=$2; shift 2 ;; --max-kill-s) MAX_KILL=$2; shift 2 ;;
  *) die "usage: $0 --from-ref REF [--path kustomize|helm|both] [--wipe] [--target minikube|k3d] [--max-gap-s N] [--max-kill-s N] [--dry-run]" ;;
esac; done
[[ -n $REF ]] || die "--from-ref REF (tag, branch or commit of the release to upgrade from) is required"
(( RW_DRY )) || git -C "$ROOT" rev-parse --verify --quiet "$REF^{commit}" >/dev/null || die "unknown git ref '$REF'"
[[ $PATHS == both && $WIPE == 0 ]] && die "--path both deletes the kustomize install (Redis state included) between the paths: pass --wipe to allow it"
if [[ $PATHS == auto ]]; then helm status kubeheal -n "$KH" >/dev/null 2>&1 && PATHS=helm || PATHS=kustomize; fi
[[ $PATHS == both ]] && PATHS="kustomize helm"
[[ $(rc GET kubeheal:mode) == observe ]] && die "runtime mode switch is observe: attacks would not be killed"
TARGET_ARG=(); [[ -n $TARGET ]] && TARGET_ARG=(--target "$TARGET")

WT=""
extra_cleanup() { [[ -n $WT ]] && { git -C "$ROOT" worktree remove --force "$WT" >/dev/null 2>&1; rm -rf "$(dirname "$WT")"; }; touch "$RW_OUT/stop" 2>/dev/null; }
(( RW_DRY )) || { WT="$(mktemp -d "${TMPDIR:-/tmp}/kh-prev-XXXXXX")/prev"; git -C "$ROOT" worktree add --detach "$WT" "$REF" >/dev/null 2>&1 || die "git worktree add $REF failed"; }

install_from() {   # install_from DIR PATH: that release's own install.sh (it builds and loads its own images)
  local dir=$1 p=$2 flags=("${TARGET_ARG[@]}")
  [[ $p == helm ]] && flags+=(--helm)
  say "install.sh from $dir ($p)"
  (( RW_DRY )) && return 0
  (cd "$dir" && ./deploy/scripts/install.sh "${flags[@]}") >> "$RW_OUT/install.log" 2>&1 || { tail -20 "$RW_OUT/install.log" >&2; die "install failed in $dir"; }
}
worst_gap() {   # worst_gap PROBES.jsonl FROM_MS TO_MS -> "<launched> <missed> <worst time-to-kill s>" for probes launched in the window
  python3 - "$@" <<'PY'
import json, sys
f, a, b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rs = [json.loads(x) for x in open(f)] if __import__("os").path.exists(f) else []
w = [r for r in rs if a <= r["t0"] <= b]
lat = [r["latency_s"] if r["killed"] and r["latency_s"] is not None else 9999 for r in w]
print(len(w), sum(1 for r in w if not r["killed"]), max(lat, default=0))
PY
}

for P in $PATHS; do
  say "=== path: $P ==="
  if [[ $P == helm && $WIPE == 1 && $PATHS == "kustomize helm" ]]; then kubectl delete -k "$ROOT/deploy/k8s" --ignore-not-found --wait=true --timeout=300s >/dev/null; fi   # cluster-scoped RBAC too: Helm cannot adopt it
  install_from "$WT" "$P"
  rw_until 600 pods_ready; check "$P: previous release ($REF) is up" pods_ready

  # --- state ---
  SN="$(rw_ns up-state)"; rw_mkns "$SN"
  for d in a b c; do
    kubectl create deploy "web-$d" -n "$SN" --image=kubeheal.invalid/chaos:v5 -- sleep 86400 >/dev/null
    kubectl patch deploy "web-$d" -n "$SN" -p '{"spec":{"template":{"spec":{"containers":[{"name":"chaos","imagePullPolicy":"IfNotPresent"}]}}}}' >/dev/null
  done
  has_baselines() { [[ $(rc --scan --pattern "kubeheal:baseline:$SN:*" | grep -c .) -ge 3 ]]; }
  rw_until 240 has_baselines; check "$P: 3 baselines stored by the previous release" has_baselines
  MARK="up-$P-$$"
  rwpy snapshot --out "$RW_OUT/before-$P.json" --marker "$MARK"
  check "$P: pending approvals before the upgrade: $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["pending_approvals"]))' "$RW_OUT/before-$P.json" 2>/dev/null || echo 0) (informational)" true

  # --- upgrade under attack ---
  rm -f "$RW_OUT/stop"; rwpy probe-loop --stop-file "$RW_OUT/stop" --interval 20 --out "$RW_OUT/probes-$P.jsonl" --tag "up-$P" &
  PROBE=$!
  T_UP0=$(date +%s%3N); install_from "$ROOT" "$P"; rw_until 600 pods_ready; T_UP1=$(date +%s%3N)
  say "upgrade took $(( (T_UP1 - T_UP0) / 1000 ))s"
  rw_sleep 90; touch "$RW_OUT/stop"; wait "$PROBE" 2>/dev/null
  check "$P: HEAD is up and all Ready" pods_ready
  check "$P: state preserved over the upgrade (secrets reused, baselines, PVC, marker, ledger, mode)" rwpy diff "$RW_OUT/before-$P.json"
  read -r launched missed worst < <(worst_gap "$RW_OUT/probes-$P.jsonl" "$T_UP0" "$T_UP1")
  printf 'INFO\t%s upgrade: %s attacks launched during it, %s missed, worst time-to-kill %ss\n' "$P" "${launched:-0}" "${missed:-0}" "${worst:-0}" >> "$RW_OUT/results.tsv"
  check "$P: no attack launched during the upgrade was missed" test "${missed:-0}" -eq 0
  check "$P: detection gap during the upgrade <= ${MAX_GAP}s (worst ${worst:-0}s)" python3 -c "import sys; sys.exit(0 if float('${worst:-0}') <= $MAX_GAP else 1)"
  R="$(attack "up-after-$P")"; check "$P: attack after the upgrade killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
  check "$P: no benign pod killed (state workloads)" test "$(benign_kills "$SN")" == 0

  # --- rollback ---
  if [[ $P == helm ]]; then
    REV="$(helm history kubeheal -n "$KH" -o json 2>/dev/null | python3 -c 'import json,sys; h=json.load(sys.stdin); print(h[-2]["revision"] if len(h)>1 else "")')"
    [[ -n $REV || $RW_DRY == 1 ]] || die "helm history has no previous revision"
    say "helm rollback to revision $REV"; helm rollback kubeheal "$REV" -n "$KH" --wait --timeout 8m >/dev/null
  else
    install_from "$WT" "$P"
  fi
  rw_until 600 pods_ready; check "$P: rolled back and all Ready" pods_ready
  check "$P: state preserved over the rollback" rwpy diff "$RW_OUT/before-$P.json"
  R="$(attack "up-rb-$P")"; check "$P: attack after the rollback killed within ${MAX_KILL}s" killed_within "$R" "$MAX_KILL"
  install_from "$ROOT" "$P"; rw_until 600 pods_ready; check "$P: cluster left on HEAD, all Ready" pods_ready
  rw_delete_namespaces
done
exit 0
