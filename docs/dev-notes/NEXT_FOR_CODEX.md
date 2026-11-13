# KubeHeal handoff for 2026-11-13

## Current state

- Nothing pushed. ALLOW_PUSH was not set. No model training or PROJECT_SPEC.md changes.
- Before the stop-for-today docs, work was f3434a1 and demo was 1fcc1ba. Handoff docs commit 4ee6c09 is on work and was merged into demo by da3e021. This hash-note commit advances both refs; the final reply gives the latest heads. F3 d0ed188 is reviewed and merged into both; work is merged into demo.
- Latest full suites after product-code changes: work 2,158 passed, 11 skipped (90.05s); demo 2,158 passed, 11 skipped (66.43s). Later commits are documentation-only. Rerun both after any code merge.
- F3 test_fusion_incident.py still checks no containment request and unsupported-owner escalation; any(...) allows the deliberately injected late escalation. D-5 produced a real Security Agent-scored event and Fusion/Executor test-mode evidence. Full containment through restore was live on a scratch Deployment. Sense was scripted because Falco is absent.

## Cluster state at stop

- Only use --context k3d-kubeheal. Mode read back test; no enforce window was active. No Helm upgrade was started during shutdown.
- Helm revision 13, deployed at 2026-11-12 21:53:13 IST.
- All KubeHeal agent images use b20261112215116: executor, fusion-agent, health-agent, dashboard, inference-server, and security-agent. They were built from demo; changes since were docs-only, so these are demo-code images, not branch-only images.
- After the non-destructive stop/start, the last read showed these pods not Running, all Pending: dev/victim-app-558564f5cc-bnjtw, kube-system/snapshot-controller-55f6584bc6-pl88r, kubeheal/fusion-agent-5d787c845b-xgltk, kubeheal/health-agent-6d8c8f596-dkpbv, monitoring/monitoring-grafana-cbd564658-p79nc, monitoring/monitoring-kube-prometheus-operator-c8fd87dbf-q54nz. Recheck readiness tomorrow before any demo action. No PVC or ledger data was deleted.
- Lock check found no docs/kubeheal/CLUSTER_LOCK.md, so there was no Codex line to remove. Before any cluster touch, check for a lock. Before each enforce window or Helm upgrade, add CLUSTER LOCK <who> <start time>, commit it, then remove and commit it afterward. Never upgrade with an older tag.

## Branches and worktrees

Worktrees were clean at handoff after preserving the unfinished cherry-pick as WIP. Completed delegated agents have no running tasks. Branches still listed by git branch --no-merged demo:

| Branch | Tip | What remains |
|---|---:|---|
| wave/claude-F3b | 207ad87 (`e6c5aa6`) | PVC-claim guard reviewed; focused 8 tests pass. Run full suites, then merge green change into work and demo. |
| wave/Codex-ThawHmac-docs | f730a7a | Dedicated HMAC Secret doc fix reviewed; focused 5 tests pass. Run full suites, then integrate into work and demo. |
| wave/demo-runbook | b1eb497 (`1f6dffb`) | Do not merge wholesale: HPA snapshot uses fixed names and unconditional cleanup. Current work has safer run-owned cleanup. Consider only nonduplicated F2 evidence after diff review. |
| wave/Codex-F4-HMAC-smoke | 520c8f8 | Reviewed; implementation already represented on work. No merge needed. Keep the exclusive lock and test mode for a live smoke. |
| wave/Codex-F8-freeze-ui | 656ed87 | Reviewed; implementation represented on work. Focused dashboard tests 275 passed; live walkthrough remains. |
| wave/Codex-NP-k6 | d2c6cde | Redundant with work; narrow inference ingress rule and tests are already present. |
| wave/p11-safe-runner | a2ba42a | Reviewed; no runner fix needed. E1 remains unaccepted; E2-E6 and V5-E1 not measured. |
| wip/f4-hmac-smoke | fad3518 | Preserve as WIP; do not merge blindly. |
## Feature checklist

| Feature | Status | Where it stopped |
|---|---|---|
| F1 Test safety | TESTED-ONLY | Default tests skip live cluster/Redis/MinIO/mode writes; guard is in suite. dev/freeze-scratch is absent. |
| F2 D-5 replay | LIVE-VERIFIED | Hand-written replay emitted a real scored Security event, Fusion decision, and Executor dry-run evidence. Not live Falco capture. Do not rerun without Claude ownership review. |
| F3 Containment | LIVE-VERIFIED | d0ed188 merged. Freeze, forensic snapshot, quarantine, scale-to-zero, pre-T0 restore, entropy Job, quarantine lift, ledger verified. Sense was scripted because Falco is absent. |
| F4 HMAC | LIVE-VERIFIED | Test-mode smoke: signed request dry-ran; unsigned/tampered requests refused; signed results checked; run-owned Redis entries cleaned. Evidence in docs/kubeheal/demo-evidence/F4/. |
| F5 Baseline promotion | TESTED-ONLY | Namespace-mode gate has 90 focused passing tests. Live candidate promotion and ledger entry not shown. |
| F6 Executor validation | TESTED-ONLY | Request validation covered by suite. No safe live injector; runbook forbids direct Redis injection and fabricated workload patches. |
| F7 M2/D1/rollback | TESTED-ONLY | Single-label, inclusive 10x boundary, fresh Security response tests pass. No live boundary/rollback sequence. |
| F8 Dashboard | TESTED-ONLY | Controls are covered by tests. No populated incident walkthrough for approve/reject, kill switch, baseline, containment, ledger, and SnapshotFreeze release. |
| F9 Kill switch | TESTED-ONLY | Automated tests pass. No validated paired test/enforce trigger; mode was not changed for a demo window. |
| F10 Drift healing | TESTED-ONLY | Drift tests pass. No live canary-only patch, rollback point, bad-p99 measurement, or rollback. |
| F11 Queue-depth HPA | LIVE-VERIFIED | Clean run: 32 VUs/90s, 121,088/121,088 checks, median 22.86ms, p95 38.45ms, HPA 2 -> 7 -> 2. Grafana API/Prometheus evidence exists. Post-merge repeat scaled 2 -> 8 -> 2 but had 12/99,431 refusals; visual screenshot missing. |
| F12 U6 acceptance | NOT DONE | up.ps1 has not passed twice from a clean baseline. down.ps1 was not run because it deletes MinIO, Redis, ledger, and victim PVC data. |
| F13 P11 evaluation | NOT DONE | No accepted E1 benchmark; both attempts failed. E2-E6 and V5-E1 remain not measured. |

## Handoff snapshot (2026-11-13)

- Audit baseline heads before the handoff checkpoint: `work` `8b6461a`, `demo` `8b85048`. `d0ed188` is already merged into both.
- Last known cluster state: Helm revision 13, image tag `b20261112215116`, six pods Pending after the prior stop/start. Mode is currently unverified; its last prior read was `test`. This session could not read `<home>\.kube\config`, so no fresh API read was made.
- `CLUSTER_LOCK.md` remains `CLUSTER LOCK Codex 2026-11-13 06:17 +05:30 IST`. Keep it until cluster state is freshly verified and the active window is safely released.
- Full suites on work and demo stopped at collection in `tests/test_platform_chart.py` because `helm` is not on PATH and the protected Winget Helm path raises `PermissionError`. No suite counts are available.

## Ordered remaining work

1. Verify the cluster read-only using only `--context k3d-kubeheal`: mode, revision, images, pod status, inference `/readyz`.
2. Diagnose the six Pending pods; wait for required pods to become Ready and record the actual cause. Keep mode test.
3. Run full suites on work and demo; do not skip the chart suite.
4. Merge the reviewed F3b PVC-claim guard into work, then demo, only after green suites.
5. Rebuild all images from demo and redeploy under the cluster lock. Record revision and tags; smoke-check Ready pods, `/readyz` 200, and mode test.
6. Resolve leftover open escalations and remove only confirmed orphan SnapshotFreeze keys for deleted scratch PVCs; record each action.
7. Complete F1-F13 live evidence in `docs/kubeheal/demo-evidence/<F>/`, including F5-F10; rerun F2/F3/F4 as requested. Run U6 twice without losing MinIO/Redis/ledger data. Diagnose P11 refusals; run E1-E6 and V5-E1 with actual numbers, marking unmeasured items honestly.
8. Rehearse `DEMO_RUNBOOK.md` end to end from a fresh cluster start. Ask before any data deletion; save screenshots/output and mark each step LIVE or FALLBACK.
9. Run final suites, update README and AGENTS without changing PROJECT_SPEC, secret-scan the diff, update docs/dev-notes/PUSH_PLAN.md, verify test mode and released lock, and commit. Never push or set ALLOW_PUSH.
## Verification commands

Run from the demo checkout in PowerShell using Python 3.11. Do not deselect the default suite.

git status
git worktree list
git log --oneline -10 work
git log --oneline -10 demo
git diff --check origin/main...work
git diff --check origin/main...demo
$env:PYTHONPATH='.'
Push-Location ..\Unisys_Model-wt-metric-query
.\.venv\Scripts\python.exe -m pytest tests -q -p no:warnings
Pop-Location
Push-Location .
.\.venv\Scripts\python.exe -m pytest tests -q -p no:warnings
Pop-Location


