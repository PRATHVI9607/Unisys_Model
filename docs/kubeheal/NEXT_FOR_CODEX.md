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
| wave/claude-F3b | 207ad87 | Reviewed: PVC claim guard protects a restore from drift reverting to the old claim. Focused tests 8 passed. Keep unmerged until the required full suite can run. |
| wave/Codex-F4-HMAC-smoke | 520c8f8 | Reviewed: implementation is already represented on work; focused tests 203 passed, 3 skipped. Live evidence exists, with a mode-change race requiring the exclusive lock and test mode. |
| wave/Codex-ThawHmac-docs | f730a7a | Reviewed: one operator docstring correction for the dedicated HMAC Secret is not on work. Focused tests 5 passed; integrate only after full suite is available. |
| wave/demo-runbook | b1eb497 | Reviewed: do not merge wholesale; its HPA script snapshot has fixed names and unconditional cleanup. Current work has safer run-owned cleanup. Branch adds historical F2 evidence only. |
| wave/Codex-F8-freeze-ui | 656ed87 | Reviewed: controls/API are represented on work; focused dashboard suite 275 passed. Still needs populated live walkthrough. |
| wave/Codex-NP-k6 | d2c6cde | Reviewed: redundant with current work. Narrow k6 inference ingress allowance and chart assertions are already present; 35 offline tests passed. |
| wave/p11-safe-runner | a2ba42a | Reviewed: no runner fix needed; focused tests 41 passed. Attempt 2 refusal cause unproven; E1 not accepted and remaining runs not measured. |
| wip/f4-hmac-smoke | fad3518 | WIP preservation of a conflicted F4 cherry-pick. Do not merge blindly. |

The branch refs listed here are not ancestors of demo; review found several changes already represented elsewhere. Compare diffs before cherry-picking.
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

## Ordered work for tomorrow

1. F3 `d0ed188` is confirmed as an ancestor of work and demo. Fresh read-only cluster verification is blocked: this sandbox cannot read the user kubeconfig. Once authorized access is available, verify mode, revision, image tags, pod readiness, and `/readyz` before any write. Do not rerun Claude-owned D-5 or containment work.
2. Recheck the cluster after stop/start and wait for needed pods to become Ready. Keep mode test. Do not run down.ps1 unless the owner explicitly authorizes deletion of cluster volumes.
3. F3b, F4, F8, P11, k6, and runbook branches have been reviewed; see the table. F3b and the thaw-doc correction remain unmerged pending the full suite. The full suite currently fails collection because the sandbox cannot access Helm. Do not bypass or deselect chart tests.
4. Rehearse docs/kubeheal/DEMO_RUNBOOK.md once from a fresh cluster start. Use saved F2/F3 evidence where rerunning crosses Claude ownership. Capture actual output/screenshots under docs/kubeheal/demo-evidence/; skip unsupported live steps and state why.
5. Run U6 twice from a clean baseline only if reset does not delete user data; otherwise keep NOT DONE. No model training.
6. Finish push prep: exact full-suite counts, full diff/secret scan against origin/main, no .env/tokens/kubeconfig/venvs/large binary changes, correct .gitignore, README/AGENTS verified design, measured numbers only, updated PUSH_PLAN.md, PROGRESS.md, and handoff. Never push or set ALLOW_PUSH.

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

