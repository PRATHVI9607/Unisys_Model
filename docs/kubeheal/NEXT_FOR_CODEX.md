# KubeHeal next agent handoff

This file is tool-neutral. It is the first resume point for Codex, Claude Code, or another repository agent.
Read `AGENTS.md`, `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md` before changing files or using the cluster.

## Current checkout

- Active checkout: `C:/My_projects_1/cLOUD/Unisys_Model`, branch `demo`.
- Last committed checkpoint before the current P10 continuation: `e09e7f4` (`docs: record handoff sync on work`). The P10 continuation files and refreshed handoff are uncommitted; no stage/commit approval was given. The owner requested a handoff to Claude. Do not stage/commit until explicitly approved.
- Do not push or set `ALLOW_PUSH`. No model training is approved.
- Shared core fixes go to `work` first, then merge `work` into `demo`. Demo-only scripts and cluster materials stay under `demo/`.

## Branches and worktrees

| Branch | Tip/state | Worktree |
|---|---|---|
| `demo` | Active, base tip `e09e7f4`; current P10 continuation is uncommitted pending owner approval | `C:/My_projects_1/cLOUD/Unisys_Model` |
| `work` | `3fcbef0`, shared disk metric query fix and prior handoff sync; clean when last checked | `C:/My_projects_1/cLOUD/Unisys_Model-wt-metric-query` |
| `wave/P11` | Unreviewed WIP commit `47e1b34`; focused tests passed (8), full merge review still required | `C:/My_projects_1/cLOUD/Unisys_Model-wt-P11` |
| `wip/docs-p6d2` | Unreviewed WIP commit `c7c9f5b`; focused tests passed (23), full suite was blocked by environment/dependency/temp-path issues | `C:/My_projects_1/cLOUD/Unisys_Model-wt-docs` |
| `main` | Base branch; no worktree | — |
| `wave/P5`, `wave/P6`, `wave/P7`, `wave/P8`, `wave/P9` | Historical phase branches | — |
| `wave/docs-p6d2` | Inactive historical base | — |

Remote refs at last inspection: `origin/main`, `origin/master`, `origin/test`, `origin/kali`, and `origin/feat/dit-sec-train-integrate`. No remote was changed.

Only the P10 orchestrator uses the cluster. Every Kubernetes command must include `--context k3d-kubeheal`; never use `hybrid-demo` or another context.

## Cluster state

- Cluster `kubeheal` is running. Global ConfigMap `kubeheal-mode` is `test`.
- Prod and dev `victim-app` resources are restored to CPU request `100m`, limit `500m`.
- Health Model Deployment/HPA are restored to 2 replicas; HPA current=2, desired=2, metric=0 at final check.
- Security Agent is restored to `FALCO_MODE=auto`. Falco is not installed. Temporary replay ConfigMap and mount were removed.
- The temporary k6 Job, ConfigMap, and NetworkPolicy were removed. No drift injection or model outage is left active. `kubeheal.ledger.pending` length was 0.
- A later `up.ps1 -Stage install` invocation was interrupted by the owner after about 168 seconds; it is not considered a successful full install. The post-interruption check found all Deployments ready, HPAs at 2/2 with metric 0, Security Agent in `auto`, standard victim image tags active, and no temporary resources. Events showed temporary pod sandbox recreation, probe connection refusals, and custom-metric API errors during recovery; these had recovered by the final check.
- Prod PVC retains seeded data and the harmless `/data/.kubeheal-metric-probe` marker from metric verification. Rolling snapshots remain. Temporary restore resources are gone.

## Next tasks, in order

1. **Finish P10-U6 acceptance.** Touch only the necessary `demo/scripts/`, `demo/k3d/`, `demo/README.md`, and P10 checklist entries. Run the complete setup/demo/reset sequence twice when Helm is usable; current PowerShell cannot resolve/read the Helm executable, so full chart install was not verified. Keep mode `test`, keep any drift injection paired at request=limit `50m`, and restore both victims to `100m/500m`. Verify with the project's Windows PowerShell `up.ps1` stages, `demo.ps1 -Action status|drift|reset`, and two clean acceptance passes. Do not change `decision_policy.py`, Executor write paths, or RBAC.
2. **Finish P10-D5 replay-to-event path.** Core files to inspect/change on `work`: `agents/security_agent/agent.py`, `falco_client.py`, `syscall_window.py`, and focused `tests/test_sense_falco_replay.py`; demo fixture/mount steps belong under `demo/`. A hand-written fixture was temporarily mounted and 21 events per Security Agent pod were consumed; the model-client latency metric advanced, but no `kubeheal.security.events` entry or Fusion ransomware decision appeared. Verify consumed events, a successful model response, then the Security/Fusion streams. Keep Security Agent in `auto` outside the bounded replay step. Do not claim live Falco or a real capture. Do not edit `decision_policy.py`, Executor write paths, or RBAC. Run focused replay tests and a bounded replay on `--context k3d-kubeheal`; keep global mode `test`.
3. **Investigate the live drift attribution mismatch on `work`.** Core files to inspect/change: `agents/health_agent/agent.py`, `agents/health_agent/metric_queries.py`, `models/health_model/`, and related tests. With all 15 metrics present, a drift event had `health_ci_width=0.1192` and Fusion queued `auto_patch` in test mode, but the Health Model top field was `template.spec.initContainers[0].securityContext`, not the drifted CPU field; Executor correctly escalated `no_drift_at_field`. Inspect model output and Health Agent mapping; add focused tests before any fix. Keep the `0.15` CI gate unchanged. Do not edit `decision_policy.py`, Executor write paths, or RBAC. Verify with focused tests, then `demo/scripts/demo.ps1 -Action drift` on the authorized context after the cooldown; merge a reviewed core fix from `work` to `demo` only after tests pass.
4. **Fix the Health Agent aiohttp session leak on `work`.** Inspect `agents/health_agent/agent.py` and the related lifecycle tests. Logs still show `Unclosed client session` per event. Add focused lifecycle coverage, then run the full suite before merging this core fix into `demo`. Do not change `decision_policy.py`, Executor write paths, or RBAC.

## Verified results and open findings

- The earlier `health_ci_width=1.0` was the Health Agent missing-metric sentinel. The missing channel was `http_error_rate`: the old verifier used victim Service port 80 instead of 8000. The kubelet did not expose `container_fs_*`; `disk_io_bytes` now uses the victim app's fsync-backed counter. The corrected verifier returned all 15 series. A latest drift window had `metrics_missing=[]`, 24 error-rate samples, 60 samples per other channel, and width `0.1192`. An earlier complete window had width `0.2607` and `human_patch`. Do not loosen the CI gate.
- Latest dry-run drift was not remediated: the model's top attribution did not match the drifted CPU field, and Executor escalated. Global mode remained `test`.
- Executor logged a transient MinIO `S3Error` during bootstrap. The queued fallback record drained; `XLEN kubeheal.ledger.pending` was 0 at the final check. It was not reproduced after bootstrap; keep it recorded as a transient finding.
- D-6 fail-closed was observed on `dev/victim-app`: Health Model was briefly scaled to zero during paired 50m drift, and Fusion wrote a `required=human` escalation because the model did not answer. Dev resources, Health Model replicas/HPA, and global mode were restored.
- D-8 used `grafana/k6:0.54.0`, 32 VUs for 90 seconds. Observed 4,999 score requests; 4,993 checks passed (99.87%), six were non-200 during initial connection recovery, and p95 request duration was 889.03 ms. HPA metric rose from 0 to 16; replicas scaled 2 -> 4 -> 8, then returned to 2 after load. This is one run, not a performance guarantee.
- P10-U4 driver/image flow is in the current uncommitted continuation: standard tag `b20261111113631` was used for Health Agent and victim app; the ignored tag manifest is `demo/k3d/.image-tags.json`.
- P10-U6 full setup/demo/reset twice remains incomplete. Helm is not available to the current shell. Snapshot/restore was verified separately once; the full ransomware recovery flow is not complete.

## Unmerged work and reserved work

- Do not merge `wave/P11` or `wip/docs-p6d2` until each diff is reviewed against current `work` and the full test suite is run after each merge. Subagents are finished; their worktrees are clean as recorded above.
- Reserved for Claude/strong reviewer: `agents/fusion_agent/decision_policy.py`, `agents/executor/` write paths, and `k8s/rbac/`. Leave conflicting merges for review. P12 training is not approved.
- The shared handoff and checklist must be synced to both `work` and `demo` after the owner approves staging/commits. No changes have been pushed.

## Useful checks

```powershell
git status
git branch -a
git worktree list
git log --oneline -15
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode
kubectl --context k3d-kubeheal -n kubeheal get pods,jobs,pvc
$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=.pytest-tmp/<task>
```
