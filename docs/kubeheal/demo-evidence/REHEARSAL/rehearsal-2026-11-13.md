# KubeHeal rehearsal status, 2026-11-13

**Machine:** native Windows 11  
**Cluster:** `k3d-kubeheal`  
**Mode at close:** `test`  
**Build:** demo images `b20261113071011`, Helm revision 17  
**Result:** **Not a clean end-to-end rehearsal.** Per-feature runs were performed on the existing cluster, but the fresh-cluster start was not run and the all-stage install failed at Helm repository DNS. No claim is made that a single complete runbook pass succeeded.

| Runbook area | Rehearsal status | Result / fallback evidence |
|---|---|---|
| Fresh cluster start and install | FALLBACK | Existing cluster and PVC data preserved. Two `up.ps1 -Stage all -SkipImages` attempts stopped at `prometheus-community.github.io` DNS. Existing release stages were Ready; see [F12](../F12/U6_status_2026-11-13.md). Awaiting owner approval before `down.ps1`, which deletes PVCs. |
| F1 test safety | FALLBACK | Default full suite passed on both branches; live tests remain opt-in. No destructive live test was run. |
| F2 D-5 replay | LIVE | Demo-image replay produced a real model-scored Security event and Fusion/Executor dry-run; no workload write. See [F2 evidence](../F2/README.md). |
| F3 containment and restore | LIVE | Scratch staging containment completed with scripted alert, dead-man switch, freeze, snapshot, quarantine, restore, clean rescan, and cleanup. 38-second enforce window; see [F3 evidence](../F3/README.md). This is not live Falco detection. |
| F4 signed messages | LIVE | Signed accepted in test mode; unsigned and tampered requests refused; run-owned keys cleaned. See [F4 evidence](../F4/README.md). |
| F5 baseline promotion | FALLBACK | Dashboard returned zero candidates; no candidate fabricated. See [F5 status](../F5/F5_baseline_promotion_2026-11-13.md). |
| F6 request validation | FALLBACK | No supported live request injector; no synthetic Redis action added. See [F6 status](../F6/F6_invalid_request_status_2026-11-13.md). |
| F7 policy boundaries and rollback | FALLBACK | No validated live trigger for M2, D1, and fresh Security response rollback. See [F7 status](../F7/F7_policy_live_status_2026-11-13.md). |
| F8 dashboard controls | FALLBACK | APIs/pages responded; incident and empty candidate state read. Full interactive controls and screenshots unavailable. See [F8 read-through](../F8/F8_dashboard_readthrough_2026-11-13.md). |
| F9 kill switch | LIVE | Authenticated dashboard toggle `test -> enforce -> test`; mode changes ledgered and dead-man armed. No action was generated during enforce, so paired applied-action comparison is not measured. See [F9 evidence](../F9/README.md). |
| F10 drift walkthrough | LIVE | Live metrics and drift were recorded as a `human_patch` dry-run; CPU request/limit restored. Canary heal and bad-p99 rollback not measured. See [F10 evidence](../F10/F10_drift_walkthrough_2026-11-13.md). |
| F11 HPA/Grafana | FALLBACK | HPA scaled and returned to 2/2, but the latest load had 12 first-timestamp refusals. No Grafana screenshot: browser surface unavailable and renderer absent. See [F11 evidence](../F11/README.md). |
| F12 U6 twice | FALLBACK | Two partial all-stage attempts stopped at Helm DNS; standalone KubeHeal install/adapter/victim stages and reset succeeded. U6 acceptance remains incomplete. See [F12 status](../F12/U6_status_2026-11-13.md). |
| F13 P11 | LIVE / FALLBACK | E2 measured one inference pod recovery at 1.25 seconds. E1 failed with 12 initial connection refusals; E3-E6 and V5-E1 not measured. See [F13 evidence](../F13/P11_live_status_2026-11-13.md). |

## Screenshots and saved output

No UI screenshots were captured because computer-use browser access timed out and Grafana's renderer is not installed. The HTTP/API summaries, runner output, F3 ledger excerpts, F11 k6 summary, and P11 JSON/CSV/log artifacts are saved under the linked feature evidence directories. Tokens, Secret values, and Redis credentials were not included.

## Fresh-start approval boundary

The owner has been asked whether to authorize `down.ps1` followed by cluster recreation. Verified MinIO and Redis backups are outside the repository at `C:\My_projects_1\cLOUD\KubeHeal-PreClean-20261113-1430`. No PVC deletion has occurred. Until approval arrives, this rehearsal remains fallback-only at the fresh-start step.
