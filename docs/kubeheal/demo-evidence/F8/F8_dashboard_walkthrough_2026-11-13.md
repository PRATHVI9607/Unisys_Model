# F8 dashboard control walkthrough

**Date:** 2026-11-13  
**Machine:** LAPTOP-74N9LTFA  
**Cluster:** `k3d-kubeheal`  
**Mode:** `test` before and after; no PVC-backed resources were changed.

## Live controls

| Dashboard control | Result | Evidence |
|---|---|---|
| Kill switch | The UI button was clicked `test -> enforce -> test` in a scripted window with an independent 60-second dead-man. Both mode changes were ledgered. The dead-man observed the return to test and exited; final ConfigMap readback is `test`. | `screenshots-2026-11-13/kill-switch-enforce.png`, `screenshots-2026-11-13/kill-switch-test.png`, `deadman_f8_7f967133fbe1439a8c69b9841d8d4507.txt`, [mode control result](screenshots-2026-11-13/mode-control-result.json) |
| Incident approve | A run-owned F7 M2 incident was approved from its incident detail page. The dashboard returned `dry_run_approved`, `mode=test`, `dry_run=true`; no Kubernetes write occurred. | `screenshots-2026-11-13/approve-control-before.png`, `screenshots-2026-11-13/approval-dry-run.png`; [control result](F8_control_results_2026-11-13.json) |
| Incident reject | The same M2 incident and a second run-owned F7 Q1 incident were rejected from their detail pages. The approvals list returned to zero pending entries. | `screenshots-2026-11-13/reject-control-before.png`, `screenshots-2026-11-13/approvals-resolved.png`; [control result](F8_control_results_2026-11-13.json) |
| Baseline approve | A scripted candidate was stored against the existing PVC-free F5 prod scratch Deployment and golden baseline. The UI approval returned `dry_run`, `applied=false`, `candidate_unchanged=true`; the golden baseline was not changed. | `screenshots-2026-11-13/baseline-candidate-pending.png`, `screenshots-2026-11-13/baseline-approval-dry-run.png`; [candidate result](screenshots-2026-11-13/baseline-controls-result.json) |
| Baseline reject | The same run-owned candidate was rejected through the UI. It was removed from the pending list and the golden baseline remained unchanged. | `screenshots-2026-11-13/baseline-candidate-rejected.png`; [candidate result](screenshots-2026-11-13/baseline-controls-result.json) |
| SnapshotFreeze release | The incident page shows the SnapshotFreeze section, but no freeze is held by the selected completed F3 incident. There was no valid release target, so no release was attempted. | `screenshots-2026-11-13/incident-detail.png` |

The admin token was read from its Kubernetes Secret into the local browser automation process and is never written to evidence. Screenshots show a masked field only. The scripted F7 inputs and the scripted F8 candidate are explicitly labelled in their captured output; the assessment fields are not claims of model quality.

## Screenshot inventory

- `approvals-before-actions.png`: kill switch, mode history, pending approvals and incident list.
- `approve-control-before.png`, `approval-dry-run.png`, `reject-control-before.png`: incident approve/reject controls and the test-mode dry-run state.
- `approvals-resolved.png`: resolved incident list after both scripted decisions were rejected.
- `kill-switch-enforce.png`, `kill-switch-test.png`: kill-switch mode control during and after its dead-man-protected window.
- `baseline-candidate-pending.png`, `baseline-approval-dry-run.png`, `baseline-candidate-rejected.png`: candidate controls before and after test-mode approval and rejection.
- `baseline-candidates.png`: empty-state view after the candidate was resolved.
- `incident-detail.png`: full F3 incident detail and SnapshotFreeze empty state.

**Status:** the available dashboard controls were exercised live or shown in a documented fallback state. SnapshotFreeze release remains not measured because the cluster has no held freeze target. Global mode is `test`, pending approvals are zero, and pending baseline candidates are zero.
