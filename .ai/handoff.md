# Handoff

- **Agent:** Codex
- **Date:** 2026-11-11
- **Branch:** `work`
- **Goal:** Complete P7-RR-10 after recording owner decisions; P7-RR-9 is complete.
- **Latest code commit:** `65b3585 fix(P7): close remediation recovery gaps`.

## What changed and why

- Added an Executor-created read-only Job that scans every restored PVC before the restore path can lift quarantine. The existing Security Agent sampler only observes writes through live process file descriptors and cannot inspect restored data at rest.
- Scanner returns clean only after reading at least one regular file completely with no unreadable or skipped paths. High entropy means keep quarantined; empty, unreadable, symlinked, failed, timed-out, unavailable-image, and malformed-result scans are unknown and keep quarantine.
- Job mounts PVCs read-only, disables service-account token mounting, uses a read-only root filesystem, RuntimeDefault seccomp, no privilege escalation, and dropped capabilities. Create/delete are kill-switch-gated writes; read access is namespaced to prod/staging/dev.
- P6-D2 Health Agent periodic rescoring remains deferred. OBSERVE TTL is a freshness limit, not a sampling interval; no 100-second cadence can be inferred from 300 seconds divided by factor 3.

## Files touched

- `agents/executor/entropy_probe.py`, `agents/executor/restore_entropy.py`, `agents/executor/main.py`, `agents/executor/restore.py`
- `k8s/rbac/rbac.yaml`, `k8s/executor-deployment.yaml`
- `deploy/helm/kubeheal/templates/rbac.yaml`, `deploy/helm/kubeheal/templates/agents.yaml`, `deploy/helm/kubeheal/values.yaml`
- `tests/test_restore_entropy_probe.py`, `tests/test_remediation_static.py`, `tests/test_platform_chart.py`
- `docs/kubeheal/PROGRESS.md`, `docs/kubeheal/NEXT_FOR_CODEX.md`, `.ai/handoff.md`

## Verification and open issues

- Python compile succeeded for all four changed Executor modules.
- Focused scanner/remediation/static/no-writes tests: 73 passed, 4 existing datetime deprecation warnings.
- Helm chart test collection is blocked because Windows denied access to the installed `helm.exe` under WinGet. No Kubernetes command or cluster check was run; image availability/pull-secret setup and live RBAC remain for Claude.
- REV-3 graph contract test remains open because `torch_geometric` is unavailable in this environment. P7-RR-7 and P10/P11 are cluster tasks for Claude. No training, push, or P6 worktree change.

## P7-RR-10 partial completion

- Commit `65b3585` moves action metrics after successful durable result recording, tests duplicate completed incident/action requests, recovers a pending drift rollback after restart, waits for rollback rollout, pins initContainer digests during restore, clears the original-replicas annotation before quarantine is lifted, checks containment ownership before creating policy, and uses unique snapshot-run ledger IDs.
- Focused tests: `tests/test_executor.py tests/test_remediation_drift.py tests/test_remediation_ransomware.py tests/test_remediation_static.py tests/test_no_writes_outside_executor.py`: 106 passed, 11 datetime deprecation warnings. Changed Python modules compile. No cluster calls.
- User input is pending for ledger-write behavior (fail closed or best effort) and approval for an operator release tool that deletes a `SnapshotFreeze` Redis key. Do not implement either until answered.
- Remaining review item: restore crashes partway through do not resume automatically; preflight fails closed and requires human review. Assess whether to expose cleanup/recovery for orphaned restored PVC/freeze state without deleting user data.

## Current task

- P7-RR-10 remains `[~] Codex` in `docs/kubeheal/PROGRESS.md`. Resolve the pending owner decisions before continuing the ledger failure and operator unfreeze items. Review restore crash recovery and any remaining per-incident gaps. Do not run cluster work or model training.
- P7-RR-11 follows RR-9; it remains a candidate local task after RR-10 unless its dependencies add a constraint.

## Review fixes in agents/executor (Claude builder, 2026-11-11, branch `work`)

- drift.py: rollback point saved only after the gate allows the write; closed ("failed") when nothing was patched (ModeBlocked, pre-patch error, API 4xx); a missing `state` is terminal, only "pending" blocks. An ambiguous patch failure (timeout) keeps "pending" on purpose.
- main.py: `contain_failed`, `restore_failed`, `restored_kept_isolated` are not final markers (still escalate); `_dead_letter` counts metrics after the record. restore.py: pod 404 in preflight escalates `pod_not_found` with a scaled-to-zero hint. No resume action.
- snapshots.py re-checks freeze before every prune delete. Threshold and Job resource comments added. Job `list` verb removed from the entropy read role (k8s and Helm).
- Not done: scanner Job runAsNonRoot (Dockerfile.executor has no USER, not verified), restore resume, scan-job node pinning, scanner image digest pinning.
