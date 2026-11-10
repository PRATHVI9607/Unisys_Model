# Handoff

- **Agent:** Codex
- **Date:** 2026-11-11
- **Branch:** `work`
- **Goal:** P7-RR-9 is implemented and committed; continue P7-RR-10, the next checklist task whose declared dependency P6-R1 is complete.
- **Latest code commit:** `178754e feat(P7): scan restored PVCs before lifting quarantine`.

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

## Current task

- P7-RR-10 is claimed as `[~] Codex` in `docs/kubeheal/PROGRESS.md`. Inspect each listed redelivery/cleanup issue and implement the safe pieces with tests. Do not run cluster work or model training. Record and leave any behavior needing an owner decision.
- P7-RR-11 follows RR-9; it remains a candidate local task after RR-10 unless its dependencies add a constraint.
