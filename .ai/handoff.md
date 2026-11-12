# Handoff

- **Agent/date:** Codex tests/demo/docs, 2026-11-12. Nothing pushed; no cluster run yet.
- **Goal:** Complete the bounded P11 E1/E2 evidence safely; preserve E3-E6 and V5-E1 as `not measured` until safe procedures exist.
- **What changed and why:** Added owner/selector/readiness validation for E2 pod recovery and context-pinned localhost `kubectl proxy` DELETE with Kubernetes UID precondition. This avoids name-only deletion races. Updated P11 progress state. Focused offline suite: 39 passed.
- **Files touched:** `eval/p11_run.py`, `tests/test_p11_run.py`, `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`.
- **Open issues:** P11 E1/E2 live evidence is pending. Confirm mode=test and deployment/HPA baseline before each run; wait for desired 2/2 after E1 before E2. Do not run E3-E6 or V5-E1. No persistent volumes may be deleted.
- **Next step:** Commit this reviewed safety fix, then run authorized E1 and E2 on `k3d-kubeheal`, recording exact commands, output, timing, cleanup, and recovery under `docs/kubeheal/results/p11/`.
