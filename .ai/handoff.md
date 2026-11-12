# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training or cluster writes were run.
- **Goal:** Demo readiness. Work is split between `wave/docs-runbook` (F1 safety, core docs) and `wave/demo-runbook` (runbook and push plan), both based on the latest corresponding branches.
- **What changed and why:** Removed import-time cluster probes from live RBAC and kill-switch tests; both now require explicit opt-in, with a guard test. README and AGENTS now describe the LightGBM/conformal design and current k3d evidence with its limits.
- **Files touched:** `tests/test_killswitch.py`, `tests/test_rbac_k3d.py`, `tests/test_live_test_safety.py`, `README.md`, `AGENTS.md`.
- **Checks:** Focused safety run: 34 passed, 2 skipped. `git diff --check` passed. Full suite remains for the orchestrator.
- **Open issues:** Runbook commands need final review against merged feature implementations; F2-F13 live acceptance/evidence are not complete. Handoff update is on the work-based branch and should be reconciled after merge.
- **Next:** Review and commit the two isolated branches, merge green core work into `work`, merge `work` into `demo`, then rehearse and update actual measured evidence.
