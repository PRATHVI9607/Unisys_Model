# Handoff

- **Agent:** Claude Code (orchestrator)
- **Date:** 2026-11-11
- **Branch:** `work` (nothing pushed). `wave/P6` is merged; its worktree was removed, the branch is kept.
- **Goal:** Review Codex's work after `5cafe8b`, finish P7-RR-10, then P10 (k3d demo, `demo` branch) and P11.

## State

- Reviews done (two Sonnet reviewers, PASS WITH FIXES, all findings fixed or recorded): see "Review and fixes" at the end of `docs/kubeheal/PROGRESS.md`.
- P7-RR-10 is DONE: ledger failure policy (`agents/executor/ledger_guard.py`, wired in `actions._write`) and the admin SnapshotFreeze release tool (`dashboard/admin_routes.py`). Owner decisions are applied; there are no pending owner questions.
- P8-D5 was done by Codex (`b7436e3`); review fixes for the approval claim are in `8b6b61d`.
- Full suite on this machine: 857 passed, 2 skipped (Python 3.11.9 venv). Run with `--basetemp=.pytest-tmp/<your-name>`, because `.pytest-tmp/run` is locked by an earlier session.
- A third reviewer is checking `fb4ba4b`, `8b6b61d`, `27d1748`, `48c6e87` and the drift fix; fix its findings if any remain unaddressed (see PROGRESS.md).
- Not started: P10 and P11 (they need the cluster and stay with Claude). `k3d`, `helm` live under `%LOCALAPPDATA%\Microsoft\WinGet\Packages\...` and are not on PATH. Only ever use `--context k3d-kubeheal`; never touch `hybrid-demo`.

## Open

- P7-RR-11 (re-baseline after restore) and P7-RR-12 (restore resume action, scanner hardening) are open; see the checklist.
- REV-3 graph contract test still needs `torch_geometric`. P6-D6 still has no legitimate KernelExplainer background data. P12-H training is not approved.

## Next

1. P10: create `demo` from `work`; `demo/k3d/up.ps1`, `down.ps1`, victim apps, V2/V3/U7, then `demo/scripts/demo.ps1`, `demo/README.md` (only observed results).
2. P11 evaluation harness after P10.
