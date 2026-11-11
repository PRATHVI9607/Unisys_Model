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
- Third review findings 1 to 10 are fixed by a builder (Claude Code, 2026-11-11, 3 commits on `work`, not pushed): in-progress marker (90 s TTL, refreshed, owner-checked, no dead letter while alive), approve re-check after claim, ledger write timeout (`LEDGER_WRITE_TIMEOUT_S`, 5 s chosen default) and FileExistsError retry, ledger-refused requests return `escalated:ledger_unavailable` (not final), `restore_begin` corrective entry before the first restore write, flush batches plus `kubeheal.ledger.dead`, `LedgerUnavailable` is never "already exists", freeze release (reason always required, compare-and-delete), scan Job pinned to the node of the pod that mounts the PVC. Limit: a hung MinIO thread cannot be cancelled (documented in `ledger_guard.py`).
- Known failing outside these changes: `tests/test_killswitch.py::test_live_watch_follows_configmap_without_polling` and `tests/test_rbac_k3d.py::test_rbac_matrix` (cluster tool, 100 s).
- Not started: P10 and P11 (they need the cluster and stay with Claude). `k3d`, `helm` live under `%LOCALAPPDATA%\Microsoft\WinGet\Packages\...` and are not on PATH. Only ever use `--context k3d-kubeheal`; never touch `hybrid-demo`.

## Open

- P7-RR-11 (re-baseline after restore) and P7-RR-12 (restore resume action, scanner hardening) are open; see the checklist.
- REV-3 graph contract test still needs `torch_geometric`. P6-D6 still has no legitimate KernelExplainer background data. P12-H training is not approved.

## Next

1. P10: create `demo` from `work`; `demo/k3d/up.ps1`, `down.ps1`, victim apps, V2/V3/U7, then `demo/scripts/demo.ps1`, `demo/README.md` (only observed results).
2. P11 evaluation harness after P10.
