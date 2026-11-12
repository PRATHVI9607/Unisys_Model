# F3 evidence: alert-driven ransomware containment

Date: 2026-11-12 (times UTC). Machine: the owner's Windows 11 laptop, k3d cluster `k3d-kubeheal` only. Branch `wave/claude-F3`.
Runbook text: `RUNBOOK_F3.md`. Tooling: `f3_window.py` (prep, rehearse, window, cleanup) and `ledger_dump.py` (read-only).

| Files | What |
|---|---|
| `00_pre_state.txt` | images and Helm revision before and after each upgrade (rollback: `helm rollback kubeheal 9`) |
| `10_d5_rerun.txt`, `11_d5_rerun_ledger.jsonl` | Task 2: D-5 replay in test mode, Security event now carries `deployment: victim-app`, Executor accepted, dry-run "would have" entries |
| `20_*`, `21_*`, `30_*`, `40_*`, `41_*`, `42_*`, `43_*` | window 1 (14:01:28 - 14:01:42): old Executor image, freeze refused `invalid_hmac` |
| `50_*` to `63_*` | window 2 (14:06:28 - 14:07:04): entropy result unreadable, `restored_kept_isolated` |
| `70_*` to `87_*` | window 3 (14:15:49 - 14:16:34): full chain, `restored`; ledger, state before and after, component logs, ledger keys written in the window, cleanup |

The alert is scripted (see `RUNBOOK_F3.md`); no screenshots were taken. Nothing here is a performance claim.
