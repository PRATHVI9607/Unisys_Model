# F3 evidence: alert-driven ransomware containment

Date: 2026-11-12 (times UTC). Machine: native Windows 11 with Docker Desktop, k3d cluster `k3d-kubeheal` only. Branch `wave/claude-F3`.
Runbook text: `RUNBOOK_F3.md`. Tooling: `f3_window.py` (prep, rehearse, window, cleanup) and `ledger_dump.py` (read-only).

| Files | What |
|---|---|
| `00_pre_state.txt` | images and Helm revision before and after each upgrade (rollback: `helm rollback kubeheal 9`) |
| `10_d5_rerun.txt`, `11_d5_rerun_ledger.jsonl` | Task 2: D-5 replay in test mode, Security event now carries `deployment: victim-app`, Executor accepted, dry-run "would have" entries |
| `20_*`, `21_*`, `30_*`, `40_*`, `41_*`, `42_*`, `43_*` (moved to `docs/dev-notes/F3-attempts/`) | window 1 (14:01:28 - 14:01:42): old Executor image, freeze refused `invalid_hmac` |
| `50_*` to `63_*` (moved to `docs/dev-notes/F3-attempts/`) | window 2 (14:06:28 - 14:07:04): entropy result unreadable, `restored_kept_isolated` |
| `70_*` to `87_*` | window 3 (14:15:49 - 14:16:34): full chain, `restored`; ledger, state before and after, component logs, ledger keys written in the window, cleanup |

The alert is scripted (see `RUNBOOK_F3.md`); no screenshots were taken. Nothing here is a performance claim.

## Commands, in order (all with `--context k3d-kubeheal`; times UTC)

1. `git worktree add ../Unisys_Model-wt-claude-F3 -b wave/claude-F3 55aefaf`; code fix, tests, commits `7871bab`, `98df6b5`.
2. A cluster-use lock line was committed (`97c7fdf`) and removed in the last commit; that lock file is no longer tracked.
3. `& .\demo\k3d\images.ps1 -Only security-agent,fusion-agent` -> tag `b20261112192037`.
4. `helm upgrade kubeheal deploy/helm/kubeheal --reuse-values --set securityAgent.image.tag=b20261112192037 --set fusionAgent.image.tag=b20261112192037 --wait` -> revision 10 (13:51Z; after a `--dry-run=server`).
5. `.venv\Scripts\python.exe scripts/d5_replay_runner.py --timeout-s 120` (13:51:53Z, test mode) -> `10_d5_rerun.txt`.
6. `F3_NAME=f3-scratch` `f3_window.py prep`, `rehearse`; `window` (window 1, 14:01Z); `ledger_dump.py inc-20261112-140132-fe13751f`; `cleanup`.
7. `& .\demo\k3d\images.ps1 -Only executor` -> `b20261112193403`; `helm upgrade ... --reuse-values --set executor.image.tag=b20261112193403 --wait` -> revision 11 (14:05Z; the cluster ran Executor `b20261112081307`, built before the HMAC change).
8. `F3_NAME=f3-scratch-b` `prep`, `rehearse`, `window` (window 2, 14:06Z), `ledger_dump.py inc-20261112-140632-c8ed65b8`.
9. Operator debug scan Job in `staging` (`job_body(...)` applied with `kubectl apply`, restored PVC of window 2) and a read-only `kubectl exec deploy/executor -- python` that printed the pod-log string the client returns.
10. Code fix `98df6b5`; `cleanup`; `images.ps1 -Only executor` -> `b20261112194300`; `helm upgrade ... --set executor.image.tag=b20261112194300 --wait` -> revision 12 (14:13Z).
11. `F3_NAME=f3-scratch-c` `prep`, `rehearse`, `window` (window 3, 14:15Z), `ledger_dump.py inc-20261112-141554-1d76b1ed`, `ledger_dump.py --list-since 2026-11-12T14:15:40Z`, state before and after, `cleanup`.
12. `88_hmac_requests_and_breaker.txt`: the freeze request entries (window 1 unsigned, windows 2 and 3 signed) and the staging containment breaker.
13. Full suite on the final commit, see the reply.
