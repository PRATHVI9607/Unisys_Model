# F3 evidence: alert-driven ransomware containment

Date: 2026-11-12 (times UTC). Machine: native Windows 11 with Docker Desktop (per `AGENTS.md`), k3d cluster `k3d-kubeheal` only. Branch `wave/claude-F3`.
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
2. Lock line committed (`97c7fdf`, `docs/kubeheal/CLUSTER_LOCK.md`), removed in the last commit.
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

## Demo-image reruns (2026-11-13)

The complete scripted Fusion-to-Executor containment and restore chain ran twice after rebuilding the demo images. The first scratch Deployment reused the older victim image; the second rerun below used the freshly rebuilt `victim-app:b20261113071011` image. Both enforced windows completed and returned global mode to `test`.

- Helm revision: 15. KubeHeal agent images: `b20261113071011`.
- Second run: `f3-demo-victim-20261113`, incident `inc-20261113-015540-cff4eea6`.
- Enforce window: 2026-11-13 01:55:35Z to 01:56:13Z (38 seconds). The script confirmed mode propagation to Executor, both Fusion replicas, and the Security Agent on the scratch pod's node. An independent 400-second dead-man process was armed and stopped after the script restored `test`.
- The scripted alert led to `auto_contain`, confirmed freeze, forensic snapshot, quarantine, scale to zero, restore from the pre-T0 rolling snapshot, digest-pinned image, entropy scan, clean quarantine lift, and final `restored` result. Ledger has 42 ordered entries. The restored volume scan found 5 files, 0 high-entropy files, and 0 unreadable paths. The restored pod contained only `clean_1.txt` through `clean_5.txt`; the original encrypted files and ransom note were absent.
- Sense remains scripted: model fields were copied from the real Security Agent-scored hand-written D-5 replay. This is k3d evidence, not a live Falco capture or real-node validation.
- Both scratch runs were cleaned by the updated run-label/incident-label helper. It printed only the exact run-owned Deployment, PVCs, and snapshots before deleting them. `staging` has no remaining pods, Deployments, PVCs, Jobs, VolumeSnapshots, or NetworkPolicies from these runs.
- Five staging SnapshotFreeze keys were removed only after verifying `staging` had no PVCs. Each key was deleted with an atomic compare-and-delete against its expected incident ID. Two historical fail-safe escalations were resolved with append-only `human_resolution` ledger entries; the original escalation stream records remain intact.

Raw records: `90_demo_image_prep_2026-11-13.txt` through `100_demo_image_victim_cleanup_2026-11-13.txt`. The 42-entry read-only ledger dump is `99_demo_image_victim_ledger_2026-11-13.jsonl`.
