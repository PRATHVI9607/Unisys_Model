# KubeHeal next agent handoff (Codex or Claude Code)

Updated 2026-11-11 after the P10 Session 1 pause.

## Resume state

- Current demo checkout: `C:/My_projects_1/cLOUD/Unisys_Model`, branch `demo`. Implementation checkpoint is merge commit `f4264d1` (demo contains the shared query fix from `work`). Read `git log -1 --oneline` for the handoff-doc commit at the tip.
- Core branch: `work`, commit `382d137` (`fix: source demo disk I/O metric from victim app`). This change was built and exercised on k3d before merge to demo.
- No push was performed. Never push or set `ALLOW_PUSH`.
- Cluster `kubeheal` is running. Only use `--context k3d-kubeheal`; never touch `hybrid-demo` or any other context. `kubeheal-mode` is `test`. Prod victim CPU resources are restored to request `100m`, limit `500m`.
- Victim app and Health Agent are currently running manually built registry tags ending in `:metric-probes`. The ignored generated image-tag values do not reference those tags; a later `up.ps1 -Stage install` or `-Stage victim` can replace them with older images. Update the normal image build/tag flow before relying on a reinstall.
- Live query verification generated `/data/.kubeheal-metric-probe` on the prod victim PVC. This is a harmless test marker and was left in place. Temporary snapshot restore pod/PVC/snapshot were removed; the original PVC and rolling snapshots remain.

## Branches and worktrees

| Branch | State | Worktree |
|---|---|---|
| `demo` | Current; includes P10 metric probe changes and merge `f4264d1` from `work` | `C:/My_projects_1/cLOUD/Unisys_Model` |
| `work` | Core disk metric query fix at `382d137`; handoff docs synced from `demo` at `6ba9109` | `C:/My_projects_1/cLOUD/Unisys_Model-wt-metric-query` |
| `wave/P11` | Unreviewed WIP commit `47e1b34`; no cluster access used | `C:/My_projects_1/cLOUD/Unisys_Model-wt-P11` |
| `wip/docs-p6d2` | Unreviewed WIP commit `c7c9f5bf7a078702e2dd0c1d47d862df7ef1b77f`; includes P6-D2 and docs | `C:/My_projects_1/cLOUD/Unisys_Model-wt-docs` |
| `main` | Base branch at `88ce586`, ahead of `origin/main` by one local commit | no worktree |
| `wave/P5` | Historical merged branch at `8f1d8b6` | no worktree |
| `wave/P6` | Historical merged branch at `7f95f6c` | no worktree |
| `wave/P7` | Historical merged branch at `a294eb9` | no worktree |
| `wave/P8` | Historical merged branch at `246b973` | no worktree |
| `wave/P9` | Historical merged branch at `0451237` | no worktree |
| `wave/docs-p6d2` | Inactive historical base at `e611844` | no worktree |

Remote refs at pause: `origin/HEAD -> origin/main`, `origin/main` (`b419053`), `origin/master` (`1ca9418`), `origin/test` (`e8e9feb`), `origin/kali` (`7e78f4b`), and `origin/feat/dit-sec-train-integrate` (`30f3b17`). No remote branch was changed.

The `wave/P11` and `wip/docs-p6d2` branches were not merged. Review each diff, bring it up to the current `work` base without overwriting work, and run the full test suite after each approved merge. Their focused tests passed (P11: 8; docs/P6-D2: 23), but the docs agent's full-suite run was blocked by environment/dependency/temp-path issues.

## Next tasks, in order

1. **Finish P10-U4 driver and image reproducibility.** Touch `demo/scripts/demo.ps1`, `demo/k3d/images.ps1`, and only necessary demo docs. Add safe status, drift, reset, and clearly reported HUMAN/dry-run behavior. The drift patch must set both requests and limits to `50m`, then restore `100m`/`500m`. Bring `metric-probes` into the standard image-tag workflow. Do not touch `agents/fusion_agent/decision_policy.py`, `agents/executor/`, or `k8s/rbac/`. Verify with `.\demo\scripts\demo.ps1 -Action drift`, `.\demo\scripts\demo.ps1 -Action reset`, and `.\demo\k3d\up.ps1 -Stage victim` once the helper's Helm requirement is available.
2. **Complete P10-U2 and D-5 Falco path.** Falco is absent; Security Agent logs show `FALCO_MODE=auto` resolves to `off` and `/proc` write tracking only. Helm was unavailable to `Initialize-Tools`; no Falco install/replay config was applied. Try a bounded install, or explicitly mount a hand-written replay fixture and label the result as replay. Keep live Falco claims separate. Do not change `FALCO_MODE` without recording it and restoring the intended mode. Verify logs and a replay event through the Security Agent/Fusion streams.
3. **Run P10 D-6 fail-closed / HUMAN path.** The latest drift already produced `human_patch` with `dry_run=true` because the Health CI width was `0.2607`, above the `0.15` gate. If testing an outage, delete only a KubeHeal model pod with `--context k3d-kubeheal`, confirm HUMAN escalation, and let its controller restore the replica. Keep mode `test`; do not loosen policy or train models.
4. **Run P10 D-8 HPA scale-out under k6 load.** Use pinned `grafana/k6:0.54.0` as an in-cluster Job with resource limits and pod anti-affinity from model servers. Target a scoring endpoint and capture HPA replicas/metrics before, during, and after. This is still unmeasured; no P11 cluster evaluation is approved by this handoff.
5. **Complete P10-U6 acceptance.** Add remaining safe demo/reset steps, run setup/demo/reset twice, record only observed output in `PROGRESS.md` and `demo/README.md`. Snapshot/restore was separately verified once; the full demo suite was not.

For shared core fixes, edit and commit on `work` first, then merge `work` into `demo`. Keep demo-only files under `demo/`. The Health Agent aiohttp session leak is still open and belongs on `work`.

## Verified findings and open issues

- On 2026-11-11 10:24 local time, the corrected verifier returned all 15 series under active traffic. The previous verifier used Service port 80 instead of 8000, so its app requests never reached the app. `http_error_rate` then had no series. The k3d kubelet exposed no `container_fs_*` series; `disk_io_bytes` now uses `kubeheal_victim_disk_io_bytes_total`, incremented after an app write and `fsync` under the mounted data path.
- The Health Agent sets `health_ci_width=1.0` when any metric is missing. The Health Model computes its own width as `1 - max(class probability)`. After all channels were present, the 50m drift event had `metrics_missing=[]`, `health_ci_width=0.2607`, and Fusion recorded `human_patch` (`dry_run=true`, CI limit `0.15`). Automatic patch remains blocked. Do not change the CI gate or policy.
- The Health Model pod logs confirmed the baked-in trained checkpoint loaded with preprocessing `v1-legacy`. Security Model `/health` reported a loaded baked-in checkpoint. No training was run.
- Executor startup had one MinIO `S3Error` while bootstrap was still running. Redis stream `kubeheal.ledger.pending` later had length `0`; the queued record drained. The transient startup failure was not reproduced after bootstrap.
- Health Agent still logs `Unclosed client session` per event.
- Falco is not running. The security-agent auto mode is off on this machine; replay is not configured.
- P10 snapshot restore succeeded: a snapshot of `prod/victim-data` restored to a temporary PVC, and the check pod read all 20 seeded files. Test resources were cleaned up.
- P10-U7 custom-metric HPA discovery works at idle (`0/4` observed earlier); scale-out under load is untested.
- Historical streams and incident keys remain in Redis; they are not cleanup targets without a reason.

## Files and operations to avoid

- Reserved for Claude/strong reviewer: `agents/fusion_agent/decision_policy.py`, Executor write paths in `agents/executor/`, and `k8s/rbac/`.
- Do not run `models/train_*.py`; P12-H is not approved. Do not run destructive Git commands or delete user data.
- Do not merge the two WIP branches until their diffs are reviewed against current `work` and the full suite is run after each merge.
- Expected test command when dependencies and venv are available: `$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=.pytest-tmp/<task>`.
