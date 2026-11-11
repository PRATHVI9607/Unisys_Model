# Handoff

- **Agent:** Claude Code (orchestrator)
- **Date:** 2026-11-11
- **Status:** PAUSED by the owner. Nothing is running except the k3d cluster `kubeheal` (and its registry), and nothing is pushed.
- **Branches:** `work` has every core fix. `demo` (checked out when paused) = `work` plus `demo/` scripts. Core fixes go to `work` first, then `git switch demo; git merge work`. `wave/P6` is merged, worktree removed, branch kept.

## Done this session

- Reviewed everything after `5cafe8b` with Sonnet reviewers (three rounds), fixed all findings (see "Review and fixes" in `docs/kubeheal/PROGRESS.md`). Full suite on `work`: 897 passed, 2 skipped, plus 2 live-cluster tests that need the chart installed (`test_live_watch_follows_configmap_without_polling`, `test_rbac_k3d.py::test_rbac_matrix`).
- P7-RR-10 done (ledger failure policy, SnapshotFreeze release tool). P8-D5 done (Codex) plus review fixes. `wave/P6` merged earlier by Codex; worktree removed.
- P10-U1 partly done on `demo`: fresh k3d cluster with registry, snapshot CRDs and controller, CSI hostpath driver, `csi-hostpath-snapclass`, kube-prometheus-stack, images built and pushed, chart installed once. Found by running: Executor and Fusion images lacked `minio` (fixed on `work`, images rebuilt, not yet rolled out).

## Next (in this order)

1. `.\demo\k3d\up.ps1 -Stage install` (PowerShell; Helm upgrade recovers the failed release and rolls the new images). Check `kubectl --context k3d-kubeheal -n kubeheal get pods`.
2. `-Stage adapter`, `-Stage victim`; then P10-V2 (each of the 15 Health Agent queries returns data), P10-U7 (queue-depth metric read by the HPA), rerun `scripts/rbac_check.py` and the two cluster tests.
3. `demo/scripts/demo.ps1` in this order: D-1 to D-4 (drift, kill switch), then D-5, D-6, then D-7 to D-9. Falco attempt with a fixed time limit, else replay mode (P10-U2). `demo/README.md` only with observed results. Acceptance twice in a row (U6) last.
4. P11 after P10. k6 is not installed: run the pinned `grafana/k6` image as a Job in the cluster.

## Rules that still apply

- Only `--context k3d-kubeheal`; never touch `hybrid-demo`. Never push, never set `ALLOW_PUSH`, no destructive git commands, no training (P12 not approved), no invented numbers.
- `k3d` and `helm` are not on PATH; `demo/k3d/lib.ps1` finds them. Pass `--basetemp=.pytest-tmp/<name>` to pytest.
- Open task list: P7-RR-11, P7-RR-12, REV-3 graph test (needs `torch_geometric`), P6-D6 KernelExplainer background data.
