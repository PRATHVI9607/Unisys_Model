# KubeHeal continuation notes (2026-11-11, written by Claude at the owner's PAUSE)

Read `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`, the Task checklist and the "Session pause" section of `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md`. Read them from branch `demo` if you can: it has the newest copies.

## State

- `work`: all core fixes, 897 tests passing (2 skipped) plus 2 cluster-only tests. `demo`: `work` plus `demo/k3d/` scripts. Nothing pushed.
- Cluster `kubeheal` (k3d, context `k3d-kubeheal`) is running and partly installed. Executor and Fusion pods crash-loop on old images until `up.ps1 -Stage install` is run again.

## Next tasks

1. Cluster tasks stay with Claude: `up.ps1 -Stage install|adapter|victim`, P10-V2, P10-U7, `demo.ps1`, Falco, P11. Do not run them unless the owner says so.
2. Local tasks that need no cluster: P7-RR-11 (re-baseline after restore: `agents/health_agent/baseline.py`, `scripts/baseline_tool.py`, Executor hook), P7-RR-12 (restore resume action and scanner hardening, reserved for a stronger agent), REV-3 graph test (needs `torch_geometric`).
3. Verify with `$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=.pytest-tmp/<name>`.

## Do not touch

- `decision_policy.py` purity, `agents/executor/actions.py::_write` ordering, `ledger_guard.py` step classification, `k8s/rbac/`, unless a test and a review cover it. Never edit core code only on `demo`.
- `hybrid-demo` and any other cluster. No training (P12), no push, no `ALLOW_PUSH`.

## Pitfalls

- PowerShell's `h` alias shadows a function named `H`; the demo helper is `Hc`. `K` forwards piped stdin.
- `k3d`, `helm` are not on PATH (see `demo/k3d/lib.ps1`). `k6` is not installed.
- CSI hostpath volumes exist only on node `k3d-kubeheal-agent-0`; workloads with PVCs are pinned there.
- Every threshold in code is a chosen default; write no metric that a run did not produce.
