# KubeHeal continuation notes (2026-11-11, written by Claude)

Read `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`, the Task checklist in `docs/kubeheal/PROGRESS.md` and `.ai/handoff.md` first.

## State

- Repository `C:\My_projects_1\cLOUD\Unisys_Model`, branch `work`. Nothing is pushed. `wave/P6` is merged (`391b8ac`), worktree removed.
- P7-RR-10 and P8-D5 are done and reviewed. The owner decisions are applied (ledger failure policy, SnapshotFreeze release tool). Nothing is waiting on the owner.
- Full suite: 857 passed, 2 skipped. Command: `$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=.pytest-tmp/<name>`.

## Next tasks (local, no cluster)

1. P7-RR-11: re-baseline the golden baseline after a restore (`agents/health_agent/baseline.py`, `scripts/baseline_tool.py`, Executor hook). Verify with tests/test_remediation_ransomware.py and a new test.
2. P7-RR-12: restore resume action and scanner hardening (`agents/executor/restore.py`, `restore_entropy.py`, `entropy_probe.py`, `dockerfiles/Dockerfile.executor`). Reserved for a stronger agent: it touches Executor write paths.
3. REV-3 graph contract test needs `torch_geometric`; skip if it cannot be installed.

## Do not touch

- `decision_policy.py` purity, `agents/executor/actions.py::_write` ordering (gate, intent entry, gate again, call), `k8s/rbac/`, `ledger_guard.py` classification, unless a test and a review cover the change.
- No Kubernetes access: P10 and P11 are cluster tasks owned by Claude (`k3d-kubeheal` only, never `hybrid-demo`). `k3d` and `helm` are under `%LOCALAPPDATA%\Microsoft\WinGet\Packages\`, not on PATH.
- No training (P12 is not approved). Never push, never set `ALLOW_PUSH`, no destructive git commands.

## Pitfalls

- `.pytest-tmp/run` is locked by an earlier session: always pass your own `--basetemp`.
- Each gated write asks the kill-switch gate twice (before and after the "about to do" ledger entry). Test fakes that count gate calls need `FlippingMode(2)` for one allowed write.
- A new Kubernetes write step name is treated as corrective (needs MinIO) unless it is added to `PROTECTIVE_STEPS` in `ledger_guard.py`; that decision is the owner's.
- Redis fakes used with `ExecutorService` need `set(nx, ex)` and `delete`.
- Not measured: every threshold in code is a chosen default. Do not write metrics that were not produced by a run.
