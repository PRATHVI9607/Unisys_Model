# Handoff

- **Agent/date:** Claude Code, 2026-11-12. Nothing pushed.
- **Resume here:** `docs/kubeheal/NEXT_FOR_CODEX.md` (tool-neutral, task list) and the section "Claude session 2026-11-12" at the end of `docs/kubeheal/PROGRESS.md`. Decisions are final in section 11 of `V5_INTEGRATION_PLAN.md`.
- **Branches:** `work` (worktree `../Unisys_Model-wt-metric-query`) and `demo` (main checkout) are in sync apart from demo-only files; run `git log -1` for the tips. Merged since Codex paused: V5-S2, D4 review fixes, chart cleanup (no legacy model URLs, no DCM_URL), namespace tier map (`demo` to dev), V5-S1 (Falco rules), V5-D6 and V5-D9 (Executor validation and candidate fields), CH1 (Health Agent ledger wiring). Last suite on work: 1528 passed, 7 skipped, 34 deselected.
- **In progress:** `wave/V5-D5` (baseline promotion, worktree `../Unisys_Model-wt-V5-D5`): built and reviewed, its review fixes (including a kill-switch dry run for promotion in mode test) are being applied; NOT merged. If the worktree has uncommitted changes, commit them to the branch first.
- **Cluster (read-only checks, `k3d-kubeheal` only):** reachable; `kubeheal-mode` is `test`; Helm release `kubeheal` revision 4 deployed; no failing pods. It still runs the old neural stack; the LightGBM stack is not installed (Task 4). Docker pulls work.
- **Next:** merge V5-D5, then V5-S5 containment (design decisions in PROGRESS), dashboard V5-I3, Task 4 (install the stack on k3d, mode `test`), the D-5 replay on the cluster, P10 U6 twice, P11 runs, P13 docs, eBPF last.
- **Open issues:** Falco rules and values are not verified on a running Falco; the Security Agent score Lua script was verified once on a scratch Redis (CI uses a Python mirror); model training is not approved.
