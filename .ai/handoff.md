# Handoff

- **Agent/date:** Claude Code, 2026-11-12. Nothing pushed.
- **Resume here:** `docs/kubeheal/NEXT_FOR_CODEX.md` (tool-neutral, task list) and the section "Claude session 2026-11-12" at the end of `docs/kubeheal/PROGRESS.md`. Decisions are final in section 11 of `V5_INTEGRATION_PLAN.md`.
- **Branches:** `work` (worktree `../Unisys_Model-wt-metric-query`) and `demo` (main checkout) are in sync apart from demo-only files; run `git log -1` for the tips. Merged: V5-S2, D4 review fixes, Task 3 chart cleanup, namespace tier map (`demo` to dev). Suites: work 1471 passed, 7 skipped, 34 deselected; demo 1476 passed, 6 skipped. No other worktree is open.
- **Cluster (read-only checks, `k3d-kubeheal` only):** reachable; `kubeheal-mode` is `test`; Helm release `kubeheal` revision 4 deployed; no failing pods. It still runs the old neural stack; the LightGBM inference stack is not installed. Docker pulls work.
- **Next:** V5-S1 Falco rules and the D-5 replay, V5-D5 baseline promotion, Executor validation (D6/D9), containment (S5), dashboard (I3), then Task 4 (install the stack), P10 U6 twice, P11 runs, P13 docs, eBPF last.
- **Open issues:** the Falco rules still lack open flags and rename source (the model scores the ransomware window benign on live rules; a heuristic-only human event covers it); the Security Agent Lua score script was verified once on a scratch Redis, CI uses a Python mirror; model training is not approved.
