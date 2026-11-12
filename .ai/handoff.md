# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training.
- **Goal:** Finish the KubeHeal k3d demo. `work` is `62426c0`; `demo` is `9986b73`.
- **Scope:** Claude Code owns F3 on `wave/claude-F3`; Codex is not editing its replay, Fusion publish, Executor containment, or Security Agent freeze paths. Only Codex merges to `work` and `demo`.
- **Cluster:** only `k3d-kubeheal`; lock file absent at last check, mode `test`, `dev/freeze-scratch` absent. No cluster changes made this session.
- **Changed this session:** removed four clean merged worktrees (`Codex-F3`, `codex-integration`, `docs-runbook`, `Codex-F7F8`) and pruned metadata. P11 isolated review tests passed 35/35 with a dedicated temp directory.
- **In progress:** agents have separate branches for F1 test safety, F5-F8 policy/dashboard, and F2/F4-F11 runbook documentation. They do not merge or edit PROGRESS/handoff. The Codex P11 branch is under review.
- **Open:** Claude F3; HMAC live verification; F5-F11 acceptance and P11 rerun; U6 twice; rehearsal; final docs, secret scan, clean full suites on both branches, and PUSH_PLAN.
- **Next:** review each agent commit, run the full safe suite, merge green work into `work`, then merge `work` into `demo`. Check `CLUSTER_LOCK.md` before any cluster access; log/commit a lock before any enforce window or Helm upgrade.
