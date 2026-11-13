# KubeHeal final acceptance handoff, 2026-11-13

- **Agent:** Codex
- **Branch:** demo
- **Goal:** finish authorized acceptance and push preparation. Nothing pushed; `ALLOW_PUSH` was not set. No training or `PROJECT_SPEC.md` changes.
- **What changed and why:** Full suites passed on work and demo. Reviewed work was merged into demo. D-5 target selection now excludes scripted F10 scratch pods sharing the victim image label; focused tests passed 9/9 and the runbook replay succeeded. F2/F4 were rerun. F5-F10 scripted live evidence, clean warmed F11/P11 E1, F12 U6 twice on a separate fresh cluster, and F8 screenshots/results are recorded. Final runbook and current feature statuses are in the docs and evidence folders.
- **Files touched:** D-5 runner/tests; README, AGENTS, PROGRESS, DEMO_RUNBOOK, NEXT_FOR_CODEX, PUSH_PLAN, F5-F7 status pages, final rehearsal evidence, F2/F4 outputs, cluster lock, and this handoff.
- **Tests:** work 2,169 passed, 11 skipped in 82.92s. Demo 2,178 passed, 11 skipped in 89.30s. D-5 focused suite 9 passed.
- **Cluster:** only `k3d-kubeheal`; mode `test`, Helm revision 17, inference `/readyz` HTTP 200, all three PVCs Bound. Original cluster/PVCs preserved; lock released.
- **Open limits:** Falco sensing/real-node behavior unverified. F8 SnapshotFreeze release and F9 paired same-input enforcement not measured. P11 E3-E6/V5-E1 not measured with reasons. Full base-to-head whitespace check has 1,803 findings, including raw output; captured output was left unchanged. High-confidence secret scan matches: zero; broad candidates reviewed as ordinary code/config/test references.
- **Next step:** owner reviews `PUSH_PLAN.md` and decides whether to push. This agent did not push and will not set `ALLOW_PUSH`.
