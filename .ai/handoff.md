# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training.
- **Goal:** Finish and verify the KubeHeal k3d demo. Current tips: `work` `7560901`, `demo` `a5b6cd8`; code merge commits are `48bbda3` and `e41eb3d`.
- **Merged and green:** F1 opt-in integration-test guard, F4 HMAC smoke runner, F8 SnapshotFreeze incident controls, and F2/F4-F11 runbook/evidence are in both branches. HPA script cleanup is in `demo`.
- **Suites:** `work` 2,079 passed, 12 skipped in 58.93s. `demo` 2,088 passed, 11 skipped in 59.77s. Live tests are skipped by default.
- **F3 scope:** Claude owns `wave/claude-F3`, including the pod-to-Deployment owner fix, D-5 rerun, and live containment chain. Codex has not edited those paths or merged Claude's branch. Codex alone merges to `work` and `demo`.
- **Cluster:** last checked only `k3d-kubeheal`; lock file absent, mode `test`, and `dev/freeze-scratch` absent. No cluster mutation this session. Check the lock before any cluster access. Commit `CLUSTER LOCK <who> <start time>` before enforce windows or Helm upgrades, then remove it.
- **Open:** F3 in progress; live HMAC, baseline promotion, kill switch, drift healing and rollback acceptance; Grafana evidence; U6 twice; successful P11 evaluation; post-cutoff rehearsal; final README/AGENTS, secret scan, and PUSH_PLAN.
- **Next:** continue non-F3 acceptance after Claude's cluster work is clear. Keep measured failures labelled as failed runs, not accepted benchmarks. Merge only after review and a green full suite. Never push or set `ALLOW_PUSH`.
