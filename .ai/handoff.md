# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training.
- **Current F3 review:** `wave/claude-F3` at `d0ed188` passed the full suite under Python 3.11: 2,138 passed, 11 skipped. The test change still asserts no contain request and requires the unsupported-owner escalation.
- **F3 status:** LIVE-VERIFIED for the Fusion-to-restore chain. Sense input is scripted because Falco is absent. D-5 replay produced a real Security Agent event and Fusion dry-run/Executor intake evidence. Main runbook includes F3 and blocks unsafe prefix-based cleanup.
- **Cluster lock:** `docs/kubeheal/CLUSTER_LOCK.md` is committed on both branches. Keep it through all upgrades and enforce windows; remove it only after cluster work is complete. Mode remains `test` outside logged windows.
- **Next:** finish work merge and full suite, merge work into demo and run the full suite, then rebuild all demo images from demo and upgrade only to fresh tags. Record actual revision and tags in `PROGRESS.md`.
- **Remaining:** F4-F13 live checks, U6 twice, measured P11 evidence, post-cutoff rehearsal, final README/AGENTS, secret scan, and `PUSH_PLAN.md`.
- **Safety:** only `--context k3d-kubeheal`; never push or set `ALLOW_PUSH`; no model training or `PROJECT_SPEC.md` edits. No destructive reset or clean.
