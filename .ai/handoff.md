# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training.
- **Current F3 review:** `wave/claude-F3` at `d0ed188` passed the full suite under Python 3.11: 2,138 passed, 11 skipped. The test change still asserts no contain request and requires the unsupported-owner escalation.
- **F3 status:** LIVE-VERIFIED for the Fusion-to-restore chain. Sense input is scripted because Falco is absent. D-5 replay produced a real Security Agent event and Fusion dry-run/Executor intake evidence. Main runbook includes F3 and blocks unsafe prefix-based cleanup.
- **Cluster lock:** held through the revision 13 upgrade and readbacks, then released. Before any later Helm upgrade or enforce window, recreate `docs/kubeheal/CLUSTER_LOCK.md`, commit it, and remove it afterward. Mode remains `test` outside logged windows.
- **Suites:** merged work 2,155 passed, 11 skipped in 58.77s; demo 2,155 passed, 11 skipped in 78.43s.
- **Cluster:** demo rebuilt all 11 images from demo with tag `b20261112215116`; Helm revision 13 deployed at 21:53:13 IST. Mode is `test`, KubeHeal workloads are Ready, all use the fresh tag, and the HMAC Secret exists. Exact record is in `PROGRESS.md`.
- **Next:** sync this deployment record to demo, release the committed cluster lock, then continue F4-F13, U6 twice, post-cutoff rehearsal, final docs/secret scan/PUSH_PLAN, and final suite runs. Do not touch the cluster without taking a new committed lock.
- **Remaining:** F4-F13 live checks, U6 twice, measured P11 evidence, post-cutoff rehearsal, final README/AGENTS, secret scan, and `PUSH_PLAN.md`.
- **Safety:** only `--context k3d-kubeheal`; never push or set `ALLOW_PUSH`; no model training or `PROJECT_SPEC.md` edits. No destructive reset or clean.
