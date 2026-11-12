# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training.
- **Current F3 review:** `wave/claude-F3` at `d0ed188` passed the full suite under Python 3.11: 2,138 passed, 11 skipped. The test change still asserts no contain request and requires the unsupported-owner escalation.
- **F3 status:** LIVE-VERIFIED for the Fusion-to-restore chain. Sense input is scripted because Falco is absent. D-5 replay produced a real Security Agent event and Fusion dry-run/Executor intake evidence. Main runbook includes F3 and blocks unsafe prefix-based cleanup.
- **Cluster lock:** held through the revision 13 upgrade and readbacks, then released. Before any later Helm upgrade or enforce window, recreate `docs/kubeheal/CLUSTER_LOCK.md`, commit it, and remove it afterward. Mode remains `test` outside logged windows.
- **Full suites:** work 2,158 passed, 11 skipped in 90.05s; demo 2,158 passed, 11 skipped in 66.43s after merging F5 and F11 evidence/docs.
- **Cluster:** demo rebuilt all 11 images from demo with tag `b20261112215116`; Helm revision 13 deployed at 21:53:13 IST. Mode is `test`, KubeHeal workloads are Ready, all use the fresh tag, and the HMAC Secret exists. Exact record is in `PROGRESS.md`.
- **F4:** live mode-test smoke passed; signed freeze request returned dry_run, unsigned/tampered requests were refused, all result HMACs valid, cleanup verified. Evidence is in `demo-evidence/F4/`. Future smoke runs need an exclusive committed lock due a possible concurrent mode-change race.
- **F5:** namespace-specific dashboard mode gate fixed at `4500998`; focused suite 90 passed. Live baseline promotion is still unverified.
- **F11:** prior clean run passed 121,088/121,088 checks and scaled 2 -> 7 -> 2. Post-merge repeat scaled 2 -> 8 -> 2, with 12 of 99,431 checks refused during scale-up. Grafana API and Prometheus evidence are saved; screenshot is missing because the image renderer is unavailable.
- **Next:** prune clean merged worktrees, complete the full-diff secret scan and refresh `PUSH_PLAN.md`. Continue F5-F10/F12 live work and schedule the post-cutoff rehearsal. Do not touch the cluster without checking the lock; take a committed lock before enforce or Helm upgrade.
- **Remaining:** F5 promotion, F6 live Executor intake, F7 live policy scenarios, F8 populated UI walkthrough, F9 enforce paired run, F10 canary rollback, F11 visual Grafana screenshot, U6 twice, P11 accepted evaluation, post-cutoff runbook rehearsal, final suites, secret scan, PUSH_PLAN.
- **Safety:** only `--context k3d-kubeheal`; never push or set `ALLOW_PUSH`; no model training or `PROJECT_SPEC.md` edits. No destructive reset or clean.
