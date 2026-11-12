# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training.
- **Current work/demo tips before F3:** `work` `3aa5994`, `demo` `036f54b`. F1/F4/F8 and F9/F10 test work are already merged and green.
- **Suites:** work 2,081 passed, 12 skipped; demo 2,090 passed, 11 skipped. F3 branch `wave/claude-F3` is ready at `d0ed188`; review and full suite are pending.
- **Cluster lock:** created and committed as `CLUSTER LOCK Codex 2026-11-12 20:00 IST`. Keep it until the post-merge Helm upgrade and live checks finish, then remove and commit it. No cluster operation has run since taking the lock.
- **F3 scope:** review the whole branch, especially the `test_fusion_incident.py` contract change; merge only after full suite green. Merge its F3 runbook section into `DEMO_RUNBOOK.md`.
- **Next:** merge F3 to work, then work to demo; rebuild all demo images from demo and upgrade only while holding this lock. Record Helm revision/image tags and F3 status. Continue remaining non-F3 demo checks afterward.
- **Safety:** only context `k3d-kubeheal`; no push/ALLOW_PUSH; no `PROJECT_SPEC.md` edits. Re-check the lock and mode before any cluster command.
