# Handoff

- **Agent:** Codex; **Date:** 2026-11-12.
- **Goal:** Resume KubeHeal demo readiness and prepare green changes for work/demo; nothing pushed.
- **What changed and why:** Integration branch `wave/codex-integration` combines F1 default-off live tests and the containment HMAC protocol from `wave/Codex-F3`. HMAC covers freeze requests/results and operator thaw; its key is the Redis password Secret, so Redis credential holders can also sign.
- **Files touched:** F1 safety tests and README/AGENTS; containment auth helper, Executor/Security Agent paths, Helm/plain manifests, thaw script, tests, and `docs/kubeheal/PROGRESS.md`.
- **Checks:** F1 focused run 34 passed, 2 skipped. Containment focused run 299 passed, 3 skipped. A fresh HPA attempt failed because the demo script flattened the JS file; its temporary resources were cleaned. `dev/freeze-scratch` is absent; merged S5c/CH4 worktrees were removed.
- **Open issues:** Full suite and official work/demo merges remain. HPA cleanup hardening and rerun, D-5 replay, live stream-driven containment, F9/F10 acceptance, U6/P11, runbook rehearsal, final docs/evidence, and push prep remain.
- **Next step:** Finish the integration merge, run the full suite, then merge only after review and green results. Keep mode `test` except one coordinated scripted acceptance window; never push or train models.

