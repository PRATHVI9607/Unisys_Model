# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete KubeHeal acceptance and owner push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** README, AGENTS, PROGRESS, NEXT, DEMO_RUNBOOK, and PUSH_PLAN now reflect the live evidence, exact suite counts, and remaining acceptance gaps. F1 evidence distinguishes full-suite safety coverage from opt-in live tests.
- **Files touched:** README.md, AGENTS.md, PUSH_PLAN.md, docs/kubeheal/PROGRESS.md, docs/kubeheal/NEXT_FOR_CODEX.md, docs/kubeheal/DEMO_RUNBOOK.md, F1/F10/F12/F13/REHEARSAL evidence, .ai/handoff.md
- **Open issues:** Fresh-cluster rehearsal awaits owner approval before `down.ps1`; U6 incomplete from Helm DNS. F5-F8 completeness, F10 rollback, clean F11/Grafana screenshot, and accepted P11 E1 remain. Cluster lock is still held pending final release.
- **Next step:** Commit these docs, release the cluster lock after confirming mode `test` and no active port-forwards, rerun the final diff/secret audit, update PUSH_PLAN and handoff. Never push.
