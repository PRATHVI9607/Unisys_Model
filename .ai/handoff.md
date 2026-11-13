# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Continue KubeHeal live acceptance, then rehearsal and push preparation. Nothing pushed; no training or PROJECT_SPEC.md edits.
- **What changed and why:** F10 demo-image drift walkthrough evidence added. It confirms live metrics and a test-mode `human_patch` dry-run, then verifies restoration; it does not claim canary healing or p99 rollback.
- **Files touched:** docs/kubeheal/demo-evidence/F10/F10_drift_walkthrough_2026-11-13.md, .ai/handoff.md
- **Open issues:** F5/F6/F7 live triggers remain unverified; F8 dashboard has API/page read coverage but no browser screenshot; F10 canary rollback not measured; P11 E1/E2 and U6 twice remain; full rehearsal and push prep remain. Preserve MinIO/Redis data and keep mode test outside controlled windows.
- **Next step:** Verify F8 dashboard reads and controls, then continue F5-F7, P11, U6, rehearsal, and final prep. Never push.
