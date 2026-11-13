# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Continue KubeHeal live acceptance, then rehearsal and push preparation. Nothing pushed; no training or PROJECT_SPEC.md edits.
- **What changed and why:** Refreshed the exclusive cluster lock before the U6 Helm/reinstall pass. U6 will preserve all PVC-backed MinIO/Redis/ledger data; no cluster teardown is planned.
- **Files touched:** docs/kubeheal/CLUSTER_LOCK.md, .ai/handoff.md
- **Open issues:** F5-F7 live scenarios, F8 complete interactive controls, F10 canary rollback, F11 clean run/screenshot, P11 E1/E2, U6 two runs, full rehearsal, and final prep remain incomplete.
- **Next step:** Run U6 twice through `up.ps1 -Stage all -SkipImages` with a reversible workload reset and verify test mode, readiness, and persistent PVCs after each pass. Never push or delete data.
