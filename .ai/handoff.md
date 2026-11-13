# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Continue KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** Completed two offline-chart U6 setup and drift-scenario runs on isolated `kubeheal-rehearsal`. Both produced a dry-run Fusion action in test mode and restored victim CPU settings. Recorded install, scenario, Redis action-stream, and state evidence. Core Redis stream-group retry and URL-log sanitization fix is on work (`c714fe3`) and merged into demo (`85f8660`).
- **Files touched:** `docs/kubeheal/demo-evidence/F12/U6_offline_rehearsal*.txt`, `docs/kubeheal/demo-evidence/F12/U6_offline_rehearsal.md`
- **Open issues:** Delete only the authorized rehearsal cluster after recording evidence. Original cluster remains untouched. F5-F8 walkthroughs, F10 enforce canary/rollback, clean F11/P11 runs, original-cluster runbook rehearsal, and final push prep remain outstanding. The accidental earlier start command briefly restarted the existing original cluster; it did not change pods, PVCs, releases, or data. Original mode remains test.
- **Next step:** Commit U6 evidence, remove only `kubeheal-rehearsal`, then continue the remaining requested acceptance work without modifying the original cluster until asking the owner.
