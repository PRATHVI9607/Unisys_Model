# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** U6 passed twice on isolated `kubeheal-rehearsal` using vendored Helm charts and local cached images. Both scripted drift scenarios recorded Fusion dry-runs in mode `test` and restored CPU settings. The rehearsal cluster was then deleted as authorized. Evidence and updated status are committed in `7407033`.
- **Files touched:** U6 raw evidence and summary under `docs/kubeheal/demo-evidence/F12/`; `docs/kubeheal/NEXT_FOR_CODEX.md`, `docs/kubeheal/PROGRESS.md`, `docs/kubeheal/DEMO_RUNBOOK.md`.
- **Open issues:** Owner authorization is pending before any further access to original `k3d-kubeheal`; its cluster and PVCs remain in place. F5-F8, F10 enforce canary/rollback, clean F11/P11 runs, original-cluster runbook rehearsal, and push prep remain. Earlier accidental command briefly restarted the original cluster, but changed no pods, releases, PVCs, or data; its mode remained test.
- **Next step:** Continue code and evidence preparation that does not access the original cluster while awaiting authorization. Never push.
