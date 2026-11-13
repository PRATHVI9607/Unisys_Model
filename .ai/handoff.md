# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** Hardened `demo/k3d/up.ps1`: it now requires an explicit `TargetCluster`, refuses missing/blank targets before loading shared helpers, and routes cluster start/create, kube context, and storage-node labeling through that exact target. Added static routing and no-argument PowerShell regression tests. Targeted checks passed: 2 tests and PowerShell parser.
- **Files touched:** `demo/k3d/up.ps1`, `tests/test_demo_k3d_target.py`, `.ai/handoff.md`.
- **Open issues:** User has authorized original `k3d-kubeheal` live checks but prohibited deletion of it and its PVCs. Need acquire lock before live writes; mode remains test except scripted enforce windows with dead-man switches. F5-F8, F10 canary/rollback, clean F11/P11, original-cluster rehearsal, full suites, and push prep remain. Never push.
- **Next step:** Commit this safety task, then run the complete suites on work and demo before live work.
