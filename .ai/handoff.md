# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** F10 completed on two PVC-free run-owned Deployments. The Executor restored dev CPU drift and kept the patch after three p99/throttling windows. A scripted high-load prod change raised real Prometheus p99 from 495.21 ms to 4,407.69 ms and rolled back in window 1; exact pre-patch resources were read back. The dead-man ended the enforce window and mode is test. Cluster setup and shutdown now both require an explicit target name; shutdown no longer defaults to the original cluster.
- **Files touched:** `docs/kubeheal/demo-evidence/F10/`, `demo/scripts/deadman_test_mode.ps1`, `demo/k3d/down.ps1`, `tests/test_demo_k3d_target.py`, `.ai/handoff.md`.
- **Open issues:** F8 screenshot walkthrough remains blocked by unavailable browser access; F11/P11 clean load and results, original-cluster rehearsal, final suites and push prep remain.
- **Next step:** Run the P11 E1 and F11 load paths with readiness/warm-up, then continue the requested evidence and rehearsal.
