# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** F10 completed on two PVC-free run-owned Deployments. The Executor restored dev CPU drift and kept the patch after three p99/throttling windows. A scripted high-load prod change raised real Prometheus p99 from 495.21 ms to 4,407.69 ms and rolled back in window 1; exact pre-patch resources were read back. The dead-man ended the window and mode is test. Cluster setup and shutdown both require an explicit target name. P11 now waits for Deployment and Service endpoints, then has a visible five-second settling delay and five fail-fast setup requests; warm-up requests remain in aggregate metrics. The prior P11 and F11 attempts each failed on their first TCP connection to the Service, despite both inference endpoints being Ready for hours.
- **Files touched:** `docs/kubeheal/demo-evidence/F10/`, `demo/scripts/deadman_test_mode.ps1`, `demo/k3d/down.ps1`, `eval/p11_run.py`, `tests/test_demo_k3d_target.py`, `tests/test_p11_run.py`, `.ai/handoff.md`.
- **Open issues:** F8 screenshots remain blocked by unavailable browser access; P11/F11 clean load, original-cluster rehearsal, final suites and push prep remain. NetworkPolicy propagation and the new k6 pod path remain suspected but unproven.
- **Next step:** Add the settling interval to F11's generated k6 setup, rerun P11 E1 and F11, then continue the requested evidence and rehearsal.
