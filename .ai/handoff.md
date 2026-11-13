# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** Full suites passed (work 2,169 passed/11 skipped; demo 2,173 passed/11 skipped). Original cluster lock is committed. F6 passed on k3d: four HMAC-signed invalid Security Agent requests were refused with valid result HMACs and `frozen=0`; run-owned Redis records were cleaned and the exact prior namespace label restored. Added an independent dead-man helper pinned to `k3d-kubeheal` that can only return mode to test.
- **Files touched:** `docs/kubeheal/demo-evidence/F6/`, `demo/scripts/deadman_test_mode.ps1`, `tests/test_demo_f6_invalid_requests.py`, `tests/test_demo_k3d_target.py`, `docs/kubeheal/CLUSTER_LOCK.md`.
- **Open issues:** F5, F7, F8, F10 canary/rollback, F11/P11 clean load and measurements, original-cluster rehearsal, and push prep remain. Original cluster and PVCs must not be deleted. Mode remains test.
- **Next step:** Run F5 with scratch dev/prod Deployments, an enforce window protected by the independent dead-man, and dashboard approval evidence.
