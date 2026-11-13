# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** Hardened `demo/k3d/up.ps1` to require an explicit cluster name and added regression coverage (`ed5a17e`). Full suites passed: work 2,169 passed/11 skipped; demo 2,173 passed/11 skipped. Acquired the `k3d-kubeheal` lock (`c366117`); original cluster is healthy, mode `test`, all pods Ready, Helm rev 17, inference `/readyz` 200 with both bundles loaded.
- **Files touched:** `demo/k3d/up.ps1`, `tests/test_demo_k3d_target.py`, `docs/kubeheal/CLUSTER_LOCK.md`.
- **Open issues:** F6/F5/F7/F10/F8/F11/P11 and rehearsal/push prep remain. No original PVC or cluster deletion is allowed. Any enforce window must have a dead-man switch and return mode to test.
- **Next step:** Implement and run F6 with unique signed invalid requests and prove refusal before writes; keep script-owned inputs and outcomes under `docs/kubeheal/demo-evidence/F6/`.
