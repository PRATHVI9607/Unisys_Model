# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** F10 completed on two PVC-free run-owned Deployments; drift healed in three real p99 windows and a bad p99 caused a ledgered rollback. Cluster up/down scripts require explicit target names. P11 has a Deployment/Service readiness wait, a five-second network settling delay and five fail-fast setup requests. The first P11 and F11 live attempts were refused on the first Service connection while inference endpoints had been Ready for hours. F11 now waits five seconds after creating its run-specific NetworkPolicy before creating its k6 pod, and its visible warm-up also waits five seconds.
- **Files touched:** F10 evidence, `demo/k3d/down.ps1`, `eval/p11_run.py`, `demo/scripts/hpa_load.ps1`, `demo/scripts/k6_health_model.js`, related tests and `.ai/handoff.md`.
- **Open issues:** P11/F11 clean reruns, F8 dashboard screenshots, original-cluster rehearsal, final full suites and push preparation remain. The precise cause of first-request TCP refusal remains unproven.
- **Next step:** Rerun P11 E1 and F11 with the settling intervals and retain full output, then continue the requested evidence and rehearsal.
