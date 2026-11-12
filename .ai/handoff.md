# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training.
- **Goal:** Complete KubeHeal k3d demo readiness and prepare a reviewable push plan.
- **Branches:** Official `work` is `62426c0` with reviewed F1/F3 changes. Official `demo` remains `9986b73`. Candidate `wave/codex-demo-candidate` combines work, runbook, and HPA changes for pre-rehearsal validation only.
- **What changed and why:** F1 live tests are opt-in. HMAC signs/verifies freeze requests, Security Agent results, and operator thaw. Its key is being moved to a dedicated Secret on the F2/F4 branch. HPA load resources use per-run UUIDs, exact cleanup, and a kubectl-compatible labeled ConfigMap.
- **Checks:** Candidate full suite: 2073 passed, 11 skipped in 57.30 s. F11 HPA live run passed: 32 VUs/90 s, 121,088/121,088 checks, p50 22.86 ms, p95 38.45 ms, HPA 2 -> 7 -> 2, cleanup succeeded. Evidence summary is in `docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md`; full transcript/screenshots remain for rehearsal.
- **Open issues:** D-5 replay and stream-driven containment are not live-verified; F9/F10, U6 twice, P11, runbook rehearsal, screenshot evidence, final full suites and push prep remain. P11 E1/E2 run is authorized and held to the agent’s exclusive cluster window.
- **Next step:** Finish bounded P11, then coordinate replay/containment/drift windows and U6. Keep mode test except scripted enforce windows with start/end recorded. Do not run `down.ps1`, push, train, or change PROJECT_SPEC.

