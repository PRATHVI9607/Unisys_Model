# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training.
- **Goal:** Complete KubeHeal k3d demo readiness and prepare a reviewable push plan.
- **Branches:** Official `work` is `62426c0` with reviewed F1/F3 changes. Official `demo` remains `9986b73`. Candidate `wave/codex-demo-candidate` combines work, runbook, and HPA changes for pre-rehearsal validation only.
- **What changed and why:** F1 live tests are opt-in. HMAC signs/verifies freeze requests, Security Agent results, and operator thaw. Its key currently reuses the Redis password Secret. HPA load resources now use per-run UUIDs, exact cleanup, and a kubectl-compatible labeled ConfigMap.
- **Checks:** Candidate full suite before the latest HPA compatibility fix: 2073 passed, 11 skipped in 60.34 s. HPA focused tests: 4 passed; PowerShell parser and diff checks passed. Earlier live HPA attempts failed before action/resources; cleanup left no temporary resources and mode remained test.
- **Open issues:** HPA live rerun, D-5 replay, stream-driven containment, F9/F10, U6 twice, P11, runbook rehearsal, screenshots/evidence, final full suites and push prep remain. P11 live execution is held pending review fixes.
- **Next step:** Run full candidate suite after the latest HPA fix, rerun HPA, then finish P11/U6 safely and coordinate replay/containment/drift windows. Do not run `down.ps1`, push, train, or change PROJECT_SPEC.

