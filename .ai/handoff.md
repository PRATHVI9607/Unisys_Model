# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training.
- **Goal:** Complete KubeHeal k3d demo readiness and prepare a reviewable push plan.
- **Branches:** Official `work` is `62426c0` with reviewed F1/F3 changes. Official `demo` remains `9986b73`. Candidate `wave/codex-demo-candidate` combines work, runbook, and reviewed HPA cleanup for pre-rehearsal validation only.
- **What changed and why:** F1 tests are opt-in and the default suite is offline. HMAC signs/verifies freeze requests, Security Agent results, and operator thaw. The key reuses the Redis password Secret, so Redis credential holders can also sign. HPA script now uses UUID-scoped objects and ownership-checked best-effort cleanup.
- **Checks:** Candidate full suite: 2073 passed, 11 skipped in 60.34 s. F1 focused 34 passed, 2 skipped; HMAC focused 299 passed, 3 skipped; HPA focused 4 passed. HPA live run still pending after an earlier failed attempt whose temporary resources were cleaned.
- **Open issues:** D-5 replay and live containment, F9/F10, HPA live rerun, U6 twice, P11 results, runbook rehearsal, screenshots/evidence, final full suites and push prep remain. P11 runner is being expanded to report E1-E7/V5-E1 and mark unmeasured items explicitly.
- **Next step:** Finish P11/U6 safely, coordinate the scripted acceptance windows with mode restored to test, then rehearse and merge work into demo. Do not run `down.ps1`, push, train, or change PROJECT_SPEC.

