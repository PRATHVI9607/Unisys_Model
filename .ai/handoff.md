# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training.
- **Goal:** Finish KubeHeal k3d demo readiness and prepare a reviewable push plan.
- **Official branches:** `work` includes reviewed F1/F3 code at `62426c0`. Official `demo` remains `9986b73`; a pre-rehearsal candidate branch combines work with demo runbook/HPA changes for integration testing.
- **What changed and why:** F1 live tests are opt-in and default suite runs offline. HMAC signs/verifies containment freeze requests, Security Agent results, and operator thaw. Key uses the Redis password Secret, so Redis credential holders can also sign.
- **Checks:** Combined full suite before official work merge: 2064 passed, 12 skipped, 61.93 s. F1 focused: 34 passed, 2 skipped; containment focused: 299 passed, 3 skipped. Cluster is healthy, mode test, `dev/freeze-scratch` absent. The failed HPA attempt cleaned all its temporary resources.
- **Open issues:** HPA fix `ce5a183` and runbook `840a9be` are in the candidate branch, not official demo; independent review/focused checks passed, live rerun pending. D-5 replay, stream-driven containment, F9/F10, U6 twice, P11, runbook rehearsal, final suites and evidence remain.
- **Next step:** Complete safe P11/U6 evidence, coordinate the scripted replay/containment/drift windows, rehearse, then merge work into demo and run final suites. Do not use `down.ps1`; it destroys PVCs and MinIO/Redis data. Never push or change PROJECT_SPEC.

