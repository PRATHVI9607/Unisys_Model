# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training; `PROJECT_SPEC.md` unchanged.
- **Goal:** Complete KubeHeal live demo readiness and prepare a reviewable push plan.
- **Official branches:** `work` at `62426c0`, `demo` at `9986b73`. Candidate `wave/codex-demo-candidate` is a staging branch only.
- **Candidate integrations:** current work + HPA + reviewed D5/F4 and P11/NetworkPolicy are now integrated for combined verification. Separate full suites passed: D5/F4 2101 passed, 12 skipped; P11/NetworkPolicy 2101 passed, 11 skipped; HPA candidate suite 2073 passed, 11 skipped. Combined candidate full suite remains pending.
- **F11 measured:** `k3d-kubeheal`, mode `test`, machine `LAPTOP-74N9LTFA`; 32 VUs/90 s, 121,088/121,088 checks, median 22.86 ms, p95 38.45 ms, HPA 2 -> 7 -> 2, elapsed 7m14s. Evidence summary: `docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md`; transcript/screenshots remain to capture.
- **P11 E1 attempt:** 297 requests, 0/297 checks passed, 297/297 failed due default-deny ingress excluding the k6 Job. HPA stayed 2/2; temporary Job and ConfigMap were deleted. p50/p95 are `not measured`. Artifacts: `docs/kubeheal/results/p11/`. A scoped k6-to-inference TCP policy is integrated but not deployed. E2 remains paused.
- **F2/F4 code:** dedicated upgrade-stable HMAC Secret, signed requests/results, replay dry-run enforcement, non-target Falco auto fallback, and bounded replay cleanup are integrated and unit-tested; no cluster deployment or replay yet.
- **Remaining:** run combined candidate suite; deploy only this candidate chart; rerun P11 E1 and E2; live-verify F2-F10, run U6 twice, rehearse, capture evidence/screenshots, update README/AGENTS/PUSH_PLAN, run final work/demo suites and secret scan, commit. Runbook currently marks flows without safe triggers `NOT VERIFIED`.
- **Safety:** only context `k3d-kubeheal`; mode stays `test` except bounded scripted windows with start/end in PROGRESS. Do not run `down.ps1`, push, set `ALLOW_PUSH`, train, or change `PROJECT_SPEC.md`.
- **Next:** full candidate suite, review, then chart preflight and the bounded P11 retry. Preserve cluster volumes; fresh-cluster baseline remains not measured.
