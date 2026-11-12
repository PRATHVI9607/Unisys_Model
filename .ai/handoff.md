# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training; `PROJECT_SPEC.md` unchanged.
- **Goal:** Complete the KubeHeal live demo and prepare a reviewable push plan.
- **Official branches:** `work` at `62426c0`; `demo` at `9986b73`. Candidate `wave/codex-demo-candidate` is staging only.
- **Candidate:** current work, HPA, D5/F4, P11/NetworkPolicy, and runbook are integrated. Full suite: 2130 passed, 11 skipped in 59.57 s. Candidate is not yet merged to official `work` or `demo`.
- **F11 measured:** `k3d-kubeheal`, mode `test`, machine `LAPTOP-74N9LTFA`; 32 VUs/90 s, 121,088/121,088 checks, median 22.86 ms, p95 38.45 ms, HPA 2 -> 7 -> 2, elapsed 7m14s. Summary: `docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md`; transcript/screenshots remain to capture.
- **P11 E1 attempt:** 297 requests, 0/297 checks passed, 297/297 failed because default-deny ingress excluded the k6 Job. HPA stayed 2/2; Job and ConfigMap were deleted. p50/p95 are `not measured`. Artifacts: `docs/kubeheal/results/p11/`. The scoped same-namespace k6-to-inference TCP policy is integrated but not deployed; E2 remains paused.
- **F2/F4:** dedicated upgrade-stable HMAC Secret, signed requests/results, replay dry-run enforcement, non-target Falco auto fallback, and bounded replay cleanup are integrated and unit-tested. No cluster deployment or replay yet.
- **Runbook:** updated through `wave/demo-runbook`; live flows without safe triggers are `NOT VERIFIED`, evidence/screenshots remain incomplete.
- **Remaining:** verify current image tags and chart delta; deploy candidate chart; retry P11; live-verify F2-F10; run U6 twice; rehearse and capture evidence; update README/AGENTS/PUSH_PLAN; run final work/demo suites and secret scan; commit.
- **Safety:** only context `k3d-kubeheal`; mode stays `test` except bounded scripted windows with start/end recorded. Do not run `down.ps1`, push, set `ALLOW_PUSH`, train, or change `PROJECT_SPEC.md`.
- **Next:** inspect image tags and chart delta before any cluster upgrade. Preserve cluster volumes; fresh-cluster baseline remains not measured.
