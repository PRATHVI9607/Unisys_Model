# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training; `PROJECT_SPEC.md` unchanged.
- **Goal:** Complete the KubeHeal live demo, integrate only reviewed green work, and prepare push instructions.
- **Official branches:** `work` at `62426c0`; `demo` at `9986b73`. Candidate `wave/codex-demo-candidate` is a staging branch for integration and rehearsal, not the official demo merge.
- **Integrated on candidate so far:** reviewed D5/F4 hardening from `b516a0d` is being merged; F11 HPA fix and measured run are present. P11+NetworkPolicy (`4c07d8c`) is green separately at 2101 passed, 11 skipped. D5/F4 full suite is green separately at 2101 passed, 12 skipped. Candidate full suite must run after all integrations.
- **Measured evidence:** F11 HPA run on `k3d-kubeheal`, mode `test`: 32 VUs/90 s, 121,088/121,088 checks, median 22.86 ms, p95 38.45 ms, HPA 2 -> 7 -> 2, elapsed 7m14s. Summary: `docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md`; screenshots/transcript still needed.
- **P11 E1:** first bounded run attempted 297 requests, all failed because default-deny NetworkPolicy excluded the k6 Job. HPA stayed 2/2; Job and ConfigMap were deleted. Checks: 0/297; p50/p95 not measured. Evidence is under `docs/kubeheal/results/p11/`. A narrow same-namespace k6-to-inference TCP port rule is now implemented and tested but not deployed. E2 is paused.
- **Remaining:** combine current work + P11/NetworkPolicy + D5/F4 + HPA in candidate, run full suite, deploy only from that candidate, then retry P11 and run F2 replay. F3/F5-F10 live proof, U6 twice, runbook rehearsal, screenshots, final work/demo suites, README/AGENTS/PUSH_PLAN updates, secret scan, and final commits remain.
- **Safety:** cluster context is only `k3d-kubeheal`; mode stays `test` except bounded scripted windows, with start/end times recorded. Do not run `down.ps1`, push, set `ALLOW_PUSH`, train, or touch `PROJECT_SPEC.md`.
- **Next:** complete candidate merges and full-suite review before any cluster upgrade or P11 retry. Rehearse with volumes preserved; a fresh-cluster baseline is not measured.
