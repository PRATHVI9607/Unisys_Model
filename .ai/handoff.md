# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training; `PROJECT_SPEC.md` unchanged.
- **Goal:** Finish live KubeHeal demo on k3d, merge green changes to official `work` and `demo`, and prepare push plan.
- **Branches:** `work` `62426c0`; `demo` `9986b73`; staging candidate `wave/codex-demo-candidate` `20153b0` before this progress note. Candidate full suite: 2130 passed, 11 skipped, 266 warnings, 59.57s.
- **Cluster:** Only `k3d-kubeheal`; candidate chart deployed at 18:29 IST, release revision 9. Fusion/Security images `b20261112182628`; all pods Ready; mode `test`; HPA 2 replicas; HMAC Secret and P11 NetworkPolicy present; Redis/MinIO PVCs Bound. No Secrets changed.
- **F11:** measured HPA run: 32 VUs/90s, 121088/121088 checks, median 22.86ms, p95 38.45ms, HPA 2 -> 7 -> 2, 7m14s. Evidence summary in `docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md`; screenshots/transcript still missing.
- **P11:** first E1 attempt failed 0/297 because the k6 ingress rule was absent; latency not measured. Fix is deployed. Agent 3 is rerunning E1 and may run bounded E2 only after successful load and HPA recovery.
- **F2/F4:** candidate code deployed, but live D5 replay and HMAC behavior still need evidence. F3, F5-F10 live acceptance, U6 twice, fresh-start runbook rehearsal, README/AGENTS/PUSH_PLAN, full-diff secret scan, final work/demo suites and merges remain.
- **Safety:** mode remains `test`; do not run `down.ps1` (deletes PVC data), do not push, set `ALLOW_PUSH`, train, or change `PROJECT_SPEC.md`. Record scripted enforce window start/end in `PROGRESS.md`.
- **Next:** complete P11 E1/E2, then live replay and feature acceptance; commit status/evidence; merge only reviewed green changes before 23:30 IST.
