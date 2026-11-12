# Handoff

- **Agent:** Codex; **Date:** 2026-11-12. Nothing pushed; no model training; `PROJECT_SPEC.md` unchanged.
- **Goal:** Complete live KubeHeal demo on k3d, merge only green changes into official `work`/`demo`, and prepare push plan.
- **Branches:** `work` `62426c0`; `demo` `9986b73`; staging candidate includes combined work/HPA/D5/F4/P11/runbook. Candidate full suite after the D-5 cleanup fix: 2109 passed, 11 skipped, 258 warnings, 58.64s.
- **Cluster:** Only `k3d-kubeheal`; Helm revision 9 deployed at 18:29 IST. Fusion/Security tags `b20261112182628`; all pods Ready; mode `test`; HPA baseline 2/2; HMAC Secret and scoped P11 policy present; MinIO/Redis PVCs Bound.
- **F2:** D-5 hand-written replay ran at 13:18 UTC. Security event was model-scored `ransomware`, single-label, risk 0.9500; Fusion emitted `auto_contain`, `dry_run=true`, `queued_for_executor`. The Executor refused because replay target's deployment field equaled the pod name. F2 verified through Fusion only; F3 is not verified. Runner cleanup defect fixed and full suite green. Manual recovery restored `FALCO_MODE=auto`, removed run-owned ConfigMap, mode stayed test.
- **P11 E1:** 111,576 requests, 111,564 passed, 12 refused at one timestamp during scale-up; observed median 24.02ms/p95 40.33ms, but run failed and E1 is not accepted. HPA recovered 8 -> 2/2. E2 not run. Details on `wave/p11-safe-runner` `a2ba42a`; no rerun yet.
- **F11:** measured HPA run: 32 VUs/90s, 121088/121088 checks, median 22.86ms, p95 38.45ms, replicas 2 -> 7 -> 2, 7m14s. Evidence summary exists; screenshots/transcript missing.
- **Remaining:** P11 clean retry and E2 if green; F3-F10 live acceptance; F8 isolated UI fix `wave/Codex-F8-freeze-ui` `656ed87`; thaw HMAC docs fix `wave/Codex-ThawHmac-docs` `f730a7a`; U6 twice; runbook fresh-start rehearsal/screenshots; README/AGENTS/PUSH_PLAN, full-diff secret scan, final work/demo suites and merges.
- **Safety:** mode stays `test` except logged scripted windows; do not run `down.ps1` (deletes PVC data), push, set `ALLOW_PUSH`, train, or change `PROJECT_SPEC.md`.
- **Next:** commit the tested runner fix and this progress/handoff; have Agent 3 record replay evidence; review isolated docs/UI branches, then continue live acceptance.
