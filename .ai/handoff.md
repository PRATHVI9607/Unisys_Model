# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Finish authorized KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **What changed and why:** P11 E1 is clean at 32 VUs for 90 seconds: 112,327/112,327 checks, 0 refusals, p50 24.34 ms, p95 38.19 ms. F11 is clean at 113,873/113,873 checks, 0 refusals, p50 24.03 ms, p95 37.9 ms, HPA 2 -> 8 -> 2; its fixed Grafana dashboard screenshot is saved. F8 browser walkthrough exercised kill switch, incident approve/reject, and baseline approve/reject. Dashboard approval in test mode was dry-run and left baseline unchanged. The dead-man observed the F8 UI toggle return mode to test. SnapshotFreeze release had no held target and is documented as not measured. P11 E3-E6 and V5-E1 reasons are concrete; original PVC data remains untouched.
- **Files touched:** F8/F11/F13 evidence and screenshots, P11 results and coverage, `eval/p11_run.py`, Grafana dashboard, and tests.
- **Open issues:** Runbook rehearsal, merge all reviewed work into demo, final suites, README/AGENTS updates, secret scan, PUSH_PLAN, lock release and final handoff remain. F8 SnapshotFreeze release has no live target.
- **Next step:** Commit F8/F11/P11 evidence, then rehearse `DEMO_RUNBOOK.md` on the existing cluster and complete push preparation without pushing.
