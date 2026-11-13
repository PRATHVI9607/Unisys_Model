# KubeHeal final handoff, 2026-11-13

## Completed in this acceptance pass

- `work` was fully tested and merged into `demo`. Current suites: work 2,169 passed, 11 skipped in 82.92s; demo 2,178 passed, 11 skipped in 89.30s.
- The D-5 runner now excludes scripted F10 scratch pods that share the victim image label. Focused suite: 9 passed. Runbook replay was retried successfully after two safe precondition failures; output is under `demo-evidence/REHEARSAL/`.
- The original `k3d-kubeheal` remained online with mode `test`, Helm revision 17, demo images `b20261113071011`, inference `/readyz` 200, and all three nodes/workloads Ready. Redis, MinIO, and prod victim PVCs remain Bound and were not deleted.
- F2-F13 current LIVE/FALLBACK classifications and rehearsal evidence are in `DEMO_RUNBOOK.md` and `demo-evidence/REHEARSAL/rehearsal-2026-11-13.md`.
- U6 passed twice on the separate fresh `kubeheal-rehearsal` cluster with vendored charts and locally cached images. That second cluster was deleted after the runs; the original demo cluster was preserved.
- P11 E1 passed 112,327/112,327 checks, zero refusals, p50 24.34 ms, p95 38.19 ms; E2 recovery was 1.25 seconds. E3-E6 and V5-E1 remain not measured with reasons in `results/p11/P11_COVERAGE.md`.
- F11 passed 113,873/113,873 checks with zero refusals, p50 24.03 ms, p95 37.9 ms; HPA 2 -> 8 -> 2. Warm-ups are disclosed and excluded. Grafana screenshot is saved.

## Honest remaining limits

- F3's Sense event is scripted; no live Falco detection or real-node behavior is claimed.
- F8 SnapshotFreeze release is not measured because there is no held target. F9's same-input paired test/enforce action comparison is not measured.
- F1 uses the default full-suite safety checks; live integrations remain opt-in.
- F13 E3-E6 and V5-E1 remain not measured for documented scenario/safety reasons.

## Owner push review

See `PUSH_PLAN.md` for feature status, full-suite counts, diff summary, and secret scan result. Nothing has been pushed, and `ALLOW_PUSH` remains unset. Review the final diff and decide whether to push from the owner's environment. Do not perform cluster teardown as part of push preparation; the original cluster and PVCs are preserved.
