# KubeHeal final rehearsal, 2026-11-13

**Machine:** native Windows 11
**Primary cluster:** `k3d-kubeheal`
**Original cluster/PVCs:** preserved, not deleted
**Mode at close:** `test`
**Helm release:** revision 17, deployed
**Result:** clean evidence-led runbook rehearsal on the existing cluster. Fresh-start U6 was separately completed twice on `kubeheal-rehearsal`.

The runbook steps use individual run-owned scenarios, so this is a complete rehearsal assembled from their captured live results, not a single uninterrupted process. No production or protected PVC data was deleted. The fresh-cluster U6 check ran only on the separate disposable cluster, which was deleted after both successful runs.

| Runbook step | Status | Rehearsal result |
|---|---|---|
| Preflight | LIVE | All three nodes Ready; all workload pods Ready (the MinIO bootstrap Job is Completed); Helm revision 17; demo image tag `b20261113071011`; mode `test`; Redis, MinIO, and prod victim PVCs Bound. `preflight-2026-11-13.txt`. |
| Inference readiness | LIVE | `/readyz` returned HTTP 200 with health/security bundles loaded; HPA idle at 2 replicas. `inference-readyz-2026-11-13.txt`. |
| F1 safety | FALLBACK | Full default suites are the safety check; live integration tests remain opt-in. Exact final counts recorded in the handoff after the final runs. |
| F2 D-5 replay | LIVE | First attempt found four run-owned F10 pods sharing the image label and safely stopped before patching. The runner was fixed to exclude `kubeheal.io/scripted=F10`; retry produced a real model-scored replay Security event, Fusion `auto_contain` dry-run, and restored the DaemonSet/replay resources. Both outputs retained as `rehearsal-f2-2026-11-13*.txt`. |
| F3 containment and restore | LIVE | Existing demo-image evidence completed a scripted Sense alert through freeze, snapshot, quarantine, restore, entropy scan, and cleanup. The enforce window returned mode to `test`; no live Falco sensing claim. See F3 evidence. |
| F4 message authentication | LIVE | Rehearsal rerun accepted signed dry-run and refused unsigned/tampered messages with `invalid_hmac`; run-owned Redis records cleaned and mode remained `test`. `rehearsal-f4-2026-11-13.txt`. |
| F5 baseline promotion | LIVE | Scripted PVC-free dev config auto-promoted with a ledger entry. Scripted prod config waited as a dashboard candidate, then was approved in a bounded dead-man-protected enforce window. Mode returned to `test`. |
| F6 invalid requests | LIVE | Signed bad namespace, protected label, unknown action, and missing pod UID were all refused. Every result HMAC verified and frozen count was zero; label restored and owned Redis records removed. Security logs/results are evidence because refusals are not currently written to MinIO ledger. |
| F7 policy gates | LIVE | Scripted ambiguous M2 reached HUMAN; D1 inclusive CPU 50m and memory 32Mi edges fired; rule rollback was held without fresh Security Model response and queued with a fresh scripted response. Executor stayed dry-run. |
| F8 dashboard | LIVE / FALLBACK | Screenshots cover incident approval/rejection, baseline approval/rejection, incident details, mode toggle, ledger/status controls. Approvals in test mode were dry-run; rejected items resolved. SnapshotFreeze release is FALLBACK because no incident had a held target. |
| F9 kill switch | LIVE / FALLBACK | Authenticated dashboard changed `test -> enforce -> test`, ledger entries verified, dead-man observed return to test. Paired same-input test-mode no-write/enforce-mode applied-action proof remains not measured. |
| F10 drift | LIVE | Scripted dev canary patch was kept after three improving windows. Scripted prod canary rolled back in window 1 after p99 rose from 495.21 ms to 4,407.69 ms. Dead-man and mode readback were clean. |
| F11 HPA/Grafana | LIVE | Warmed 32 VU/90 second load passed 113,873/113,873 checks, zero refusals, p50 24.03 ms, p95 37.9 ms; HPA 2 -> 8 -> 2. Grafana screenshot saved. |
| F12 U6 | LIVE | Separate fresh cluster completed offline chart install and drift scenario twice. Both runs returned 15/15 metric series and dry-run drift decisions. Original cluster and PVCs were not used for reset. |
| F13 P11 | LIVE / FALLBACK | E1 passed 112,327/112,327, zero refusals, p50 24.34 ms, p95 38.19 ms. E2 recovery measured at 1.25 seconds. E3-E6 and V5-E1 are not measured with concrete reasons in P11 coverage. |

## Runbook correction discovered during rehearsal

The D-5 runner previously selected every `prod` pod with `app.kubernetes.io/name=victim-app`, which included F10 scripted scratch pods. It now excludes the F10 marker while keeping the original victim target. The focused runner suite passed 9 tests. The first failed attempts are preserved; no Kubernetes write occurred before the guard stopped them.

## Evidence

- `preflight-2026-11-13.txt`
- `inference-readyz-2026-11-13.txt`
- `rehearsal-f2-2026-11-13.txt` and `rehearsal-f2-2026-11-13-retry.txt`
- `rehearsal-f4-2026-11-13.txt`
- Per-feature outputs/screenshots in `../F2/` through `../F13/`

The live cluster remained in mode `test` at close. No cluster/PVC deletion, model training, push, or `PROJECT_SPEC.md` change occurred.
