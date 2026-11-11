# KubeHeal k3d demo

## Current state

The `kubeheal` k3d cluster was exercised on 2026-11-11. It is left running with the global kill switch in `test` mode. The prod victim Deployment is restored to CPU request `100m` and limit `500m`.

The victim app and Health Agent were built through `demo/k3d/images.ps1` with the standard generated tag `b20261111113631` and rolled out with that tag. The per-image tag record and generated Helm values live in ignored files under `demo/k3d/`; they are local machine state. The prod PVC contains the seeded files and one harmless `.kubeheal-metric-probe` file written during verification.

The verifier `demo/scripts/verify_health_queries.py` now targets the victim Service port `8000` and generates a 5xx response, bounded CPU work, and a synced data-volume write. A 120-second live run returned all 15 Health Agent metric queries. This is evidence of series availability under generated traffic, not a performance claim.

## Observed drift behavior

The status/drift/reset driver is `scripts/demo.ps1`. On 2026-11-11, it primed the metric window, changed both prod CPU request and limit to `50m`, then restored `100m` / `500m` in `finally`. The latest event had `metrics_missing=[]` and `health_ci_width=0.1192`; Fusion queued `auto_patch` with `dry_run=true` because global mode was `test`. Executor escalated because the model's top attribution was `template.spec.initContainers[0].securityContext`, not a drifted field. No remediation write occurred and no CI threshold was changed. An earlier fully populated drift window had width `0.2607` and produced `human_patch`.

The earlier `health_ci_width=1.0` was the Health Agent's missing-input sentinel for `http_error_rate`: the verifier used Service port 80 instead of 8000. The kubelet exposed no `container_fs_*` series, so `disk_io_bytes` now comes from the victim app's fsync-backed byte counter. The corrected verifier returned all 15 query series.

## Verified snapshot behavior

A snapshot of `prod/victim-data` was restored to a temporary PVC on 2026-11-11. A check pod read all 20 seeded record files. The temporary pod, PVC, and snapshot were removed. The original PVC and rolling snapshots remain. This verifies CSI snapshot/restore on this cluster, but not the full ransomware recovery flow.

## Still pending

- The Security Agent's `FALCO_MODE=auto` resolves to `off`; live Falco is not running. A hand-written replay trace was temporarily mounted, all 21 events were consumed, and the model-client latency counter advanced. No security event was published; replay config and ConfigMap were removed afterwards.
- D-6 fail-closed was verified on dev: a brief Health Model outage during paired 50m drift produced a Fusion HUMAN escalation. Health Model replicas and victim resources were restored; global mode remained `test`.
- HPA custom-metric discovery is active. In one corrected `demo/scripts/hpa_load.ps1` run on 2026-11-11, a pinned k6 Job used 32 VUs for 90 seconds. It sent 4,999 score requests; 4,993 returned 200 (99.87% checks), six requests failed during startup/recovery, and observed p95 request duration was 889.03 ms. The HPA metric rose from 0 to 16 and replicas scaled from 2 to 4 to 8; after load the metric returned to 0 and the HPA reconciled to 2. The temporary Job, ConfigMap, and narrow ingress policy were removed. This is one test run, not a performance guarantee. The k6 script posts empty specs, so it is a synthetic load for the scaling signal, not a representative scoring workload. Source excerpts: `docs/kubeheal/results/p10-k3d-2026-11-11.md`.
- Complete P10 acceptance twice in a row remains pending.
- Health Model live scores have not been validated against real training-distribution windows. P12-H retraining is not approved. The CI gate remains 0.15 and must not be changed; the latest drift passed its width check but Executor escalated because the model's top field did not match the drifted field.

See [PROGRESS](../docs/kubeheal/PROGRESS.md) for detailed measured query samples and [NEXT_FOR_CODEX](../docs/kubeheal/NEXT_FOR_CODEX.md) for the ordered continuation tasks.

The demo scripts under `demo/scripts/` and `demo/k3d/` require PowerShell 7 (`pwsh`). They were reviewed and fixed on 2026-11-11 but not re-run end to end afterwards.
