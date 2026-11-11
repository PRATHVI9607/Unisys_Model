# KubeHeal k3d demo

## Current state

The `kubeheal` k3d cluster was exercised on 2026-11-11. It is left running with the global kill switch in `test` mode. The prod victim Deployment is restored to CPU request `100m` and limit `500m`.

The victim app image and Health Agent image were manually built and rolled out with the `metric-probes` tag. The generated image-tag files are not updated, so a later chart reinstall can replace these images. The prod PVC contains the seeded files and one harmless `.kubeheal-metric-probe` file written during verification.

The verifier `scripts/verify_health_queries.py` now targets the victim Service port `8000` and generates a 5xx response, bounded CPU work, and a synced data-volume write. A 120-second live run returned all 15 Health Agent metric queries. This is evidence of series availability under generated traffic, not a performance claim.

## Observed drift behavior

On 2026-11-11, the prod victim was temporarily changed to CPU requests `50m` and limits `50m`, then restored to `100m` / `500m`. The Health Agent event had all metric channels present and `health_ci_width=0.2607`. Fusion recorded `human_patch` with `dry_run=true` because the CI width exceeded the `0.15` automatic-action limit. Global mode remained `test`; no remediation write occurred and no policy threshold was changed.

The earlier `health_ci_width=1.0` was the Health Agent's missing-input sentinel. The old verifier used the wrong victim Service port, so `http_error_rate` had no series. The kubelet also exposed no `container_fs_*` series; the demo disk input now comes from the victim app's fsync-backed byte counter.

## Verified snapshot behavior

A snapshot of `prod/victim-data` was restored to a temporary PVC on 2026-11-11. A check pod read all 20 seeded record files. The temporary pod, PVC, and snapshot were removed. The original PVC and rolling snapshots remain. This verifies CSI snapshot/restore on this cluster, but not the full ransomware recovery flow.

## Still pending

- `scripts/demo.ps1` does not exist yet. P10-U4 needs a driver with status, drift, and reset steps, then the remaining safe scenarios.
- Falco is not running here. The Security Agent's `FALCO_MODE=auto` resolves to `off` and falls back to `/proc` write tracking. Replay is not configured.
- HPA custom-metric discovery is active at idle (`0/4` observed earlier); scale-out under k6 load has not been tested.
- The fail-closed model outage scenario and complete P10 acceptance twice in a row remain pending.
- Health Model live scores have not been validated against real training-distribution windows. P12-H retraining is not approved. The latest conformal CI still blocks automatic patching; do not change the gate for the demo.

See [PROGRESS](../docs/kubeheal/PROGRESS.md) for detailed measured query samples and [NEXT_FOR_CODEX](../docs/kubeheal/NEXT_FOR_CODEX.md) for the ordered continuation tasks.
