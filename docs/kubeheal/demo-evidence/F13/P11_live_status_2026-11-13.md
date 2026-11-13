# F13 P11 live status

**Date:** 2026-11-13  
**Cluster:** `k3d-kubeheal`  
**Mode:** `test`

## E1 load and refused-request diagnosis

The third recorded P11 E1 attempt ran 32 VUs for 90 seconds. It made 66,819 requests: 66,807 checks passed and 12 failed. All 12 were connection refusals on the first timestamp to the inference Service VIP `10.43.219.57:8000`; no HTTP status was received. The run took 108.344 seconds, sampled HPA 21 times, and observed replicas 2 -> 7. The P11 runner cleaned its uniquely named Job and ConfigMap. The recorded p50 40.01 ms and p95 71.16 ms are observations from a failed run; its latency status is `not measured`, and it is not an accepted benchmark.

The two 2026-11-12 E1 attempts also had first-second connection refusals; the 2026-11-13 F11 demo load reproduced 12 refusals in the first timestamp in both its dashboard-HPA script and this P11 script. In the latest P11 run, the failures preceded HPA scale-up. The inference Service later had Ready endpoints, and the load returned the HPA to 2/2 after the metric cleared. The evidence is consistent with a short Service/data-plane startup or routing race, but does not prove whether kube-proxy, CNI policy programming, or another component issued the refusal. No request result was discarded and no retry or warm-up was added to make the run appear clean.

Raw E1 artifacts are in [`results/p11`](../../results/p11/): `p11-load-32-20261113082055-f11248bf6e7345b88fdecc2686d1cdc7.{csv,json,log}` and its `-hpa.json`. The coverage index records all three failed E1 attempts.

## E2 inference recovery

The supported delete-one-pod scenario deleted one inference pod by captured UID while the HPA was at 2/2 and mode was `test`. The replacement returned the deployment to 2 Ready replicas in 1.25 seconds (one readiness sample). The row is marked measured in the E2 CSV/JSON sidecar in [`results/p11`](../../results/p11/).

## Other P11/V5-E1 items

| Item | Status | Reason |
|---|---|---|
| E1 accepted load | Not measured | Three attempts failed on 12 first-timestamp connection refusals; latest failed-run observations are retained above. |
| E2 inference pod recovery | Measured | One delete/recreate run; 1.25 seconds to 2/2 Ready. |
| E3 RPO/RTO | Not measured | No disposable database-volume scenario is configured; existing MinIO/Redis PVC data must not be overwritten or deleted. |
| E4 stage timing | Not measured | The live event path does not expose per-stage timestamps. |
| E5 baselines | Not measured | No controlled drivers exist for the five comparisons; live Falco rules-only and fixed-entropy runs are not available. |
| E6 FP32/FP16 latency and memory | Not measured | No paired FP32/FP16 deployment variants are available for a controlled comparison. |
| V5-E1 | Not measured | The V5-E1 acceptance matrix and supporting telemetry were not run. The separately recorded F3 containment pass is not a V5-E1 run. |

All current status/reasons are summarized in [`P11_COVERAGE.md`](../../results/p11/P11_COVERAGE.md). The failed E1 latency observations are not presented as accepted benchmark figures.
