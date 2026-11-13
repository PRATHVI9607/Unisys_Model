# F13 P11 live status

**Date:** 2026-11-13
**Cluster:** `k3d-kubeheal`
**Mode:** `test`

## E1 load and first-request refusal diagnosis

The newest P11 E1 run used 32 VUs for 90 seconds. Its readiness gate observed both inference Deployment replicas ready and two Service endpoints. k6 then waited five seconds before starting a five-request warm-up. All five warm-up calls returned 200. The measured run passed 112,327/112,327 checks with zero failed requests; median latency was 24.34 ms and p95 was 38.19 ms. HPA was 2 replicas before load and 8 when the load Job completed. P11 records the accepted E1 result as measured. Raw k6 output, the CSV/JSON sidecar and HPA samples are in [`results/p11`](../../results/p11/).

The earlier failed runs received 12 TCP `connection refused` responses on their first timestamp at Service IP `10.43.219.57:8000`; no HTTP response was received. In the investigated run, both inference pods had Ready conditions and EndpointSlice entries hours before k6 started. The F11 runner created its run-specific NetworkPolicy about 0.55 seconds before its k6 Job. Follow-up requests from the Health Agent and an inference pod to the Service returned 200. P11 and F11 both passed after adding a five-second policy settling wait for F11 and a five-second in-pod network settling delay before five visible warm-up requests. The evidence supports a transient startup race on the new k6 pod's Service path. It does not prove whether kube-proxy, CNI policy programming, or another component issued the refusal. Failed run artifacts remain recorded and no requests were retried or discarded.

## E2 to E6 and V5-E1

| Item | Status | Evidence or reason |
|---|---|---|
| E1 accepted load | Measured | 32 VUs, 90 seconds, 112,327/112,327 checks, 0 failed requests, p50 24.34 ms, p95 38.19 ms. |
| E2 inference pod recovery | Measured | One inference pod delete/recreate run returned to Ready in 1.25 seconds; see existing CSV/JSON sidecar. |
| E3 RPO/RTO | Not measured | No disposable database-volume scenario exists. Current PVCs belong to the prod victim, MinIO ledger, and Redis. The owner instructed that PVC data remain untouched. |
| E4 stage timing | Not measured | The event pipeline does not expose timestamps at each action stage; aggregate incident timestamps cannot provide valid per-stage duration. |
| E5 baseline comparisons | Not measured | There are no controlled drivers for the five comparison baselines. Falco rules-only and fixed-entropy runs are unavailable; diff-only, single-replica, and pod-delete-only comparisons have no paired controlled scenarios. |
| E6 FP32/FP16 latency and memory | Not measured | The deployed LightGBM service has no paired FP32 and FP16 deployment variants, so a controlled comparison cannot be made. |
| V5-E1 scripted scenario matrix | Not measured | The V5-E1 runner is not ported to the context-pinned P11 harness. Its legacy evaluation driver is documented as Minikube-specific and may restart Redis, Falco, and Health Agent and create or delete `khe-*` namespaces. This cluster has no disposable scenario PVC; existing prod victim, MinIO, and Redis PVCs remain protected. The separate F3 scripted containment run is narrower and is not a V5-E1 matrix run. |

P11 coverage summary is in [`P11_COVERAGE.md`](../../results/p11/P11_COVERAGE.md). The clean F11 HPA result and Grafana screenshot are indexed in [F11 evidence](../F11/README.md).
