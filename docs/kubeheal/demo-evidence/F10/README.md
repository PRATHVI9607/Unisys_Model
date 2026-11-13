# F10 scripted live canary evidence

Accepted run on `k3d-kubeheal`, 2026-11-13, run ID `30de436bd53a4ceebb89b2586414bb18`. Both scratch Deployments
were PVC-free and used the demo victim image. The runs were explicitly scripted and went through the Executor
request stream. Prometheus supplied the real p99 and CPU-throttle samples.

## Canary heal

Dev scratch drifted from CPU request/limit 100m/500m to 10m/50m. The Executor patched back to the golden values,
then kept the patch after three canary windows:

| Reading | p99 latency | CPU throttling |
|---|---:|---:|
| Before patch | 778.23 ms | 100.00% |
| Window 1 | 496.11 ms | 84.20% |
| Window 2 | 497.69 ms | 85.17% |
| Window 3 | 496.09 ms | 96.73% |

Executor result: `patched_kept`.

## Bad-p99 rollback

Prod scratch started at request/limit 100m/500m, while its scripted golden baseline was 50m/200m. After the
Executor applied that scripted change, the run reconnected the load generator to the replacement pod and added
24 bounded `/cpu` workers. The first canary window measured p99 4,407.69 ms against 495.21 ms before the patch.
The Executor rolled back in window 1 and read back the exact prior 100m/500m CPU resources.

| Reading | p99 latency | CPU throttling |
|---|---:|---:|
| Before patch | 495.21 ms | 97.97% |
| Window 1 | 4,407.69 ms | 49.93% |

Executor result: `rolled_back:window 1: http_p99_latency_ms worse: 4407.688293090404 > 495.2149812739342`.

The dead-man recorded start/end; the run restored and read back global mode `test`. Captured output is
[F10_scripted_run_30de436bd53a4ceebb89b2586414bb18.txt](F10_scripted_run_30de436bd53a4ceebb89b2586414bb18.txt).
The MinIO ledger samples are in [F10_canary_ledger_metrics.json](F10_canary_ledger_metrics.json), and the
dead-man/load logs are retained alongside this README. Earlier incomplete attempts remain captured with their
specific setup causes and are not used as acceptance evidence.
