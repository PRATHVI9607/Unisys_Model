# P11 evaluation results

No P11 evaluation run has been performed yet. Values below are **not measured**. The harnesses are
designed to collect evidence on an explicitly selected cluster; unit tests use fake command runners
and do not contact Kubernetes.

## Planned runs

| Run | Method | Result |
|---|---|---|
| Load and scaling | k6 Job (image pin 0.54.0, chosen default), 10 to 200 virtual users, compare p50/p95 with model replica counts | not measured |
| Detection continuity | restart/delete-one-pod chaos cases; compare expected and observed detections | not measured |
| Fail-closed rate | remove a model server during scored incidents; count HUMAN escalations and unsafe actions | not measured |
| RPO/RTO | write sequence markers to a test database PVC, restart its pod, compare the last durable marker and recovery time | not measured |
| Stage latency | timestamp Sense, Score, Decide, Act, Record events from one incident | not measured |
| Baselines | Falco rules only, fixed entropy threshold, diff-only drift, single replica, pod-delete-only recovery | not measured |
| Precision | compare FP32 and FP16 latency and memory using the same checkpoint, input batch, and runtime | not measured |

Each generated result consists of CSV data and JSON metadata with machine, cluster, UTC date,
scenario, status, and row count. Empty result sets are stamped `not measured`. Never replace this
with a fabricated value. Keep load, namespace, model checkpoint, image digests, replica count, and
test duration with the run notes so comparisons can be reproduced.

The current P11 harness builders live in `eval/p11_harness.py`. Its cluster-facing functions only
accept the context `k3d-kubeheal` (`hybrid-demo` is explicitly rejected), restrict chaos, delete,
restart and load helpers to the namespaces prod, staging, dev and kubeheal, and accept an injectable
runner. `write_results` refuses to overwrite an existing `<scenario>.csv` or `.json` unless
`overwrite=True` is passed. Tests use a fake runner. The cluster runs and
result CSVs remain pending the orchestrator's P10 acceptance and owner approval.

## Harness defaults (chosen defaults, not measured)

These values are plain choices made for the harness. None of them came from a measurement.

| Setting | Value | Status |
|---|---|---|
| k6 image pin | `grafana/k6:0.54.0` | chosen default, not measured; the tag's existence was not verified here |
| k6 run duration | 2 minutes | chosen default, not measured |
| Job `activeDeadlineSeconds` | 900 | chosen default, not measured |
| Client wait for Job complete or failed | 960 s | chosen default, not measured |
| Job poll interval | 10 s | chosen default, not measured |
| k6 container resources | requests cpu 100m / 128Mi, limits cpu 1 / 512Mi | chosen defaults, not measured |

The k6 Job uses preferred (soft) pod anti-affinity against the model-server pods, so it does not stay
Pending on a small cluster, and the wait ends as soon as the Job is complete or failed.

The harness maps k6 virtual users to simulated monitored pods as a stand-in. A virtual user is not a
pod, so results from these runs describe request load, not a real fleet of monitored pods.
