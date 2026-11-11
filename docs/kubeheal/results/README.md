# P11 evaluation results

No P11 evaluation run has been performed yet. Values below are **not measured**. The harnesses are
designed to collect evidence on an explicitly selected cluster; unit tests use fake command runners
and do not contact Kubernetes.

## Planned runs

| Run | Method | Result |
|---|---|---|
| Load and scaling | k6 0.54.0 Job, 10 to 200 virtual users, compare p50/p95 with model replica counts | not measured |
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

The current P11 harness builders live in `eval/p11_harness.py`. Its cluster-facing functions require
an explicit context and accept an injectable runner. Tests use a fake runner. The cluster runs and
result CSVs remain pending the orchestrator's P10 acceptance and owner approval.
