# F9 kill-switch evidence

## Dashboard toggle, 2026-11-13

- Context: `k3d-kubeheal`; Helm revision 15; dashboard image built from `demo`, tag `b20261113071011`.
- The authenticated dashboard endpoint `/api/kill-switch` read mode `test`, accepted `test -> enforce` and `enforce -> test`, and returned mode `test`, `readable=true`, `dry_run=true` afterward. Kubernetes ConfigMap readback also returned `test`.
- Dashboard ledger entries: `mode-c9705fc1d8d34dbbb6d8fd9e805b999f` at `2026-11-13T02:00:44.921300Z` (`test -> enforce`) and `mode-35d2eee216f64c8c897656024b66ca8d` at `2026-11-13T02:00:47.872547Z` (`enforce -> test`). The mode interval was three seconds, with no incident trigger published in that interval. An independent dead-man switch was armed during the call and stopped after test-mode readback.
- Output: `dashboard-toggle-demo-2026-11-13.json`. The local admin token was read from the ignored token file and is not included in output.

## Test-mode dry run

The D-5 replay in [F2 evidence](../F2/README.md) produced a real Security Agent-scored event and Fusion `auto_contain`; the Executor recorded `DRY RUN: would have CONTAIN ...` and no workload action. The F3 test-mode rehearsals also emitted `DRY RUN: would have CONTAIN ...`. The signed F4 freeze request returned `dry_run` with `mode_seen=test` and `frozen=0`. These checks demonstrate the test-mode action path and dashboard toggle. The replay fixture and F3 alert are scripted inputs, not live Falco sensing.
