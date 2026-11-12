# P11 and V5-E1 evaluation coverage

Values below come from files in this directory. `not measured` means no run produced that value; it is not a zero.

| Item | Status | Evidence or reason |
|---|---|---|
| P11-E1 k6 scoring load | not measured | No completed live load run recorded yet. |
| P11-E2 inference pod recovery | not measured | No completed live recovery run recorded yet. |
| P11-E3 RPO/RTO | not measured | No disposable database-volume scenario is configured; existing PVC data must not be overwritten or deleted. |
| P11-E4 stage timing | not measured | The current event path does not expose timestamps for each action stage. |
| P11-E5 baseline comparisons | not measured | Controlled comparison drivers for the baselines are not implemented or verified. |
| P11-E5 Falco rules only | not measured | No live Falco rules-only baseline is installed; replay fixtures are hand-written. |
| P11-E5 fixed entropy threshold | not measured | No controlled fixed-threshold detector run is available. |
| P11-E5 diff-only drift | not measured | No controlled comparison run is available. |
| P11-E5 single replica | not measured | No controlled single-replica comparison run is available. |
| P11-E5 pod-delete-only | not measured | No controlled pod-delete-only ransomware comparison run is available. |
| P11-E6 FP32/FP16 latency and memory | not measured | The deployed LightGBM bundle has no paired FP32/FP16 deployment variants for a controlled comparison. |
| P11-E7 run metadata | not measured | No live result sidecar exists yet. |
| V5-E1 scripted lab scenarios | not measured | The scripted V5 acceptance lab scenarios have not been run; full containment is not yet live-verified. |

The upcoming U6 run uses a **clean workload baseline with cluster volumes preserved**. A fresh-cluster baseline is not measured because `demo/k3d/down.ps1` destroys the victim PVCs, MinIO ledger, and Redis data.
