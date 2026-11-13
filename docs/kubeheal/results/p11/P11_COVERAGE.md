# P11 and V5-E1 evaluation coverage

Values below come from files in this directory. `not measured` means no run produced that value; it is not a zero.

| Item | Status | Evidence or reason |
|---|---|---|
| P11-E1 k6 scoring load | measured | VUs 32; see per-run CSV, raw k6 logs, and HPA samples below |
| P11-E2 inference pod recovery | measured | 1 completed recovery run(s); see per-run CSV |
| P11-E3 RPO/RTO | not measured | no disposable database-volume scenario is configured; the run must not overwrite or delete existing PVC data |
| P11-E4 stage timing | not measured | the current event path does not expose timestamps for each action stage |
| P11-E5 baseline comparisons | not measured | controlled comparison drivers for the five baselines are not implemented or verified |
| P11-E5 Falco rules only | not measured | no live Falco rules-only baseline is installed; replay fixtures are hand-written |
| P11-E5 fixed entropy threshold | not measured | no controlled fixed-threshold detector run is available |
| P11-E5 diff-only drift | not measured | no controlled comparison run is available |
| P11-E5 single replica | not measured | no controlled single-replica comparison run is available |
| P11-E5 pod-delete-only | not measured | no controlled pod-delete-only ransomware comparison run is available |
| P11-E6 FP32/FP16 latency and memory | not measured | the deployed LightGBM bundle has no paired FP32/FP16 deployment variants for a controlled comparison |
| P11-E7 run metadata | recorded per run | machine, cluster, timestamp, and status are stored in each JSON sidecar |
| V5-E1 scripted lab scenarios | not measured | the V5-E1 runner is not ported to the context-pinned P11 harness. The legacy Minikube-specific driver may restart Redis, Falco, and Health Agent and create/delete khe-* namespaces. The original cluster has no disposable scenario PVC; its prod victim, MinIO, and Redis PVC data remain protected. F3 is narrower than the V5-E1 matrix. |

## Run files

- `E2 pod delete/recreate`: `measured`; elapsed `1.25` seconds.
- `E1 k6 health inference`: `failed`; elapsed `125.047` seconds.
- `E1 k6 health inference`: `failed`; elapsed `105.141` seconds.
- `E1 k6 health inference`: `failed`; elapsed `108.344` seconds.
- `E1 k6 health inference`: `failed`; elapsed `16.891` seconds.
- `E1 k6 health inference`: `measured`; elapsed `115.375` seconds.
