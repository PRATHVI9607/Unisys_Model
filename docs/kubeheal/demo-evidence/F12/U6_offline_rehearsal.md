# U6 offline setup rehearsal

Date: 2026-11-13 (local)
Cluster: `kubeheal-rehearsal` / context `k3d-kubeheal-rehearsal`, separate from `k3d-kubeheal`.

## Offline install path

`demo/k3d/up.ps1 -Stage all -SkipImages -TargetCluster kubeheal-rehearsal -TargetRegistryPort 5151 -TargetHttpPort 8081` completed twice. Helm installed the vendored `kube-prometheus-stack` 65.5.1 and `prometheus-adapter` 4.11.0 archives without adding or updating a remote Helm repository. Container images were preloaded into the new cluster's containerd from local cache and the already-built demo registry because external registry DNS was unavailable; `-SkipImages` reused those local images. This verifies the chart-install path is offline, with image-cache availability as a prerequisite.

The cluster was created separately from scratch using the cluster stage, with its own registry, context, and host port. The original `k3d-kubeheal` cluster and its PVCs were not modified. The rehearsal cluster started with newly provisioned MinIO and Redis PVCs; no original data was copied.

## U6 runs

| Run | Full `all` stage | Scenario | Result |
|---|---|---|---|
| 1 | `U6_offline_rehearsal_run1_up.txt`, completed in 71 seconds | `U6_offline_rehearsal_run1_fixed.txt` | 15/15 metric queries returned samples. Scripted CPU drift yielded Fusion `human_patch`, `outcome=logged`, `dry_run=true` in global mode `test`. Script restored the victim. |
| 2 | `U6_offline_rehearsal_run2_up.txt`, completed in 71 seconds | `U6_offline_rehearsal_run2.txt` | 15/15 metric queries returned samples. Scripted CPU drift yielded Fusion `human_patch`, `outcome=logged`, `dry_run=true` in global mode `test`. Script restored the victim. |

`U6_offline_rehearsal_actions.txt` reads back both action entries from the Redis action stream. At verification, all workload pods were Ready (the MinIO bootstrap Job was Completed), mode was `test`, Helm release `kubeheal` was deployed at revision 4, and `prod/victim-app` was restored to CPU request `100m` / limit `500m`.

An earlier pre-fix attempt had no Fusion action because the Fusion consumer could start before Redis was ready and did not recreate its stream group. The startup retry fix is in `work` commit `c714fe3`, merged into `demo` as `85f8660`; the two accepted runs above used the rebuilt Fusion and Health Agent images. The earlier failed attempt remains in `U6_offline_rehearsal_run1.txt` and is not counted as a pass.

## Limits

This verifies fresh k3d setup and the demo drift scenario with local chart and image caches. It is not a claim that external container images are vendored in the repository or that the install works without those images being available locally. It does not verify real Falco sensing or enforce-mode remediation.
