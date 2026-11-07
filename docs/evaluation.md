# Live evaluation

Measured on the deployed stack, not on held-out training data. Driver: `deploy/scripts/evaluate.py`
(see [Reproduce](#reproduce)). Raw per-pod rows are printed by the driver as TSV.

## What was run

| Item | Value |
|---|---|
| Date | 2026-11-07 |
| Cluster | minikube (Kubernetes v1.37.0, 8 CPU, 8 GB, kernel 7.3.1), docker driver, 1 node |
| KubeHeal | `kubeheal/*:v5`, fusion `KUBEHEAL_MODE=enforce`, security model `security-5.0.0-c6fa12d8`, health model `health-5.0.0-421cec83`, `MAX_KILLS_PER_HOUR=3` |
| Falco | 0.45.1-rc1 (limit 2 CPU) |
| Namespaces | throwaway `khe-*`, tier label `prod`, unprotected pods; all deleted afterwards |

Attack-like runs use only `deploy/chaos/detection-test-workload.py` (sandbox-gated, image `kubeheal/chaos:v5`) with other parameters. No attack or encryption code was added.

## Scorecard

| Area | Result |
|---|---|
| Automated | `pytest` rc 0, 323 passed, 0 failed; `ruff check .` clean; `cargo test` (sensor) 4 passed; `kubectl kustomize` of `deploy/k8s` and the production overlay renders; `bash -n` clean |
| False kills, 11 real-tool workloads (about 3.5 min each, all at once) | **0 AUTO_KILL**. Every pod ran to completion. 2 workloads raised alerts, see below |
| Detection recall, 12 parameter rows, 39 attack pods | **39 / 39 killed** (the default row was first missed because of a Falco backlog left by the soak, then re-run after it drained, see weaknesses). Latency overall: median 1.5 s, p90 4.9 s |
| Resilience | inference down, fusion down, Redis restart, Falco restart all recovered with no crash loop and no stuck state. **Failed: kill under 20-pod load came ~160 s late** |
| Drift, 11 changes | 0 false patches on 3 benign changes. 6 of 8 harmful changes were rolled back (1 to 13 s). 2 were not acted on (wrong readiness path: HUMAN; CPU 5m: BENIGN) |
| Resources (idle, 2 min) | Falco 43m / 199 Mi, security agent 5m / 93 Mi, inference 4m / 94 Mi, fusion 2m / 74 Mi |
| Resources (11-pod soak) | Falco 1869m / 449 Mi (max 526), security agent 162m / 97 Mi, inference 57m / 94 Mi, fusion 4m / 74 Mi |

### B. False-kill soak (none of these are in the training data)

Max risk is taken over the **published** security events. The agent publishes only windows at or above `SECURITY_PUBLISH_RISK`, so "none" means every window scored below it.

| Workload | AUTO_KILL | HUMAN | OBSERVE | Max published risk | Survived |
|---|---|---|---|---|---|
| postgres:16, `pgbench -i -s 20` then `-T 120` | 0 | 0 | 0 | none | yes |
| redis:7, `save 1 1` + BGSAVE every 1 s under redis-benchmark | 0 | 0 | 0 | none | yes |
| logrotate (`compress`, `rotate 5`, forced every 2 s) | 0 | 0 | 0 | none | yes |
| tar czf / gzip -r / zstd of a 200-file tree, repeated | 0 | 0 | 0 | none | yes |
| git clone podinfo + checkout of 8 tags + gc + local clones | 0 | 3 | 4 | 0.45 (suspicious) | yes |
| pip install into a venv in /data, repeated | 0 | 0 | 0 | none | yes |
| npm install (express, lodash, axios), repeated | 0 | **6** | 0 | **0.84 (ransomware, 2 windows)** | yes |
| sqlite, WAL then rollback journal, one commit per INSERT | 0 | 0 | 0 | none | yes |
| rsync with and without `--inplace` | 0 | 0 | 0 | none | yes |
| nginx serving + log-heavy loop | 0 | 0 | 0 | none | yes |
| restic init + backup + forget/prune (encrypts and compresses) | 0 | 0 | 0 | none (in this run) | yes |

borg was not run. In the 20-pod load test (section D) restic was rated **ransomware, risk 0.82, uncertain** and went to HUMAN. It was not killed only because the conformal set held more than one label. Treat restic-like tools as a near miss, not a pass.

### C. Detection sweep (3 pods per row, defaults: 400 files, 180 files/s)

"Files before kill" is an estimate: rate x latency, capped at the file count. The kill action is logged when the pod delete returns, and the process stops a little later, so the workload had already finished all files in most 180 files/s rows (its own log shows completion). Early kill limits damage only for slow or long attacks.

| Row | Recall | Latency median / p90 (s) | Files before kill (est.) |
|---|---|---|---|
| default 400 @ 180/s (re-run after backlog drained) | 3/3 | 1.55 / 1.59 | about 280 of 400 |
| rate 2 files/s (100 files) | 3/3 | 4.72 / 5.63 | 9 to 11 of 100 |
| rate 1000 files/s (500 files) | 3/3 | 2.24 / 2.33 | all (done in under 1 s) |
| 2000 files | 3/3 | 4.89 / 4.93 | about 890 of 2000 |
| tiny files (128 B) | 3/3 | 1.46 / 1.55 | about 260 of 400 |
| large files (12 x 8 MiB, 4/s) | 3/3 | 1.64 / 1.65 | about 7 of 12 |
| partial overwrite 0.05 | 3/3 | 1.19 / 1.25 | about 215 of 400 |
| `--no-rename` (in place) | 3/3 | 1.04 / 1.11 | about 190 of 400 |
| `--swap-ext` | 3/3 | 1.43 / 1.45 | about 260 of 400 |
| delay 10 s (quiet gap before overwrite) | 3/3 | 0.42 / 0.53 | about 75 of 400 |
| delay 60 s | 3/3 | 0.63 / 0.75 | about 115 of 400 |
| 2 concurrent pods in one namespace (6 pods) | 6/6 | 3.32 / 6.56 | up to all |
| **All rows** | 39/39 | **1.46 / 4.93** (36 pods in the main run, 3 in the re-run) | |

Latency is from the workload's `overwrite_start_ms` to the `pod_killed` entry in `kubeheal.actions`, the same method as `bench.sh`.

### D. Resilience

| Test | Result |
|---|---|
| Inference down (scaled to 0) during a slow attack | Pod stayed alive for 40 s while down, no crash loop. Killed 0.6 s after inference came back (44.9 s after the first overwrite). A new attack afterwards was killed in 0.4 s |
| Fusion down 30 s during a slow attack | Pod alive while down. Pending events were processed on return and the pod was killed (31.5 s after the first overwrite, about when fusion was Ready) |
| Redis restart (ephemeral, no persistence) | Agents reconnected, consumer groups present again after 45 s, next attack killed in 0.9 s. Baselines are lost: `demo/victim-app` had no baseline 20 s after the health agent restart; it was back at the next check |
| Falco restart during benign load (took 13 s) | No false kills. No security event was published before or after (everything scored below the publish threshold), so "events resuming" is shown by the next row |
| Attack right after a Falco restart | Killed in 0.6 s |
| 20 benign pods + 1 attack | 0 benign AUTO_KILL; 4 benign alerts (3 OBSERVE, 1 HUMAN for restic). **The attack was not killed in time**: Falco, with 20 pods writing, delivered its events about 160 s late (event window ended 18:11:45, published 18:14:24), after the attack and its namespace were gone |
| Agent restarts (crash loops) | none outside the deliberate ones |

### E. Health and drift (podinfo, 2 replicas, 120 s baseline, 8 min window, all changes at once)

| Change | Decision | Time to action | Restored |
|---|---|---|---|
| Image upgrade 6.12.0 to 6.14.1 (benign) | BENIGN, no action | | |
| Replicas 2 to 4 (benign) | BENIGN, no action | | |
| Env var added (benign) | BENIGN, no action | | |
| Bad image tag | AUTO_PATCH (ErrImagePull, risk 0.90) | 7 s | yes, 7 s |
| Privileged added | AUTO_PATCH (`policy:privileged_added`, 0.95) | 1 s | yes |
| hostNetwork added | AUTO_PATCH (`policy:host_namespace_added`) | 1 s | yes |
| hostPath added | AUTO_PATCH (`policy:host_path_added`) | 1 s | yes |
| Memory 8Mi (request and limit) | AUTO_PATCH (CrashLoopBackOff, OOMKilled, 0.94) | 7 s | yes |
| Wrong command (`/bin/false`) | AUTO_PATCH (CrashLoopBackOff, 0.91) | 10 s | yes, 13 s |
| Readiness probe to a wrong path | **HUMAN** (benign 0.40, uncertain) at 62 s | | no |
| CPU request and limit 5m | **BENIGN, no action** (risk 0.10) at 62 s | | no |

False patches on benign changes: 0.

## Weaknesses found

1. **Detection lags under heavy I/O.** With 20 busy pods Falco ran at its CPU limit and its events reached the agent about 160 s late, so the attack finished and was killed after the fact (or not at all if the pod is gone). Also after the 11-pod soak, the first detection row (3 pods) got no kill within the 45 s watch for the same reason; re-run after the backlog drained it was killed in 1.5 s. Fusion later looked the namespace up, got a 404, and fell back to tier `dev`, which makes the score 0.66 and the decision HUMAN. Falco's output queue also logged one `Outputs queue out of memory` drop during the soak.
2. **Encrypting backup tools are the nearest false-kill risk.** restic reached ransomware 0.82 under load and npm reached 0.84 (2 windows). Both stopped at HUMAN. restic stopped because the verdict was uncertain; the npm rationale was not kept (the Redis restart in section D cleared the streams). No AUTO_KILL on real tools, but there is no wide margin.
3. **Drift blind spots.** A readiness probe that never passes leaves a stuck rollout at HUMAN/benign (no rule fires, and `ProgressDeadlineExceeded` did not produce an action inside 8 min). A 5m CPU limit is rated benign.
4. **Redis is ephemeral.** A restart wipes baselines, streams and breakers. Baselines are re-learned within about a minute after the health agent restarts, but until then AUTO_PATCH escalates.
5. **Kill is not instant.** Termination lands about a second after the action entry. A 400-file attack at 180 files/s completes in 2.2 s, so the kill saves little for fast, small attacks.
6. **Coverage of the measurement.** One run per workload; the 0.00 "max risk" values are lower bounds on risk (unpublished windows are not recorded); borg and extra encrypting tools were not tried; files-before-kill is estimated.

No code bugs were found that justify a code change. The driver shows these as measured behaviour, not defects.

## Reproduce

```bash
uv run --all-extras python deploy/scripts/evaluate.py --out /tmp/eval          # all sections, about 70 min
uv run --all-extras python deploy/scripts/evaluate.py --sections B,D --dur 120 # subset
uv run --all-extras python deploy/scripts/evaluate.py --sections C --c-rows rate2
```

Sections: A automated checks, F resources, B soak, C detection sweep, E drift, D resilience. It needs
network access from the cluster (apk, pip, npm, git, public images). It creates only `khe-*` namespaces
and deletes them, and Section D scales inference and fusion to 0 and restarts Redis, the health agent and
Falco, then restores them. A final `CLEAN` row verifies that no `khe-*` namespace or key is left, capture is off,
fusion is in enforce mode and all KubeHeal pods are Ready. Run it only on a lab cluster.
