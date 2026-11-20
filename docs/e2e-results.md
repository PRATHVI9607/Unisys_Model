# End-to-end results

Date 2026-11-21 (cluster clock IST). Image tag `:v5`, sensor event source, fusion `enforce`, models
`health-5.0.0-a374e498` / `security-5.0.0-c6fa12d8`. Clusters: minikube (kustomize install, 1 node) and k3d v5.8.3
(Helm install, 1 server + 2 agents, sensor works on the host kernel). Latency is measured from the workload's logged
`overwrite_start_ms` to the action (`kill`) or to the `kubeheal.contain` entry (`freeze`), using the Redis stream ids.

## Install

| Case | Expected | Actual | Result |
|---|---|---|---|
| minikube `install.sh` over an old install | Secret Job creates the missing Secrets, rollout Ready | Job created `kubeheal-admin`, `-contain-hmac`, `-approval-hmac`, kept `kubeheal-redis`; 5m33s (images cached) | pass |
| minikube `smoke.sh` | PASS | First runs failed at `kill` (see Fix 1); after the fix PASS in 106 s (kill 35 s, patch 69 s) | pass after fix |
| k3d `install.sh --target k3d --helm` | Ready | 3m35s, 3 security-agent pods | pass |
| k3d `smoke.sh` | PASS | PASS in 119 s (kill 45 s, patch 69 s) | pass |

## Security (minikube)

| Case | Expected | Actual | Result |
|---|---|---|---|
| Default attack (400 files @180/s), 3 pods | kill + freeze | kill 0.38 s median, freeze 0.34 s | pass |
| Slow 2 files/s | kill | 2.56 s median (3.49 s max) | pass |
| 1000 files/s | kill | 0.35 s | pass |
| 2000 files | kill | 0.73 s | pass |
| 128 B files / 8 MiB files / partial 5% | kill | 0.85 s / 1.59 s / 0.83 s | pass |
| In place (`--no-rename`) | kill | 0.77 s | pass |
| `--swap-ext` | kill | 0.35 s | pass |
| Delay 10 s / 60 s before overwrite | kill | 0.25 s / 0.44 s | pass |
| 2 attack pods in one namespace (6 pods total) | all killed | 6/6, 0.53 s median | pass |
| Attack with 10 busy I/O pods (500 ops/s each) | kill, no false action | kill 0.50 s, freeze 0.46 s, 0 actions on the 10 pods | pass |
| Namespace in the protected set (`kube-system`) | no kill, no freeze | The security agent drops protected-namespace events, so no action is recorded at all (not `skipped_protected`); pod survived | pass (by design) |
| Pod labelled `kubeheal.io/protected=true` | `skipped_protected`, no freeze | `AUTO_KILL:skipped_protected`, containment empty, pod survived | pass |
| Namespace labelled `kubeheal.io/protected` | n/a | Label is read on pod/controller only (docs say so); the namespace label does nothing | note |
| Deployment, 4 attacks in a row | 3 kills, then `skipped_circuit_open` | kills at 3/5/7 s, 4th `skipped_circuit_open` | pass |
| DaemonSet (pod name changes each time) | breaker keyed by controller | 3 kills, 4th `skipped_circuit_open` | pass |
| StatefulSet | same | 3 kills (one preceded by an uncertain HUMAN), 4th `skipped_circuit_open` | pass |
| Benign soak, 11 real tools (restic, npm, pip, git, tar/gzip/zstd, logrotate, postgres pgbench, redis bgsave, sqlite, rsync, nginx) 120 s | 0 AUTO_KILL | 0 AUTO_KILL, 0 pods killed. HUMAN/OBSERVE decisions: npm 3 HUMAN (max risk 0.84), restic 1 HUMAN (0.89), git 1, pip 1 | pass (noisy approval queue) |

## Health (minikube, podinfo, 2 replicas)

| Change | Expected | Actual | Result |
|---|---|---|---|
| Bad image tag | AUTO_PATCH | patched at 9 s (`ErrImagePull`) | pass |
| Privileged added / hostNetwork / hostPath | AUTO_PATCH (policy) | patched at 1-2 s | pass |
| Memory 8Mi | AUTO_PATCH | `policy:memory_cut_10x`, 2 s | pass |
| Wrong command | AUTO_PATCH | `CrashLoopBackOff`, 10 s | pass |
| Readiness wrong path | HUMAN, then follow-up AUTO_PATCH | HUMAN at 62 s, `ReadinessNeverPassed` AUTO_PATCH at 66 s | pass |
| CPU 500m to 5m | AUTO_PATCH | `policy:cpu_cut_10x`, 2 s | pass |
| Image upgrade / replicas 2 to 4 / env var | no patch | BENIGN, no patch | pass |
| Memory halved, CPU quartered, older image | no patch | BENIGN | pass |
| Memory quartered / liveness period 1 s | HUMAN (approval queue) | HUMAN (not deterministic: the same memory change was BENIGN on k3d) | pass |
| HPA scaling replicas 1 to 3 | no drift event | 0 health events, 0 actions | pass |

## Ops

| Case | Expected | Actual | Result |
|---|---|---|---|
| Approve HUMAN health drift | AUTO_PATCH executed | `patched`, memory restored within 2 s of the click | pass |
| Reject path | state `rejected`, no change | rejected, deployment untouched | pass |
| Approve while mode is observe | refused | `refused:observe_mode`, item back to pending; ledgered | pass |
| Approve for a pod that is gone | no action | `pod_already_gone`, state executed | pass |
| Forged approval record written with the dashboard Redis user | `refused:bad_sig` | refused, victim pod survived, ledger entry | pass |
| Kill switch to observe | takes effect at once, no freeze | `kubeheal:mode:effective` = observe 0.71 s after the POST (poll cost included); next attack `would_kill`, no freeze, pod survived; back to enforce OK | pass |
| Ledger | approvals, rejections, mode, actions | all present with actor and detail | pass |
| Alert webhook (in-cluster receiver) | kill and patch alerts | both received, Slack-style `text` plus fields | pass |
| Redis restart | baselines and consumer groups survive | 5/5 baselines, groups unchanged; next attack killed in 0.6 s | pass |
| Fusion pod force-deleted at attack start | kill after it returns | kill 3.4 s after the first overwrite | pass |
| Security-agent pod force-deleted at attack start | kill after it returns | kill 4.4 s | pass |
| Inference scaled to 0 | security still detects (embedded) | kill 0.2 s | pass |
| Sensor container killed (`pkill` on the node) | restarts, detects | restart count 1, next attack killed in 0.67 s | pass |

## UI (live minikube console)

`tests/ui/test_live.py` (new, skipped unless `KUBEHEAL_UI_BASE_URL` is set) walks overview, approvals, ledger, mode, models and
one incident against a port-forward: no console errors, no CSP violations. The seeded `tests/ui/test_console.py` asserts
fake-Redis data, so it cannot run live. Screenshots: `live-{overview,incident,approvals,ledger,mode,models}.png` in the scratchpad `ui/` directory.

## Resources (`kubectl top`, minikube; security agent = agent + sensor containers)

| Component | Idle CPU / mem | 11 benign heavy pods | 10 I/O pods x 500 ops/s |
|---|---|---|---|
| security-agent | 74m / 126Mi | p50 388m, max 652m / 149Mi | about 530m / 164Mi |
| inference | 3m / 94Mi | 4m / 93Mi | 3m / 93Mi |
| fusion | 4m / 80Mi | 7m / 81Mi | 4m / 82Mi |
| health-agent | 3m / 84Mi | 1m / 84Mi | 1m / 84Mi |
| redis | 26m / 38Mi | 36m / 37Mi | 24m / 38Mi |
| dashboard | 4m / 44Mi | - | 4m / 44Mi |

## k3d (Helm)

| Case | Result |
|---|---|
| Default attack | kill 0.72 s, freeze 0.68 s |
| Privileged added | AUTO_PATCH 0.29 s |
| Kill switch | observe: HUMAN then `would_kill`, pod survived; enforce restored |
| Approval | approve of the held attack: `pod_killed` within 7 s |
| Memory quartered | BENIGN here, so no HUMAN health item to approve (model variance) |

## Fixes

1. `deploy/scripts/smoke.sh` `acted()`: the awk quit at the first hit, SIGPIPE hit `kubectl exec redis-cli` once the actions
   stream was larger than the pipe buffer, and `pipefail` made the lookup fail. The `kill` step reported "no AUTO_KILL" although fusion had killed the pod. Now awk reads all input. Test: `test_smoke_acted_reads_whole_stream`.
2. `tests/ui/test_live.py`: live-console walk (no fix, new coverage).

## Observations, not fixed

- `evaluate.py` section E names Deployments by stripping uppercase letters (`host-ath`, `host-etwork`); cosmetic.
- `evaluate.py` cleanup leaves `kubeheal:dedupe:approval:khe-*` and similar keys (they expire by TTL; "redis_khe_keys_left" is not 0).
- HUMAN approvals for attacks that were killed seconds later stay pending until they expire; approving them is a harmless `pod_already_gone`.
- Benign npm and restic raise `ransomware`-labelled HUMAN items (risk up to 0.89); none acted.
