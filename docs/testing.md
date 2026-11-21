# Testing

How KubeHeal is tested, from a unit test to a multi-hour soak on a real cluster. Each layer says what it proves, how to
run it, and how long it takes. Offline layers run in CI-like conditions (no cluster); cluster layers need the lab
cluster and are never run by `pytest`.

| Layer | Proves | Needs | Runs | Time |
|---|---|---|---|---|
| 1 Unit | functions and contracts do what they say | nothing | `pytest` | with the rest, a few minutes |
| 2 Property / fuzz | parsers and features hold for any input | nothing | `pytest tests/test_fuzz_*.py tests/test_property_*.py` | ~1 min |
| 3 API hardening | hostile requests get a 4xx, never a 500 | nothing | `pytest tests/test_security_*_hardening.py` | ~15 s |
| 4 Manifest safety | every render is locked down | `kubectl`, `helm` | same command, `test_security_manifest_hardening.py` | ~3 s |
| 5 Script self-tests | the cluster scripts parse, honour the guard, dry-run cleanly | bash | `pytest tests/test_realworld_scripts.py` | ~10 s |
| 6 Smoke | a fresh install works end to end | cluster | `deploy/scripts/smoke.sh` | ~2 min |
| 7 E2E matrix | detection, drift, ops, install on minikube and k3d | cluster | `deploy/scripts/evaluate.py`, `docs/e2e-results.md` | ~30 min per section set |
| 8 UI | the console renders and behaves | Chromium | `pytest tests/ui` | ~1 min |
| 9 Soak | no benign kill and every attack killed over hours | cluster | `realworld/soak.sh` | N hours |
| 10 Scale | 300 pods plus churn stay inside every limit | cluster + metrics-server | `realworld/scale.py` | ~12 min |
| 11 Upgrade | upgrade and rollback keep state, detection stays up | cluster | `realworld/upgrade.sh` | ~25 min per path |
| 12 Chaos | faults degrade safely and recover | cluster (k3d for drain) | `realworld/chaos.sh` | ~35 min |
| 13 Multinode | the right node's agent acts | k3d with 3 agents | `realworld/multinode.sh` | ~8 min |

Install the dev tools once: `uv sync --all-extras`. Lint: `uv run --all-extras ruff check .`

## 1 Unit

`uv run --all-extras pytest` runs everything under `tests/` (the UI tests skip without Chromium; the Helm and manifest
tests skip without `helm`/`kubectl`). Fixtures use `fakeredis`, so no Redis is needed.

## 2 Property and fuzz (hypothesis)

| File | Properties |
|---|---|
| `tests/test_fuzz_parsers.py` | `falco.parse_line` on arbitrary bytes, text and JSON never raises (except the xfails below) and never invents fields; `open_syscall` flag handling; quantity parsers return `None` or a finite number |
| `tests/test_property_features.py` | `security_features`/`recent_features` never raise, values are finite or `None`, fractions in [0, 1], unknown stays `None` (never 0), permuting events with identical timestamps keeps the unordered features; `canonical_spec`/`spec_hash` stable under key order and ignore empty values; `changed_paths` is empty iff the hashes are equal |
| `tests/test_property_contracts.py` | `to_fields`/`from_fields` round-trip for `HealthEvent`, `SecurityEvent`, `ActionEvent` (also with bytes keys); garbage values raise only `ValueError`; containment and approval HMACs reject any change to a signed field, a wrong key, a missing field, a non-ASCII or non-string signature |

Hypothesis runs 200-300 examples per test and prints a minimal failing input; the example database is off, so a failure
is not replayed next time: copy the printed input into a regular test. For a deeper run raise `max_examples` in the file's `settings`.

### Known bugs the tests pin as `xfail(strict=True)`

A strict xfail fails the suite when the bug is fixed, which is the cue to delete the marker.

| Where | Bug | Severity |
|---|---|---|
| `agents/security_agent/falco.py` `parse_line` (pid) | `str.isdigit()` is true for `"²"`, `int("²")` raises `ValueError` | low (Falco emits ints) |
| `kubeheal/features/security.py` `open_syscall` | same `isdigit()`/`int()` mismatch; also > 4300 digits | low |
| `kubeheal/features/quantity.py` `_parse` | `"1e999"` parses to `inf` | low (apiserver rejects it) |
| `kubeheal/features/health.py` `_clean` | keys `a_b` and `aB` collide after camel-casing, hash depends on key order | low |
| `agents/common.py` `contain_sign` | `\|`-joined fields: `("a\|b","c")` and `("a","b\|c")` sign identically | low (names are DNS labels) |
| `dashboard/fastapi_app.py` | no `RequestValidationError` handler: `NaN`/`Infinity` in a JSON body gives HTTP 500 (inference already has the fix) | medium |
| `dashboard/admin.py` `ledger()` | a malformed `cursor` returns 503 "redis unavailable" instead of 4xx | low |
| `deploy/k8s/base/security-agent-daemonset.yaml` | sensor container has no liveness probe | medium |
| dashboard Deployment | no NetworkPolicy selects the dashboard pods | medium |

## 3 API hardening

- `tests/test_security_dashboard_hardening.py`: 5 MB bodies (rejected with 401 before validation when unauthenticated),
  malformed JSON, type confusion, wrong content type, 200 000-level nesting, unicode and control characters in reasons,
  CR/LF and over-long `X-Actor`, path-traversal and wildcard approval ids, replayed and conflicting approvals (409, no second
  command on the approvals stream), bad and oversized tokens, the failed-auth rate limit, foreign `Host`, cross-origin POST and
  WebSocket, query fuzz on `/api/ledger` and `/api/events`, wrong methods, read throttling, security headers.
- `tests/test_security_inference_hardening.py`: wrong types, `NaN`/`Infinity`/`1e999`, over-long keys and ids, 201 features,
  10 000-row batch, the 256-row maximum, oversized single body (413), chunked body without `Content-Length` (413), bogus
  `Content-Length`, deep nesting, extreme but finite numbers, random feature vectors always score, no bundles means 503.

Rule: the answer is a deliberate 4xx (or a normal 2xx), never a 5xx and never a crash. The clients run with
`raise_server_exceptions=False`, so a server exception shows up as a 500 and fails the assertion.

## 4 Manifest safety

`tests/test_security_manifest_hardening.py` renders five variants (kustomize dev and production, Helm dev, production, k3d)
and checks all of them. The test file is the source of truth for the exceptions; they are repeated here.

| Rule | Exceptions (justified) |
|---|---|
| requests and limits for cpu and memory on every container | none |
| `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `drop: [ALL]`, not privileged | none |
| capabilities added after the drop | security-agent `agent`: `SYS_PTRACE`, `DAC_READ_SEARCH` (read other containers' `/proc/<pid>/root`); `sensor`: `BPF`, `PERFMON` (load eBPF) |
| `runAsNonRoot` with a non-zero uid, seccomp `RuntimeDefault` | security-agent runs as uid 0 (ptrace and mount-namespace access need it) |
| no `hostNetwork`/`hostIPC`; `hostPID` and `hostPath` | security-agent only; its hostPath mounts are read-only except the cgroup tree, which containment writes (`cgroup.freeze`) |
| liveness probe everywhere, readiness on workloads behind a Service (inference, dashboard, Redis) | the one-shot secret Job; the sensor (known gap, xfail) |
| images tagged, never `:latest`; third-party images pinned by digest | none |
| API token mounted only for workloads that call the API | health, security, fusion, the secret Job |
| NetworkPolicy ingress for Redis and inference admits only the documented clients | dashboard has none (known gap, xfail) |
| RBAC: no wildcards, no `escalate`/`bind`/`impersonate`, secrets only by the `kubeheal-redis-secret` Role (`create` only), only fusion mutates | none |

Pod Security Standards. The tests compute the strictest level each workload satisfies. Every workload is `restricted`
except the security-agent DaemonSet, which is `privileged` (hostPID, hostPath, added capabilities, uid 0). Namespace
`kubeheal` therefore cannot enforce `baseline` or `restricted`; the test fails if someone sets an `enforce` label stricter
than `privileged`. Recommended: leave `enforce` unset (default privileged) for `kubeheal`, and set
`pod-security.kubernetes.io/warn=restricted` to be told when a new workload regresses. Every other namespace
(`khe-*`, the demo) is unaffected by KubeHeal.

## 5 Script self-tests

`tests/test_realworld_scripts.py`: every cluster script parses (`bash -n`, `py_compile`), sources the guard through
`lib.sh`, has the EXIT/INT/TERM trap, names only `khe-rw-*` namespaces, refuses a non-lab kubectl context before issuing
any command (a fake `kubectl` on PATH proves it), and `--dry-run` succeeds with fakes of kubectl/helm/docker/k3d/git that
fail the test if called.

## 6-8 Smoke, E2E matrix, UI

- Smoke: `./deploy/scripts/smoke.sh` after `install.sh`: pods, Redis ACL, inference, dashboard, a real kill and a real patch.
  Exits at the first failure; cleans its `khe-smoke-*` namespaces.
- E2E: `uv run --all-extras python deploy/scripts/evaluate.py --sections A,F,B,C,E,D [--repeat N]` (sections in its
  docstring). Results and the use-case matrix: `docs/e2e-results.md`.
- UI: `uv run playwright install chromium`, then `uv run --all-extras pytest tests/ui` (seeded fake Redis);
  `tests/ui/test_live.py` walks a live console (`KUBEHEAL_UI_BASE_URL=http://localhost:8080` against a port-forward). `KUBEHEAL_SHOTS=<dir>` writes screenshots.

## 9-13 Real-world cluster scripts (`deploy/scripts/realworld/`)

Common behaviour (`lib.sh`): cluster guard (minikube or `k3d-kubeheal`, `--force-context NAME` to override); `--dry-run`
prints every kubectl/helm/docker call instead of making it; all objects live in `khe-rw-*` namespaces; the trap deletes
those namespaces and the Redis keys matching `kubeheal:*khe-rw-*`, and runs the registered undo commands in reverse
order (fault injections are always reverted, also on Ctrl-C). A run ends with a PASS/FAIL table (`results.tsv` in the
printed results directory) and exit 1 when any check failed. Run them one at a time: they share the cluster and the
detection pipeline, and `evaluate.py` deletes every `khe-*` namespace on cleanup.

Do not run any of them while a lab data collection (`training/collect/run_lab.sh`) is active.

### Soak (`soak.sh`)

`./deploy/scripts/realworld/soak.sh --hours 4 [--attack-every 600] [--cycle 600] [--workloads postgres,restic] [--seed 1]`

Eleven real benign tools (restic, npm, pip, git, postgres+pgbench, redis bgsave, nginx+logs, logrotate, tar/gzip/zstd,
sqlite, rsync) run in a loop, restarted every `--cycle` seconds. About every `--attack-every` seconds (jittered) a random
sandboxed attack profile (rate, size, rename style, delay) runs in a fresh namespace. Needs enforce mode and a cluster that
can pull the tool images. Fails on: any benign pod killed, any attack not killed, a kill later than `--max-kill-s` (30), a
false-alert rate above `--max-false-alerts-per-hour` (2 HUMAN/OBSERVE per workload-hour), a KubeHeal pod restart, new
dead letters. Reports kill-latency p50/p90/p95/p99/max, false alerts, CPU/memory p50/p95/p99/max per component
(`soak-report.json`). Expected duration: `--hours` plus about 5 minutes. Start with `--hours 1` before a long run.

### Scale (`scale.py`)

`python3 deploy/scripts/realworld/scale.py [--namespaces 20 --deployments 200 --pods 300 --churn-seconds 300 --churn-interval 3]`

Creates the Deployments (pause containers, 1 mCPU / 2 Mi requests), waits for Running, then changes an env var on a random
Deployment every few seconds (each is a real rollout and a spec change for the health agent). Measures health-agent and
fusion CPU/memory (`kubectl top`), Redis `used_memory` against `maxmemory` (noeviction: full means failing writes), the
fusion consumer-group lag, event lag (spec change to health event) and fusion lag (health event to action). Fails when:
a KubeHeal pod restarted (OOM), memory over 90 % of a limit, Redis over 80 % of maxmemory, p95 event or fusion lag over
30 s, dead letters, fewer than half the rollouts produced an event, or any AUTO_KILL/AUTO_PATCH hit the benign churn.
Refuses more than 25 namespaces, 1000 Deployments, 3000 pods. Needs metrics-server and capacity for 300 small pods
(minikube: start with `--cpus 4 --memory 8g`; the default 110-pods-per-node limit also binds).

### Upgrade (`upgrade.sh`)

`./deploy/scripts/realworld/upgrade.sh --from-ref v5.0.0 [--path kustomize|helm|both --wipe] [--target minikube|k3d]`

Checks out `--from-ref` as a git worktree and installs it with that release's own `install.sh`; creates state (three
baselines, a Redis marker key, a ledger entry; the pending approval queue and the runtime mode are recorded as they are);
launches an attack every 20 s while HEAD's `install.sh` upgrades; then rolls back (kustomize: the old `install.sh` again;
Helm: `helm rollback` to the previous revision) and finally reinstalls HEAD. HEAD means the working tree, uncommitted changes
included. Asserts after the upgrade and after the rollback that Secrets are the same objects with the same data, the Redis
PVC is the same, baselines are byte-identical, marker and ledger entry survive, mode is unchanged and pending approvals were
not lost; during the upgrade no attack is missed and the worst time-to-kill stays under `--max-gap-s` (180); after each
step an attack is killed within `--max-kill-s` (40). `--path both` deletes the kustomize install between paths (Helm cannot
adopt kustomize objects), so it asks for `--wipe`. The ref needs `deploy/scripts/install.sh` and the same image names.

### Chaos (`chaos.sh`)

`./deploy/scripts/realworld/chaos.sh [--only pods,redis,inference,redisfull,drain,sensor] [--fill-pct 90]`

While attacks and three light benign tools run, each fault is injected, an attack is launched during it, the fault is
reverted, the recovery time is measured and a second attack is launched. Expected behaviour (what the script enforces is
marked must):

| Fault | Expected |
|---|---|
| kill fusion, health, inference and one security-agent pod | must: attack after recovery killed within 40 s; no duplicate kills; recovery back to all-Ready in 240 s. An attack during the restarts may be killed late |
| restart Redis | must: baselines identical (AOF on the PVC), agents reconnect, no crash loop, attack after recovery killed. During the outage events cannot be written, so a kill is not required, but nothing benign may die and stale events must not kill later |
| NetworkPolicy blocks inference | must: security agent (embedded model) still kills; no benign kill; after the revert a bad-image drift is AUTO_PATCHed again. The health agent degrades quietly while inference is away |
| Redis filled to 90 % then 99 % of maxmemory (noeviction) | must: attack killed at 90 %; at 99 % only no crash, no OOM, no benign kill; after deleting the filler keys an attack is killed again. At 99 % XADD may fail, so detection can be late: that is the documented limit, alert on `used_memory` |
| cordon + drain a worker without Redis (k3d) | must: attacks on other nodes killed meanwhile; after uncordon all Ready and the returned node kills again. Skipped on a single-node cluster |
| delete the security-agent pod on one node every 12 s for 90 s | must: no kill storm, no false kill when it returns (no replay of old events), attack after stabilisation killed on that node |

Global must: 0 benign kills, kills not above attacks launched, nothing outside `khe-rw-*` killed, final state all-Ready.
It edits objects in namespace `kubeheal`: a temporary NetworkPolicy `khe-rw-deny-inference` (the allow policy
`kubeheal-inference-clients` is saved and restored), Redis keys `kubeheal:khe-rw-fill:*`, the cordon state of one node.
If the script is killed with `-9` run: `kubectl -n kubeheal apply -f <results dir>/inference-netpol.yaml`,
`kubectl uncordon <node>` and delete the filler keys.

### Multinode (`multinode.sh`)

`KUBEHEAL_K3D_AGENTS=3 ./deploy/k3d/create.sh`, install, then `./deploy/scripts/realworld/multinode.sh [--rounds 2]`.
Pins an attack to each worker (shuffled, `--rounds` times). Asserts: one Ready security-agent pod per node; the attack
pod really ran on the pinned node; killed within 40 s; fusion requested containment; the freeze counter
(`kubeheal_security_contain_total{outcome="frozen"}`, scraped through the API-server proxy) grew on that node's agent and
on no other; no other pod killed.

## Caveats

The cluster scripts were written and dry-run tested while the lab cluster was busy; `bash -n`, `py_compile`, the
`--dry-run` self-tests and the guard refusal test are verified, but the first live run of each script may need small
fixes (label selectors, metric names, image pulls). Run each once with a short setting first (soak `--hours 0.2`,
scale `--deployments 40 --pods 60 --churn-seconds 60`, chaos `--only pods`, upgrade `--path` of the current install).
