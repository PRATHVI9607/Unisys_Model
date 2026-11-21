# Performance

Goal: the shortest path from a malicious file operation to a frozen pod, with agents that stay small.
Everything below was measured offline; nothing here was measured on a cluster (see "What was not measured").

## Method

`tests/bench_kill_latency.py` replays the detection-test attack (`deploy/chaos/detection-test-workload.py`:
400 placeholder creates, then per file a read, an overwrite and a rename to `<name>.khlocked`) into a real
`events.jsonl` from a separate process, at a fixed files/s. In one event loop it runs the real security agent
(real `FalcoTail`, real entropy reads from a fake `/proc`, the embedded model with TreeSHAP) and the real fusion
agent, against a fake kube API with a fixed 5 ms per call and a fakeredis TCP server in its own process (with
`TCP_NODELAY`; BLOCK is emulated by a 1 ms poll because fakeredis does not block). It stamps the event chain that
ends in the kill and prints the median of N runs per stage:

```bash
nice -n 19 uv run --all-extras python tests/bench_kill_latency.py --rate 180 --runs 9
nice -n 19 uv run --all-extras python tests/bench_kill_latency.py --rate 2 --files 60 --runs 7
#   --trace  every evaluation (time, events, label, risk)     --oracle  score after every event
#   --cold   leave the TreeSHAP explainer unbuilt             --kube-ms  per-call kube latency
```

`tests/bench_load.py` runs one agent in-process and reports RSS and CPU per wall second while a separate process
feeds it events (`security --rate 10000 --pods 50`).

An optimization is kept only if it is faster by median of repeated runs and decisions, features and published
events are unchanged (`uv run --all-extras pytest`, plus the tests added for each path). The box was shared with
other work (load average 8 on 12 cores, `nice -n 19`), so absolute numbers are noisy; compare columns, not digits.

## Result: first malicious write to cgroup freeze

Median ms, 9 runs (7 for 2 files/s). "Before" is the code at the start of this work.

| stage | 180 files/s before | after | 2 files/s before | after |
|---|---|---|---|---|
| evidence (first malicious write to the newest event of the killing window) | 284 | 56 | 2000 | 1500 |
| sensor write to tail read | 1.4 | 0.3 | 143 | 0.4 |
| tail read to ingest | 1.6 | 0.3 | 0.3 | 0.3 |
| ingest to evaluation start (trigger wait) | 92 | 1.9 | 245 | 0.2 |
| features (entropy reads, 32+13 features) | 7.3 | 7.3 | 3.1 | 3.7 |
| predict + TreeSHAP | 8.9 | 10.1 | 9.0 | 8.1 |
| owner lookup + publish to fusion wake | 23 | 11.5 | 22 | 11.3 |
| fusion decide, kube reads, lock, breaker, up to the contain XADD | 19.1 | 19.5 | 19.9 | 19.8 |
| contain stream to agent | 1.3 | 1.6 | 1.5 | 1.8 |
| freeze write | 0.2 | 0.2 | 0.2 | 0.2 |
| **total to freeze** | **440** | **112** | **2452** | **1546** |
| total to delete call | 450 | 127 | 2462 | 1555 |

Not in the table: the first attack after an agent start used to pay ~0.8 to 1 s to build the TreeSHAP explainer
(`ModelBundle.class_boosters`, lazy). Measured with `--cold`: 1401 ms total at 180 files/s. Both the agent and the
inference service now build it at startup.

What the numbers say:

- The old floor was not the model. `MIN_TICK_S` (0.25 s pause after every round), `POD_MIN_INTERVAL_S` (0.5 s per
  pod; the setup phase's score used it up before the attack started) and the 0.2 s idle sleep of the tail made the
  chain wait for the clock, not for evidence.
- The remaining time at 180 files/s is evidence (56 ms: about 10 files must be seen before the model is certain)
  and one pass of compute; at 2 files/s it is all evidence. The model needs 4 files with a suffix rename (72
  events, 1.5 s at 2 files/s); scoring earlier returns benign (`--trace` shows risk 0.07 at 3 files). Going below
  1.5 s needs a model that decides on fewer files, which is a training question.
- Redis stages are fakeredis numbers (a publish pipeline is 5 to 9 ms here, about 1 ms on a real Redis). Kube
  stages use the fixed 5 ms per call. Fusion's 19 ms is three sequential kube round trips on a cold path
  (namespace, pod with its Deployment, ReplicaSet) plus Redis; warm it is one.

## What changed

Security agent:

- A rename that adds a suffix (`a.txt` to `a.txt.locked`; rotations `x.log` to `x.log.1` do not count) marks the
  pod hot: it is scored at once, not at the next burst or timer tick, held only to `HOT_INTERVAL_S` (0.05 s)
  since its last scoring. A pod whose last score was at or above the publish risk is re-scored at the same pace.
  Everyone else keeps `POD_MIN_INTERVAL_S` (0.5 s) and `MIN_TICK_S`. A failed window keeps its backoff.
- The pause between evaluation rounds ends as soon as a pod turns hot (`hot_seen`), and is `HOT_TICK_S` (20 ms)
  while a hot pod is waiting for its slot.
- The owner (Deployment) of a hot pod is looked up while its features and score are computed, so the publish does
  not wait for two kube reads.
- The tail waits on an inotify watch of the events directory instead of sleeping 0.2 s; without inotify it polls
  every `IDLE_POLL_S` as before.
- The TreeSHAP explainer is built at startup.
- In a cluster the owner lookup is two GETs over aiohttp (`KubeLite`) and `kubernetes_asyncio` is not imported at
  all (`agents.common.load_kube_config` imports it lazily). Outside a cluster `main()` still uses the full client.

Fusion: security events have their own consumer (a side task on `STREAM_SECURITY`; the main loop reads
`STREAM_HEALTH`), so a patch, an approval-triggered action or a slow health event never delays a kill. Events of the
same workload still run one at a time (`_one_at_a_time`), which keeps pairing and the act-once markers as they were.

Inference service: explainer built at startup.

## CPU and RSS

| | before | after |
|---|---|---|
| security agent, RSS after import (sklearn absent, as in the agents image) | 118 MB | 85 MB |
| security agent, import time | 1.08 s | 0.85 s |
| security agent, idle CPU | 0.4 to 0.5 % | 0.3 to 0.5 % |
| security agent, 10k events/s over 50 pods, CPU | 10.0 to 10.4 % | 10.3 to 10.9 % |
| security agent, peak RSS above idle at 10k events/s | +50 MB | +50 MB |
| fusion and health agent, RSS after import | 102 and 101 MB | unchanged |

The 33 MB comes from not importing `kubernetes_asyncio.client` (34 MB, every generated model) in the security agent,
which runs on every node. The 10k events/s cost is parse (5 us per event), ingest (1.8 us) and features (4 ms per
512-event window); the hot trigger changes it by less than the noise. Windows hold at most 512 events per pod and
are dropped after 300 s idle; that bound is what the +50 MB is.

Fusion CPU was not measured: fakeredis' TCP server does not block, so the consumer spins and the number is an
artifact.

## Tried and rejected

| idea | why not |
|---|---|
| TreeSHAP after the publish | 3.7 of 5.3 ms (unloaded) of one scoring: about 3 % of the path. Fusion builds the action's summary from `top_factors`, so a kill would lose its explanation. |
| uvloop | 10.9 vs 10.4 % CPU and 9.9 vs 10.0 % at 10k events/s: within noise, far below the 10 % bar. No dependency added. |
| quarantine label and policy after the delete | They isolate the pod while the kubelet tears it down, and when the freeze cannot happen (no agent on the node, `not_on_node`). It would save one kube round trip on the delete only; the freeze time does not depend on it. |
| freeze in parallel with fusion's reads | The protected label, the incident lock and the circuit breaker must be checked before any cluster mutation; freezing a protected pod for 20 ms and thawing it is a violation, and a freeze with no kill (breaker open) is the worse outcome. |
| prefetching the namespace tier and ReplicaSet in parallel | Saves one kube round trip only on a cold cache (5 min TTL); the warm path is already one. |
| lower `BLOCK_MS`, throttled `XAUTOCLAIM` | XREADGROUP BLOCK returns on the XADD; the autoclaim is one extra round trip off the critical path. |
| inlining `_field` calls in `parse_line` | About 1 us of 7 per event; 0.7 % CPU at 10k events/s. |
| orjson in more places | The agent's hot paths (Falco parse, capture, sensor stats) already use it; what is left on the kill path is pydantic `from_fields`, in `kubeheal/contracts.py`. |

## Recommendations

Image builder (applied; local docker, amd64, `docker images` sizes):

| image | before | after | what changed |
|---|---|---|---|
| agents | 464 MB | 335 MB | scipy trimmed to `scipy.sparse` (-90 MB: lightgbm imports only that), numpy.libs/lightgbm/kubernetes_asyncio stay |
| inference | 425 MB | 296 MB | same scipy trim |
| dashboard | 249 MB | 180 MB | numpy moved out of the core dependencies into the `inference`/`agents`/`training` extras (the dashboard never imports it) |
| sensor | 40 MB (current Dockerfile, distroless/cc); an older local tag was 116 MB | unchanged | |
| chaos | 175 MB | unchanged | |

- The agents image has no scikit-learn, pandas or FastAPI (checked: the three agent modules import, `import sklearn` fails).
  The Dockerfiles run a LightGBM train + predict + TreeSHAP check in the final stage, so an upgrade that needs more of scipy fails the build.
- `MALLOC_ARENA_MAX=2` is not set: 3 % on the security agent's peak (298 to 288 MB, measured above), and on the inference
  image none (124 vs 125 MiB under load) with 16 % lower throughput (570 vs 690 rows/s, 64-row batches, 2 CPUs).
  `OMP_NUM_THREADS=1` made no difference (the bundle already scores with one thread).
- One agents image serves three processes; the security agent no longer needs the Kubernetes client but fusion and
  health do, so splitting the image would save disk, not RSS.
- Byte-compile at build time (`python -m compileall`) to shorten the 0.85 s import on a cold start.
- The security agent's in-cluster lookup uses the service-account token and CA at
  `/var/run/secrets/kubernetes.io/serviceaccount`; `automountServiceAccountToken` must stay on, RBAC is unchanged
  (get pods, get replicasets).

For later work:

- `security_features` is 4 ms of the ~8 ms scoring pass, and `_ext`, `basename` and `_is_note` are called
  repeatedly per path in it. A per-window cache would cut it by about a third; it lives in `kubeheal/features/`
  and must stay identical to the training side, so it was left alone.
- The 1.5 s floor of a slow attack is the model's need for 4 renamed files.
- inotify needs the events directory on the node's own filesystem (tmpfs or hostPath, as shipped); on a network
  filesystem the agent falls back to the 0.2 s poll.

## What was not measured

Real cluster, real Redis, real kube API latency (a fixed 5 ms per call here), the sensor and Falco in front of the
file, fusion CPU, and false-positive exposure of the hot trigger on live benign workloads. For the last one: the
model rates none of the 43,148 benign rows of `training/data/security_lab.jsonl.gz` as a kill (3455 of 3458
ransomware rows are), and the trigger only samples more windows, it does not change what the model says about one.
