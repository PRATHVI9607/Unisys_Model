# KubeHeal

**Autonomous configuration-drift and ransomware remediation for Kubernetes.**

KubeHeal watches every real Deployment spec change and every pod's file activity, scores them with two
small LightGBM models (with conformal uncertainty and exact TreeSHAP explanations), correlates the two
signals per workload, and a single fusion agent acts: it quarantines and deletes a pod that behaves
like ransomware, rolls a drifted Deployment back to its last known-good template, or hands the case
to a person. Every decision is published to a live dashboard with a plain-English rationale.

```mermaid
flowchart LR
  subgraph sources["Cluster signals"]
    direction TB
    API["kube-apiserver<br/>Deployments · Pods"]
    PROM["Prometheus<br/>cAdvisor · kube-state-metrics · app /metrics"]
    FALCO["Falco DaemonSet (modern eBPF)<br/>KubeHeal rule → events.jsonl on the node"]
    PROC["Node /proc<br/>written files · pod cgroup io.stat · pod net/dev"]
  end

  subgraph kh["namespace kubeheal"]
    direction TB
    HA["health-agent<br/>Deployment ×1"]
    SA["security-agent<br/>DaemonSet, one per node"]
    INF["inference :8000<br/>LightGBM · split-conformal · TreeSHAP"]
    R[("Redis 7 streams + keys<br/>kubeheal.health.events<br/>kubeheal.security.events<br/>kubeheal.actions · kubeheal.deadletter<br/>kubeheal:spec / baseline / lock / cb")]
    FU["fusion-agent ×1<br/>correlation · decision policy · actions"]
    DB["dashboard :8080<br/>read-only console"]
  end

  API -- "watch Deployments,<br/>list pods" --> HA
  PROM -- "query_range<br/>[change, assess time]" --> HA
  FALCO -- "tail JSON lines" --> SA
  PROC -- "entropy · bytes written · bytes out" --> SA
  HA -- "POST /v1/health/predict" --> INF
  SA -- "POST /v1/security/predict" --> INF
  HA -- "HealthEvent · spec + baseline" --> R
  SA -- "SecurityEvent (risk ≥ 0.4)" --> R
  R -- "XREADGROUP fusion" --> FU
  FU -- "ActionEvent" --> R
  FU == "AUTO_KILL: label · deny-all NetworkPolicy · delete pod<br/>AUTO_PATCH: restore baseline /spec/template" ==> API
  R -- "XREAD + WebSocket" --> DB
```

## Capabilities

| | What it does |
|---|---|
| **Config-drift detection** | The health agent assesses a Deployment 60 s after a real spec change (at once on a posture violation, within about 2 s of a failed rollout appearing): 24 spec-diff features plus 12 features of the post-change Prometheus window (CPU/memory utilisation, throttling, p99 latency, 5xx ratio, restarts, ready ratio). |
| **Rule-based rollback** | Hard rollout failures after a change trigger AUTO_PATCH by rule, at any tier and any model confidence. These are pods created after the change stuck in `ImagePullBackOff`, `ErrImagePull`, `InvalidImageName`, `CrashLoopBackOff`, `CreateContainer*Error`, `RunContainerError` or `OOMKilled`, and `ProgressDeadlineExceeded` on the rollout. The model handles subtle drift: throttling, latency, memory pressure. |
| **Ransomware-like behaviour** | The security agent tails Falco file syscalls on data volumes, samples the entropy of files the pod wrote, measures the pod's write and network-out bytes, and scores a per-pod 60 s window every 1 s, or at once at 32 new events. |
| **Correlation** | A deterministic score joins a health and a security event of the same workload within 120 s. A compound incident raises both scores by ×1.15. |
| **Explanations** | Every event carries class probabilities, the conformal prediction set and the top 5 TreeSHAP factors. Every action carries a rationale and a summary. |
| **Remediation** | AUTO_KILL: label the pod `kubeheal.io/quarantined`, create a deny-all NetworkPolicy owned by the pod, delete it. AUTO_PATCH: JSON-patch `/spec/template` (and `/spec/replicas` if it changed) back to the stored baseline. |

### Safety rails

These are always on:

- **One actor.** Only the fusion agent can change the cluster. Its RBAC covers pods (get, patch, delete), Deployments (get, patch), NetworkPolicies (create) and nothing else.
- **Observe by default.** In code, `KUBEHEAL_MODE` defaults to `observe` (decide and publish `would_*`, change nothing). The shipped manifest sets `enforce`.
- **Protected scope.** KubeHeal never acts in `kube-system`, `kube-public`, `kube-node-lease`, `kubeheal`, any namespace in `EXTRA_PROTECTED_NAMESPACES`, or on objects labelled `kubeheal.io/protected=true`.
- **Confidence gates.** A model-driven AUTO_* decision needs an adjusted score of at least 0.85 and a single-label conformal set. Dev-tier namespaces (×0.7) can never reach that score, so only the rollback rule acts there.
- **Blast radius.** Quarantine is per pod and is garbage-collected with the pod. A per-workload incident lock prevents overlapping actions, and per-workload hourly circuit breakers apply (3 kills, 5 patches).
- **No invented data.** No action is taken without a real event, a pod or a stored baseline. A missing pod or baseline escalates to HUMAN.

## Quickstart (minikube)

You need `uv`, `kubectl`, `helm` and `minikube` (or `docker` plus any cluster). The lab runs were
measured on an 8 CPU / 8 GB minikube.

```bash
minikube start --cpus=8 --memory=8g
uv sync --all-extras                 # Python 3.13 env from pyproject.toml + uv.lock
uv run --all-extras pytest && uv run --all-extras ruff check . # tests + lint

./deploy/scripts/install.sh   # builds 4 images, installs Prometheus + Falco (Helm), kubectl apply -k deploy/k8s/, demo app
./deploy/scripts/demo.sh      # A) CPU-limit drift → health → decision   B) detection-test workload → AUTO_KILL
./deploy/scripts/reset.sh     # back to a clean demo baseline (streams, keys, circuit breakers, victim app)
```

To open the dashboard, run `kubectl -n kubeheal port-forward svc/kubeheal-dashboard 8080:8080` and go
to <http://localhost:8080>. `demo.sh` starts this port-forward for you.

The fusion agent ships in **enforce** mode, so the demo really patches and kills inside the `demo`
namespace. Install, demo, dashboard, lab collection and troubleshooting are covered in
[docs/operations.md](docs/operations.md).

## Repository layout

| Path | What |
|---|---|
| `kubeheal/contracts.py` | The single source of truth: stream names, Redis keys, labels, event models |
| `kubeheal/features/` | Feature code shared by training and the live agents (train/serve parity) |
| `kubeheal/ml/` | `ModelBundle`: LightGBM + split-conformal + TreeSHAP |
| `kubeheal/correlation.py` | Deterministic compound-incident score |
| `kubeheal/inference/app.py` | FastAPI inference service (:8000) |
| `agents/{health,security,fusion}_agent/`, `agents/common.py` | The agents. Fusion owns every cluster mutation |
| `dashboard/` | Read-only FastAPI + JS console (:8080) |
| `training/` | `train.py`, dataset adapters, synthetic security generator, lab collectors (`collect/`) |
| `models/{health,security}/` | Trained bundles (`model.txt` + `meta.json`) baked into the inference image |
| `deploy/k8s/` | Kustomize: `base/` manifests + RBAC (default dev install), `overlays/production` (no dashboard, inference HPA/PDB, PriorityClass); Falco rule, Helm values for Prometheus and Falco |
| `deploy/docker/` | 4 images: `inference`, `agents` (all three agents), `dashboard`, `chaos` |
| `deploy/scripts/` | `install.sh`, `demo.sh`, `reset.sh`, `seed_demo.sh` |
| `deploy/chaos/`, `deploy/demo/` | Non-destructive detection-test workload; demo app (podinfo + load generator) |
| `tests/` | pytest suite, including the train/serve contract tests |

## Configuration

These are the main settings. The full per-component table is in
[docs/architecture.md](docs/architecture.md#runtime-configuration).

| Env var | Default | Effect |
|---|---|---|
| `KUBEHEAL_MODE` | `observe` (manifest: `enforce`) | `observe` publishes `would_*` decisions and changes nothing |
| `MAX_KILLS_PER_HOUR` / `MAX_PATCHES_PER_HOUR` | `3` / `5` | Per-workload circuit breakers |
| `EXTRA_PROTECTED_NAMESPACES` | empty | Namespaces added to the built-in protected set |
| `WATCH_NAMESPACES` | empty (all) | Limits the health and security agents to these namespaces |
| `ASSESS_DELAY_S` | `60` | Length of the post-change metric window before a health assessment (sooner on a posture violation or failed rollout) |
| `KUBEHEAL_CAPTURE` | `0` | `1` makes the security agent record every scored window (lab collection only) |

The namespace label `kubeheal.io/namespace-tier: prod|staging|dev` sets the tier multiplier. Without
the label, the tier is guessed from the namespace name.

## Results

Measured on 2026-11-07 on minikube (8 CPU / 8 GB, one node); bundles `health-5.0.0-37c9309f` and
`security-5.0.0-ca2438d3`. The ransomware data comes from **one simulator** (`deploy/chaos/`), and the security
data is **partly synthetic**: `suspicious` and `exfiltration` windows are generated, so those two classes are
unvalidated on real traffic. Treat the near-perfect security scores as "separable in the lab", not as field accuracy.

| | Health | Security |
|---|---|---|
| Training data (rows / groups) | 2,519 lab rows / 237 groups (+2,519 metric-dropout copies, fit only) | 40,286 rows / 1,663 groups: 37,406 lab windows (benign, ransomware) + 2,880 synthetic (7.2 %: suspicious and exfiltration, plus 1,369 benign hard-negative windows = 3.9 % of benign) |
| Grouped-CV macro-F1 | 0.922 (spec-changed rows, n = 2,279) | 0.9996 (n = 36,355) |
| Held-out test macro-F1 | 0.939 (n = 240) | 1.000 (n = 3,931) |
| Held-out-family macro-F1 (pooled) | 0.851 | 0.999 over benign + ransomware (meta.json shows 0.50: it scores the two synthetic-only classes as 0). Pod level: no benign lab family is killed when held out, see [limitations](docs/models-and-data.md#known-limitations) |
| Conformal coverage / mean set size (α = 0.1) | 0.900 / 0.93 | 1.000 / 1.00 |
| Inference latency p50 / p99 (incl. TreeSHAP) | 1.9 / 2.3 ms | 10.4 / 12.6 ms |

| End-to-end (demo, minikube, enforce mode) | Time |
|---|---|
| Detection-test workload first overwrite → pod killed, 20 files/s created then encrypted at once (5 runs) | median 8.85 s (8.73 to 8.96 s); 2.25 s before the hard-negative hardening |
| Same, default 180 files/s (3 runs) | median 1.33 s (1.17 to 1.34 s); 0.67 s before the hardening |
| Same, 20 files/s after a 65 s quiet gap, as in the lab data (2 runs, measured with `a49c7ed8`) | 0.26 s and 0.75 s |
| Spec change → AUTO_PATCH (rule path: bad image, `ErrImagePull`) | 6 s |
| Spec change → AUTO_PATCH (model path: CPU limit 500m → 20m) | not reached: HUMAN after 62 s (degradation risk 0.60, adjusted 0.72 < 0.85) |

Resources and kill latency under the 300 s heavy-I/O load (`deploy/scripts/bench.sh`, 5 runs; kill time is
measured from the workload's first malicious operation):

| | Previous bench (interim security model) | This bench |
|---|---|---|
| Falco CPU p50 / max | 60m / 135m | 49m / 49m |
| Falco memory p50 | 212 Mi | 195 Mi |
| Security agent CPU p50 / max | 10m / 26m | 8m / 9m |
| Security agent memory p50 | 88 Mi | 84 Mi |
| Inference CPU p50 / max (total) | 6m / 15m | 6m / 6m |
| Falco events file growth | 8.0 KB/s | 8.9 KB/s |
| Kills / kill time median (20 files/s) | 5 / 9.5 s | 5 / 8.85 s |

Tier 1 capture (no `read`/`write` hooks) cut Falco from 1985m CPU p50 and 565 Mi to the numbers above under the same load. Details in [docs/architecture.md](docs/architecture.md#resources).

How the models are trained and evaluated is described in
[docs/models-and-data.md](docs/models-and-data.md).

## Limitations

- **Exfiltration is unvalidated.** The `exfiltration` class (and `suspicious`) is trained only on synthetic windows. The serve-time byte counters are real, but no real exfiltration was ever observed.
- **One workload and one node.** Health lab data comes from one workload type (podinfo) on a single-node minikube. Effects on a multi-node cluster under real traffic can differ.
- **Simulated ransomware.** Ransomware windows come from one parameterised, non-destructive simulator, not from real malware families.
- **60 s window.** Health is judged on the first 60 s after a change. Harm that appears later (slow leaks) is missed.
- **Pre-existing drift.** The first spec the health agent sees is assumed good and becomes the baseline, so drift that predates the agent is not detected.
- **Redis is a single point of failure.** It runs without persistence. On a restart the streams and baselines are lost, and baselines are re-learned on first sight.

## License

RVCE · Unisys UIP. Built for Unisys "Agents Unleashed".

Team: Ryan Dave Fernandes · P Koti Darshan · Rakshak S. Mentor: Dr. Mohana.
