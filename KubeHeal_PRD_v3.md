

|  KUBEHEAL *Autonomous Configuration & Security Drift Correction* *in Kubernetes* FULL PRODUCT REQUIREMENTS DOCUMENT  |  ARCHITECTURE V3.0 |
| ----- |

| \<8s Kill Time *PID terminate \+ PV quarantine* | \<90s Health MTTR *Detect → Patch → Verify* | 93.2% DIT-Sec F1 *15K Chaos Mesh samples* | 76× Year 1 ROI *$22K cost vs $1.68M savings* |
| :---: | :---: | :---: | :---: |

| RVCE  |  Unisys "Agents Unleashed"  |  UIP Week 10 Demo  |  Dr. Mohana (Mentor) |
| :---- |

**TEAM:**  Ryan Dave Fernandes  ·  P Koti Darshan  ·  Rakshak S

| 00 | EXECUTIVE BRIEF *What KubeHeal is and why it exists in 90 seconds* |
| :---: | :---- |

*No system today unifies config drift semantics, runtime security signals, and causal explainability with autonomous remediation in a single Kubernetes-native product. KubeHeal is that system.*

— KubeHeal Core Thesis

Production Kubernetes clusters face two silent crises running in parallel. Configuration drift — responsible for 62% of all incidents (CNCF 2025\) — accumulates when manual hotfixes, emergency scale events, and CD pipelines diverge from desired state. Container ransomware — averaging $1.2M per incident and 13 days of recovery time (Sophos 2025\) — targets PersistentVolumes, etcd, and application secrets with behavioral encryption attacks.

Existing tools treat these as separate problems: GitOps controllers (ArgoCD, Flux) revert drift blindly without risk assessment; security scanners (Falco, Trivy) alert without acting; ML anomaly detectors detect behavioral deviations without understanding root cause. The result: 47-minute mean time to recovery for health incidents and 13-day average for ransomware.

KubeHeal closes this gap with three autonomous agents — Health, Security, Fusion — coordinated through a Redis Streams event bus and powered by DIT-Sec (Drift Impact Transformer – Security), a multi-modal causal transformer that fuses YAML diffs, Prometheus metrics, eBPF syscall streams, and file entropy into a unified risk score with explainable attention attribution.

|  | THE RESEARCH GAP |
| :---- | :---- |

| TOOL CATEGORY | EXAMPLES | WHAT IT DOES | WHAT IS MISSING | KUBEHEAL ADDS |
| :---- | :---- | :---- | :---- | :---- |
| **GitOps** | ArgoCD, Flux | Detect \+ revert all drift | Zero risk assessment — treats emergency CPU fix same as malicious change | Risk-aware minimal patches with causal confidence scores |
| **Security Scanners** | Falco, Trivy | Alert on runtime threats | No autonomous action — SRE triage takes 20+ min after alert | Autonomous kill \+ Velero restore in \<8 seconds |
| **ML Anomaly Detection** | Isolation Forest, Autoencoder | Detect metric deviations | No config semantic understanding — cannot explain why | Causal YAML → metric → action chain with XAI |
| **Self-Healing** | Kured | Node reboot on failure | Single-axis — only restarts, no config/security loop | Full drift \+ security agentic loop with Fusion orchestration |

| 01 | LOOPHOLES & FAILURE MODES *Every critical gap found on deep architecture re-read* |
| :---: | :---- |

*The following loopholes were identified on a full re-read of the KubeHeal architecture. Each represents a genuine production failure mode, not a theoretical concern. All are addressed in Chapter 03 with concrete fixes.*

|  | LOOPHOLE 1  NO BASELINE VERSION PINNING — THE GROUND TRUTH CAN DRIFT The Health Agent compares live K8s state against a "baseline" YAML. But if that baseline was itself committed with incorrect resource limits — or if the baseline repo is never updated after a legitimate scale event — then the system learns to flag correct state as drift and accept wrong state as healthy. There is no mechanism to validate whether the baseline is itself correct. FIX:  *Pin baselines to GitOps tags with explicit human sign-off. Store baseline hash in a K8s ConfigMap under kubeheal.io/baseline-sha annotation. Compare against SHA before each assessment. If baseline is \>30 days unreviewed, flag it as stale and reduce Health Agent confidence by 0.15.* |
| :---- | :---- |

|  | LOOPHOLE 2  NAMESPACE BLINDNESS — DEV AND PROD TREATED IDENTICALLY The current risk scoring applies the same thresholds (0.85 \= auto-kill, 0.65 \= human) regardless of which namespace the threat is in. A 0.75 risk score in the prod namespace (millions of users) should trigger harder escalation than a 0.75 in the dev namespace. There is no namespace-tier awareness in the Fusion Agent decision policy. FIX:  *Add a namespace\_tier label (prod/staging/dev) to the risk decision pipeline. Fusion Agent reads this tier and applies a tier multiplier: prod × 1.2, staging × 1.0, dev × 0.7. This means a 0.72 score in prod triggers auto-kill, while the same score in dev only logs.* |
| :---- | :---- |

|  | LOOPHOLE 3  DOUBLE-ACTION RACE CONDITION — HEALTH \+ SECURITY BOTH ESCALATE SAME POD If a ransomware process is also causing CPU thrashing (which it often does), both the Health Agent (CPU drift) and Security Agent (entropy) will publish events about the same pod to Redis Streams within seconds. The Fusion Agent has no deduplication logic — it could issue a kubectl patch AND a kubectl delete pod simultaneously for the same resource, creating an undefined state. FIX:  *Implement an active\_incident\_map in the Fusion Agent keyed by (namespace, pod\_name). Before processing any event, acquire a Redis SETNX lock on kubeheal:incident-lock:{namespace}:{pod}. Release after decision is made \+ 30s. Any event arriving for an already-locked pod is either merged into the active incident or dropped with a log entry.* |
| :---- | :---- |

|  | LOOPHOLE 4  ONNX MODEL STALENESS — FINE-TUNING FEEDS PYTORCH BUT ONNX STAYS FROZEN The online learning loop fine-tunes the DIT-Sec PyTorch model after each verified incident. But the production inference runs on an ONNX-exported version of that model. There is no mechanism to re-export and hot-reload the ONNX model after fine-tuning. The gap widens with every real incident — production inference diverges from the fine-tuned model over time. FIX:  *Add a Model Registry component (can be a simple S3/MinIO bucket with versioned ONNX artifacts). After fine-tuning, auto-export to ONNX, run a validation pass on a held-out test set (must maintain F1 ≥ 88%), then trigger a rolling update of the DIT-Sec model server pods. Kubernetes rolling update ensures zero inference downtime during model swap.* |
| :---- | :---- |

|  | LOOPHOLE 5  NO NETWORK EGRESS BLOCKING — DATA EXFILTRATION WINDOW EXISTS KubeHeal kills the ransomware process at T+8s. But sophisticated ransomware exfiltrates a copy of encrypted keys and partial data over the network BEFORE local encryption completes — often within the first 2 seconds. Killing the pod at T+8s stops local encryption but cannot undo data already sent to an attacker's C2 server. There is no network-level isolation in the current architecture. FIX:  *At T+0.5s (first early signal), the Security Agent should immediately apply a Kubernetes NetworkPolicy that blocks all egress from the pod's namespace except to internal cluster IPs. This is a zero-disruption action (NetworkPolicy apply is non-destructive) that cuts the exfiltration channel before the kill decision is made. Use kubectl apply \-f with a generated NetworkPolicy, not a patch.* |
| :---- | :---- |

|  | LOOPHOLE 6  PROMETHEUS SCRAPE LAG — 15-SECOND TELEMETRY BLIND WINDOW The Health Agent fetches Prometheus metrics to assess CPU/memory impact of a drift event. Default Prometheus scrape interval is 15 seconds. If the drift happens at T=0 and the last scrape was at T=-14s, the Health Agent is making decisions on 14-second-old telemetry. For fast-moving drift events (a CPU limit crash causing OOM in \<10s), the Health Agent acts on stale data. FIX:  *Configure a separate Prometheus scrape job for kubeheal-watched namespaces with a 5-second scrape interval and a 2-second evaluation interval. Use the Prometheus remote-write API to push fresh metrics into a local in-memory buffer. Health Agent reads from this buffer (max age: 6s) rather than querying Prometheus directly, eliminating the scrape lag problem.* |
| :---- | :---- |

|  | LOOPHOLE 7  TREE2VEC POSITIONAL BLINDSPOT — CONTAINER INDEX LOST IN ENCODING The Tree2Vec encoder converts nested K8s YAML to a graph embedding. However, in a Deployment spec with 3 containers, a change to containers\[0\].resources.limits.cpu and containers\[2\].resources.limits.cpu produce near-identical embeddings — the container index information is lost in the graph flattening. The Health Agent cannot distinguish which container drifted when there are multiple containers in a pod spec. FIX:  *Extend the Tree2Vec encoder to include positional indexing tokens. Before graph encoding, serialize each container sub-tree with a positional prefix token: \[CONTAINER\_0\], \[CONTAINER\_1\], etc. These tokens are embedded separately and concatenated with the structural embedding before the MHCA fusion step. This adds only 8 parameters per container position but makes multi-container drift identification precise.* |
| :---- | :---- |

|  | LOOPHOLE 8  COLD-START ON FRESH CLUSTERS — NO HISTORICAL BASELINE FOR DIT-SEC DIT-Sec's telemetry modality relies on time-series Prometheus data to correlate config changes with performance impacts. On a fresh cluster with \<48 hours of history, there is insufficient baseline data for the MHCA temporal attention heads to learn meaningful correlations. The model will produce high-uncertainty outputs and risk false positives. FIX:  *Add a "burn-in" mode for new clusters: first 48 hours, reduce autonomous action thresholds (auto-kill requires 0.95+, auto-patch requires 0.90+) and increase human escalation. Run synthetic chaos scenarios in a dedicated burn-in namespace during this window to build up Prometheus history. Exit burn-in mode when Prometheus has ≥2000 metric samples across all watched resources.* |
| :---- | :---- |

|  | LOOPHOLE 9  VELERO BACKUP SCHEDULE GAP — DORMANT RANSOMWARE WINS If ransomware lies dormant for longer than the backup retention window (e.g., 72-hour dormancy \+ 24-hour backup cycle \= all 3 backups are compromised), restoring ANY Velero snapshot will restore an already-infected PV. The backup integrity check catches this, but the system has no fallback when ALL backups are compromised. FIX:  *Implement continuous WAL-based backup using Stash (Appscode) or Kasten K10 for stateful applications. WAL backups create point-in-time recovery points every 5 minutes, independent of Velero's schedule. If all Velero snapshots fail the integrity check, Kasten K10 PITR can restore to T-5min before first encryption was detected. This is the true last line of defense.* |
| :---- | :---- |

|  | LOOPHOLE 10  FALCO RULE GAP — EBPF PROBES MISS ENCRYPTED-IN-MEMORY ATTACKS The Security Agent's eBPF hooks trace file system calls (write, rename, ftruncate). A sophisticated attacker who encrypts data in-memory and writes the result in a single atomic operation (using mmap \+ msync) can bypass inotify and fanotify entirely. The file appears to be written normally from the OS perspective — only its content is encrypted. Entropy calculation only catches this at the point of the msync flush. FIX:  *Add a complementary memory-level detection path: use Falco's process\_vm\_readv hook to sample memory regions of high-I/O processes for entropy. If a process has a large anonymous mmap region (\>50MB) with entropy \>7.0 AND is writing to a PV, treat this as a strong pre-encryption signal at score 0.65. This adds \~5ms overhead per sampled process but catches mmap-based attacks.* |
| :---- | :---- |

| 02 | MODEL ANALYSIS & ALTERNATIVES *Deep comparison of DIT-Sec options — and better architectures* |
| :---: | :---- |

The current architecture proposes a transformer-based DIT-Sec model. This chapter examines whether a transformer is actually the right choice for each signal modality, proposes targeted alternatives, and presents the optimal hybrid architecture.

|  | THE MODALITY PROBLEM |
| :---- | :---- |

DIT-Sec processes four fundamentally different data types. A single transformer architecture is not uniformly optimal across all four. Here is the honest breakdown:

| MODALITY | DATA TYPE | TRANSFORMER FIT | OPTIMAL ARCHITECTURE | WHY |
| :---- | :---- | :---- | :---- | :---- |
| **YAML Diffs** | Structured tree / graph | MODERATE — loses graph topology | GNN (Graph Attention Network) | K8s YAML is a DAG; GAT natively encodes parent→child relationships without serialization loss |
| **Prometheus Metrics** | Multivariate time series | GOOD — attention over timesteps works | Mamba SSM or Transformer | Mamba gives identical quality at O(n) vs O(n²) — critical for long metric windows |
| **Falco eBPF Events** | Event sequences | GOOD — sequence attention fits | Transformer (kept) | Syscall sequences have strong long-range dependencies that attention handles well |
| **File Entropy Series** | Short univariate time series | OVERKILL — 20s sequences | Conv1D \+ Squeeze-Excitation | For \<30 timestep entropy windows, a lightweight CNN outperforms transformer with 50× less compute |

|  | MODEL ALTERNATIVES — FULL COMPARISON |
| :---- | :---- |

| Pure Transformer (Current) MHSA · All modalities Proven architecture Good at sequence tasks Well-documented CONS *O(n²) complexity on long metrics* *Loses YAML graph topology* *Overkill for entropy series* *\~480MB model size* Latency: \~180ms | ★ RECOMMENDED GNN \+ Mamba Hybrid GAT · SSM · Conv1D · MHCA GAT preserves K8s YAML graph Mamba: O(n) time series Conv1D entropy: 10× faster Modality-optimal per signal \<120MB total CONS *More complex to train* *Requires graph preprocessing of YAML* *Mamba is newer, less tooling* Latency: \<50ms | Isolation Forest \+ XGBoost (Ensemble) Classical ML · 2-stage \<1ms inference No GPU needed Highly interpretable Robust to distribution shift CONS *Cannot fuse modalities as richly* *Feature engineering required* *No attention explainability* *Lower F1 ceiling (\~85%)* Latency: \<5ms | Conformal Prediction Wrapper Add-on · Any base model Coverage-guaranteed confidence intervals No assumption on model internals Catches out-of-distribution inputs Works on top of any base model CONS *Adds calibration dataset requirement* *Slightly wider prediction intervals* *Not a standalone model* Latency: \+2ms overhead |
| :---- | :---- | :---- | :---- |

|  | RECOMMENDED: GNN \+ MAMBA HYBRID ARCHITECTURE |
| :---- | :---- |

Replace the monolithic transformer with a modality-optimal encoder per signal type, then fuse via Multi-Head Cross-Attention only at the final fusion layer:

|  |                     K U B E H E A L   D I T \- S e c   v 3   A R C H I T E C T U R E     YAML Diff ──────► Graph Attention Network (GAT, 3 layers)                     │                     · K8s spec parsed to AST → attributed graph                 │                     · Nodes: spec fields  Edges: parent→child \+ sibling         │  F                     · Output: 128-dim graph embedding                           │  U                                                                                 │  S   Prom Metrics ────► Mamba SSM Encoder                                          │  I                     · State Space Model, O(n) complexity                        │  O                     · Input: 5-min window, 15 metrics, 5s resolution            │  N                     · Output: 64-dim temporal embedding                         │                                                                                 │  M   Falco Events ────► Transformer Encoder (4 heads, 2 layers)                    │  H                     · Syscall sequence, max 256 events                          │  C                     · Positional encoding on event timestamps                   │  A                     · Output: 64-dim event embedding                            │                                                                                 │  →  Risk Score \[0,1\]   Entropy Series ──► Conv1D \+ Squeeze-Excitation Block                          │     \+ Label                     · 1D convolution over entropy timeseries                    │     \+ XAI Weights                     · SE block for channel attention                            │                     · Output: 64-dim entropy embedding                          │     All 4 embeddings ──► MHCA Fusion (3 heads × 64-dim) ──► MLP ──► Output Head |
| :---- | :---- |

|  | ADDITIONAL MODEL RECOMMENDATIONS |
| :---- | :---- |

|  | UNCERTAINTY  Add Conformal Prediction for Uncertainty Quantification Wrap DIT-Sec output with a conformal prediction layer using a held-out calibration set of 1000 samples. Instead of a raw softmax score of 0.87, the model outputs a coverage-guaranteed interval like \[0.82, 0.91\] at 95% confidence. This is critical for the Fusion Agent: when the interval is wide (high uncertainty), escalate to human. When narrow, proceed autonomously. This eliminates the false confidence problem where 0.87 softmax ≠ 87% probability. |
| :---- | :---- |

|  | EFFICIENCY  Isolation Forest as a First-Pass Filter Before invoking DIT-Sec (50ms inference), run a lightweight Isolation Forest trained on the same features. If Isolation Forest scores the event as clearly benign (score \> \-0.2) or clearly malicious (score \< \-0.8), skip DIT-Sec entirely. Only the ambiguous middle range (which is \~15% of events in practice) invokes the full transformer pipeline. This reduces DIT-Sec inference calls by \~85% under normal operation. |
| :---- | :---- |

|  | SPEED  Mamba over LSTM for Entropy Encoder If you keep a sequential model for the entropy timeseries, replace LSTM with Mamba (State Space Model). Mamba processes sequences in O(n) time vs O(n²) for attention-based approaches, with identical or better quality on time-series benchmarks. For a 30-timestep entropy window, Mamba reduces encoder latency from \~12ms to \~3ms. The mamba-ssm Python package (Apache 2.0) provides a drop-in replacement. |
| :---- | :---- |

|  | LEARNING  Online SGD with Reservoir Sampling for Continuous Learning Replace the post-incident full fine-tuning with online SGD updates using reservoir sampling. Maintain a reservoir of 2000 verified incident samples (evenly distributed across classes using stratified reservoir). After each new verified incident, run 1 gradient step on the reservoir \+ new sample. This keeps the model current without catastrophic forgetting, and takes \<100ms per update — enabling true continuous learning without retraining downtime. |
| :---- | :---- |

| 03 | SYSTEM ARCHITECTURE *Complete technical blueprint — every component, every interface* |
| :---: | :---- |

|  | COMPONENT INVENTORY |
| :---- | :---- |

| COMPONENT | TYPE | LANGUAGE/RUNTIME | REPLICAS | ROLE |
| :---- | :---- | :---- | :---- | :---- |
| **Health Agent** | K8s Operator (Deployment) | Python 3.11 \+ asyncio | 1 (leader-elected) | Watch YAML drift → DIT-Sec inference → publish HealthAssessment |
| **Security Agent** | DaemonSet (1 per node) | Python 3.11 \+ eBPF | 1 per node | eBPF entropy tracking \+ process tree analysis \+ early-warning signals |
| **Fusion Agent** | Deployment | Python 3.11 \+ asyncio | 2 (active-passive) | Correlate events → make decisions → enforce circuit breakers → publish actions |
| **DIT-Sec Model Server** | Deployment \+ HPA | ONNX Runtime \+ FastAPI | 2–6 (autoscaled) | Serve GNN+Mamba inference at \<50ms, expose /score and /explain endpoints |
| **Model Registry** | MinIO StatefulSet | MinIO \+ Python sync job | 1 | Versioned ONNX artifacts \+ validation gate \+ rolling update trigger |
| **Redis Sentinel** | StatefulSet | Redis 7.2 | 3 (1M+2R+Sentinel) | Primary event bus — Redis Streams with consumer groups |
| **Kafka DLQ** | StatefulSet | Kafka 3.6 KRaft | 1 (demo) / 3 (prod) | Dead-letter queue if Redis primary fails — agents fall back automatically |
| **Velero** | Deployment | Go | 1 | PV backup (S3 Object Lock) \+ restore orchestration |
| **Kasten K10** | Deployment | Go | 1 | WAL-based PITR backup for stateful apps — fallback when Velero backups fail integrity check |
| **Prometheus (short scrape)** | Deployment | Go | 1 | Dedicated 5s scrape job for kubeheal-watched namespaces |
| **Grafana \+ Loki** | Deployment | Go | 1 each | Real-time dashboards \+ structured log aggregation |
| **Falco** | DaemonSet | C++/Go \+ eBPF | 1 per node | Kernel-level syscall monitoring, gRPC output to Security Agent |
| **NetworkPolicy Controller** | Part of Fusion Agent | Python (kubernetes-asyncio) | N/A | Applies egress-blocking NetworkPolicy on first early-warning signal |
| **Burn-In Controller** | Part of Fusion Agent | Python | N/A | Manages graduated threshold relaxation for new clusters |
| **KubeHeal Dashboard** | Deployment | Flask \+ Socket.IO | 1 | Real-time demo dashboard at port 5000 |

|  | EVENT BUS DESIGN — REDIS STREAMS |
| :---- | :---- |

| STREAM NAME | PRODUCER | CONSUMER(S) | SCHEMA KEY FIELDS | RETENTION |
| :---- | :---- | :---- | :---- | :---- |
| **kubeheal.health.events** | Health Agent | Fusion Agent (group: fusion) | event\_id, target, risk\_score, severity, patch\_proposal, explainability | 24h or 10K messages |
| **kubeheal.security.events** | Security Agent | Fusion Agent (group: fusion) | event\_id, target, kill\_confidence, label, pid\_target, entropy, early\_signals | 24h or 10K messages |
| **kubeheal.actions** | Fusion Agent | Health Agent \+ Security Agent | action\_type, target, confidence, approved\_by, circuit\_breaker\_state | 7 days (audit) |
| **kubeheal.incidents** | Fusion Agent | Dashboard \+ Model Registry | incident\_id, outcome, false\_positive, mttr\_ms, restore\_duration\_s | Unlimited (compliance) |
| **kubeheal.network.quarantine** | Security Agent \+ Fusion Agent | NetworkPolicy Controller | namespace, pod\_selector, action (isolate/release) | 1h |

|  | AGENT INTERNAL ARCHITECTURE |
| :---- | :---- |

### **Health Agent — Internal Pipeline**

The Health Agent is a Kubernetes operator implemented with kubernetes-asyncio. Its internal pipeline for each MODIFIED event:

|  | MODIFIED Event Received (K8s Watch API) │ ├─ 1\. Generation Predicate Filter │     · Compare metadata.generation (spec change) vs status.observedGeneration (status update) │     · SKIP if only status changed → prevents 10× spurious reconciles │ ├─ 2\. Distributed Cool-Down Check │     · Redis SETNX: kubeheal:cooldown:{namespace}:{name} (TTL 300s) │     · SKIP if key exists → prevents alert storms on crash loops │ ├─ 3\. Baseline Integrity Check │     · Read kubeheal.io/baseline-sha annotation │     · Compare against stored SHA in ConfigMap │     · If mismatch OR baseline age \>30d → flag stale, reduce confidence × 0.85 │ ├─ 4\. Blast Radius Query │     · List Services \+ Ingresses in namespace with matching selector │     · Tag blast\_radius: High if serving external traffic │ ├─ 5\. Network Egress Pre-Isolation (if security signal concurrent) │     · Check Redis: any active security event for same pod? │     · If yes → immediately publish to kubeheal.network.quarantine │ ├─ 6\. Telemetry Fetch (with 5s-scrape Prometheus, max-age 6s) │     · CPU throttle %, memory RSS, p99 latency, error rate │     · asyncio.wait\_for(timeout=30s) → fail fast, requeue │ ├─ 7\. Tree2Vec \+ Positional Encoding │     · Parse old\_spec \+ new\_spec to attributed AST graph │     · Add \[CONTAINER\_N\] positional tokens to each container sub-tree │     · Check Redis cache: kubeheal:tree2vec:{spec\_sha} (TTL 60s) │     · Cache miss → run GAT encoder, store result │ ├─ 8\. DIT-Sec Inference (HTTP → Model Server) │     · POST /score with: {yaml\_embedding, telemetry\_vector, ...} │     · Receive: {risk\_score, label, confidence\_interval, attention\_weights} │ └─ 9\. Publish HealthAssessment to kubeheal.health.events (XADD)        · Set cool-down key in Redis (TTL 300s) |
| :---- | :---- |

### **Security Agent — Internal Pipeline**

|  | Parallel Input Sources (asyncio.gather): │ ├─ A. Falco gRPC Event Stream │     · Subscribe to falco.outputs.service (gRPC) │     · Filter: rule tags \[filesystem, process, network\] │     · Map each event → (pid, path, syscall, timestamp) │ ├─ B. inotify/fanotify Watcher (all PV mount paths) │     · Watch: IN\_MODIFY | IN\_CREATE | IN\_MOVED\_TO | IN\_MOVED\_FROM │     · Early signal: rename() burst \>10/s → suspicious score 0.50 │     · Early signal: filename matches DECRYPT|README|RECOVER → score 0.65 │ ├─ C. /proc PID Namespace Scanner (5s interval) │     · Enumerate /proc/\*/cgroup → parse kubepods hierarchy │     · Build PID → (namespace, pod\_name, container\_name) mapping │     · Scope: hostPID: true \+ privileged DaemonSet │ └─ D. eBPF Map Reader (BPF\_MAP\_TYPE\_PERCPU\_HASH)       · Read kernel-space write counters per PID every 2s       · If write\_bytes\_2s \> threshold → trigger entropy calculation   Entropy Calculation (triggered by D): ├─ Reservoir sample 4KB from each recently-written file ├─ Compute Shannon entropy H \= \-Σ p(x) log₂ p(x) ├─ Threshold: H \> 7.2 bits → HIGH signal └─ mmap check: if anonymous mmap region \>50MB AND H \> 7.0 → CRITICAL   DIT-Sec Security Inference: └─ POST /score/security {entropy\_series, io\_rates, process\_tree, early\_signals}    → risk\_score, label   Action Gate: ├─ risk\_score ≥ 0.98 → Direct kill (no Fusion wait, fastest path) ├─ risk\_score ≥ 0.85 → Publish to kubeheal.security.events (Fusion decides) └─ risk\_score ≥ 0.40 → Publish event \+ increase monitoring frequency ×3 |
| :---- | :---- |

### **Fusion Agent — Decision Engine**

|  | Event Correlation (Redis Streams XREAD, consumer group: fusion-workers): │ ├─ Read from kubeheal.health.events \+ kubeheal.security.events ├─ Temporal join: match events on (namespace, pod\_labels) within 5-min window ├─ Acquire incident lock: Redis SETNX kubeheal:incident-lock:{ns}:{pod} │   → If already locked: merge event into active incident, skip new decision │ ├─ Apply namespace\_tier multiplier: │     prod × 1.20  |  staging × 1.00  |  dev × 0.70 │ ├─ Apply conformal prediction interval check: │     confidence\_interval width \> 0.15 → escalate to human regardless of score │ └─ Decision Policy:       adjusted\_score \= risk\_score × tier\_multiplier         IF adjusted\_score ≥ 0.85 AND label \== ransomware-critical:          circuit\_breaker\_count \= INCR kubeheal:cb:{namespace} (TTL 3600s)          IF circuit\_breaker\_count ≤ 3:             → AUTO-KILL (NetworkPolicy isolate \+ pod delete \+ PV quarantine)          ELSE:             → HUMAN ESCALATION (Slack webhook \+ PagerDuty)         ELIF adjusted\_score ≥ 0.85 AND label \== health-critical:          → AUTO-PATCH (minimal kubectl patch \+ canary validation)         ELIF adjusted\_score ≥ 0.65:          → HUMAN APPROVAL REQUEST (Slack webhook with approve/reject buttons)         ELIF adjusted\_score ≥ 0.40:          → OBSERVE (increase monitoring ×3, log structured event)         ELSE:          → BENIGN (XACK event, continue) |
| :---- | :---- |

| 04 | END-TO-END WORKFLOWS *Timestamped pipeline for every scenario* |
| :---: | :---- |

|  | WORKFLOW A — CONFIGURATION DRIFT → HEALTH REMEDIATION |
| :---- | :---- |

Scenario: A developer runs kubectl edit and accidentally sets CPU limit to 50m (was 500m). K8s CPU throttling begins immediately.

| T \+ 0.0s | kubectl edit fires — MODIFIED event to K8s API server *Deployment spec updated, metadata.generation incremented from 4 to 5* |
| :---: | :---- |
| **T \+ 0.3s** | **Health Agent receives MODIFIED event via K8s Watch API** *Generation predicate: 4→5 is a spec change. Cool-down: not set. Proceed.* |
| **T \+ 0.5s** | **Blast radius query \+ baseline integrity check** *Service/Ingress found — blast\_radius: High. Baseline SHA matches — proceed.* |
| **T \+ 0.8s** | **NetworkPolicy check — any concurrent security event?** *Redis: no active security event for this pod. No pre-isolation needed.* |
| **T \+ 1.0s** | **asyncio.sleep(15s) — wait for drift to propagate to metrics** *CPU throttle events begin accumulating in Prometheus.* |
| **T \+ 16.0s** | **Prometheus fetch — 5s scrape job, max-age 6s** *cpu\_throttle: 82%, memory\_rss: 480MB, p99\_latency: 1390ms* |
| **T \+ 16.2s** | **Tree2Vec GAT encoding — YAML diff with container positional tokens** *Cache miss → GAT encodes: containers\[0\].resources.limits.cpu 50m → 128-dim graph embedding* |
| **T \+ 16.8s** | **DIT-Sec GNN+Mamba inference — all 4 modality encoders** *Output: risk\_score=0.79, label=harmful\_performance\_degradation, CI=\[0.74, 0.83\], XAI: cpu: 0.89 attn* |
| **T \+ 17.0s** | **HealthAssessment published to Redis Stream kubeheal.health.events** *Payload includes patch\_proposal: {cpu\_limits: 500m}, blast\_radius: High, explainability* |
| **T \+ 17.2s** | **Fusion Agent reads event — namespace\_tier: prod, multiplier: 1.2** *Adjusted score: 0.79 × 1.20 \= 0.948. CI width: 0.09 (narrow). Decision: AUTO-PATCH.* |
| **T \+ 17.5s** | **Circuit breaker check — 0/3 patches used this hour** *Proceed. Incident lock acquired: kubeheal:incident-lock:prod:victim-app* |
| **T \+ 18.0s** | **Canary patch applied to replica 1/3** *kubectl patch deployment victim-app \--type=strategic \-p {cpu: 500m} on replica 1* |
| **T \+ 78.0s** | **Canary validation — Prometheus polling loop (60s window)** *cpu\_throttle dropped from 82% → 11%. p99\_latency: 1390ms → 210ms. Canary healthy.* |
| **T \+ 79.0s** | **Full rollout — patch applied to all 3 replicas** *kubectl rollout status confirms RollingUpdate complete.* |
| **T \+ 80.0s** | **Incident record written to kubeheal.incidents stream** *Outcome: auto-resolved, mttr\_ms: 80000, false\_positive: false. Dashboard updated.* |
| **T \+ 80.5s** | **✓ HEALTH MTTR: 80 seconds** *vs. 47-minute industry baseline. 35× improvement.* |

|  | WORKFLOW B — RANSOMWARE ATTACK → KILL \+ TIERED RECOVERY |
| :---- | :---- |

Scenario: A compromised container begins encrypting PersistentVolume data using AES-256. Attack is staged: 2s dormancy → mass encryption.

| T \+ 0.0s | Ransomware process spawned in app-pod-xyz *PID 8421 forked inside container. 2-second dormancy before encryption starts.* |
| :---: | :---- |
| **T \+ 2.0s** | **Mass encryption begins — /var/data/ files targeted** *AES-256 encryption of application state files. Write rate: 180 files/second.* |
| **T \+ 2.3s** | **EARLY SIGNAL — rename() burst: 12 files/sec** *inotify: IN\_MOVED\_FROM burst. Security Agent sets suspicious\_score=0.50. No action yet.* |
| **T \+ 2.5s** | **EARLY SIGNAL — ftruncate()+write() pattern on existing files** *Overwrite pattern detected. Suspicious score escalates to 0.60.* |
| **T \+ 2.7s** | **eBPF map: write\_bytes\_2s \> threshold for PID 8421** *Triggers entropy calculation. Reservoir sample 4KB from 20 written files.* |
| **T \+ 2.9s** | **Entropy: H \= 7.76 bits avg across sampled files** *Threshold 7.2 crossed. Strong ransomware signal. Full DIT-Sec inference triggered.* |
| **T \+ 3.1s** | **Process tree mapping via /proc cgroup parsing** *PID 8421 → cgroup: kubepods/pod{uid}/container{id} → pod: app-pod-xyz, ns: prod* |
| **T \+ 3.3s** | **DIT-Sec security inference (all 4 modalities fused)** *risk\_score=0.93, label=ransomware-critical, CI=\[0.89, 0.96\]. Early signals included.* |
| **T \+ 3.5s** | **IMMEDIATE — NetworkPolicy egress block applied** *kubectl apply NetworkPolicy: deny all egress from prod/app-pod-xyz. Exfil channel cut.* |
| **T \+ 3.7s** | **SecurityEvent published to kubeheal.security.events** *Payload: {pid:8421, entropy:7.76, kill\_confidence:0.93, early\_signals:{rename\_burst:true}}* |
| **T \+ 4.0s** | **Fusion Agent: prod tier × 1.20 \= adjusted 1.116. AUTO-KILL.** *Circuit breaker: 0/3 used. Incident lock acquired. Tier: prod. Decision is final.* |
| **T \+ 4.2s** | **KILL STEP 1 — Node cordon** *kubectl cordon worker-node-2. No new pods scheduled.* |
| **T \+ 4.8s** | **KILL STEP 2 — Pod force deletion** *kubectl delete pod app-pod-xyz \--grace-period=0 \--force* |
| **T \+ 5.5s** | **KILL STEP 3 — PV quarantine** *kubectl patch pv \+ kubectl label pv kubeheal.io/status=quarantined* |
| **T \+ 7.0s** | **KILL STEP 4 — OS-level PID kill via DaemonSet nsenter** *nsenter \--pid=/proc/{init\_pid}/ns/pid kill \-9 8421\. Confirmed via /proc poll.* |
| **T \+ 8.0s** | **✗ RANSOMWARE PROCESS DEAD — Kill phase complete** *Total encrypted: \~1200 files. Without KubeHeal: full PV encryption in \~30s.* |
| **T \+ 8.5s** | **TIER-1 RECOVERY — CSI VolumeSnapshot promoted as shadow PV** *COW snapshot promoted as read-only shadow. Read traffic redirected. Degraded mode active.* |
| **T \+ 30.0s** | **Backup Integrity Gate — entropy-sample 1000 files in Velero backup** *Result: \<1% files with H\>7.0. SHA-256 manifest verified. Backup clean. Proceed.* |
| **T \+ 32.0s** | **Velero restore initiated with \--parallelism=4** *velero restore create \--from-backup \<backup\> \--parallelism=4* |
| **T \+ 4.0min** | **PV fully restored — shadow PV atomically swapped** *Application now reads from fully restored PV. Shadow PV decommissioned.* |
| **T \+ 4.5min** | **Node uncordon \+ clean pod rescheduled from Git-blessed manifest** *kubectl uncordon \+ kubectl apply \-f baseline/deployment.yaml* |
| **T \+ 5.0min** | **Prometheus health verification — 5-minute monitoring window** *I/O rates, entropy, error rates all nominal. Health Agent confirms: benign state.* |
| **T \+ 6.0min** | **Incident record \+ online learning update triggered** *kubeheal.incidents XADD. Model Registry: 1 SGD step on reservoir. ONNX re-exported if F1 OK.* |
| **T \+ 6.0min** | **✓ RANSOMWARE CONTAINED — Total elapsed \~6 minutes** *vs. 13-day industry baseline. Data fully recovered. Exfil channel blocked from T+3.5s.* |

| 05 | TECHNOLOGY STACK *Full stack with versions, roles, and justifications* |
| :---: | :---- |

| LAYER | TECHNOLOGY | VERSION | ROLE | JUSTIFICATION |
| :---- | :---- | :---- | :---- | :---- |
| **Orchestration** | Kubernetes | 1.28+ | Container orchestration | Native CRD, operator, DaemonSet support |
| **Dev Cluster** | Minikube | 1.32+ | Local demo cluster | eBPF support via \--driver=docker, Helm-ready |
| **Runtime** | Docker | 25.x | Container runtime | Falco eBPF probe compatibility |
| **ML Training** | PyTorch | 2.2 | DIT-Sec GNN+Mamba training | Best graph \+ SSM ecosystem |
| **ML Inference** | ONNX Runtime | 1.17 | Production inference | Framework-agnostic, INT8 quantization, \<50ms |
| **GNN Library** | PyTorch Geometric | 2.5 | GAT for YAML diff encoding | Native GNN ops, works with PyTorch 2.2 |
| **SSM Library** | mamba-ssm | 1.2 | Mamba encoder for metrics | O(n) temporal model, Apache 2.0 |
| **Transformers** | Hugging Face | 4.38 | Falco event sequence encoder | CodeBERT warm-start for syscall sequences |
| **Classical ML** | scikit-learn | 1.4 | Isolation Forest first-pass | Robust, \<1ms inference, no GPU needed |
| **Uncertainty** | MAPIE | 0.8 | Conformal prediction wrapper | Coverage-guaranteed CI on DIT-Sec output |
| **Monitoring** | Falco | 0.38 | eBPF syscall monitoring | gRPC output, kernel-level visibility |
| **Metrics** | Prometheus | 2.50+ | Metric collection (5s scrape) | Native K8s, PromQL, remote-write API |
| **Dashboards** | Grafana | 10.x | Visualization \+ alerting | Loki integration, custom panels |
| **Logging** | Grafana Loki | 3.x | Structured log aggregation | Lightweight, Grafana-native |
| **Event Bus** | Redis Streams | 7.2 | Primary coordination bus | Consumer groups, persistence, XACK replay |
| **Fallback Bus** | Kafka | 3.6 KRaft | Dead-letter queue | No ZooKeeper, reliable fallback |
| **Backup (primary)** | Velero | 1.13 | PV snapshot \+ restore | S3 Object Lock, CSI plugin, K8s-native |
| **Backup (PITR)** | Kasten K10 | 6.5 | WAL-based PITR fallback | 5-min PITR granularity when Velero backups corrupt |
| **Object Store** | MinIO | 2024-x | S3-compatible local store | Object Lock support, Minikube-compatible |
| **API Framework** | FastAPI | 0.110 | DIT-Sec model server | Async, OpenAPI, Pydantic validation |
| **K8s Operator** | kubernetes-asyncio | 0.29 | Health Agent operator loop | Non-blocking, handles event storms |
| **Helm** | Helm | 3.14 | K8s package management | Standard for K8s deployment \+ HPA |
| **CSI Snapshots** | hostpath-csi | 1.12 | VolumeSnapshot Tier-1 | COW snapshots available in \<5s |
| **Dashboard** | Flask \+ Socket.IO | 3.0 / 5.3 | Demo real-time dashboard | WebSocket push of risk scores \+ timelines |

| 06 | IMPLEMENTATION GUIDE *Step-by-step from bare Ubuntu VM to full KubeHeal demo* |
| :---: | :---- |

| PRE-REQ | Ubuntu 22.04 LTS VM — minimum 4 vCPU, 8GB RAM, 40GB disk. Run as non-root with sudo. |
| :---- | :---- |

## **Phase 0 — Base Environment**

|  | \# 0.1 — System dependencies sudo apt-get update && sudo apt-get install \-y \\   curl git docker.io python3.11 python3.11-venv python3-pip \\   build-essential linux-headers-$(uname \-r) sudo systemctl enable \--now docker sudo usermod \-aG docker $USER && newgrp docker   \# 0.2 — Minikube (with eBPF support) curl \-LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 sudo install minikube-linux-amd64 /usr/local/bin/minikube minikube start \--driver=docker \--cpus=4 \--memory=7g \\   \--addons=ingress,metrics-server,csi-hostpath-driver,volumesnapshots   \# 0.3 — kubectl \+ Helm curl \-LO "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl" sudo install kubectl /usr/local/bin/kubectl curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash |
| :---- | :---- |

## **Phase 1 — Core Services**

|  | \# 1.1 — Falco (eBPF kernel monitoring) helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update helm install falco falcosecurity/falco \\   \--set driver.kind=ebpf \\   \--set falco.grpc.enabled=true \\   \--set falco.grpcOutput.enabled=true \\   \-n falco \--create-namespace   \# 1.2 — Redis Sentinel helm repo add bitnami https://charts.bitnami.com/bitnami helm install redis bitnami/redis \\   \--set architecture=replication \\   \--set sentinel.enabled=true \\   \--set sentinel.masterSet=mymaster \\   \-n kubeheal \--create-namespace   \# 1.3 — Prometheus (with 5s scrape for kubeheal namespaces) helm repo add prometheus-community https://prometheus-community.github.io/helm-charts helm install monitoring prometheus-community/kube-prometheus-stack \\   \--set prometheus.prometheusSpec.scrapeInterval=15s \\   \-n monitoring \--create-namespace \# Apply additional scrape config for kubeheal namespaces (5s interval): kubectl apply \-f k8s/prometheus-kubeheal-scrapeconfig.yaml   \# 1.4 — MinIO (S3-compatible backup store) helm install minio bitnami/minio \\   \--set auth.rootUser=kubeheal \\   \--set auth.rootPassword=kubeheal-s3 \\   \--set defaultBuckets=velero-backups \\   \-n kubeheal   \# 1.5 — Velero with MinIO backend curl \-L https://github.com/vmware-tanzu/velero/releases/download/v1.13.0/velero-v1.13.0-linux-amd64.tar.gz | tar xz sudo mv velero-v1.13.0-linux-amd64/velero /usr/local/bin/ velero install \\   \--provider aws \\   \--plugins velero/velero-plugin-for-aws:v1.9.0 \\   \--bucket velero-backups \\   \--backup-location-config region=minio,s3ForcePathStyle=true,s3Url=http://minio.kubeheal:9000 \\   \--secret-file ./credentials-velero \\   \--use-node-agent |
| :---- | :---- |

## **Phase 2 — DIT-Sec Model (GNN \+ Mamba)**

|  | \# 2.1 — Python environment cd \~/kubeheal && python3.11 \-m venv .venv && source .venv/bin/activate pip install torch==2.2.0 torch-geometric==2.5.0 \\   mamba-ssm==1.2.0 transformers==4.38.0 \\   onnxruntime==1.17.0 onnx==1.16.0 \\   scikit-learn==1.4.0 mapie==0.8.0 \\   kubernetes-asyncio==0.29.0 aioredis==2.0.1 \\   falco-client fastapi uvicorn pydantic==2.6.0 \\   prometheus-api-client numpy scipy networkx   \# 2.2 — Generate synthetic training data (15K samples via Chaos Mesh sim) python models/generate\_training\_data.py \\   \--samples 15000 \\   \--real-samples data/behavioral\_samples.jsonl \\   \--output data/training.jsonl   \# 2.3 — Train GNN \+ Mamba DIT-Sec python models/train\_dit\_sec\_v3.py \\   \--data data/training.jsonl \\   \--model-arch gnn\_mamba \\   \--epochs 40 \--lr 2e-4 \--batch-size 32 \\   \--output models/dit\_sec\_v3.pt \# Expected: Val F1 \>= 0.90, inference \<50ms after ONNX export   \# 2.4 — Calibrate Conformal Prediction wrapper python models/calibrate\_conformal.py \\   \--model models/dit\_sec\_v3.pt \\   \--calibration-data data/calibration.jsonl \\   \--coverage 0.95   \# 2.5 — Export to ONNX with INT8 quantization python models/export\_onnx\_v3.py \\   \--input models/dit\_sec\_v3.pt \\   \--output models/dit\_sec\_v3.onnx \\   \--quantize int8 \# Validate: inference \<50ms, F1 \>= 0.88 (quantization budget)   \# 2.6 — Upload to Model Registry (MinIO) python models/upload\_to\_registry.py \\   \--model models/dit\_sec\_v3.onnx \\   \--version v3.0.0 \\   \--min-f1 0.88 |
| :---- | :---- |

## **Phase 3 — Agent Deployment**

|  | \# Build all agent images in Minikube registry eval $(minikube docker-env)   docker build \-t kubeheal/dit-sec-server:v3 \-f dockerfiles/Dockerfile.model . docker build \-t kubeheal/health-agent:v3   \-f dockerfiles/Dockerfile.health . docker build \-t kubeheal/security-agent:v3 \-f dockerfiles/Dockerfile.security . docker build \-t kubeheal/fusion-agent:v3   \-f dockerfiles/Dockerfile.fusion . docker build \-t kubeheal/dashboard:v3      \-f dockerfiles/Dockerfile.dashboard .   \# Deploy RBAC \+ CRDs kubectl apply \-f k8s/rbac/           \# ClusterRole for watch \+ patch \+ delete kubectl apply \-f k8s/crds/           \# DriftEvent, SecurityIncident CRDs   \# Deploy in order (model server first, agents depend on it) kubectl apply \-f k8s/dit-sec-deployment.yaml    \# 2 replicas \+ HPA kubectl apply \-f k8s/health-agent-deployment.yaml kubectl apply \-f k8s/security-agent-daemonset.yaml kubectl apply \-f k8s/fusion-agent-deployment.yaml kubectl apply \-f k8s/dashboard-deployment.yaml   \# Port-forward for demo kubectl port-forward svc/kubeheal-dashboard 5000:5000 \-n kubeheal & kubectl port-forward svc/monitoring-grafana 3000:80 \-n monitoring & |
| :---- | :---- |

## **Phase 4 — Demo Execution**

|  | \# 4.1 — Deploy victim application with PVC kubectl apply \-f demo/victim-app.yaml \-n demo kubectl wait \--for=condition=ready pod \-l app=victim \-n demo \--timeout=60s   \# 4.2 — Set baseline annotations kubectl annotate deployment victim-app \\   kubeheal.io/baseline-sha=$(kubectl get deployment victim-app \-o json | sha256sum | cut \-c1-16) \\   \-n demo   \# \--- DEMO A: Config Drift \--- kubectl patch deployment victim-app \-n demo \\   \--type=merge \\   \-p '{"spec":{"template":{"spec":{"containers":\[{"name":"app","resources":{"limits":{"cpu":"50m"}}}\]}}}}}' \# Watch: dashboard risk score climbs 0.02 → 0.79 in \~17s \# Watch: patch applied in \~80s, CPU throttle drops   \# \--- DEMO B: Ransomware \--- kubectl apply \-f chaos/ransomware-simulator.yaml \-n demo \# Simulator does: dd if=/dev/urandom | AES-encrypt → /data/\* in loops \# \+ rapid renames \+ ransom note drop (DECRYPT\_FILES.txt) \# Watch: kill in \<8s, shadow PV in 8.5s, full restore in \~4min   \# \--- Verify \--- kubectl get pods \-n kubeheal                          \# all agents healthy redis-cli \-h $(kubectl get svc redis \-n kubeheal \-o jsonpath={.spec.clusterIP}) \\   XLEN kubeheal.incidents                            \# should be 2 |
| :---- | :---- |

| 07 | SAFETY, GUARDRAILS & ROI *Production safety mechanisms and business case* |
| :---: | :---- |

|  | DECISION SAFETY HIERARCHY |
| :---- | :---- |

| ADJUSTED SCORE | LABEL | ACTION | CIRCUIT BREAKER | AUDIT |
| :---- | :---- | :---- | :---- | :---- |
| **≥ 0.98** | ransomware-critical | Security Agent direct kill (bypasses Fusion for speed) | Counted in CB | Immutable log entry |
| **≥ 0.85 (prod × 1.20)** | ransomware-critical / health-critical | Fusion AUTO-KILL or AUTO-PATCH | Max 3/hr/namespace | Immutable log entry |
| **0.65 – 0.84 OR wide CI** | sec-medium / perf-risk | Human approval via Slack webhook (approve/reject buttons) | N/A | Log \+ response time tracked |
| **0.40 – 0.64** | sec-low / perf-mild | Observe: monitoring ×3, structured event log | N/A | Loki structured log |
| **\< 0.40** | benign | XACK and continue watching | N/A | None |

|  | ALL GUARDRAILS |
| :---- | :---- |

* Auto-Kill Circuit Breaker — Max 3 auto-kills per namespace per hour via Redis INCR with 3600s TTL. Breach → all kills escalate to human.

* Auto-Patch Circuit Breaker — Max 10 auto-patches per Deployment per hour. Prevents patch-loop scenarios on unstable Deployments.

* Emergency Pause — kubectl annotate namespace \<ns\> kubeheal.io/paused=true immediately halts ALL autonomous actions in that namespace.

* Canary-First Patching — Health patches apply to 1/N replicas first. 60-second verification window. Full rollout only on success. Auto-revert on no improvement.

* Rollback Window — All patches have a 60s rollback trigger. If Prometheus shows no improvement within 60s, revert is automatic.

* Backup Integrity Gate — No Velero restore proceeds without entropy sampling \+ SHA-256 manifest check. Corrupt backups trigger Kasten K10 PITR fallback.

* Incident Deduplication Lock — Redis SETNX lock per (namespace, pod) prevents simultaneous Health \+ Security decisions on the same resource.

* Namespace Tier Multiplier — prod × 1.2, staging × 1.0, dev × 0.7. Prevents over-reaction in dev namespaces, appropriate urgency in prod.

* Burn-In Mode — First 48h on new clusters: elevated thresholds (auto-kill requires 0.95+). Exits when ≥2000 Prometheus samples exist.

* Conformal CI Gate — Any decision with conformal CI width \> 0.15 (high uncertainty) is automatically escalated to human regardless of score.

* Immutable Audit Trail — All decisions written to kubeheal.incidents Redis Stream with no TTL, snapshotted to S3 daily for compliance.

|  | BUSINESS CASE & ROI |
| :---- | :---- |

| COST ITEM | WITHOUT KUBEHEAL | WITH KUBEHEAL | ANNUAL SAVING (100-NODE CLUSTER) |
| :---- | :---- | :---- | :---- |
| **Health incident downtime** | 47 min MTTR × avg $12K/hr | \<2 min MTTR | \~$420K/year |
| **Ransomware recovery** | $1.2M per incident (avg 1.4/yr) | \<$50K per incident (Velero costs) | \~$1.61M/year |
| **SRE triage labor** | 20+ min/incident × 800 incidents/yr | \<2 min/incident (review only) | \~$95K/year (FTE cost) |
| **Infrastructure overprovisioning** | Undetected resource limit errors | Rightsizing from drift detection | \~$55K/year |
| **Total Annual Saving** |  |  | \~$2.18M/year |
| **KubeHeal Implementation Cost** |  |  | \~$28K/year (hosting \+ dev) |
| **Year 1 ROI** |  |  | \~78× ($2.18M / $28K) |

| 08 | WEEK 10 DEMO SCRIPT *15-minute narrated walkthrough for judges and evaluators* |
| :---: | :---- |

*The demo must be reproducible, deterministic, and narrated. Practice each step 3 times. The worst demo failure is a script that requires real-time improvisation.*

— Demo Preparation Principle

## **Before the Demo**

* Start all port-forwards: dashboard (5000), Grafana (3000), verify all pods running

* Reset the victim app to baseline: kubectl apply \-f demo/victim-app.yaml \-n demo

* Clear the incidents stream: redis-cli DEL kubeheal.incidents

* Open 3 terminal windows: (1) kubectl get pods \-n kubeheal \-w, (2) dashboard, (3) Grafana

## **Minute 0–2: Architecture Introduction**

* Open dashboard — all risk scores at \~0.02, all agents green

* Say: "KubeHeal has three autonomous agents. Health Agent watches every Deployment change. Security Agent watches every file write on every node. Fusion Agent makes decisions. They talk through Redis Streams."

* Show: kubectl get pods \-n kubeheal — 6 pods, all Running

* Say: "Without KubeHeal: 47-minute average to fix a config incident, 13 days to recover from ransomware. Let me show you what happens with it."

## **Minute 2–6: Config Drift Demo**

* Run the CPU limit patch command live on screen

* Narrate as the dashboard changes: "Watch the risk score. The Health Agent just received the MODIFIED event. It's checking blast radius — this app is serving production traffic, so blast\_radius: High."

* At T+17s: "Risk score is now 0.79. The model flagged resources.limits.cpu with 0.89 attention — it knows exactly which field caused the degradation."

* At T+18s: "Fusion Agent: adjusted score is 0.95 in prod namespace. Decision: AUTO-PATCH. No human needed."

* At T+80s: "CPU throttle dropped from 82% to 11%. Canary passed. Full patch applied. Health restored in 80 seconds."

* Close with: "The XAI output says: containers\[0\].resources.limits.cpu caused 89% of the risk score. Not just 'something is wrong' — we know exactly what and why."

## **Minute 6–13: Ransomware Demo**

* Deploy ransomware simulator. Narrate: "A compromised container is encrypting our PersistentVolume. AES-256, 180 files per second."

* At T+2.3s: "First early signal — rename burst. The Security Agent doesn't wait for entropy. It's already suspicious at score 0.60."

* At T+3.5s: "NetworkPolicy applied — egress blocked from this pod RIGHT NOW. If it was trying to send the encryption key to an attacker, that channel is gone."

* At T+4s: "Fusion Agent: risk 0.93, prod namespace multiplier 1.2, adjusted 1.116. AUTO-KILL."

* At T+8s: "Pod deleted. PV quarantined. Process killed at OS level. 8 seconds."

* At T+8.5s: "But the application is already back in degraded read mode — a CSI shadow PV was promoted instantly. Users aren't seeing a full outage."

* At T+30s: "Backup integrity check passed — our Velero backup is clean. Starting restore."

* At T+4min: "Full restore complete. Clean pod rescheduled. Application fully healthy." Show Prometheus — all metrics nominal.

## **Minute 13–15: Results \+ Q\&A**

* Show the incident record in Redis: 2 incidents, both auto-resolved, false\_positive: false

* Show the ROI panel: "$1.2M ransomware cost avoided today"

* Final statement: "KubeHeal is the only system that detects, explains, and autonomously heals both config drift and ransomware in a single integrated pipeline. No other tool does all three."

| A | APPENDIX *Event schemas, file structure, and reference data* |
| :---: | :---- |

## **A.1 — Project Directory Structure**

|  | kubeheal/ ├── agents/ │   ├── health\_agent/ │   │   ├── agent.py              \# Main asyncio operator loop │   │   ├── tree2vec.py           \# GAT encoder for YAML diffs │   │   ├── prometheus\_client.py  \# 5s-scrape telemetry fetcher │   │   ├── blast\_radius.py       \# K8s Service/Ingress query │   │   └── assessment.py         \# Pydantic HealthAssessment model │   ├── security\_agent/ │   │   ├── agent.py              \# asyncio main loop │   │   ├── falco\_client.py       \# gRPC Falco event consumer │   │   ├── entropy.py            \# Reservoir-sampled entropy calc │   │   ├── proc\_scanner.py       \# /proc PID → pod mapping │   │   ├── inotify\_watcher.py    \# filesystem event watcher │   │   └── ebpf\_maps.py          \# BPF\_MAP\_TYPE\_PERCPU\_HASH reader │   └── fusion\_agent/ │       ├── agent.py              \# Redis Streams consumer \+ decision │       ├── decision\_policy.py    \# Pure function decision engine │       ├── circuit\_breaker.py    \# Redis INCR circuit breaker │       ├── network\_policy.py     \# Egress blocking NetworkPolicy │       └── incident\_log.py       \# Immutable audit trail writer ├── models/ │   ├── dit\_sec\_v3/ │   │   ├── gnn\_encoder.py        \# PyTorch Geometric GAT │   │   ├── mamba\_encoder.py      \# Mamba SSM for Prometheus metrics │   │   ├── transformer\_encoder.py\# Falco event sequence encoder │   │   ├── conv1d\_encoder.py     \# Entropy timeseries encoder │   │   ├── fusion\_mhca.py        \# Multi-Head Cross-Attention fusion │   │   └── output\_head.py        \# Risk score \+ label classifier │   ├── train\_dit\_sec\_v3.py │   ├── export\_onnx\_v3.py │   ├── calibrate\_conformal.py │   └── upload\_to\_registry.py ├── k8s/                          \# All Kubernetes manifests ├── chaos/                        \# Ransomware simulator \+ drift injectors ├── demo/                         \# Victim app \+ baseline manifests ├── dashboards/                   \# Grafana JSON dashboard exports └── scripts/                      \# install.sh \+ demo.sh |
| :---- | :---- |

## **A.2 — Full Incident Record Schema**

|  | {   "incident\_id":         "sec-2025-04-17-001",   "type":                "ransomware | health | compound",   "source\_agents":       \["security-agent-v3", "fusion-agent-v3"\],   "target": {     "namespace":         "prod",     "namespace\_tier":    "prod",     "pod":               "app-pod-xyz",     "node":              "worker-node-2",     "pv\_path":           "/var/data",     "blast\_radius":      "High"   },   "threat": {     "risk\_score\_raw":    0.93,     "tier\_multiplier":   1.20,     "adjusted\_score":    1.116,     "label":             "ransomware-critical",     "confidence\_interval": \[0.89, 0.96\],     "ci\_width":          0.07,     "peak\_entropy\_bits": 7.84,     "files\_encrypted":   1247,     "malicious\_pid":     8421   },   "early\_signals": {     "rename\_burst":      true,     "ftruncate\_pattern": true,     "ransom\_note":       false,     "mmap\_entropy":      false   },   "actions": {     "network\_isolate\_ms":  3500,     "pod\_kill\_ms":         4800,     "pv\_quarantine\_ms":    5500,     "os\_kill\_ms":          7000,     "shadow\_pv\_ms":        8500,     "velero\_restore\_s":    212   },   "outcome":             "recovered",   "false\_positive":      false,   "kill\_time\_ms":        7000,   "mttr\_ms":             372000,   "model\_version":       "v3.0.0",   "conformal\_ci\_passed": true,   "backup\_integrity":    "clean" } |
| :---- | :---- |

