# KubeHeal v4 — Architecture Flow

![KubeHeal v4 architecture](architecture-flow.png)

> Source diagram: [`architecture-flow.mmd`](architecture-flow.mmd) · render with
> `npx -y @mermaid-js/mermaid-cli -i docs/architecture-flow.mmd -o docs/architecture-flow.png -s 2`

KubeHeal v4 replaces the v3 **DIT-Sec monolith** (one model fusing all four
signals) with **two specialized models + a Dependency Correlation Module (DCM)
+ an Interpretation Layer**. Each model is trained on, and excellent at, one
problem. The DCM then asks whether the two signals are *causally related*.

---

## 1 · Signal Sources (Kubernetes telemetry)

| Source | What it carries | Shape into the model |
|--------|-----------------|----------------------|
| **K8s Watch API** | Deployment YAML — baseline vs live spec | YAML diff → graph |
| **Prometheus** (5s scrape) | 15 metrics: cpu throttle/usage, memory rss/working-set/limit, cpu limit, request/error rate, p50/p99/p999 latency, restarts, net rx/tx, disk io | `[60 × 15]` window |
| **Falco eBPF** | syscall trace (≤256 events): open·read·write·rename·ftruncate·mmap… + file paths | token sequence |
| **inotify + entropy** | Shannon entropy of recently-written bytes, 30 steps @ 2s | `[30]` series |

The first two feed the **Health Agent**; the last two feed the **Security Agent**.

---

## 2 · Collector Agents

- **Health Agent** (Deployment) — watches Deployments with a **reconnecting**
  watch loop (resumes on the K8s watch timeout, never exits), diffs the live
  spec against a **recorded golden baseline** (set-if-not-exists, so persistent
  drift keeps being detected), queries blast radius, and polls Prometheus
  through a **shared fresh-metric cache** (replaces v3's `sleep(15)` — 100
  events for one pod = 1 query, not 100).
- **Security Agent** (DaemonSet, `hostPID`) — maps PIDs to pods via
  **cgroups v1 *and* v2** (v3 broke on Ubuntu 22.04), tracks per-PID write
  bytes from `/proc/<pid>/io`, samples file entropy, and reads
  `/proc/<pid>/mem` for **real mmap entropy** (not just mapping size).

---

## 3 · Health Model — *"is this config change harming performance?"*

```
YAML diff ─► GATv2 Encoder ─┐
                            ├─► Cross-Attention ─► Output Head ─► health_risk + label + 128-dim embedding
Prom window ─► BiLSTM ──────┘
```

| Layer | Detail | Why |
|-------|--------|-----|
| **GATv2 Encoder** | 3 layers × 8 heads. YAML → attributed DAG (node = field, edge = parent→child). Container subtrees get learned positional tokens. Per-node attention → field importance. **→ 128-dim** | K8s YAML is hierarchical; GATv2's *dynamic* attention learns that a parent's importance depends on which child changed. Stable md5 node IDs (not `hash()`) so train==serve. |
| **BiLSTM Encoder** | 2 stacked bidirectional LSTM layers, input LayerNorm. **→ 64-dim** | Replaces v3 Mamba (needed CUDA, broke on CPU). Bidirectional captures leading (cpu rises before latency) + lagging (latency stays after cpu recovers) indicators. CPU-fast. |
| **Cross-Attention Fusion** | query = YAML, key/value = metrics. **→ 128-dim** | Asks "given *this* change, which metric trajectory is relevant?" — a cpu_limits change attends to cpu_throttle + p99 latency. |
| **Output Head** | 4-class softmax (`benign · low_risk_drift · harmful_performance_degradation · critical_config_error`) + sigmoid risk regressor | Severity resolution the Fusion Agent needs to choose patch vs escalate. |
| **Conformal wrapper** | split-conformal `q` on held-out calibration → `ci_width` | Calibrated uncertainty; wide CI ⇒ escalate to human. |

**Emits:** `health_risk [0–1]`, 4-class label, `field_attention_weights`,
conformal CI, and a **128-dim `health_embedding`** for the DCM.

---

## 4 · Security Model — *"is there an attack in progress?"*

```
syscalls ─► Transformer ─┐
                         ├─► Cross-Attention ─► Output Head ─► sec_risk + label + 64-dim embedding
entropy ─► Conv1D+SE ────┘
```

| Layer | Detail | Why |
|-------|--------|-----|
| **Falco Transformer** | 4 heads × 2 layers, **Pre-LN**, learnable **CLS** token, sinusoidal PE, syscall+path embeddings. **→ 64-dim** | Ransomware patterns (open→reads→reopen→encrypt→write→rename) span hundreds of events; self-attention models any-to-any long-range deps. Kept from v3. |
| **Entropy Conv1D + SE** | multi-scale kernels **k=3·7·15** + squeeze-excitation channel attention. **→ 64-dim** | Different ransomware speeds: k=3 catches fast spikes, k=15 catches slow onset. SE amplifies the informative filters. |
| **Cross-Attention Fusion** | query = syscalls, key/value = entropy. **→ 64-dim** | "How random were the writes this process made?" |
| **Output Head** | 5-class softmax (`benign · suspicious · ransomware_staging · ransomware_active · data_exfiltration`) + risk regressor | Staging label enables early NetworkPolicy egress block before full confidence. |
| **Conformal wrapper** | same as health | Uncertainty gate. |

**Emits:** `sec_risk [0–1]`, 5-class label, `syscall_attention_weights`,
entropy spike, conformal CI, and a **64-dim `security_embedding`** for the DCM.

---

## 5 · Dependency Correlation Module (DCM) — ★ the novel contribution ★

```
health_embedding (128) ─┐
                        ├─► Bidirectional Cross-Modal Attention ─► correlation_score [0–1] + causal_chain
security_embedding (64) ─┘                                          compound_flag (>0.60)
```

The DCM is what no existing K8s tool has. It runs **bidirectional cross-modal
attention** (health-queries-security **and** security-queries-health) over the
two model embeddings and outputs a single **correlation score**:

| health_risk | sec_risk | correlation | meaning | action |
|---|---|---|---|---|
| 0.88 | 0.93 | **0.84** | ransomware CPU-thrash *looks like* drift | **compound** — escalate harder |
| 0.85 | 0.12 | 0.09 | pure config drift | health-only auto-patch |
| 0.15 | 0.91 | 0.11 | ransomware on a healthy pod | security-only kill |

Without the DCM, two *independent* events (a bad CPU limit **and** unrelated
ransomware elsewhere) would falsely amplify into a "compound attack." The DCM
prevents that. The **Causal Chain Builder** turns the signals into an ordered
`T+Xs` narrative for the dashboard.

> Trained **staged**: Health + Security models are frozen, the DCM learns only
> to correlate their embeddings (so it never corrupts the specialists).

---

## 6 · Interpretation Layer — auditable AI

- **SHAP explainer** → per-field (health) and per-syscall (security) attributions.
- **Field-name mapper** → GAT node id ⇒ real K8s path
  (`spec.template.spec.containers[0].resources.limits.cpu`).
- **NL summary generator** → Claude Haiku turns the structured incident into a
  1–3 sentence SRE-readable summary; **template fallback** if the API key is
  absent so it never blocks the pipeline.

---

## 7 · Redis Streams (consumer groups)

`kubeheal.health.events` · `kubeheal.security.events` · `kubeheal.dcm.events` ·
`kubeheal.actions`. The Fusion Agent reads via a **consumer group** so each
event is processed by exactly one replica (v3 double-processed with `replicas:2`).

---

## 8 · Fusion Agent v4 — three-signal decision engine

Reads `health_risk`, `sec_risk`, `correlation_score` and runs a **pure,
fully-unit-tested decision function**:

1. **Namespace tier multiplier** — prod ×1.20 · staging ×1.00 · dev ×0.70
2. **Compound escalation** — ×1.15 when `compound_flag`
3. **Conformal CI gate** — CI width > 0.15 ⇒ route to human
4. **Circuit breakers** — ≤3 auto-kills/ns/hr · ≤10 auto-patches/dep/hr
5. **Burn-in mode** — raises thresholds until 2000 metric samples exist

Executed under a **heartbeat incident lock** (10s TTL, 3s refresh) — a crash
mid-incident frees the lock in ≤10s instead of v3's 30s gap.

**Decisions:** `AUTO-KILL` · `AUTO-PATCH` · `HUMAN-KILL/PATCH` · `OBSERVE` · `BENIGN`.

---

## 9 · What changed v3 → v4 (summary)

| v3 | v4 |
|----|----|
| 1 monolith (DIT-Sec) fusing 4 signals | 2 specialist models + DCM |
| Mamba SSM (CUDA, CPU-broke) | BiLSTM (torch core, CPU-fast) |
| GAT | **GATv2** (dynamic attention) |
| single `risk_score` | `health_risk` + `sec_risk` + `correlation_score` |
| no explainability | SHAP + field mapper + NL summary + causal chain |
| `replicas:2` double-processed | Redis consumer groups |
| 30s incident lock | 10s heartbeat lock |
| Kafka DLQ (heavy) | removed (Redis Streams + consumer groups) |
| cgroups v1 only | cgroups v1 **and** v2 |
