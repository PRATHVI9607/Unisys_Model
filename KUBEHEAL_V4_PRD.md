# KubeHeal v4 — Full Product Requirements Document
## Instructions for Claude Code: Migrating KubeHeal v3 → v4 Architecture

---

**Document Version:** 4.0.0  
**Target System:** KubeHeal — Autonomous Configuration & Security Drift Correction in Kubernetes  
**Predecessor:** KubeHeal Architecture v3.0 (DIT-Sec monolith, single GNN+Mamba fusion model)  
**This Document Is For:** Claude Code — read every section before touching a single file  
**Team:** Ryan Dave Fernandes · P Koti Darshan · Rakshak S  
**Institution:** RVCE, Bengaluru · Unisys "Agents Unleashed" · UIP  
**Mentor:** Dr. Mohana  

---

## HOW TO READ THIS DOCUMENT

This PRD is structured as a **migration guide** from the existing v3 codebase to the new v4 architecture. Every section tells you:

1. **What exists now** (the v3 state)
2. **What is wrong with it** (the specific technical problem)
3. **What to build instead** (the v4 solution with full justification)
4. **Exactly how to implement it** (file paths, function signatures, pseudo-code, integration points)

Do not skip ahead. The sections build on each other. If you implement section 6 before section 3, you will create a dependency graph that cannot be resolved. Read the entire document first, then execute in the order prescribed in Section 11 (Implementation Sequence).

When you encounter a `> WHY:` block, that is the engineering justification. When you encounter a `> CLAUDE CODE INSTRUCTION:` block, that is a direct instruction to you. Do not summarize these — act on them precisely.

---

## TABLE OF CONTENTS

```
00  Executive Summary & Migration Rationale
01  What Changed and Why — v3 → v4 Delta
02  Architecture Overview — KubeHeal v4 System Map
03  Health Model (Dedicated) — GAT + BiLSTM Encoder
04  Security Model (Dedicated) — Transformer + Conv1D Encoder
05  Dependency Correlation Module (DCM) — The Novel Contribution
06  Interpretation Layer — SHAP + Natural Language Explainability
07  Fusion Agent v4 — Three-Signal Decision Engine
08  Infrastructure Changes — What to Cut, What to Modify, What to Add
09  Agent Pipeline Changes — Health Agent, Security Agent, Fusion Agent
10  Testing & Validation Strategy
11  Implementation Sequence — Exact Order of Operations for Claude Code
12  File Structure — v4 Complete Directory Tree
13  API Contracts — All Internal Interfaces
14  Demo Script v4 — Updated 15-Minute Walkthrough
15  Appendix — Schema Definitions, Config Files, Known Failure Modes
```

---

## SECTION 00 — EXECUTIVE SUMMARY & MIGRATION RATIONALE

### What KubeHeal Does (Do Not Skip This — Context Matters)

KubeHeal is a Kubernetes-native autonomous healing system that solves two simultaneous production crises:

**Crisis 1 — Configuration Drift:** When developers, CD pipelines, and emergency hotfixes diverge from the desired YAML state of a Kubernetes cluster, system performance degrades silently. A CPU limit accidentally set to 50m instead of 500m causes throttling that manifests as latency spikes, which manifest as error rates, which manifest as on-call pages. The root cause (a single YAML field change) is invisible without careful YAML diffing across time. Existing GitOps tools (ArgoCD, Flux) can detect and revert drift, but they do so blindly — they have no concept of whether a change is dangerous (reduced CPU in prod) versus intentional (a developer testing lower resource limits in staging). KubeHeal adds risk assessment: it scores the drift using a machine learning model that fuses the YAML diff with live Prometheus metrics, and only autonomously patches when confidence is high. Otherwise, it routes to human approval.

**Crisis 2 — Container Ransomware:** Ransomware in Kubernetes targets PersistentVolumes (PVs) — the durable storage attached to database pods, file servers, and stateful workloads. The attack pattern: a compromised container forks a process that encrypts files on the PV at high speed, then drops a ransom note. Traditional security tools (Falco, Trivy) generate alerts but do not act. An SRE receiving a Falco alert at 2 AM takes 20+ minutes to triage, decide, and manually kill the pod. In those 20 minutes, the entire PV is encrypted. KubeHeal's Security Agent detects the behavioral signature of encryption (high file-write rate, high Shannon entropy on written bytes, rename bursts consistent with file-locking) and autonomously kills the process, quarantines the PV, and initiates backup restoration — all within 8 seconds.

### Why v3 Had a Fundamental Model Architecture Problem

In v3, both of these detection tasks were handled by a single model called **DIT-Sec** (Drift Impact Transformer — Security). DIT-Sec ingested all four signal types simultaneously:

- YAML diffs (structural/semantic signals about configuration changes)
- Prometheus metrics (time-series signals about performance impact)
- Falco eBPF events (behavioral signals about kernel-level syscall activity)
- File entropy series (statistical signals about the randomness of file writes)

The problem with fusing all four into one model is that the first two signals are completely unrelated to ransomware detection, and the last two signals are completely unrelated to config drift assessment. A monolithic fusion model must learn to simultaneously:

- Understand K8s YAML semantics (a graph-structured problem)
- Understand metric time series (a sequential/temporal problem)
- Understand syscall event sequences (an NLP-like sequence problem)
- Understand entropy statistics (a signal processing problem)

These are four fundamentally different learning objectives. When combined into one model, they compete with each other during training. The gradient from the YAML graph task interferes with the gradient from the entropy regression task. The model ends up mediocre at all four rather than excellent at two. More critically, when the model produces a risk score, there is no way to determine which of the four signals drove the score — you cannot explain whether a 0.87 risk score came from the YAML diff, the entropy, or both.

### The v4 Solution: Two Specialized Models + A Dependency Layer

v4 separates concerns into two dedicated models:

**Health Model:** Trained exclusively on YAML diffs and Prometheus metrics. Its job is to answer: "Is this configuration change causing performance harm?" It outputs a `health_risk` score and `field_attention_weights` that identify exactly which YAML field contributed most to the risk.

**Security Model:** Trained exclusively on Falco eBPF events and file entropy series. Its job is to answer: "Is there behavioral evidence of an attack in progress?" It outputs a `security_risk` score and `syscall_attention_weights` that identify exactly which syscall patterns were most suspicious.

**Dependency Correlation Module (DCM):** A lightweight cross-attention layer that takes the embeddings from both models and asks: "Are these two signals correlated for this specific resource?" High correlation (ransomware causing CPU thrash so severe it appears as drift) means a compound incident — escalate harder. Low correlation means two independent events that should be handled by separate policies.

**Interpretation Layer:** Converts the attention weights from both models into human-readable K8s field names and generates a natural language summary of what happened and why. This is the demo-winning feature.

This separation gives you: independent training, independent tuning, cleaner explainability, and a novel contribution (the DCM) that no existing Kubernetes security paper has described.

---

## SECTION 01 — WHAT CHANGED AND WHY: v3 → v4 DELTA

This section is a complete inventory of every change from v3 to v4. Read this first so you understand the scope before modifying any file.

### What Gets Deleted

```
models/dit_sec_v3/           → DELETED ENTIRELY
  gnn_encoder.py             → replaced by health_model/yaml_gat_encoder.py
  mamba_encoder.py           → replaced by health_model/metric_bilstm_encoder.py
  transformer_encoder.py     → replaced by security_model/falco_transformer_encoder.py
  conv1d_encoder.py          → kept, moved to security_model/entropy_conv1d_encoder.py
  fusion_mhca.py             → replaced by dcm/cross_modal_attention.py
  output_head.py             → split into health_model/health_output_head.py
                               and security_model/security_output_head.py
  train_dit_sec_v3.py        → replaced by two separate training scripts
  export_onnx_v3.py          → replaced by two separate export scripts
  calibrate_conformal.py     → kept, applied separately to each model
  upload_to_registry.py      → updated to handle two models + DCM

k8s/kafka/                   → DELETED (Kafka DLQ removed from demo setup)
```

> WHY DELETE KAFKA: Kafka requires a StatefulSet, ZooKeeper (or KRaft mode with careful config), persistent volumes, and correct broker configuration. On a demo VM with 8GB RAM and 4 CPUs already running Minikube, Falco, Prometheus, Grafana, Redis Sentinel, MinIO, Velero, and the KubeHeal agents, Kafka will cause resource contention that invalidates all latency measurements. Redis Sentinel with 3 nodes (1 master + 2 replicas + Sentinel process) is already highly available. If Redis fails during the demo, the answer to judges is "Redis is HA — this is the failover process." Kafka adds operational complexity for zero demo value. It belongs in a production architecture document, not a Week 10 demo setup.

### What Gets Modified

```
agents/health_agent/agent.py
  → Remove asyncio.sleep(15s) anti-pattern
  → Add Prometheus polling loop with exponential backoff
  → Add shared in-process Prometheus cache
  → Update DIT-Sec call to Health Model endpoint

agents/security_agent/proc_scanner.py
  → Add cgroups v2 compatibility layer
  → Add CRI API fallback for pod name resolution

agents/security_agent/agent.py
  → Update DIT-Sec call to Security Model endpoint

agents/fusion_agent/agent.py
  → Update to three-signal decision policy (health_risk, sec_risk, correlation_score)
  → Update Redis lock to use heartbeat pattern

agents/fusion_agent/decision_policy.py
  → Full rewrite for v4 three-input policy

models/export_onnx_v3.py → models/export_onnx_v4.py
  → Change INT8 quantization to FP16 for GAT component

k8s/dit-sec-deployment.yaml → k8s/health-model-deployment.yaml + k8s/security-model-deployment.yaml
  → Split into two separate model server deployments

dashboards/kubeheal-main.json
  → Add DCM correlation score panel
  → Add interpretation panel showing NL summaries
  → Add per-model confidence intervals
```

### What Gets Added (New Files)

```
models/health_model/
  yaml_gat_encoder.py        → Graph Attention Network for YAML diffs
  metric_bilstm_encoder.py   → BiLSTM encoder for Prometheus metrics (replaces Mamba)
  health_fusion_attention.py → Cross-attention between GAT and BiLSTM embeddings
  health_output_head.py      → Risk score + label + confidence for health signals
  health_conformal.py        → Conformal prediction wrapper for health model

models/security_model/
  falco_transformer_encoder.py → Transformer encoder for syscall event sequences
  entropy_conv1d_encoder.py    → Conv1D + SE block for entropy time series
  security_fusion_attention.py → Cross-attention between transformer and conv1d
  security_output_head.py      → Risk score + label + confidence for security signals
  security_conformal.py        → Conformal prediction wrapper for security model

models/dcm/
  cross_modal_attention.py   → Bidirectional cross-attention between health+security embeddings
  causal_chain_builder.py    → Constructs ordered causal chain from attention weights
  correlation_head.py        → Outputs correlation_score + causal_chain

models/interpretation/
  shap_explainer.py          → SHAP values computed on both model outputs
  field_name_mapper.py       → Maps attention weight indices to K8s field names
  nl_summary_generator.py    → Calls LLM API to generate natural language incident summary

models/train_health_model.py → Training script for Health Model only
models/train_security_model.py → Training script for Security Model only
models/train_dcm.py          → Training script for DCM (requires frozen health+security models)
models/export_health_model.py → Export Health Model to ONNX (FP16)
models/export_security_model.py → Export Security Model to ONNX (FP16)
models/export_dcm.py         → Export DCM to ONNX (FP16)

k8s/health-model-deployment.yaml   → K8s deployment for Health Model server
k8s/security-model-deployment.yaml → K8s deployment for Security Model server
k8s/dcm-deployment.yaml            → K8s deployment for DCM server

agents/fusion_agent/interpretation_client.py → Client for interpretation layer
```

---

## SECTION 02 — ARCHITECTURE OVERVIEW: KubeHeal v4 SYSTEM MAP

### The Complete Data Flow

Understanding the flow before implementing any component is critical. Here is the exact path a signal takes from detection to action in v4:

```
═══════════════════════════════════════════════════════════════════════════════
                        KUBEHEAL v4 — SIGNAL FLOW
═══════════════════════════════════════════════════════════════════════════════

SIGNAL SOURCES                 AGENTS                    MODEL SERVERS
──────────────                 ──────                    ─────────────
K8s Watch API (MODIFIED)  ──►  Health Agent
  └─ YAML diff                   ├─ Baseline check         ┌─────────────────┐
  └─ Generation predicate        ├─ Blast radius query     │  HEALTH MODEL   │
                                 ├─ Prometheus fetch        │  ─────────────  │
Prometheus (5s scrape)    ──►    └─ POST /health/score ──► │  GAT Encoder    │
  └─ CPU throttle %              ▼                         │  + BiLSTM       │──► health_embedding
  └─ memory RSS           HealthAssessment                 │  + Fusion Attn  │    health_risk [0,1]
  └─ p99 latency           published to                    │  + Output Head  │    field_attention_weights
  └─ error rate            Redis Stream ─────────────────► └─────────────────┘
                           kubeheal.health.events                   │
                                                                     ▼
Falco gRPC events ────────►  Security Agent               ┌─────────────────┐
  └─ syscall traces              ├─ PID → Pod mapping      │ SECURITY MODEL  │
  └─ file operations             ├─ Entropy calculation    │  ─────────────  │
                                 ├─ mmap detection         │  Transformer    │──► security_embedding
inotify/fanotify ─────────►      └─ POST /security/score ►│  + Conv1D+SE    │    sec_risk [0,1]
  └─ rename bursts                ▼                        │  + Fusion Attn  │    syscall_attn_weights
  └─ ftruncate patterns    SecurityEvent                   │  + Output Head  │
                           published to                    └─────────────────┘
eBPF maps ────────────────►  Redis Stream ─────────────────────────│
  └─ write byte counts      kubeheal.security.events               │
                                                                    ▼
                                                         ┌─────────────────────┐
                                                         │        DCM          │
                                                         │  ─────────────────  │
                                                         │  Cross-Modal Attn   │──► correlation_score
                                                         │  Causal Chain       │    causal_chain[]
                                                         │  Correlation Head   │    compound_flag
                                                         └─────────────────────┘
                                                                    │
                                                                    ▼
                                                         ┌─────────────────────┐
                                                         │  INTERPRETATION     │
                                                         │  LAYER              │
                                                         │  ─────────────────  │
                                                         │  SHAP explainer     │──► field_attributions
                                                         │  Field name mapper  │    nl_summary
                                                         │  NL generator       │    causal_narrative
                                                         └─────────────────────┘
                                                                    │
                           FUSION AGENT v4                          │
                           ──────────────                           │
                           Reads all three streams             ◄────┘
                           + interpretation output
                           Applies:
                             - Namespace tier multiplier
                             - Conformal CI gate
                             - DCM correlation adjustment
                             - Circuit breaker check
                           Makes decision:
                             AUTO-KILL / AUTO-PATCH /
                             HUMAN-APPROVAL / OBSERVE /
                             BENIGN

═══════════════════════════════════════════════════════════════════════════════
```

### Why This Topology Is Superior to v3

In v3, the flow was:

```
All 4 signals → DIT-Sec monolith → single risk_score → Fusion Agent decision
```

This means: one gradient, one training loop, one ONNX export, one model server, one risk score that conflates health and security signals. When the score is 0.87, you don't know if it's 0.87 because the entropy was high, or because the CPU limit was wrong, or both.

In v4, the flow is:

```
YAML + Metrics → Health Model → health_risk + field_attention_weights
eBPF + Entropy → Security Model → sec_risk + syscall_attention_weights
Both embeddings → DCM → correlation_score + causal_chain
All signals → Interpretation Layer → nl_summary
All signals → Fusion Agent → three-signal decision
```

This means: you can say "this is a pure health incident with 0.91 drift confidence — the security model is calm at 0.12, and the DCM shows no correlation between the events." Or: "this is a compound incident — health risk 0.88, security risk 0.94, DCM correlation 0.82 — the ransomware is causing CPU thrash that appears as drift. Treat as compound."

That second sentence is what judges will screenshot.

---

## SECTION 03 — HEALTH MODEL (DEDICATED): GAT + BiLSTM ENCODER

### 3.1 What the Health Model Replaces

In v3, the `gnn_encoder.py` (GAT) and `mamba_encoder.py` (Mamba SSM) were two components inside the monolithic DIT-Sec. They processed YAML diffs and Prometheus metrics respectively, then fed their embeddings into a shared `fusion_mhca.py` layer that also received inputs from the security-domain encoders.

In v4, these two encoders become the dedicated **Health Model** — a self-contained model that receives only YAML and metric signals, fuses them internally, and outputs a health-specific risk score and embedding.

> WHY DEDICATE A MODEL TO HEALTH SIGNALS: When you train a model jointly on config-drift and ransomware data, the loss function is a weighted sum of both tasks' errors. The gradient updates at each step push the shared parameters toward satisfying both tasks simultaneously. For a GAT encoder that understands YAML structure, this means it must also — through the same weight matrix — learn to be useful for understanding syscall sequences. These are incompatible objectives. The GAT learns to be mediocre at both. By training the Health Model only on (YAML diff, Prometheus metric) pairs labeled with health outcomes, the GAT becomes excellent at its actual task: understanding which YAML fields correlate with performance degradation.

### 3.2 Component 1: YAML GAT Encoder (yaml_gat_encoder.py)

**What it does:** Converts a Kubernetes YAML diff (old spec vs new spec) into a 128-dimensional graph embedding that captures the structural semantics of what changed and where.

**Why Graph Attention Network (GAT) and not a standard transformer:**

Kubernetes YAML is hierarchically structured. A Deployment spec looks like this:

```
Deployment
├── spec
│   └── template
│       └── spec
│           └── containers[0]
│               ├── resources
│               │   └── limits
│               │       └── cpu: "50m"  ← the changed field
│               └── env[*]
└── metadata
```

This is a directed acyclic graph (DAG), not a flat sequence. If you serialize this to text and feed it to a transformer (as v3's Tree2Vec approach did), you lose the parent-child relationships. The transformer sees `cpu: 50m` but doesn't know that `cpu` is a child of `limits`, which is a child of `resources`, which is a child of `containers[0]`. That hierarchical context is critical — `cpu` in `resources.limits` is entirely different from `cpu` in a pod affinity rule.

A GAT encodes each field as a node and parent-child relationships as directed edges. The attention mechanism then learns to propagate information through the graph in a way that respects the hierarchy. A change deep in `containers[0].resources.limits.cpu` propagates up through `resources`, through the container spec, through the pod template — and the attention weights at each hop tell you how much each parent level contributed to the risk assessment.

**Positional encoding for multi-container specs:**

v3 identified a loophole: in a pod with 3 containers, changes to `containers[0].resources.limits.cpu` and `containers[2].resources.limits.cpu` produce near-identical graph embeddings because the container index information is lost. v4 fixes this by adding a positional prefix token to each container sub-tree before encoding.

**Implementation specification:**

```python
# FILE: models/health_model/yaml_gat_encoder.py
# This file must be created exactly as specified below.

import torch
import torch.nn as nn
from torch_geometric.nn import GATv2Conv
from torch_geometric.data import Data
import yaml
import hashlib

# WHY GATv2 OVER GAT: The original GAT (Velickovic et al., 2018) computes
# attention as e_ij = a(W * h_i, W * h_j) — a static function of the
# concatenated transformed features. GATv2 (Brody et al., 2022) makes
# attention dynamic: e_ij = a(W * [h_i || h_j]) — it concatenates FIRST,
# then transforms. This fixes the "static attention" problem in GAT where
# the attention ranking of neighbors is the same regardless of the query
# node. For K8s YAML, this matters: the importance of a parent node changes
# depending on which child changed. GATv2 learns this correctly; GAT doesn't.

CONTAINER_POSITIONAL_TOKENS = [
    "[CONTAINER_0]", "[CONTAINER_1]", "[CONTAINER_2]",
    "[CONTAINER_3]", "[CONTAINER_4]", "[CONTAINER_MAX]"
]
# WHY POSITIONAL TOKENS: Each container in a pod spec is semantically
# identical in graph structure. Without positional markers, the GAT cannot
# distinguish which container changed. We prepend a learned positional
# embedding to each container sub-tree's root node. This adds only 6
# learnable token embeddings (one per container index, up to 5, plus an
# overflow token for pods with >5 containers) but completely solves the
# multi-container disambiguation problem.

class YAMLGATEncoder(nn.Module):
    def __init__(
        self,
        node_feature_dim: int = 64,   # dim of per-node feature vector
        hidden_dim: int = 128,         # hidden dim in GAT layers
        output_dim: int = 128,         # final embedding dim
        num_heads: int = 8,            # attention heads per GAT layer
        num_layers: int = 3,           # number of GATv2Conv layers
        dropout: float = 0.1
    ):
        super().__init__()
        # WHY 3 LAYERS: K8s YAML has at most 5-6 levels of nesting
        # (Deployment → spec → template → spec → containers → resources →
        # limits → cpu). 3 GAT layers gives us receptive field of depth 3,
        # meaning a leaf node (cpu: 50m) can attend to its great-grandparent
        # (containers[0]) in one forward pass. Deeper graphs don't exist in
        # standard K8s specs.
        
        self.node_embedding = nn.Embedding(10000, node_feature_dim)
        # 10000 vocabulary size covers all K8s field names + values we'll
        # encounter. Values are tokenized at the character level for numeric
        # fields (so "50m" and "500m" are different tokens).
        
        self.positional_embedding = nn.Embedding(6, node_feature_dim)
        # 6 positional tokens for containers[0..5]. Applied to the root
        # node of each container sub-tree before GAT encoding.
        
        self.gat_layers = nn.ModuleList()
        in_channels = node_feature_dim
        for i in range(num_layers):
            out_channels = hidden_dim // num_heads
            self.gat_layers.append(
                GATv2Conv(
                    in_channels=in_channels,
                    out_channels=out_channels,
                    heads=num_heads,
                    dropout=dropout,
                    add_self_loops=True,
                    # WHY add_self_loops=True: Self-loops allow each node to
                    # attend to its own features in addition to neighbors.
                    # This is critical for leaf nodes (like cpu: 50m) which
                    # have no children — without self-loops, leaf nodes
                    # would aggregate zero neighbor information.
                    concat=True if i < num_layers - 1 else False
                    # WHY concat=False on last layer: Final layer averages
                    # across heads rather than concatenating. This gives a
                    # fixed output_dim regardless of num_heads.
                )
            )
            in_channels = hidden_dim if i < num_layers - 1 else hidden_dim
        
        self.output_projection = nn.Linear(hidden_dim, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, data: Data) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            data: PyG Data object with:
                - data.x: node features [num_nodes, node_feature_dim]
                - data.edge_index: graph edges [2, num_edges]
                - data.container_indices: which nodes are container roots
                - data.container_positions: position index for each container root
                - data.change_mask: bool mask, True for nodes that changed
        
        Returns:
            graph_embedding: [output_dim] — single embedding for entire diff
            attention_weights: [num_nodes] — per-node attention weight
                               (used by Interpretation Layer to identify
                               which YAML fields were most important)
        """
        x = data.x
        
        # Apply positional embeddings to container root nodes
        if data.container_indices is not None:
            pos_emb = self.positional_embedding(data.container_positions)
            x[data.container_indices] = x[data.container_indices] + pos_emb
        
        # Track attention weights across all GAT layers
        all_attention_weights = []
        
        for i, gat_layer in enumerate(self.gat_layers):
            x, (edge_index, attn_weights) = gat_layer(
                x, data.edge_index, return_attention_weights=True
            )
            all_attention_weights.append(attn_weights)
            if i < len(self.gat_layers) - 1:
                x = torch.relu(x)
                x = self.dropout(x)
        
        # Global mean pooling: aggregate all node embeddings into one graph embedding.
        # WHY MEAN POOLING (not max): We want the embedding to reflect the
        # average "state" of the graph, not just the single most activated
        # node. A single changed field should not dominate the embedding —
        # its importance is relative to the rest of the spec.
        graph_embedding = x.mean(dim=0)
        graph_embedding = self.output_projection(graph_embedding)
        graph_embedding = self.layer_norm(graph_embedding)
        
        # Compute per-node importance for interpretation:
        # Average attention weights from the last GAT layer, then
        # aggregate to node-level by averaging over all edges pointing to each node.
        node_importance = torch.zeros(x.shape[0])
        last_attn = all_attention_weights[-1]  # [num_edges, num_heads]
        edge_index_last = data.edge_index
        for edge_idx in range(edge_index_last.shape[1]):
            target_node = edge_index_last[1, edge_idx]
            node_importance[target_node] += last_attn[edge_idx].mean()
        node_importance = node_importance / (node_importance.sum() + 1e-8)
        
        return graph_embedding, node_importance


def yaml_diff_to_graph(old_yaml: dict, new_yaml: dict) -> Data:
    """
    Converts a YAML diff into a PyG Data object.
    
    This function is the most critical preprocessing step. It must:
    1. Parse both old and new YAML specs into a tree
    2. Identify which nodes changed (for change_mask)
    3. Add container positional tokens
    4. Construct edge_index for the DAG
    
    > CLAUDE CODE INSTRUCTION: Implement this function fully.
    > The node vocabulary must be built from a scan of 1000+ real K8s specs
    > to capture all possible field names. Use the file:
    > models/health_model/k8s_field_vocabulary.json for the vocabulary.
    > If this file doesn't exist, create it by running:
    > python models/health_model/build_vocabulary.py
    > which scans the demo/ and chaos/ directories for YAML files.
    """
    # Implementation required — see Section 11 for build order
    pass
```

> CLAUDE CODE INSTRUCTION: Create the file `models/health_model/yaml_gat_encoder.py` with the full implementation. The `yaml_diff_to_graph` function must correctly handle: (a) deeply nested specs, (b) list nodes (containers[], env[], volumes[]), (c) missing keys (a key in new but not old = addition, key in old but not new = deletion), (d) the container positional token injection for any containers[] list node.

### 3.3 Component 2: Metric BiLSTM Encoder (metric_bilstm_encoder.py)

**What it replaces:** The `mamba_encoder.py` in v3 used the `mamba-ssm` library for processing Prometheus time series. This is being replaced with a BiLSTM.

**Why BiLSTM instead of Mamba:**

The v3 PRD chose Mamba (State Space Model) for its O(n) complexity advantage over transformers. This is theoretically correct but practically wrong for two reasons:

1. `mamba-ssm` requires compiled CUDA kernels. On Minikube with `--driver=docker`, there is no GPU. The library either throws a `CUDA not available` error or falls back to an extremely slow CPU reference implementation (100-200ms per forward pass instead of <5ms). This is a demo-breaking issue.

2. Our Prometheus time series are short: 5-minute windows at 5-second resolution = 60 timesteps. For sequences of length 60, the quadratic complexity of attention is not a problem. Mamba's O(n) advantage only matters for sequences of length >1000. We are operating in a regime where Mamba's architectural complexity provides zero practical benefit.

BiLSTM is:
- CPU-fast (2-3ms per forward pass on CPU)
- Minikube-compatible with zero additional dependencies
- Well-understood with predictable training behavior
- Bidirectional: processes each metric window forward AND backward, capturing both leading indicators (CPU starts rising before latency spikes) and lagging indicators (latency is still high after CPU recovers)

**Why Bidirectional LSTM specifically:**

In Prometheus metric windows, the causal direction matters. CPU throttling (the cause) happens before latency spikes (the effect). A unidirectional LSTM processes left-to-right and can learn this causal ordering. But we also care about the reverse: was the latency already elevated before the config change? A backward LSTM captures this by processing right-to-left and identifying pre-existing conditions. The concatenation of forward and backward hidden states gives the model both causal directions simultaneously.

**Implementation specification:**

```python
# FILE: models/health_model/metric_bilstm_encoder.py

import torch
import torch.nn as nn
import numpy as np
from typing import List

# The 15 Prometheus metrics we track for each resource:
METRIC_COLUMNS = [
    "cpu_throttle_percent",      # % of time CPU was throttled (0-100)
    "cpu_usage_millicores",      # actual CPU usage in millicores
    "memory_rss_bytes",          # resident set size in bytes
    "memory_working_set_bytes",  # working set (rss + cache)
    "memory_limit_bytes",        # configured memory limit
    "cpu_limit_millicores",      # configured CPU limit
    "http_request_rate",         # requests per second
    "http_error_rate",           # errors per second
    "http_p50_latency_ms",       # median latency
    "http_p99_latency_ms",       # 99th percentile latency
    "http_p999_latency_ms",      # 99.9th percentile latency
    "pod_restarts_total",        # cumulative pod restart count
    "network_receive_bytes",     # inbound network bytes per second
    "network_transmit_bytes",    # outbound network bytes per second
    "disk_io_bytes",             # disk read+write bytes per second
]
# WHY THESE 15 METRICS: This set covers the four dimensions of K8s resource
# health: compute (cpu_throttle, cpu_usage), memory (rss, working_set),
# application performance (latency, error_rate, request_rate), and
# infrastructure health (restarts, network, disk). Together they capture
# the full impact of any configuration change on workload behavior.

INPUT_SEQUENCE_LENGTH = 60   # 5 minutes at 5-second resolution
# WHY 5 MINUTES: Config drift effects propagate within 1-2 minutes (CPU
# throttling appears immediately, but latency spikes need traffic to
# manifest). 5 minutes gives enough context to see the full before/after
# pattern while keeping the sequence short enough for fast inference.

class MetricBiLSTMEncoder(nn.Module):
    def __init__(
        self,
        input_dim: int = len(METRIC_COLUMNS),   # 15 metrics
        hidden_dim: int = 64,                    # LSTM hidden units per direction
        output_dim: int = 64,                    # final embedding dim
        num_layers: int = 2,                     # stacked LSTM layers
        dropout: float = 0.1
    ):
        super().__init__()
        
        # Input normalization: z-score each metric independently.
        # WHY: CPU throttle (0-100) and memory_rss_bytes (0-8e9) are on
        # completely different scales. Without normalization, the LSTM
        # gates saturate on large-valued metrics and ignore small-valued
        # ones. LayerNorm normalizes across the feature dimension for each
        # timestep independently.
        self.input_norm = nn.LayerNorm(input_dim)
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
            # WHY dropout=0 for single layer: nn.LSTM's dropout is applied
            # between layers, not within a layer. A 1-layer LSTM with dropout
            # silently ignores the dropout parameter — the PyTorch docs
            # mention this but it's a common gotcha.
        )
        
        # After BiLSTM: hidden_dim * 2 (forward + backward concatenated)
        # We use the final hidden states, not all timesteps.
        # WHY FINAL HIDDEN STATE: The last forward hidden state summarizes
        # the entire sequence from left-to-right. The last backward hidden
        # state summarizes from right-to-left. Their concatenation gives
        # a complete bidirectional summary without needing to process all
        # 60 timesteps in the output layer.
        self.output_projection = nn.Linear(hidden_dim * 2, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)
    
    def forward(
        self, 
        metrics: torch.Tensor  # [batch, seq_len=60, num_metrics=15]
    ) -> torch.Tensor:
        """
        Returns:
            metric_embedding: [batch, output_dim=64]
        """
        x = self.input_norm(metrics)
        
        # lstm_out: [batch, seq_len, hidden_dim * 2]
        # (hn, cn): each [num_layers * 2, batch, hidden_dim]
        lstm_out, (hn, cn) = self.lstm(x)
        
        # Extract final hidden states for both directions.
        # hn shape: [num_layers * 2, batch, hidden_dim]
        # For a 2-layer BiLSTM:
        #   hn[0]: forward, layer 1
        #   hn[1]: backward, layer 1
        #   hn[2]: forward, layer 2  ← this is the final forward state
        #   hn[3]: backward, layer 2 ← this is the final backward state
        forward_final = hn[-2]   # [batch, hidden_dim]
        backward_final = hn[-1]  # [batch, hidden_dim]
        
        # Concatenate: [batch, hidden_dim * 2]
        combined = torch.cat([forward_final, backward_final], dim=-1)
        
        embedding = self.output_projection(combined)  # [batch, output_dim=64]
        embedding = self.layer_norm(embedding)
        embedding = self.dropout(embedding)
        
        return embedding


def fetch_prometheus_metrics(
    namespace: str,
    pod_name: str,
    window_minutes: int = 5,
    max_age_seconds: int = 6
) -> np.ndarray:
    """
    Fetches the 15 metrics for a given pod over the last window_minutes.
    
    Uses the short-scrape Prometheus endpoint (5s interval) for kubeheal
    namespaces. Falls back to standard scrape if short-scrape is unavailable.
    
    Returns:
        np.ndarray of shape [60, 15] — the metric matrix for BiLSTM input.
        Returns zeros for any metric that is unavailable (pod just started,
        metric not exposed, etc.)
    
    > CLAUDE CODE INSTRUCTION: This function must replace the
    > asyncio.sleep(15s) anti-pattern in agents/health_agent/agent.py.
    > Implement it with an exponential backoff polling loop:
    > - Poll every 2s, up to 30s total
    > - Check max_age_seconds on the most recent sample
    > - If fresh data available before timeout, return immediately
    > - If timeout reached, return whatever data is available (even if stale)
    > - Log a warning if data is >6s old at return time
    > Cache results in a module-level dict keyed by (namespace, pod_name):
    > _prometheus_cache: dict[tuple, tuple[np.ndarray, float]] = {}
    > where the tuple value is (data_array, timestamp_fetched)
    > Entries expire after 8 seconds (slightly longer than max_age to avoid
    > stampedes when multiple concurrent drift events hit the same pod).
    """
    pass  # Implementation required
```

### 3.4 Component 3: Health Model Fusion and Output Head

After the GAT produces a 128-dim YAML embedding and the BiLSTM produces a 64-dim metric embedding, they must be fused. In v4, this fusion is internal to the Health Model — not shared with security signals.

**Fusion mechanism:** Cross-attention between the YAML embedding and the metric embedding. The YAML embedding acts as the "query" (what changed?), and the metric embedding acts as the "key/value" (what was the impact?). This is semantically correct: we are asking "given what changed in the YAML, what does the metric signal tell us about the impact?"

```python
# FILE: models/health_model/health_fusion_attention.py

import torch
import torch.nn as nn

class HealthFusionAttention(nn.Module):
    """
    Cross-attention fusion of YAML embedding and metric embedding.
    
    Query = YAML embedding (what changed)
    Key/Value = metric embedding (what was impacted)
    
    WHY CROSS-ATTENTION INSTEAD OF SIMPLE CONCATENATION:
    Concatenation followed by an MLP treats both embeddings equally.
    Cross-attention allows the model to learn: "given this specific YAML
    change (query), which aspects of the metric trajectory (key/value)
    are most relevant to assessing risk?" 
    
    For example: a change to cpu_limits should attend heavily to
    cpu_throttle_percent and http_p99_latency metrics. A change to
    memory_limits should attend to memory_rss_bytes and pod_restarts.
    The cross-attention weights capture this conditional relevance.
    """
    def __init__(self, yaml_dim: int = 128, metric_dim: int = 64, fused_dim: int = 128, num_heads: int = 4):
        super().__init__()
        # Project both embeddings to the same dimension for attention
        self.yaml_proj = nn.Linear(yaml_dim, fused_dim)
        self.metric_proj = nn.Linear(metric_dim, fused_dim)
        self.cross_attention = nn.MultiheadAttention(
            embed_dim=fused_dim,
            num_heads=num_heads,
            batch_first=True,
            dropout=0.1
        )
        self.layer_norm = nn.LayerNorm(fused_dim)
        self.output_mlp = nn.Sequential(
            nn.Linear(fused_dim * 2, fused_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(fused_dim, fused_dim)
        )
    
    def forward(
        self,
        yaml_embedding: torch.Tensor,    # [batch, 128]
        metric_embedding: torch.Tensor   # [batch, 64]
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            fused_embedding: [batch, 128] — the health-domain embedding
            cross_attn_weights: [batch, 1, fused_dim] — attention weights
        """
        yaml_proj = self.yaml_proj(yaml_embedding).unsqueeze(1)    # [batch, 1, fused_dim]
        metric_proj = self.metric_proj(metric_embedding).unsqueeze(1)  # [batch, 1, fused_dim]
        
        # YAML embedding queries the metric embedding
        attended, attn_weights = self.cross_attention(
            query=yaml_proj,
            key=metric_proj,
            value=metric_proj
        )
        # attended: [batch, 1, fused_dim]
        attended = attended.squeeze(1)  # [batch, fused_dim]
        
        # Residual connection: preserve original YAML information
        yaml_flat = self.yaml_proj(yaml_embedding)  # [batch, fused_dim]
        residual = self.layer_norm(attended + yaml_flat)
        
        # Concatenate attended and original, then project
        combined = torch.cat([residual, attended], dim=-1)  # [batch, fused_dim * 2]
        fused = self.output_mlp(combined)  # [batch, fused_dim]
        
        return fused, attn_weights
```

### 3.5 Health Model Output Head

```python
# FILE: models/health_model/health_output_head.py

import torch
import torch.nn as nn

HEALTH_LABELS = [
    "benign",                          # No meaningful drift or all drift is safe
    "low_risk_drift",                  # Drift detected, minimal performance impact
    "harmful_performance_degradation", # Drift causing measurable performance harm
    "critical_config_error",           # Drift causing severe outage-level harm
]
# WHY FOUR LABELS (not binary): Binary (drift/no-drift) loses the severity
# dimension. The Fusion Agent needs to know not just "is there drift" but
# "how bad is it?" A critical_config_error (cpu: 0m, memory: 0) warrants
# immediate autonomous action. A low_risk_drift warrants logging only.
# Four labels provides this resolution while remaining interpretable.

class HealthOutputHead(nn.Module):
    def __init__(self, fused_dim: int = 128, num_labels: int = len(HEALTH_LABELS)):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, num_labels)
        )
        self.risk_regressor = nn.Sequential(
            nn.Linear(fused_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()  # output in [0, 1]
        )
    
    def forward(self, fused_embedding: torch.Tensor):
        """
        Returns:
            label_logits: [batch, 4] — raw logits for label classification
            risk_score: [batch, 1] — continuous risk score in [0, 1]
        """
        return self.classifier(fused_embedding), self.risk_regressor(fused_embedding)
```

---

## SECTION 04 — SECURITY MODEL (DEDICATED): TRANSFORMER + CONV1D ENCODER

### 4.1 What the Security Model Replaces

In v3, `transformer_encoder.py` (Falco events) and `conv1d_encoder.py` (entropy series) were also components inside the monolithic DIT-Sec. They are extracted into the dedicated **Security Model** in v4.

The Security Model receives only behavioral signals — Falco eBPF syscall events and file entropy time series. It knows nothing about YAML diffs or Prometheus metrics. This is intentional: a security model should not need to understand Kubernetes configuration to detect ransomware. If a pod's file writes suddenly exhibit 7.8 bits of Shannon entropy and the syscall trace shows a ftruncate + write pattern on PV mount paths, that is ransomware regardless of what the CPU limit is set to.

### 4.2 Component 1: Falco Transformer Encoder (falco_transformer_encoder.py)

**What it does:** Converts a sequence of Falco syscall events into a 64-dim embedding that captures the behavioral signature of the process.

**Why Transformer (kept from v3):**

Unlike the YAML encoder (where GAT was necessary) or the metric encoder (where BiLSTM replaces Mamba), the transformer remains the right choice for syscall event sequences. Here's why:

Ransomware syscall patterns have long-range dependencies. The attack pattern is: `open()` → long sequence of `read()` calls → `close()` → `open()` (same file) → encrypt in memory → `write()` → `rename()`. The connection between the initial `open()` and the eventual `rename()` can span hundreds of syscall events. Transformers with self-attention explicitly model long-range dependencies through their attention mechanism — any position can attend to any other position regardless of distance. LSTMs, by contrast, compress long histories into a fixed hidden state and lose distant context.

> WHY NOT REPLACE WITH MAMBA HERE: The argument for replacing Mamba with BiLSTM (in the metric encoder) was that our sequences are short (60 timesteps). Falco event sequences are different — we process up to 256 syscall events per window (the max in the PRD spec). At 256 events, the O(n²) self-attention is still fast (256² = 65,536 operations, negligible on CPU for a 4-head, 2-layer transformer). And the long-range dependency problem is real for syscall sequences in a way it isn't for metric windows. Keep the transformer.

```python
# FILE: models/security_model/falco_transformer_encoder.py

import torch
import torch.nn as nn
import math

# Syscall vocabulary: the set of syscall names we track.
# Generated from running Falco in a K8s cluster for 24 hours and
# extracting all unique syscall names from the output.
# > CLAUDE CODE INSTRUCTION: Create the file
# > models/security_model/syscall_vocabulary.json by running:
# > python models/security_model/build_syscall_vocab.py
# > which reads all Falco rule output files in chaos/ and demo/

MAX_SEQUENCE_LENGTH = 256    # max syscall events per window
SYSCALL_VOCAB_SIZE = 512     # all possible syscall names (generous upper bound)
EVENT_EMBEDDING_DIM = 64     # per-event embedding dimension

# Each Falco event has these fields:
# - syscall_name: the syscall (open, read, write, close, rename, etc.)
# - pid: process ID
# - fd_path: file path involved (if filesystem syscall)
# - direction: in/out (for network syscalls)
# - timestamp_offset: ms since window start (for temporal context)
# We encode all five as part of the token embedding.

class FalcoTransformerEncoder(nn.Module):
    def __init__(
        self,
        vocab_size: int = SYSCALL_VOCAB_SIZE,
        embed_dim: int = EVENT_EMBEDDING_DIM,
        num_heads: int = 4,
        num_layers: int = 2,
        max_seq_len: int = MAX_SEQUENCE_LENGTH,
        output_dim: int = 64,
        dropout: float = 0.1
    ):
        super().__init__()
        
        self.syscall_embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        # padding_idx=0 means token ID 0 = PAD. Sequences shorter than
        # MAX_SEQUENCE_LENGTH are right-padded with 0s.
        
        self.path_embedding = nn.Embedding(10000, embed_dim // 2)
        # Path vocabulary: hash each unique file path to an integer ID.
        # WHY HASH: We don't need the exact path string — we need to know
        # if the same path appears multiple times (pattern) vs random paths.
        # Hashing preserves this without requiring a huge vocabulary.
        
        self.position_encoding = self._build_sinusoidal_pe(max_seq_len, embed_dim)
        # WHY SINUSOIDAL POSITIONAL ENCODING: Unlike learned positional
        # embeddings, sinusoidal PE generalizes to sequence lengths not
        # seen during training. If a real attack generates 300 syscall
        # events (beyond our training max of 256), the PE still produces
        # meaningful positional signals for the first 256 tokens.
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout,
            batch_first=True,
            norm_first=True  # Pre-LayerNorm (more stable training)
            # WHY norm_first=True (Pre-LN): Post-LayerNorm (the original
            # transformer) accumulates large gradients in early training
            # when attention weights are near-uniform. Pre-LN normalizes
            # the input before attention, stabilizing training with fewer
            # warmup steps. Critical for small datasets (<15K samples).
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        self.cls_token = nn.Parameter(torch.randn(1, 1, embed_dim))
        # CLS token: a learnable token prepended to the sequence.
        # WHY CLS TOKEN: After transformer encoding, we need a single
        # summary embedding for the entire sequence. Using the CLS token's
        # final hidden state (rather than mean pooling all tokens) lets
        # the model learn what to aggregate — it attends to whichever
        # syscall events are most predictive of the label.
        
        self.output_projection = nn.Linear(embed_dim, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
    
    def _build_sinusoidal_pe(self, max_len: int, d_model: int) -> torch.Tensor:
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        return pe.unsqueeze(0)  # [1, max_len, d_model]
    
    def forward(
        self,
        syscall_ids: torch.Tensor,    # [batch, seq_len] — tokenized syscall names
        path_ids: torch.Tensor,       # [batch, seq_len] — hashed file path IDs
        padding_mask: torch.Tensor    # [batch, seq_len] — True = pad token
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            security_embedding: [batch, output_dim=64]
            attention_weights: [batch, num_heads, seq_len, seq_len]
                               — used by interpretation layer to identify
                               which syscall events were most suspicious
        """
        batch_size, seq_len = syscall_ids.shape
        
        # Build token embeddings
        syscall_emb = self.syscall_embedding(syscall_ids)   # [batch, seq_len, embed_dim]
        path_emb = self.path_embedding(path_ids)            # [batch, seq_len, embed_dim//2]
        
        # Pad path embedding to match syscall embedding dimension
        path_emb_padded = torch.zeros_like(syscall_emb)
        path_emb_padded[:, :, :path_emb.shape[-1]] = path_emb
        
        # Combine syscall + path embeddings
        x = syscall_emb + path_emb_padded
        
        # Add positional encoding
        x = x + self.position_encoding[:, :seq_len, :].to(x.device)
        
        # Prepend CLS token
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)  # [batch, 1, embed_dim]
        x = torch.cat([cls_tokens, x], dim=1)  # [batch, seq_len+1, embed_dim]
        
        # Extend padding mask for CLS token (CLS is never masked)
        cls_mask = torch.zeros(batch_size, 1, dtype=torch.bool, device=padding_mask.device)
        padding_mask_extended = torch.cat([cls_mask, padding_mask], dim=1)
        
        # Transformer encoding
        # Note: nn.TransformerEncoder doesn't return attention weights natively.
        # We hook into the last layer to extract them.
        encoded = self.transformer(x, src_key_padding_mask=padding_mask_extended)
        # encoded: [batch, seq_len+1, embed_dim]
        
        # Extract CLS token output as sequence summary
        cls_output = encoded[:, 0, :]  # [batch, embed_dim]
        
        embedding = self.output_projection(cls_output)  # [batch, output_dim=64]
        embedding = self.layer_norm(embedding)
        
        # For attention weights, use a manual extraction hook
        # (implementation in security_model_server.py using forward hooks)
        # Return placeholder here; server fills in actual weights
        attention_placeholder = torch.zeros(batch_size, 4, seq_len+1, seq_len+1)
        
        return embedding, attention_placeholder
```

### 4.3 Component 2: Entropy Conv1D + Squeeze-Excitation Encoder (entropy_conv1d_encoder.py)

**What it is:** A lightweight convolutional encoder for the file entropy time series. This component is carried over from v3 with one fix: it is no longer fused with YAML/metric signals.

**Why Conv1D + Squeeze-Excitation and not a transformer or LSTM:**

The entropy time series is short (at most 30 timesteps: 60 seconds of 2-second resolution entropy measurements) and univariate (just one value per timestep: the Shannon entropy of the most recently written file bytes). For sequences of length ≤30, transformers are computationally overkill and tend to overfit. LSTMs are reasonable but Conv1D with Squeeze-Excitation is faster and has a useful inductive bias: local patterns matter most for entropy (a sudden jump from 3.2 to 7.6 bits in 2 seconds is the signature, not a long-range dependency).

The Squeeze-Excitation block adds channel-wise attention: it learns which Conv1D filter responses are most informative for the ransomware classification task and amplifies those while suppressing less relevant filters.

```python
# FILE: models/security_model/entropy_conv1d_encoder.py

import torch
import torch.nn as nn

ENTROPY_WINDOW_LENGTH = 30  # 60 seconds at 2-second resolution
# WHY 2-SECOND RESOLUTION: Our eBPF write byte counter is read every 2s
# (as specified in the Security Agent pipeline). Entropy is computed from
# reservoir samples of recently-written bytes at each 2s interval.
# This gives us 30 timesteps for a 60-second window — enough to capture
# the characteristic entropy spike of AES-256 encryption initiation.

class EntropyConv1DEncoder(nn.Module):
    def __init__(
        self,
        input_length: int = ENTROPY_WINDOW_LENGTH,
        output_dim: int = 64,
        num_filters: int = 64,
        dropout: float = 0.1
    ):
        super().__init__()
        
        # Multi-scale convolutions: capture patterns at different time scales.
        # Kernel size 3 → detects rapid entropy changes (2-second bursts)
        # Kernel size 7 → detects medium-term patterns (14-second trends)
        # Kernel size 15 → detects slow-onset encryption (30-second patterns)
        # WHY MULTI-SCALE: Different ransomware strains encrypt at different
        # speeds. Fast ransomware (180 files/sec) shows a sharp entropy spike
        # (kernel 3 catches this). Slow/dormant ransomware shows a gradual
        # rise (kernel 15 catches this). A single kernel size would miss one
        # or the other.
        self.conv_3  = nn.Conv1d(1, num_filters, kernel_size=3,  padding=1)
        self.conv_7  = nn.Conv1d(1, num_filters, kernel_size=7,  padding=3)
        self.conv_15 = nn.Conv1d(1, num_filters, kernel_size=15, padding=7)
        
        # Squeeze-Excitation block
        # Computes a per-channel weight: which of the 3*num_filters filters
        # is most informative for the current input?
        se_input_dim = num_filters * 3  # after concatenating 3 conv outputs
        se_reduction = 4  # reduce to se_input_dim // 4 in the bottleneck
        self.se_squeeze = nn.Linear(se_input_dim, se_input_dim // se_reduction)
        self.se_excite  = nn.Linear(se_input_dim // se_reduction, se_input_dim)
        
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        # WHY ADAPTIVE AVG POOL: After convolutions, we have a tensor of
        # shape [batch, channels, time]. We want a fixed-size embedding
        # regardless of input length. AdaptiveAvgPool1d(1) reduces the
        # time dimension to 1 by averaging, giving [batch, channels, 1].
        
        self.output_projection = nn.Linear(se_input_dim, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)
        self.relu = nn.ReLU()
    
    def forward(self, entropy_series: torch.Tensor) -> torch.Tensor:
        """
        Args:
            entropy_series: [batch, sequence_length=30] — entropy values in bits
        
        Returns:
            entropy_embedding: [batch, output_dim=64]
        """
        # Add channel dimension for Conv1d: [batch, 1, seq_len]
        x = entropy_series.unsqueeze(1)
        
        # Multi-scale convolutions
        c3  = self.relu(self.conv_3(x))   # [batch, num_filters, seq_len]
        c7  = self.relu(self.conv_7(x))   # [batch, num_filters, seq_len]
        c15 = self.relu(self.conv_15(x))  # [batch, num_filters, seq_len]
        
        # Concatenate along channel dimension
        multi_scale = torch.cat([c3, c7, c15], dim=1)  # [batch, 3*num_filters, seq_len]
        
        # Global average pooling: [batch, 3*num_filters, 1] → [batch, 3*num_filters]
        pooled = self.global_pool(multi_scale).squeeze(-1)
        
        # Squeeze-Excitation: compute channel-wise attention weights
        se = self.se_squeeze(pooled)            # [batch, se_input_dim // reduction]
        se = self.relu(se)
        se = self.se_excite(se)                 # [batch, se_input_dim]
        se = torch.sigmoid(se)                  # scale to [0, 1]
        
        # Re-weight channels: amplify informative filters, suppress noise
        recalibrated = pooled * se  # [batch, se_input_dim]
        
        embedding = self.output_projection(recalibrated)  # [batch, output_dim=64]
        embedding = self.layer_norm(embedding)
        embedding = self.dropout(embedding)
        
        return embedding
```

### 4.4 Security Model Output Head

```python
# FILE: models/security_model/security_output_head.py

import torch
import torch.nn as nn

SECURITY_LABELS = [
    "benign",              # Normal process activity
    "suspicious",          # Elevated signals but below decision threshold
    "ransomware_staging",  # Early signals: rename bursts, ftruncate patterns
    "ransomware_active",   # High confidence active encryption in progress
    "data_exfiltration",   # High network egress + encryption patterns
]
# WHY FIVE LABELS: The five-label taxonomy captures the progression of an
# attack. "ransomware_staging" allows KubeHeal to issue early warnings and
# apply NetworkPolicy egress blocks before full confidence, reducing the
# exfiltration window. "data_exfiltration" as a separate label handles the
# case where data is being exfiltrated without local encryption (e.g.,
# attacker copies plaintext data out rather than encrypting in place).

class SecurityOutputHead(nn.Module):
    def __init__(self, fused_dim: int = 64, num_labels: int = len(SECURITY_LABELS)):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, num_labels)
        )
        self.risk_regressor = nn.Sequential(
            nn.Linear(fused_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    
    def forward(self, fused_embedding: torch.Tensor):
        return self.classifier(fused_embedding), self.risk_regressor(fused_embedding)
```

---

## SECTION 05 — DEPENDENCY CORRELATION MODULE (DCM): THE NOVEL CONTRIBUTION

### 5.1 What the DCM Is

The Dependency Correlation Module is the architectural innovation that separates KubeHeal v4 from every existing Kubernetes security and observability tool. It takes the embedding vectors from both the Health Model and the Security Model and computes a correlation score that answers: **"Are the health signal and the security signal for this resource causally related?"**

This distinction changes how the Fusion Agent responds:

| Health Risk | Security Risk | DCM Correlation | Interpretation | Action |
|-------------|---------------|-----------------|----------------|--------|
| 0.88 | 0.93 | 0.84 (HIGH) | Ransomware is causing CPU thrash that appears as drift | Compound incident — escalate harder |
| 0.85 | 0.12 | 0.09 (LOW) | Pure config drift, no security involvement | Health-only auto-patch |
| 0.15 | 0.91 | 0.11 (LOW) | Ransomware on a healthy pod — no drift observed | Security-only kill |
| 0.77 | 0.74 | 0.71 (HIGH) | Compound — security causing health degradation | Elevated compound response |

Without the DCM, the Fusion Agent combines health_risk and sec_risk with a simple weighted average or max operation. This loses the relationship between them. Two independent events (a misconfigured CPU limit AND an unrelated ransomware on a different container) would produce a combined score that looks like a compound attack. The DCM prevents this false amplification.

### 5.2 Why Cross-Modal Attention Is the Right Mechanism

The DCM uses bidirectional cross-modal attention between the two 128-dim embeddings (health_embedding and security_embedding). Here's why:

The health embedding encodes YAML structure and metric trajectories. The security embedding encodes syscall patterns and entropy trajectories. If these two embeddings are "pointing in the same direction" in the embedding space — if the ransomware's CPU-heavy encryption is being picked up by the metric encoder AND by the entropy encoder — then the cross-attention weights will be high and the correlation score will be high.

If the health embedding represents a mundane CPU limit change and the security embedding represents high entropy from a completely different namespace, the cross-attention weights will be distributed randomly (no coherent cross-modal pattern), and the correlation score will be low.

```python
# FILE: models/dcm/cross_modal_attention.py

import torch
import torch.nn as nn

class CrossModalAttention(nn.Module):
    """
    Bidirectional cross-modal attention between health and security embeddings.
    
    "Bidirectional" means we compute attention in BOTH directions:
    1. Health queries security: "given what the health model saw, which
       aspects of the security signal match?"
    2. Security queries health: "given what the security model saw, which
       aspects of the health signal match?"
    
    WHY BIDIRECTIONAL: Unidirectional cross-attention would only capture
    how much the security signal explains the health signal (or vice versa).
    Bidirectional captures the mutual information between both signals.
    High mutual information = high correlation = compound incident.
    
    The correlation score is computed as a function of both attention
    weight matrices. When both directions show high confidence (concentrated
    attention weights), the correlation is high. When one or both directions
    show diffuse attention (near-uniform weights = the model found no strong
    cross-modal pattern), the correlation is low.
    """
    
    def __init__(
        self,
        health_dim: int = 128,
        security_dim: int = 64,
        hidden_dim: int = 128,
        num_heads: int = 4,
        dropout: float = 0.1
    ):
        super().__init__()
        
        # Project both embeddings to shared hidden_dim for attention compatibility
        self.health_proj   = nn.Linear(health_dim, hidden_dim)
        self.security_proj = nn.Linear(security_dim, hidden_dim)
        
        # Direction 1: Health queries Security
        # Q = health_embedding, K = V = security_embedding
        self.health_queries_security = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True
        )
        
        # Direction 2: Security queries Health
        # Q = security_embedding, K = V = health_embedding
        self.security_queries_health = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True
        )
        
        # Correlation head: takes concatenation of both attended outputs
        # and produces a scalar correlation score
        self.correlation_head = nn.Sequential(
            nn.Linear(hidden_dim * 4, 64),
            # WHY hidden_dim * 4: We concatenate:
            # - health_proj (health encoding)
            # - attended_health_to_security (health viewing security)
            # - security_proj (security encoding)
            # - attended_security_to_health (security viewing health)
            # Each is hidden_dim dimensional, so total = 4 * hidden_dim
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
            # Output: correlation_score in [0, 1]
        )
        
        self.layer_norm = nn.LayerNorm(hidden_dim)
    
    def forward(
        self,
        health_embedding: torch.Tensor,    # [batch, health_dim=128]
        security_embedding: torch.Tensor   # [batch, security_dim=64]
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Returns:
            correlation_score: [batch, 1] — scalar correlation in [0, 1]
            health_to_security_attn: [batch, num_heads, 1, 1] — attention weights
            security_to_health_attn: [batch, num_heads, 1, 1] — attention weights
        """
        # Project to shared dimension
        h = self.health_proj(health_embedding).unsqueeze(1)    # [batch, 1, hidden_dim]
        s = self.security_proj(security_embedding).unsqueeze(1) # [batch, 1, hidden_dim]
        
        # Direction 1: Health queries Security
        h_attended, h_to_s_attn = self.health_queries_security(
            query=h, key=s, value=s
        )
        h_attended = self.layer_norm(h_attended + h)  # residual
        
        # Direction 2: Security queries Health
        s_attended, s_to_h_attn = self.security_queries_health(
            query=s, key=h, value=h
        )
        s_attended = self.layer_norm(s_attended + s)  # residual
        
        # Concatenate all four representations
        combined = torch.cat([
            h.squeeze(1),          # original health projection
            h_attended.squeeze(1), # health's view of security
            s.squeeze(1),          # original security projection
            s_attended.squeeze(1)  # security's view of health
        ], dim=-1)  # [batch, hidden_dim * 4]
        
        correlation_score = self.correlation_head(combined)  # [batch, 1]
        
        return correlation_score, h_to_s_attn, s_to_h_attn


class CausalChainBuilder:
    """
    Constructs a human-readable causal chain from the correlation module's
    attention weights and the individual model outputs.
    
    The causal chain is an ordered list of events that explains the incident:
    ["CPU limit changed to 50m (T+0s)",
     "CPU throttle reached 82% (T+5s)",
     "p99 latency increased to 1390ms (T+12s)",
     "Error rate increased to 3.2% (T+20s)"]
    
    For compound incidents:
    ["Ransomware process spawned (T+0s)",
     "Mass encryption started: 180 files/sec (T+2s)",
     "File entropy reached 7.76 bits (T+2.9s)",
     "CPU usage increased to 890m due to AES operations (T+3.1s)",
     "Health model flagged CPU drift (T+3.3s)",
     "Security model flagged ransomware (T+3.3s)",
     "DCM: compound incident confirmed (correlation=0.84)"]
    
    > CLAUDE CODE INSTRUCTION: Implement this class as a pure Python
    > class (no PyTorch) that takes the following inputs:
    > - health_assessment: dict from the Health Model server
    > - security_event: dict from the Security Agent
    > - correlation_score: float from DCM
    > - field_attribution: dict from Interpretation Layer
    > And returns a list of strings in chronological order.
    > Each string must include a relative timestamp (T+Xs format),
    > the signal name, and the observed value.
    """
    
    def build(
        self,
        health_assessment: dict,
        security_event: dict,
        correlation_score: float,
        field_attribution: dict
    ) -> list[str]:
        chain = []
        # Implementation required — see Section 11
        # Logic:
        # 1. Sort all events by timestamp
        # 2. For each event, format as human-readable string
        # 3. If correlation > 0.6, include the DCM confirmation line
        return chain
```

### 5.3 DCM Training Strategy

The DCM must be trained AFTER the Health Model and Security Model are trained and their weights are frozen. This is a staged training approach:

**Stage 1:** Train Health Model on (YAML diff, Prometheus metrics) pairs with health labels. 40 epochs, lr=2e-4, batch_size=32.

**Stage 2:** Train Security Model on (Falco events, entropy series) pairs with security labels. 40 epochs, lr=2e-4, batch_size=32.

**Stage 3:** Freeze both models' weights. Train DCM using the frozen models as feature extractors. DCM training data requires labeled pairs of (health_assessment, security_event, is_compound: bool). Compound incidents are generated by Chaos Mesh scenarios where ransomware AND config drift are injected simultaneously.

> WHY STAGED TRAINING: If you train all three components jointly, the DCM's gradients will flow back through both models and modify their internal representations to make the DCM's correlation detection easier — at the cost of making each model's primary task (health/security detection) worse. Freezing the base models ensures they remain specialists. The DCM learns to correlate their outputs without corrupting their representations.

```python
# FILE: models/train_dcm.py

"""
DCM Training Script — run AFTER train_health_model.py and train_security_model.py

Usage:
    python models/train_dcm.py \
        --health-model models/health_model/checkpoints/best_health_model.pt \
        --security-model models/security_model/checkpoints/best_security_model.pt \
        --data data/compound_incidents.jsonl \
        --output models/dcm/checkpoints/ \
        --epochs 30 \
        --lr 5e-4 \
        --batch-size 16

WHY SMALLER LR AND FEWER EPOCHS FOR DCM:
The DCM is a smaller model (cross-attention + 3-layer MLP) than either base model.
With frozen base models, the feature space is fixed. The DCM converges faster
because it's learning a simpler mapping (from embedding pair to correlation score)
than the base models (from raw signals to semantic embeddings). Lower LR prevents
overshooting the loss minimum in this simpler optimization landscape.
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import argparse
import json
from pathlib import Path

from health_model.yaml_gat_encoder import YAMLGATEncoder
from health_model.metric_bilstm_encoder import MetricBiLSTMEncoder
from health_model.health_fusion_attention import HealthFusionAttention
from health_model.health_output_head import HealthOutputHead
from security_model.falco_transformer_encoder import FalcoTransformerEncoder
from security_model.entropy_conv1d_encoder import EntropyConv1DEncoder
from security_model.security_fusion_attention import SecurityFusionAttention
from security_model.security_output_head import SecurityOutputHead
from dcm.cross_modal_attention import CrossModalAttention

def load_frozen_health_model(checkpoint_path: str) -> nn.Module:
    """Load health model and freeze all parameters."""
    # Load all health model components
    # Freeze all parameters: requires_grad = False for everything
    # WHY FREEZE: DCM gradients must not flow into health model weights.
    # If they do, the health model's internal representations will be
    # modified to satisfy the DCM's correlation task, breaking the
    # health model's primary classification accuracy.
    pass

def load_frozen_security_model(checkpoint_path: str) -> nn.Module:
    """Load security model and freeze all parameters."""
    pass

class CompoundIncidentDataset(torch.utils.data.Dataset):
    """
    Dataset of (health_sample, security_sample, is_compound) triples.
    
    Positive examples (is_compound=True): generated by Chaos Mesh scenarios
    that inject both ransomware AND config drift simultaneously. The config
    drift is a direct consequence of the ransomware's CPU consumption.
    
    Negative examples (is_compound=False): generated by running config drift
    injection and ransomware injection at different times on different pods,
    so there is no causal relationship between the health signal and the
    security signal.
    
    > CLAUDE CODE INSTRUCTION: Generate the compound incident dataset by
    > running: python models/generate_compound_dataset.py
    > which uses Chaos Mesh to inject 5000 positive and 5000 negative
    > examples. Both sets are stored in data/compound_incidents.jsonl
    """
    pass

def train_dcm(args):
    health_model = load_frozen_health_model(args.health_model)
    security_model = load_frozen_security_model(args.security_model)
    dcm = CrossModalAttention()
    
    optimizer = torch.optim.AdamW(dcm.parameters(), lr=args.lr, weight_decay=1e-4)
    # WHY AdamW: Weight decay in AdamW is applied correctly (decoupled from
    # the adaptive learning rate), unlike Adam + L2 regularization. This
    # prevents the DCM from overfitting to the limited compound incident dataset.
    
    criterion = nn.BCELoss()  # binary: is_compound vs is_independent
    # ... training loop implementation
```

---

## SECTION 06 — INTERPRETATION LAYER: SHAP + NATURAL LANGUAGE EXPLAINABILITY

### 6.1 Why the Interpretation Layer Wins Demos

When a judge sees KubeHeal detect a ransomware attack and kill the pod in 8 seconds, that is impressive. When they then see the dashboard display:

> **"containers[0].resources.limits.cpu changed from 500m to 50m (T+0s), causing CPU throttle to reach 82% (T+5s) and p99 latency to spike to 1390ms (T+12s). This was a pure configuration drift event. The security model was calm (sec_risk=0.12, DCM correlation=0.09). Auto-patched safely."**

— that is a fundamentally different level of system intelligence. The interpretation layer converts the model's internal attention weights into plain English. It makes the AI's reasoning auditable and trustworthy.

### 6.2 SHAP Explainer

SHAP (SHapley Additive exPlanations) is a game-theoretic approach to computing feature importance. For each model output (health_risk=0.79), SHAP computes how much each input feature contributed to that output relative to a baseline (the average output across all training data).

In the context of KubeHeal:
- For the Health Model, SHAP tells us: "containers[0].resources.limits.cpu contributed +0.43 to the health_risk score. containers[0].env[DATABASE_URL] contributed +0.02."
- For the Security Model, SHAP tells us: "rename() syscalls contributed +0.38 to the sec_risk score. ftruncate() patterns contributed +0.27."

```python
# FILE: models/interpretation/shap_explainer.py

"""
SHAP-based explainability for Health Model and Security Model outputs.

We use shap.DeepExplainer for neural network models because:
1. It handles PyTorch models natively
2. It approximates Shapley values efficiently using a background dataset
3. It handles variable-size inputs (our YAML graphs have different node counts)

> CLAUDE CODE INSTRUCTION: Install shap: pip install shap --break-system-packages
> The background dataset for DeepExplainer should be 200 samples from the
> training set (a random subset). Store this in:
> models/interpretation/shap_background_health.pt (for health model)
> models/interpretation/shap_background_security.pt (for security model)
"""

import shap
import torch
import numpy as np
from typing import Optional

class HealthModelSHAPExplainer:
    """
    Computes SHAP values for Health Model outputs.
    
    Because the Health Model has two input modalities (YAML graph + metric
    series), we compute SHAP values separately for each modality and then
    combine. This tells us: "how much did the YAML structure contribute vs
    how much did the metric signals contribute to the risk score?"
    
    Within the YAML modality, SHAP values are computed per-node in the graph,
    then mapped back to actual K8s field names using the field_name_mapper.
    
    Within the metric modality, SHAP values are computed per-metric per-timestep,
    then summarized as a per-metric importance score.
    """
    
    def __init__(self, health_model, background_dataset_path: str):
        self.model = health_model
        self.model.eval()
        background = torch.load(background_dataset_path)
        self.explainer = shap.DeepExplainer(self.model, background)
    
    def explain(self, yaml_graph, metric_tensor) -> dict:
        """
        Returns:
            field_attributions: dict mapping K8s field paths to SHAP values
                e.g., {"spec.template.spec.containers[0].resources.limits.cpu": 0.43,
                        "spec.template.spec.containers[0].env[0].value": 0.02}
            metric_attributions: dict mapping metric names to SHAP values
                e.g., {"cpu_throttle_percent": 0.31, "http_p99_latency_ms": 0.18}
            top_field: str — the single highest-attribution K8s field
            top_metric: str — the single highest-attribution metric
        """
        shap_values = self.explainer.shap_values([yaml_graph, metric_tensor])
        # ... post-process SHAP values into field_attributions dict
        pass


class SecurityModelSHAPExplainer:
    """
    Computes SHAP values for Security Model outputs.
    
    For the Falco transformer, SHAP values are per-token (per-syscall event).
    We aggregate to per-syscall-type importance:
    {"rename": 0.38, "ftruncate": 0.27, "open": 0.12, "write": 0.09}
    
    For the entropy Conv1D, SHAP values are per-timestep. We report
    which time window had the highest entropy spike:
    {"max_entropy_timestep": "T+2.7s", "max_entropy_bits": 7.76,
     "entropy_spike_rate": "+4.52 bits in 2s"}
    """
    
    def __init__(self, security_model, background_dataset_path: str):
        self.model = security_model
        self.model.eval()
        background = torch.load(background_dataset_path)
        self.explainer = shap.DeepExplainer(self.model, background)
    
    def explain(self, syscall_sequence, entropy_series) -> dict:
        """
        Returns:
            syscall_attributions: dict mapping syscall names to importance scores
            entropy_attribution: dict with entropy spike characteristics
            top_syscall: str — the single most suspicious syscall type
        """
        pass
```

### 6.3 K8s Field Name Mapper

```python
# FILE: models/interpretation/field_name_mapper.py

"""
Maps node indices from the YAML GAT encoder back to human-readable K8s field paths.

The GAT encoder assigns integer IDs to each node in the YAML graph. The SHAP
explainer produces importance scores for each node ID. This module maps:
    node_id=47 → "spec.template.spec.containers[0].resources.limits.cpu"

> CLAUDE CODE INSTRUCTION: The mapping is generated at graph-construction time
> in yaml_diff_to_graph() in yaml_gat_encoder.py. When building the PyG Data
> object, maintain a parallel list called node_id_to_field_path: list[str] that
> records the full dotted path for each node. Serialize this list alongside the
> Data object (store as data.field_paths = node_id_to_field_path).
> The FieldNameMapper then reads data.field_paths to do the lookup.
"""

class FieldNameMapper:
    def map_node_attributions_to_fields(
        self,
        node_attributions: dict[int, float],  # {node_id: shap_value}
        field_paths: list[str]                 # field_paths[node_id] = "spec.template..."
    ) -> dict[str, float]:
        """Returns {field_path: shap_value} for the top-10 highest-attribution nodes."""
        result = {}
        sorted_nodes = sorted(node_attributions.items(), key=lambda x: abs(x[1]), reverse=True)
        for node_id, shap_val in sorted_nodes[:10]:
            if node_id < len(field_paths):
                result[field_paths[node_id]] = shap_val
        return result
    
    def format_for_display(self, field_attributions: dict[str, float]) -> str:
        """
        Formats field attributions as a human-readable string.
        
        Example output:
        "spec.template.spec.containers[0].resources.limits.cpu (89% of risk)
         spec.template.spec.containers[0].resources.requests.cpu (7% of risk)"
        """
        total = sum(abs(v) for v in field_attributions.values())
        lines = []
        for field, value in sorted(field_attributions.items(), key=lambda x: abs(x[1]), reverse=True):
            pct = int(100 * abs(value) / (total + 1e-8))
            lines.append(f"  {field} ({pct}% of risk)")
        return "\n".join(lines)
```

### 6.4 Natural Language Summary Generator

```python
# FILE: models/interpretation/nl_summary_generator.py

"""
Generates natural language incident summaries using the Anthropic API.

This module takes structured incident data (health_risk, sec_risk, 
correlation_score, field_attributions, causal_chain) and sends it to
the Claude API to generate a one-to-three sentence human-readable summary.

The summary is displayed in the KubeHeal dashboard and included in all
Slack/PagerDuty notifications.

WHY USE AN LLM FOR THIS INSTEAD OF TEMPLATES:
Template-based summarization ("The field {field} was changed, causing {metric}
to reach {value}") produces mechanical, repetitive output that doesn't convey
the full context of an incident. An LLM can synthesize:
- The structural change (which field)
- The impact (which metrics, by how much)
- The DCM verdict (compound vs independent)
- The action taken (auto-patch vs auto-kill vs human-escalation)
...into a single coherent sentence that is genuinely informative to an SRE
reading the dashboard at 2 AM.

> CLAUDE CODE INSTRUCTION: This module calls the Anthropic API. Use the
> standard fetch() or the anthropic Python SDK. The API key is read from
> the environment variable ANTHROPIC_API_KEY. Do not hardcode the key.
> The model to use is claude-haiku-4-5-20251001 (fast and cheap for summaries).
> Set max_tokens=150 (summaries must be concise).
"""

import os
import json
from anthropic import Anthropic

client = Anthropic()  # reads ANTHROPIC_API_KEY from environment

SUMMARY_SYSTEM_PROMPT = """You are an expert Kubernetes SRE assistant embedded in 
the KubeHeal autonomous healing system. You receive structured incident data and 
produce a 1-3 sentence plain English summary of what happened.

Rules:
- Be specific about field paths, metric values, and timestamps
- Clearly state whether it is a health-only, security-only, or compound incident
- State the action taken and its outcome
- Do not use jargon that a non-Kubernetes engineer wouldn't understand
- Keep it under 150 tokens total
- Use past tense (this is a post-incident summary)"""

def generate_incident_summary(incident_data: dict) -> str:
    """
    Args:
        incident_data: dict containing:
            health_risk: float
            sec_risk: float
            correlation_score: float
            field_attributions: dict[str, float]
            syscall_attributions: dict[str, float]
            causal_chain: list[str]
            action_taken: str
            outcome: str
            mttr_ms: int
    
    Returns:
        nl_summary: str — 1-3 sentence incident summary
    """
    prompt = f"""Here is the structured incident data:
{json.dumps(incident_data, indent=2)}

Generate a 1-3 sentence plain English summary of this incident.
Include: what happened, which signal was highest, what action was taken, and what the outcome was."""
    
    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            system=SUMMARY_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text.strip()
    except Exception as e:
        # Fallback to template if API call fails
        # WHY FALLBACK: The interpretation layer must not block the Fusion Agent.
        # If the API is unavailable, return a structured template summary
        # and log the API error. The dashboard will show the template version.
        return _template_summary(incident_data)

def _template_summary(incident_data: dict) -> str:
    """Fallback template-based summary when API is unavailable."""
    h = incident_data.get("health_risk", 0)
    s = incident_data.get("sec_risk", 0)
    corr = incident_data.get("correlation_score", 0)
    action = incident_data.get("action_taken", "unknown")
    mttr = incident_data.get("mttr_ms", 0)
    
    if s > 0.8 and h > 0.7 and corr > 0.6:
        return (f"Compound incident: ransomware (sec_risk={s:.2f}) caused performance "
                f"degradation (health_risk={h:.2f}). DCM correlation={corr:.2f}. "
                f"Action: {action}. Resolved in {mttr}ms.")
    elif s > 0.8:
        return f"Security incident: sec_risk={s:.2f}. Action: {action}. Resolved in {mttr}ms."
    else:
        return f"Health incident: health_risk={h:.2f}. Action: {action}. Resolved in {mttr}ms."
```

---

## SECTION 07 — FUSION AGENT v4: THREE-SIGNAL DECISION ENGINE

### 7.1 What Changes in the Fusion Agent

The Fusion Agent in v3 made decisions based on a single combined `risk_score` from the monolithic DIT-Sec model. In v4, it receives three independent signals:

- `health_risk` (0-1) from the Health Model
- `sec_risk` (0-1) from the Security Model  
- `correlation_score` (0-1) from the DCM

This three-signal input enables significantly more nuanced decisions. The v4 decision policy is implemented as a pure function (no side effects, no external calls) to make it testable and auditable.

```python
# FILE: agents/fusion_agent/decision_policy.py
# FULL REPLACEMENT of v3 decision_policy.py

from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Decision(Enum):
    AUTO_KILL     = "auto_kill"      # Immediate pod kill + PV quarantine + restore
    AUTO_PATCH    = "auto_patch"     # Autonomous kubectl patch (canary-first)
    HUMAN_KILL    = "human_kill"     # Human approval required for kill
    HUMAN_PATCH   = "human_patch"    # Human approval required for patch
    OBSERVE       = "observe"        # Increase monitoring, no action
    BENIGN        = "benign"         # No action, ACK event

@dataclass
class DecisionInput:
    health_risk: float
    health_label: str           # one of HEALTH_LABELS from health_output_head.py
    health_ci_width: float      # conformal prediction interval width
    health_field_top: str       # highest-attribution K8s field

    sec_risk: float
    sec_label: str              # one of SECURITY_LABELS from security_output_head.py
    sec_ci_width: float
    sec_syscall_top: str        # most suspicious syscall type
    
    correlation_score: float    # from DCM
    compound_flag: bool         # True if correlation_score > 0.6
    
    namespace_tier: str         # "prod", "staging", "dev"
    circuit_breaker_kills: int  # number of kills in current hour
    circuit_breaker_patches: int
    
    burn_in_mode: bool          # True for clusters with < 2000 Prometheus samples
    
    nl_summary: Optional[str] = None  # from interpretation layer (non-blocking)

@dataclass
class DecisionOutput:
    decision: Decision
    adjusted_score: float       # the score that drove the decision
    rationale: str              # one-sentence explanation
    requires_incident_lock: bool
    action_params: dict         # parameters for the action executor

# Namespace tier multipliers
TIER_MULTIPLIERS = {
    "prod":    1.20,
    "staging": 1.00,
    "dev":     0.70
}
# WHY THESE MULTIPLIERS: A risk score of 0.72 in prod (1.20 * 0.72 = 0.864)
# crosses the auto-kill threshold, while the same score in dev
# (0.70 * 0.72 = 0.504) only triggers observe. This prevents over-reaction
# in development namespaces where engineers intentionally inject failures
# for testing, while ensuring appropriate urgency in production.

# Compound incident escalation factor
COMPOUND_ESCALATION = 1.15
# WHY 1.15: A compound incident (ransomware causing CPU thrash) is more
# dangerous than either event alone because: (1) the ransomware is actively
# encrypting data while also degrading performance, (2) the health agent
# might attribute the CPU thrash to a config change and attempt to auto-patch
# the wrong thing (the CPU limit, not the ransomware). The 1.15 multiplier
# ensures compound incidents always escalate above the human-approval threshold
# regardless of individual risk scores.

# Circuit breaker limits
CB_KILL_LIMIT_PER_HOUR    = 3   # max auto-kills per namespace per hour
CB_PATCH_LIMIT_PER_HOUR   = 10  # max auto-patches per Deployment per hour

# Threshold policy (can be overridden in burn-in mode)
class Thresholds:
    RANSOMWARE_DIRECT_KILL  = 0.98  # Security Agent direct kill, bypasses Fusion
    AUTO_KILL               = 0.85  # Fusion Agent auto-kill
    AUTO_PATCH              = 0.85  # Fusion Agent auto-patch (health only)
    HUMAN_APPROVAL          = 0.65  # Escalate to human
    OBSERVE                 = 0.40  # Increase monitoring
    # < 0.40 → BENIGN
    
    # Burn-in mode thresholds (elevated, requiring higher confidence)
    BURN_IN_AUTO_KILL   = 0.95
    BURN_IN_AUTO_PATCH  = 0.90

def make_decision(inp: DecisionInput) -> DecisionOutput:
    """
    Pure function — no side effects, no external calls, fully testable.
    Takes a DecisionInput and returns a DecisionOutput.
    
    This function is the single source of truth for all KubeHeal actions.
    Every production deployment must use this exact function.
    
    > CLAUDE CODE INSTRUCTION: Implement this function completely.
    > The function must be 100% branch-covered by unit tests.
    > Create tests/test_decision_policy.py with at least 20 test cases
    > covering all threshold boundaries, tier combinations, compound flags,
    > burn-in mode, and circuit breaker states.
    """
    t = Thresholds()
    tier_mult = TIER_MULTIPLIERS.get(inp.namespace_tier, 1.00)
    
    # Determine the base scores
    health_adjusted = inp.health_risk * tier_mult
    sec_adjusted    = inp.sec_risk    * tier_mult
    
    # Apply compound escalation if DCM reports correlation
    if inp.compound_flag:
        health_adjusted *= COMPOUND_ESCALATION
        sec_adjusted    *= COMPOUND_ESCALATION
    
    # Apply burn-in mode thresholds
    auto_kill_t  = t.BURN_IN_AUTO_KILL  if inp.burn_in_mode else t.AUTO_KILL
    auto_patch_t = t.BURN_IN_AUTO_PATCH if inp.burn_in_mode else t.AUTO_PATCH
    
    # CI width gate: if model is uncertain, escalate to human regardless of score
    # WHY CI WIDTH GATE: A conformal prediction CI width of 0.20 means the
    # model's true accuracy is ±0.10 from the point estimate. A score of 0.90
    # with CI=[0.70, 1.10] means the true score could be as low as 0.70,
    # which is in the human-approval zone. We should not auto-act on uncertain
    # predictions — route to human instead.
    ci_uncertain = (inp.health_ci_width > 0.15 or inp.sec_ci_width > 0.15)
    
    # COMPOUND INCIDENT PATH
    if inp.compound_flag and sec_adjusted >= auto_kill_t:
        if ci_uncertain:
            return DecisionOutput(
                decision=Decision.HUMAN_KILL,
                adjusted_score=sec_adjusted,
                rationale=f"Compound incident but CI too wide (health_ci={inp.health_ci_width:.2f}, sec_ci={inp.sec_ci_width:.2f}). Human approval required.",
                requires_incident_lock=True,
                action_params={"nl_summary": inp.nl_summary}
            )
        if inp.circuit_breaker_kills >= CB_KILL_LIMIT_PER_HOUR:
            return DecisionOutput(
                decision=Decision.HUMAN_KILL,
                adjusted_score=sec_adjusted,
                rationale=f"Compound incident. Circuit breaker: {inp.circuit_breaker_kills} kills this hour, limit {CB_KILL_LIMIT_PER_HOUR}. Human approval required.",
                requires_incident_lock=True,
                action_params={"nl_summary": inp.nl_summary}
            )
        return DecisionOutput(
            decision=Decision.AUTO_KILL,
            adjusted_score=sec_adjusted,
            rationale=f"Compound incident (DCM corr={inp.correlation_score:.2f}): sec_risk={inp.sec_risk:.2f}, health_risk={inp.health_risk:.2f}. Tier={inp.namespace_tier}. AUTO-KILL.",
            requires_incident_lock=True,
            action_params={"compound": True, "nl_summary": inp.nl_summary}
        )
    
    # SECURITY-ONLY PATH (health is calm)
    elif sec_adjusted >= auto_kill_t and not inp.compound_flag:
        if ci_uncertain or inp.circuit_breaker_kills >= CB_KILL_LIMIT_PER_HOUR:
            return DecisionOutput(decision=Decision.HUMAN_KILL, adjusted_score=sec_adjusted,
                rationale="Security incident. CI uncertainty or CB limit. Human approval.",
                requires_incident_lock=True, action_params={"nl_summary": inp.nl_summary})
        return DecisionOutput(decision=Decision.AUTO_KILL, adjusted_score=sec_adjusted,
            rationale=f"Security incident. sec_risk={inp.sec_risk:.2f}, label={inp.sec_label}. AUTO-KILL.",
            requires_incident_lock=True, action_params={"compound": False, "nl_summary": inp.nl_summary})
    
    # HEALTH-ONLY PATH (security is calm)
    elif health_adjusted >= auto_patch_t and inp.sec_risk < 0.4:
        if ci_uncertain or inp.circuit_breaker_patches >= CB_PATCH_LIMIT_PER_HOUR:
            return DecisionOutput(decision=Decision.HUMAN_PATCH, adjusted_score=health_adjusted,
                rationale="Health incident. CI uncertainty or CB limit. Human approval.",
                requires_incident_lock=True, action_params={"nl_summary": inp.nl_summary})
        return DecisionOutput(decision=Decision.AUTO_PATCH, adjusted_score=health_adjusted,
            rationale=f"Health incident. health_risk={inp.health_risk:.2f}, top_field={inp.health_field_top}. AUTO-PATCH.",
            requires_incident_lock=True,
            action_params={"patch_field": inp.health_field_top, "nl_summary": inp.nl_summary})
    
    # HUMAN APPROVAL ZONE
    elif max(health_adjusted, sec_adjusted) >= t.HUMAN_APPROVAL:
        return DecisionOutput(decision=Decision.HUMAN_PATCH if health_adjusted > sec_adjusted else Decision.HUMAN_KILL,
            adjusted_score=max(health_adjusted, sec_adjusted),
            rationale=f"Medium confidence. health_adj={health_adjusted:.2f}, sec_adj={sec_adjusted:.2f}. Human approval.",
            requires_incident_lock=False, action_params={"nl_summary": inp.nl_summary})
    
    # OBSERVE ZONE
    elif max(health_adjusted, sec_adjusted) >= t.OBSERVE:
        return DecisionOutput(decision=Decision.OBSERVE, adjusted_score=max(health_adjusted, sec_adjusted),
            rationale=f"Low signal. Increasing monitoring x3. health_adj={health_adjusted:.2f}, sec_adj={sec_adjusted:.2f}.",
            requires_incident_lock=False, action_params={})
    
    # BENIGN
    else:
        return DecisionOutput(decision=Decision.BENIGN, adjusted_score=max(health_adjusted, sec_adjusted),
            rationale="Benign signal. XACK and continue.", requires_incident_lock=False, action_params={})
```

### 7.2 Redis Lock Heartbeat Fix

The v3 PRD identified this as Loophole 3. The v4 implementation uses a heartbeat pattern:

```python
# FILE: agents/fusion_agent/incident_lock.py

"""
Redis incident lock with heartbeat to prevent deadlocks on Fusion Agent crash.

v3 Problem: SETNX with 30s TTL. If Fusion Agent crashes between SETNX and
the action completion, the lock stays for 30s. Any new events for that pod
during those 30s are silently dropped. This means a crash during a ransomware
incident response could leave the pod unprotected for 30 seconds.

v4 Fix: Heartbeat pattern.
1. SETNX lock with 10s TTL (short enough to recover fast)
2. Background asyncio task refreshes TTL every 3s while the decision is in progress
3. On completion (success OR exception): release the lock with a Lua DELETE script
4. If Fusion Agent crashes: heartbeat stops, lock expires in max 10s, next event is processed

WHY 10s TTL + 3s HEARTBEAT (not 30s TTL):
- Maximum recovery time after crash = 10s (TTL before heartbeat expires)
- Normal lock duration for auto-kill: ~8s (kill sequence) + ~2s (decision overhead) = 10s
- The heartbeat extends the lock as long as the decision is actively being made
- 30s TTL from v3 was too long: a 30s gap in ransomware protection is unacceptable
"""

import asyncio
import aioredis
from contextlib import asynccontextmanager

LOCK_PREFIX = "kubeheal:incident-lock"
LOCK_TTL_SECONDS = 10
HEARTBEAT_INTERVAL_SECONDS = 3

@asynccontextmanager
async def acquire_incident_lock(redis: aioredis.Redis, namespace: str, pod_name: str):
    """
    Context manager that acquires an incident lock with automatic heartbeat.
    
    Usage:
        async with acquire_incident_lock(redis, "prod", "victim-app-xyz") as acquired:
            if not acquired:
                logger.info("Lock held by another worker — skipping")
                return
            # do the decision and action here
    
    If an exception occurs inside the context, the lock is still released.
    """
    lock_key = f"{LOCK_PREFIX}:{namespace}:{pod_name}"
    
    # Try to acquire lock atomically
    acquired = await redis.set(lock_key, "1", nx=True, ex=LOCK_TTL_SECONDS)
    
    if not acquired:
        yield False
        return
    
    # Start heartbeat task
    heartbeat_task = asyncio.create_task(_heartbeat(redis, lock_key))
    
    try:
        yield True
    finally:
        # Cancel heartbeat and release lock
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        
        # Atomic delete: only delete if we still own the lock
        # (prevents deleting a lock that was re-acquired by another worker)
        delete_script = """
        if redis.call("get", KEYS[1]) == "1" then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        await redis.eval(delete_script, 1, lock_key)

async def _heartbeat(redis: aioredis.Redis, lock_key: str):
    """Continuously refresh lock TTL until cancelled."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
        await redis.expire(lock_key, LOCK_TTL_SECONDS)
```

---

## SECTION 08 — INFRASTRUCTURE CHANGES

### 8.1 What to Cut

**Cut Kafka entirely from the demo setup.**

```bash
# > CLAUDE CODE INSTRUCTION: Delete these files:
# k8s/kafka/kafka-statefulset.yaml
# k8s/kafka/kafka-service.yaml
# k8s/kafka/kafka-configmap.yaml
# k8s/kafka/kafka-pvc.yaml
# k8s/kafka/kafka-zookeeper.yaml  (if present)

# Remove all Kafka references from:
# agents/fusion_agent/agent.py (remove Kafka fallback logic)
# agents/health_agent/agent.py (remove Kafka DLQ publishing)
# agents/security_agent/agent.py (remove Kafka DLQ publishing)

# Update the implementation guide (Section 06 of original PRD) to remove
# all Kafka Helm install instructions.
```

> WHY THIS IS SAFE: Redis Sentinel already provides high availability. Redis Sentinel operates with 1 master + 2 replicas + a Sentinel process that monitors the master and promotes a replica automatically on failure. This is sufficient for a demo environment. The Kafka DLQ was a "belt and suspenders" addition that adds 500MB+ of memory overhead on an 8GB demo VM.

**Cut mamba-ssm dependency entirely.**

```bash
# > CLAUDE CODE INSTRUCTION: Remove from requirements.txt:
# mamba-ssm==1.2.0
# causal-conv1d  (mamba dependency)

# Do NOT remove:
# torch-geometric==2.5.0  (still needed for GAT)
# The metric encoder is now BiLSTM — nn.LSTM is part of PyTorch core,
# no additional installation required.
```

### 8.2 Split the Model Server Deployment

In v3, there was one `k8s/dit-sec-deployment.yaml`. In v4, there are three:

```yaml
# FILE: k8s/health-model-deployment.yaml
# This replaces the old dit-sec-deployment.yaml for health signals

apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubeheal-health-model
  namespace: kubeheal
  labels:
    app: kubeheal-health-model
    version: v4.0.0
spec:
  replicas: 2
  selector:
    matchLabels:
      app: kubeheal-health-model
  template:
    metadata:
      labels:
        app: kubeheal-health-model
    spec:
      containers:
      - name: health-model-server
        image: kubeheal/health-model-server:v4
        ports:
        - containerPort: 8001
          name: http
        env:
        - name: MODEL_PATH
          value: /models/health_model_v4.onnx
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: kubeheal-secrets
              key: anthropic-api-key
        - name: ENABLE_SHAP
          value: "true"
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "1000m"
            memory: "1Gi"
        # WHY THESE RESOURCE LIMITS: The Health Model server runs FP16 ONNX
        # inference. A single forward pass through the GAT + BiLSTM + output
        # head requires approximately 80MB peak memory. 512Mi request gives
        # comfortable headroom for concurrent requests. 1Gi limit prevents
        # runaway memory usage if SHAP computation (which batches many
        # forward passes) encounters a very large YAML graph.
        readinessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 15
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 10
        volumeMounts:
        - name: model-storage
          mountPath: /models
      volumes:
      - name: model-storage
        persistentVolumeClaim:
          claimName: kubeheal-model-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: kubeheal-health-model
  namespace: kubeheal
spec:
  selector:
    app: kubeheal-health-model
  ports:
  - port: 8001
    targetPort: 8001
    name: http
```

```yaml
# FILE: k8s/security-model-deployment.yaml
# Similar structure to health-model-deployment.yaml with:
# - name: kubeheal-security-model
# - containerPort: 8002
# - MODEL_PATH: /models/security_model_v4.onnx
# - Resource limits same as health model

# FILE: k8s/dcm-deployment.yaml
# - name: kubeheal-dcm
# - containerPort: 8003
# - MODEL_PATH: /models/dcm_v4.onnx
# - Resource requests: cpu: "200m", memory: "256Mi" (DCM is smaller than base models)
# - Resource limits: cpu: "500m", memory: "512Mi"
```

### 8.3 Fix cgroups v2 Compatibility in Security Agent

```python
# FILE: agents/security_agent/proc_scanner.py
# REPLACE the existing get_pod_for_pid() function with this:

import os
import re
import subprocess
from functools import lru_cache

def get_pod_for_pid(pid: int) -> tuple[str, str, str] | None:
    """
    Maps a Linux PID to a (namespace, pod_name, container_name) tuple.
    
    Supports both cgroups v1 and v2, with CRI API fallback.
    
    Returns None if the PID cannot be mapped (e.g., system process not
    running in a container).
    
    WHY BOTH CGROUPS VERSIONS:
    - cgroups v1: default on Ubuntu 18.04, 20.04, Debian 10
      /proc/{pid}/cgroup contains multiple lines, one per subsystem.
      The "memory" or "cpu" subsystem line contains the kubepods path:
      "10:memory:/kubepods/burstable/pod{pod_uid}/{container_id}"
    - cgroups v2: default on Ubuntu 22.04+, Fedora 33+, RHEL 9+
      /proc/{pid}/cgroup contains a single line:
      "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{pod_uid}.slice/{container_id}.scope"
    
    Minikube with --driver=docker on Ubuntu 22.04 uses cgroups v2.
    This is a demo-breaking issue in v3 that must be fixed.
    """
    cgroup_path = f"/proc/{pid}/cgroup"
    if not os.path.exists(cgroup_path):
        return None
    
    try:
        with open(cgroup_path) as f:
            lines = f.readlines()
    except PermissionError:
        return None
    
    pod_uid = None
    container_id = None
    
    for line in lines:
        line = line.strip()
        
        # cgroups v1: "10:memory:/kubepods/burstable/pod{uid}/{container_id}"
        v1_match = re.search(
            r'/kubepods(?:/[^/]+)?/pod([a-f0-9-]+)/([a-f0-9]+)',
            line
        )
        if v1_match:
            pod_uid = v1_match.group(1)
            container_id = v1_match.group(2)[:12]  # first 12 chars of container ID
            break
        
        # cgroups v2: "0::/kubepods.slice/...pod{uid}.../{container_id}.scope"
        v2_match = re.search(
            r'kubepods[^/]*/[^/]*pod([a-f0-9-]+)[^/]*/([a-f0-9]+)\.scope',
            line
        )
        if v2_match:
            pod_uid = v2_match.group(1)
            container_id = v2_match.group(2)[:12]
            break
    
    if not pod_uid:
        return None
    
    # Look up pod name from the pod UID using kubectl
    # WHY KUBECTL AND NOT CRI API DIRECTLY: The CRI API (via crictl) requires
    # the socket path which varies by runtime (containerd vs CRI-O vs Docker).
    # kubectl get pod --all-namespaces with field selector for pod UID is
    # runtime-agnostic and always works when the Security Agent has RBAC
    # access to list pods (which it must have for its other functions).
    return _kubectl_lookup_pod(pod_uid, container_id)

@lru_cache(maxsize=1000)
def _kubectl_lookup_pod(pod_uid: str, container_id: str) -> tuple[str, str, str] | None:
    """
    Cached lookup of pod_uid → (namespace, pod_name, container_name).
    
    LRU cache with 1000 entries prevents repeated kubectl calls for the
    same pod. Cache is invalidated on pod restart (pod_uid changes).
    WHY LRU_CACHE: kubectl calls are expensive (~50ms each). For a ransomware
    attack writing 180 files/second, the Security Agent processes hundreds of
    eBPF events per second, all for the same pod. Without caching, this
    generates hundreds of kubectl calls per second, saturating the API server.
    """
    try:
        result = subprocess.run(
            ["kubectl", "get", "pod", "--all-namespaces",
             "-o", "jsonpath={range .items[*]}{.metadata.namespace},{.metadata.name},{.spec.containers[0].name},{.metadata.uid}{\"\\n\"}{end}"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split('\n'):
            parts = line.split(',')
            if len(parts) == 4 and parts[3] == pod_uid:
                return (parts[0], parts[1], parts[2])
    except subprocess.TimeoutExpired:
        pass
    return None
```

### 8.4 Fix ONNX Export: INT8 → FP16

```python
# FILE: models/export_health_model.py
# FILE: models/export_security_model.py  
# FILE: models/export_dcm.py

"""
Export models to ONNX with FP16 quantization (NOT INT8).

WHY FP16 INSTEAD OF INT8:
Graph Attention Networks (GATv2Conv) compute attention scores via softmax.
The attention scores for non-neighboring nodes are near-zero (e.g., 1e-5).
INT8 quantization maps float32 values to 256 discrete levels. For values
in the range [-0.001, 0.001] (near-zero attention), INT8 resolution is
approximately 0.0001 per step — too coarse to distinguish meaningful low
attention from zero attention. This causes attention collapse: after
quantization, many legitimate edges appear to have zero attention weight,
and the model stops attending to them. On large K8s specs with many YAML
nodes, this degrades accuracy to below the 0.88 F1 threshold.

FP16 uses 16-bit floating point which maintains 3 decimal digits of
precision for values near zero — more than sufficient for attention weights.
Memory reduction: FP32 → FP16 halves model size (from ~120MB to ~60MB per model).
Inference speedup: ~1.5x on modern CPUs with AVX-512 fp16 support.

> CLAUDE CODE INSTRUCTION: In ALL three export scripts, use:
> torch.onnx.export(model, dummy_input, output_path,
>     opset_version=17,           # ONNX opset 17 for full fp16 support
>     do_constant_folding=True,
>     input_names=[...],
>     output_names=[...],
>     dynamic_axes={...}          # allow variable batch size
> )
> 
> Then quantize with:
> from onnxruntime.quantization import quantize_dynamic, QuantType
> quantize_dynamic(output_path, output_path_quantized,
>     weight_type=QuantType.QFloat16  # FP16, not QInt8
> )
> 
> Then validate F1 on the held-out test set:
> assert validation_f1 >= 0.88, f"Post-quantization F1 {validation_f1} below threshold"
"""
```

---

## SECTION 09 — AGENT PIPELINE CHANGES

### 9.1 Health Agent: Fix the asyncio.sleep Anti-Pattern

```python
# FILE: agents/health_agent/agent.py
# FIND THIS CODE (v3):
#   await asyncio.sleep(15)  # wait for drift to propagate to metrics
#   metrics = await fetch_prometheus_metrics(namespace, pod)
#
# REPLACE WITH THIS (v4):

async def wait_for_fresh_metrics(namespace: str, pod: str, 
                                  max_age_s: int = 6, timeout_s: int = 30) -> np.ndarray:
    """
    Polls Prometheus until fresh metric data is available.
    
    WHY THIS FIXES THE PROBLEM:
    asyncio.sleep(15) is a hard-coded 15-second wait in an asyncio coroutine.
    Under an event storm (100 MODIFIED events in 30 seconds — common during
    a rolling deployment), there are 100 sleeping coroutines, each holding
    a Prometheus client connection. When they all wake up within a few seconds
    of each other, they simultaneously hammer the Prometheus API with 100
    concurrent PromQL queries. This saturates Prometheus and causes cascading
    timeouts, making all 100 assessments fail.
    
    This replacement polls every 2 seconds and returns immediately when data
    is fresh enough. It uses a shared cache keyed by (namespace, pod) so
    that 100 events for the same pod make 1 Prometheus call, not 100.
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    
    while asyncio.get_event_loop().time() < deadline:
        # Check cache first
        cached = _prometheus_cache.get((namespace, pod))
        if cached is not None:
            data, fetch_time = cached
            age = asyncio.get_event_loop().time() - fetch_time
            if age <= max_age_s:
                return data
        
        # Fetch from Prometheus
        try:
            data = await _fetch_prometheus_raw(namespace, pod)
            _prometheus_cache[(namespace, pod)] = (data, asyncio.get_event_loop().time())
            return data
        except PrometheusDataTooOld:
            # Data exists but is stale — wait for next scrape
            await asyncio.sleep(2)
        except Exception as e:
            logger.warning(f"Prometheus fetch failed for {namespace}/{pod}: {e}")
            await asyncio.sleep(2)
    
    # Timeout: return whatever we have (even stale)
    cached = _prometheus_cache.get((namespace, pod))
    if cached is not None:
        data, fetch_time = cached
        age = asyncio.get_event_loop().time() - fetch_time
        logger.warning(f"Prometheus data for {namespace}/{pod} is {age:.0f}s old at timeout")
        return data
    
    # No data at all — return zeros (model handles missing data gracefully)
    logger.warning(f"No Prometheus data for {namespace}/{pod} after {timeout_s}s timeout. Using zeros.")
    return np.zeros((60, 15))  # [seq_len, num_metrics]

# Cache: {(namespace, pod): (data_array, timestamp)}
_prometheus_cache: dict[tuple, tuple[np.ndarray, float]] = {}
```

### 9.2 Updated Health Agent DIT-Sec Call

```python
# FILE: agents/health_agent/agent.py
# FIND: POST to /score (the v3 DIT-Sec monolith endpoint)
# REPLACE WITH: Two-step call to v4 Health Model + Interpretation Layer

async def assess_drift(event: dict) -> HealthAssessment:
    """Full v4 Health Agent assessment pipeline."""
    namespace = event['namespace']
    pod = event['pod_name']
    old_spec = event['old_spec']
    new_spec = event['new_spec']
    
    # Step 1: Convert YAML diff to graph
    graph_data = yaml_diff_to_graph(old_spec, new_spec)
    
    # Step 2: Wait for fresh Prometheus metrics (v4 fix)
    metrics = await wait_for_fresh_metrics(namespace, pod)
    
    # Step 3: Score with Health Model (NOT the old DIT-Sec monolith)
    async with aiohttp.ClientSession() as session:
        health_response = await session.post(
            f"http://kubeheal-health-model:8001/health/score",
            json={
                "graph_nodes": graph_data.x.tolist(),
                "graph_edges": graph_data.edge_index.tolist(),
                "container_indices": graph_data.container_indices,
                "container_positions": graph_data.container_positions,
                "change_mask": graph_data.change_mask.tolist(),
                "field_paths": graph_data.field_paths,
                "metrics": metrics.tolist()
            },
            timeout=aiohttp.ClientTimeout(total=5.0)
        )
        health_result = await health_response.json()
    
    # Step 4: Publish to Redis Stream (non-blocking — don't await interpretation)
    # The interpretation layer runs asynchronously; Fusion Agent gets the
    # raw scores immediately and the NL summary follows within 1-2 seconds.
    assessment = HealthAssessment(
        health_risk=health_result['risk_score'],
        health_label=health_result['label'],
        health_ci_width=health_result['ci_width'],
        field_attention_weights=health_result['field_attention_weights'],
        field_paths=graph_data.field_paths,
        patch_proposal=_generate_patch_proposal(old_spec, new_spec, health_result),
        blast_radius=event.get('blast_radius', 'Unknown'),
        namespace_tier=_get_namespace_tier(namespace)
    )
    
    # Publish to Redis
    await redis.xadd('kubeheal.health.events', assessment.to_redis_dict())
    
    # Fire-and-forget interpretation (fills in NL summary asynchronously)
    asyncio.create_task(
        _fetch_and_update_nl_summary(assessment, health_result)
    )
    
    return assessment
```

---

## SECTION 10 — TRAINING & VALIDATION STRATEGY

### 10.1 Dataset Requirements

**Health Model Training Data:**

The health model requires labeled examples of (YAML diff, Prometheus metrics, health_label) triples. Generating this data requires:

1. A running Kubernetes cluster (Minikube)
2. A deployed victim application
3. A Chaos Mesh instance for injecting config changes
4. Prometheus for recording metrics

The generation script (`models/generate_health_training_data.py`) must:
- Inject 3000 benign config changes (CPU/memory adjustments that are within safe ranges)
- Inject 3000 harmful changes (CPU reduced to <10% of baseline, memory reduced below RSS)
- Inject 3000 critical changes (CPU set to 0m, memory set to 0, invalid values)
- Inject 6000 benign events (no change — baseline behavior for negative examples)
- Record 5-minute Prometheus windows starting at each injection point
- Label each example with the ground truth outcome (observed via Prometheus)

```bash
# > CLAUDE CODE INSTRUCTION: Run the following to generate health training data:
python models/generate_health_training_data.py \
    --minikube-context minikube \
    --namespace demo \
    --victim-deployment victim-app \
    --output data/health_training.jsonl \
    --samples 15000 \
    --chaos-namespace chaos-testing

# Expected runtime: 8-10 hours (5 minutes of metrics per sample)
# Expected file size: ~2.5GB
# IMPORTANT: Run this overnight. Do not interrupt it.
```

**Security Model Training Data:**

The security model requires labeled (Falco events, entropy series, security_label) triples. Generation:

```bash
python models/generate_security_training_data.py \
    --namespace demo \
    --output data/security_training.jsonl \
    --ransomware-samples 5000 \
    --benign-samples 5000 \
    --staging-samples 2500 \
    --exfil-samples 2500

# The ransomware simulator (chaos/ransomware-simulator.yaml) generates:
# - Fast ransomware: AES-256, 180 files/sec, clear entropy spike
# - Slow ransomware: AES-128, 20 files/sec, gradual entropy rise
# - Dormant ransomware: 30s dormancy then rapid encryption
# - mmap-based ransomware: in-memory encryption with msync flush
# Each variant is labeled correctly in the output dataset.
```

**DCM Compound Incident Data:**

```bash
python models/generate_compound_dataset.py \
    --namespace demo \
    --output data/compound_incidents.jsonl \
    --positive-samples 5000 \
    --negative-samples 5000

# Positive (compound=True): simultaneously inject CPU limit change + ransomware
# Negative (compound=False): inject CPU limit change on pod-A, ransomware on pod-B
#   at the same time, collect both their signals as a non-compound pair
```

### 10.2 Training Scripts

```bash
# STEP 1: Train Health Model (run first, ~4 hours on CPU)
python models/train_health_model.py \
    --data data/health_training.jsonl \
    --epochs 40 \
    --lr 2e-4 \
    --batch-size 32 \
    --output models/health_model/checkpoints/ \
    --val-split 0.1 \
    --target-f1 0.90

# WHY TARGET F1 0.90: The original v3 PRD claimed 93.2% F1 on synthetic data.
# With real data (which has more distribution shift and noise), 90% is a
# realistic and defensible target. Do not inflate this number.
# If the health model reaches 90% F1 on the validation set, proceed.
# If it doesn't reach 90% F1 after 40 epochs, try:
#   - Increasing epochs to 60
#   - Reducing LR to 1e-4
#   - Adding 10% more benign examples (class imbalance often causes this)

# STEP 2: Train Security Model (run after Step 1, ~3 hours on CPU)
python models/train_security_model.py \
    --data data/security_training.jsonl \
    --epochs 40 \
    --lr 2e-4 \
    --batch-size 32 \
    --output models/security_model/checkpoints/ \
    --val-split 0.1 \
    --target-f1 0.91

# WHY HIGHER TARGET FOR SECURITY MODEL (0.91 vs 0.90):
# False negatives in the security model (missing a ransomware event) are more
# dangerous than false negatives in the health model (missing a config change).
# A missed ransomware event means continued encryption for 20+ more minutes.
# We accept slightly higher recall (at the cost of some precision) for the
# security model by targeting higher F1.

# STEP 3: Train DCM (run after Steps 1 and 2 are BOTH complete)
python models/train_dcm.py \
    --health-model models/health_model/checkpoints/best_health_model.pt \
    --security-model models/security_model/checkpoints/best_security_model.pt \
    --data data/compound_incidents.jsonl \
    --epochs 30 \
    --lr 5e-4 \
    --batch-size 16 \
    --output models/dcm/checkpoints/ \
    --target-auroc 0.88

# WHY AUROC (not F1) FOR DCM: The DCM outputs a continuous correlation_score [0,1].
# AUROC (Area Under ROC Curve) measures how well it ranks compound incidents above
# independent ones across all thresholds — this is a better metric than F1 at
# any fixed threshold because the Fusion Agent uses the continuous score directly.

# STEP 4: Calibrate conformal prediction wrappers
python models/calibrate_conformal.py \
    --health-model models/health_model/checkpoints/best_health_model.pt \
    --security-model models/security_model/checkpoints/best_security_model.pt \
    --health-calibration data/health_calibration.jsonl \
    --security-calibration data/security_calibration.jsonl \
    --coverage 0.95

# WHY CONFORMAL CALIBRATION ON A HELD-OUT SET:
# The calibration dataset must NOT overlap with the training or validation sets.
# Set aside 10% of each dataset before any training begins.
# Conformal prediction requires the calibration set to be drawn from the same
# distribution as the deployment data. Using training data for calibration
# gives coverage guarantees that don't hold in production.

# STEP 5: Export all models to ONNX with FP16
python models/export_health_model.py \
    --input models/health_model/checkpoints/best_health_model.pt \
    --output models/health_model_v4.onnx \
    --quantize fp16 \
    --validate --min-f1 0.88

python models/export_security_model.py \
    --input models/security_model/checkpoints/best_security_model.pt \
    --output models/security_model_v4.onnx \
    --quantize fp16 \
    --validate --min-f1 0.89

python models/export_dcm.py \
    --input models/dcm/checkpoints/best_dcm.pt \
    --output models/dcm_v4.onnx \
    --quantize fp16

# STEP 6: Upload to Model Registry (MinIO)
python models/upload_to_registry.py \
    --health-model models/health_model_v4.onnx \
    --security-model models/security_model_v4.onnx \
    --dcm models/dcm_v4.onnx \
    --version v4.0.0 \
    --min-health-f1 0.88 \
    --min-security-f1 0.89
```

### 10.3 Validation Requirements

Every model promotion (from checkpoint to ONNX to Model Registry) must pass these gates:

| Gate | Metric | Threshold | Failure Action |
|------|--------|-----------|----------------|
| Health Model F1 | Weighted F1 on validation set | ≥ 0.90 | Re-train with adjusted LR |
| Health Model post-quant F1 | F1 after FP16 ONNX export | ≥ 0.88 | Use FP32 ONNX instead |
| Security Model F1 | Weighted F1 on validation set | ≥ 0.91 | Re-train with more ransomware examples |
| Security Model post-quant F1 | F1 after FP16 ONNX export | ≥ 0.89 | Use FP32 ONNX instead |
| DCM AUROC | AUROC on compound vs independent | ≥ 0.88 | Re-train with more compound examples |
| Conformal coverage | Empirical coverage on calibration set | ≥ 0.93 (target 0.95) | Re-calibrate with larger calibration set |
| Inference latency (Health) | P99 latency on test set | ≤ 50ms on CPU | Investigate bottleneck, remove SHAP from inference path |
| Inference latency (Security) | P99 latency on test set | ≤ 30ms on CPU | Reduce max_sequence_length or num_layers |

> CLAUDE CODE INSTRUCTION: Create the file `models/validate_all_models.py` that runs all of the above gates automatically after training is complete. It must exit with code 0 if all gates pass and code 1 with a clear failure message if any gate fails. This script must be run before any demo.

---

## SECTION 11 — IMPLEMENTATION SEQUENCE: EXACT ORDER OF OPERATIONS FOR CLAUDE CODE

This section tells you exactly what to build, in what order, and why the order matters. Do not deviate from this sequence. Each step depends on the ones before it.

### Phase 0: Environment Setup and Cleanup (Day 1)

```bash
# 0.1 — Delete deprecated v3 files
# > CLAUDE CODE INSTRUCTION: Delete these files and directories:
rm -rf models/dit_sec_v3/
rm -f k8s/dit-sec-deployment.yaml
rm -rf k8s/kafka/  # if it exists
# Remove mamba-ssm from requirements.txt

# 0.2 — Create v4 directory structure
mkdir -p models/health_model/
mkdir -p models/security_model/
mkdir -p models/dcm/
mkdir -p models/interpretation/
mkdir -p k8s/
mkdir -p tests/

# 0.3 — Install new dependencies
pip install --break-system-packages \
    shap==0.44.0 \
    anthropic \
    torch-geometric==2.5.0 \
    onnxruntime==1.17.0 \
    onnx==1.16.0

# Note: mamba-ssm is NOT installed. BiLSTM uses nn.LSTM from torch core.
```

> WHY START WITH CLEANUP: If the old `dit_sec_v3/` directory is present when you start creating new files, import conflicts will cause confusing errors. Python's import system will find `models/dit_sec_v3/transformer_encoder.py` when you try to import `models/security_model/falco_transformer_encoder.py` if both exist and there are any `__init__.py` misconfigurations. Clean slate first.

### Phase 1: Model Architecture Files (Day 1-2)

```
1.1  Create models/health_model/__init__.py (empty)
1.2  Create models/health_model/yaml_gat_encoder.py
     → YAMLGATEncoder class (full implementation)
     → yaml_diff_to_graph() function (full implementation)
     → K8s YAML tree traversal logic
     → Container positional token injection
     → PyG Data object construction
     VALIDATE: python -c "from models.health_model.yaml_gat_encoder import YAMLGATEncoder; print('OK')"

1.3  Create models/health_model/metric_bilstm_encoder.py
     → MetricBiLSTMEncoder class (full implementation)
     → fetch_prometheus_metrics() function
     → METRIC_COLUMNS list
     VALIDATE: python -c "import torch; from models.health_model.metric_bilstm_encoder import MetricBiLSTMEncoder; m = MetricBiLSTMEncoder(); x = torch.zeros(2, 60, 15); print(m(x).shape)"
     # Expected: torch.Size([2, 64])

1.4  Create models/health_model/health_fusion_attention.py
     → HealthFusionAttention class (full implementation)
     VALIDATE: python -c "import torch; from models.health_model.health_fusion_attention import HealthFusionAttention; m = HealthFusionAttention(); h=torch.zeros(2,128); me=torch.zeros(2,64); out,attn=m(h,me); print(out.shape)"
     # Expected: torch.Size([2, 128])

1.5  Create models/health_model/health_output_head.py
     → HEALTH_LABELS list
     → HealthOutputHead class
     VALIDATE: tensor shapes correct

1.6  Create models/security_model/__init__.py (empty)
1.7  Create models/security_model/falco_transformer_encoder.py
     → SYSCALL_VOCAB_SIZE, MAX_SEQUENCE_LENGTH constants
     → FalcoTransformerEncoder class (full implementation)
     → Sinusoidal PE
     → CLS token
     VALIDATE: forward pass with dummy tensor

1.8  Create models/security_model/entropy_conv1d_encoder.py
     → EntropyConv1DEncoder class (full implementation)
     → Multi-scale Conv1D
     → Squeeze-Excitation block
     VALIDATE: python -c "import torch; from models.security_model.entropy_conv1d_encoder import EntropyConv1DEncoder; m = EntropyConv1DEncoder(); x = torch.rand(2, 30); print(m(x).shape)"
     # Expected: torch.Size([2, 64])

1.9  Create models/security_model/security_fusion_attention.py
     (same structure as HealthFusionAttention but for transformer+conv1d)
1.10 Create models/security_model/security_output_head.py
     → SECURITY_LABELS list
     → SecurityOutputHead class

1.11 Create models/dcm/__init__.py (empty)
1.12 Create models/dcm/cross_modal_attention.py
     → CrossModalAttention class (full implementation)
1.13 Create models/dcm/causal_chain_builder.py
     → CausalChainBuilder class (full implementation)
1.14 Create models/dcm/correlation_head.py
     (can be integrated into CrossModalAttention — see Section 05)

1.15 Create models/interpretation/__init__.py (empty)
1.16 Create models/interpretation/shap_explainer.py
1.17 Create models/interpretation/field_name_mapper.py
1.18 Create models/interpretation/nl_summary_generator.py
     → Must read ANTHROPIC_API_KEY from environment
     → Must have template fallback if API unavailable
```

### Phase 2: Training Infrastructure (Day 2-3)

```
2.1  Create models/generate_health_training_data.py
2.2  Create models/generate_security_training_data.py
2.3  Create models/generate_compound_dataset.py
2.4  Create models/train_health_model.py (full training loop)
2.5  Create models/train_security_model.py (full training loop)
2.6  Create models/train_dcm.py (staged training, frozen base models)
2.7  Create models/calibrate_conformal.py (updated for two models)
2.8  Create models/export_health_model.py (FP16 ONNX)
2.9  Create models/export_security_model.py (FP16 ONNX)
2.10 Create models/export_dcm.py (FP16 ONNX)
2.11 Create models/validate_all_models.py (validation gates)
2.12 Create models/upload_to_registry.py (updated for three models)
```

### Phase 3: Agent Updates (Day 3-4)

```
3.1  Update agents/security_agent/proc_scanner.py
     → Replace get_pod_for_pid() with cgroups v1/v2 compatible version
     → Add LRU cache for kubectl lookups
     VALIDATE: Test on a running pod on Ubuntu 22.04 host

3.2  Update agents/health_agent/agent.py
     → Remove asyncio.sleep(15s)
     → Add wait_for_fresh_metrics() with exponential backoff
     → Add _prometheus_cache dict
     → Update DIT-Sec call to Health Model endpoint (port 8001)
     VALIDATE: Unit test with mock Prometheus that simulates stale data

3.3  Update agents/security_agent/agent.py
     → Update DIT-Sec call to Security Model endpoint (port 8002)
     VALIDATE: Integration test with Security Model server

3.4  Create agents/fusion_agent/incident_lock.py
     → acquire_incident_lock() context manager with heartbeat
     VALIDATE: Unit test simulating crash mid-decision

3.5  Rewrite agents/fusion_agent/decision_policy.py
     → make_decision(DecisionInput) → DecisionOutput
     → All threshold logic as described in Section 07
     VALIDATE: 20+ unit tests covering all branches

3.6  Update agents/fusion_agent/agent.py
     → Replace single risk_score consumption with three-signal consumption
     → Read from kubeheal.health.events AND kubeheal.security.events
     → Call DCM (port 8003) to compute correlation_score
     → Use new decision_policy.make_decision()
     → Use acquire_incident_lock() heartbeat pattern

3.7  Create agents/fusion_agent/interpretation_client.py
     → Async client for interpretation layer
     → fire-and-forget mode (non-blocking)
```

### Phase 4: Kubernetes Manifests (Day 4)

```
4.1  Create k8s/health-model-deployment.yaml (see Section 08)
4.2  Create k8s/security-model-deployment.yaml
4.3  Create k8s/dcm-deployment.yaml
4.4  Delete k8s/dit-sec-deployment.yaml (replaced by above three)
4.5  Update k8s/rbac/ ClusterRole to add:
     - get/list/watch on pods (for proc_scanner kubectl lookup)
     - exec on pods (NOT needed — remove if present, security risk)
4.6  Create k8s/secrets/kubeheal-secrets.yaml template
     (ANTHROPIC_API_KEY must be added by user — never commit the actual key)
```

### Phase 5: Model Servers (Day 4-5)

```
5.1  Create services/health_model_server/
     → FastAPI application
     → Endpoints: GET /health, POST /health/score
     → Loads ONNX model from MODEL_PATH env var
     → Runs SHAP explainer (if ENABLE_SHAP=true)
     → Response schema as per Section 13

5.2  Create services/security_model_server/
     → FastAPI application
     → Endpoints: GET /health, POST /security/score
     → Attention weight extraction hook

5.3  Create services/dcm_server/
     → FastAPI application
     → Endpoint: POST /dcm/correlate
     → Takes health_embedding + security_embedding
     → Returns correlation_score + causal_chain

5.4  Create dockerfiles/Dockerfile.health_model
5.5  Create dockerfiles/Dockerfile.security_model
5.6  Create dockerfiles/Dockerfile.dcm
```

### Phase 6: Data Generation and Training (Day 5-7)

```
6.1  Deploy Minikube with victim app (using existing Phase 0/1/2 install script)
6.2  Run generate_health_training_data.py (overnight, ~10h)
6.3  Run generate_security_training_data.py (overnight, ~6h)
6.4  Run generate_compound_dataset.py (4h)
6.5  Run train_health_model.py (4h on CPU — can run same day as data gen completes)
6.6  Run train_security_model.py (3h on CPU)
6.7  Run train_dcm.py (2h on CPU — must be after 6.5 and 6.6)
6.8  Run calibrate_conformal.py
6.9  Run export_health_model.py, export_security_model.py, export_dcm.py
6.10 Run validate_all_models.py — ALL GATES MUST PASS before proceeding
6.11 Run upload_to_registry.py
```

### Phase 7: Integration Testing (Day 7-8)

```
7.1  Start all services: model servers, agents, dashboard
7.2  Run demo/victim-app.yaml
7.3  Execute DEMO A (config drift) manually
     → Verify: health_risk > 0.70 within 20s
     → Verify: auto-patch applied within 90s
     → Verify: NL summary appears in dashboard
     → Verify: field attribution shows correct YAML field

7.4  Execute DEMO B (ransomware) manually
     → Verify: NetworkPolicy egress block applied within 5s
     → Verify: pod kill within 8s
     → Verify: PV restore within 5 minutes
     → Verify: DCM correlation_score > 0.50 (ransomware causes CPU thrash)

7.5  Execute edge case: simultaneous drift + ransomware on DIFFERENT pods
     → Verify: DCM correlation_score < 0.20 (independent events)
     → Verify: each incident handled independently

7.6  Execute burn-in mode test:
     → Delete all Prometheus data
     → Verify: KubeHeal enters burn-in mode
     → Verify: auto-kill threshold rises to 0.95
     → Verify: exits burn-in after 2000 metric samples

7.7  Execute circuit breaker test:
     → Trigger 3 consecutive ransomware incidents within 1 hour
     → Verify: 4th kill escalates to human approval (CB triggered)
```

### Phase 8: Demo Preparation (Day 8-9)

```
8.1  Run the full demo 3 times end-to-end without interruption
8.2  Time each phase — they must hit within 10% of the spec values
8.3  Verify all dashboard panels are populated correctly
8.4  Update the demo script (Section 14) with actual observed timing
8.5  Prepare the Grafana dashboard JSON with v4 panels
8.6  Create a reset script that returns everything to baseline in <30 seconds
```

---

## SECTION 12 — FILE STRUCTURE: v4 COMPLETE DIRECTORY TREE

```
kubeheal/
├── agents/
│   ├── health_agent/
│   │   ├── agent.py                     # MODIFIED: remove sleep, add cache
│   │   ├── tree2vec.py                  # MODIFIED: renamed yaml_preprocessor.py
│   │   ├── prometheus_client.py         # MODIFIED: wait_for_fresh_metrics()
│   │   ├── blast_radius.py              # UNCHANGED
│   │   └── assessment.py               # MODIFIED: updated schema for v4
│   ├── security_agent/
│   │   ├── agent.py                     # MODIFIED: updated model endpoint
│   │   ├── falco_client.py             # UNCHANGED
│   │   ├── entropy.py                   # UNCHANGED
│   │   ├── proc_scanner.py             # MODIFIED: cgroups v2 + LRU cache
│   │   ├── inotify_watcher.py          # UNCHANGED
│   │   └── ebpf_maps.py                # UNCHANGED
│   └── fusion_agent/
│       ├── agent.py                     # MODIFIED: three-signal consumption
│       ├── decision_policy.py          # REPLACED: three-signal decision
│       ├── circuit_breaker.py          # UNCHANGED
│       ├── network_policy.py           # UNCHANGED
│       ├── incident_lock.py            # NEW: heartbeat lock
│       ├── interpretation_client.py    # NEW: async interpretation client
│       └── incident_log.py             # UNCHANGED
│
├── models/
│   ├── health_model/
│   │   ├── __init__.py
│   │   ├── yaml_gat_encoder.py         # NEW: GATv2Conv YAML encoder
│   │   ├── metric_bilstm_encoder.py    # NEW: BiLSTM metric encoder (replaces Mamba)
│   │   ├── health_fusion_attention.py  # NEW: cross-attention health fusion
│   │   ├── health_output_head.py       # NEW: health risk + label head
│   │   ├── health_conformal.py         # NEW: conformal wrapper
│   │   ├── k8s_field_vocabulary.json   # NEW: generated by build_vocabulary.py
│   │   ├── build_vocabulary.py         # NEW: scans YAML files for vocab
│   │   └── checkpoints/               # gitignored — generated by training
│   │
│   ├── security_model/
│   │   ├── __init__.py
│   │   ├── falco_transformer_encoder.py # NEW: transformer for syscall sequences
│   │   ├── entropy_conv1d_encoder.py   # NEW: Conv1D+SE for entropy series
│   │   ├── security_fusion_attention.py # NEW: cross-attention security fusion
│   │   ├── security_output_head.py     # NEW: security risk + label head
│   │   ├── security_conformal.py       # NEW: conformal wrapper
│   │   ├── syscall_vocabulary.json     # NEW: generated by build_syscall_vocab.py
│   │   ├── build_syscall_vocab.py      # NEW: scans Falco output for vocab
│   │   └── checkpoints/               # gitignored
│   │
│   ├── dcm/
│   │   ├── __init__.py
│   │   ├── cross_modal_attention.py    # NEW: bidirectional cross-modal attention
│   │   ├── causal_chain_builder.py     # NEW: constructs causal chain
│   │   ├── correlation_head.py         # NEW: outputs correlation_score
│   │   └── checkpoints/               # gitignored
│   │
│   ├── interpretation/
│   │   ├── __init__.py
│   │   ├── shap_explainer.py           # NEW: SHAP for both models
│   │   ├── field_name_mapper.py        # NEW: node_id → K8s field path
│   │   └── nl_summary_generator.py     # NEW: calls Anthropic API
│   │
│   ├── generate_health_training_data.py # NEW
│   ├── generate_security_training_data.py # NEW
│   ├── generate_compound_dataset.py    # NEW
│   ├── train_health_model.py           # NEW (replaces train_dit_sec_v3.py)
│   ├── train_security_model.py         # NEW
│   ├── train_dcm.py                    # NEW
│   ├── calibrate_conformal.py          # MODIFIED: two models
│   ├── export_health_model.py          # NEW (replaces export_onnx_v3.py)
│   ├── export_security_model.py        # NEW
│   ├── export_dcm.py                   # NEW
│   ├── validate_all_models.py          # NEW
│   └── upload_to_registry.py          # MODIFIED: three models
│
├── services/
│   ├── health_model_server/
│   │   ├── main.py                     # FastAPI application (port 8001)
│   │   └── requirements.txt
│   ├── security_model_server/
│   │   ├── main.py                     # FastAPI application (port 8002)
│   │   └── requirements.txt
│   └── dcm_server/
│       ├── main.py                     # FastAPI application (port 8003)
│       └── requirements.txt
│
├── k8s/
│   ├── rbac/                           # MODIFIED: updated ClusterRole
│   ├── crds/                           # UNCHANGED
│   ├── health-model-deployment.yaml    # NEW (replaces dit-sec-deployment.yaml)
│   ├── security-model-deployment.yaml  # NEW
│   ├── dcm-deployment.yaml             # NEW
│   ├── health-agent-deployment.yaml    # UNCHANGED (updated image tag only)
│   ├── security-agent-daemonset.yaml   # UNCHANGED
│   ├── fusion-agent-deployment.yaml    # UNCHANGED (updated image tag only)
│   ├── dashboard-deployment.yaml       # UNCHANGED
│   └── secrets/
│       └── kubeheal-secrets.yaml.template # NEW: template for ANTHROPIC_API_KEY
│
├── dockerfiles/
│   ├── Dockerfile.health_model         # NEW
│   ├── Dockerfile.security_model       # NEW
│   ├── Dockerfile.dcm                  # NEW
│   ├── Dockerfile.health               # MODIFIED: updated base image
│   ├── Dockerfile.security             # MODIFIED
│   ├── Dockerfile.fusion               # MODIFIED
│   └── Dockerfile.dashboard            # UNCHANGED
│
├── tests/
│   ├── test_decision_policy.py         # NEW: 20+ unit tests
│   ├── test_incident_lock.py           # NEW: lock heartbeat tests
│   ├── test_yaml_gat_encoder.py        # NEW: encoder shape tests
│   ├── test_bilstm_encoder.py          # NEW
│   ├── test_cgroups_compatibility.py   # NEW: v1 + v2 parsing tests
│   ├── test_prometheus_cache.py        # NEW: cache + backoff tests
│   └── test_integration_full_pipeline.py # NEW: end-to-end smoke test
│
├── chaos/                              # UNCHANGED (existing ransomware simulator)
├── demo/                               # UNCHANGED (existing victim app)
├── dashboards/
│   ├── kubeheal-main.json              # MODIFIED: v4 panels
│   └── kubeheal-v4-panels/
│       ├── dcm-correlation-panel.json  # NEW: correlation_score gauge
│       └── interpretation-panel.json  # NEW: NL summary text panel
│
└── scripts/
    ├── install.sh                      # MODIFIED: remove Kafka, remove mamba-ssm
    ├── demo.sh                         # MODIFIED: updated timing + v4 endpoints
    └── reset.sh                        # NEW: returns demo to clean state in <30s
```

---

## SECTION 13 — API CONTRACTS: ALL INTERNAL INTERFACES

### Health Model Server API (port 8001)

```
GET /health
Response: {"status": "ok", "model_version": "v4.0.0", "model_loaded": true}

POST /health/score
Request body:
{
    "graph_nodes": [[float, ...]],      // [num_nodes, node_feature_dim=64]
    "graph_edges": [[int, int], ...],   // [num_edges, 2] as edge_index
    "container_indices": [int, ...],    // indices of container root nodes
    "container_positions": [int, ...],  // positional token IDs for each container root
    "change_mask": [bool, ...],         // [num_nodes] True = node changed
    "field_paths": [str, ...],          // [num_nodes] K8s field path for each node
    "metrics": [[float, ...]],          // [60, 15] Prometheus metric matrix
    "request_id": str                   // optional, for correlation logging
}

Response body:
{
    "risk_score": float,                // [0, 1] continuous health risk
    "label": str,                       // one of HEALTH_LABELS
    "label_probabilities": {str: float}, // probability for each label
    "ci_lower": float,                  // conformal prediction interval lower bound
    "ci_upper": float,                  // conformal prediction interval upper bound
    "ci_width": float,                  // ci_upper - ci_lower
    "field_attention_weights": {        // SHAP values per K8s field
        str: float                      // {"spec.template...cpu": 0.43, ...}
    },
    "top_field": str,                   // highest-attribution K8s field
    "top_metric": str,                  // highest-attribution metric name
    "health_embedding": [float, ...],   // [128] embedding vector for DCM input
    "inference_latency_ms": float,      // time taken for this inference
    "request_id": str                   // echoed from request if provided
}
```

### Security Model Server API (port 8002)

```
POST /security/score
Request body:
{
    "syscall_ids": [[int, ...]],        // [seq_len ≤ 256] tokenized syscall names
    "path_ids": [[int, ...]],           // [seq_len] hashed file path IDs
    "padding_mask": [[bool, ...]],      // [seq_len] True = pad token
    "entropy_series": [float, ...],     // [30] entropy values in bits
    "early_signals": {                  // pre-detection signals from Security Agent
        "rename_burst": bool,
        "ftruncate_pattern": bool,
        "ransom_note": bool,
        "mmap_entropy": bool
    }
}

Response body:
{
    "risk_score": float,
    "label": str,                       // one of SECURITY_LABELS
    "label_probabilities": {str: float},
    "ci_lower": float,
    "ci_upper": float,
    "ci_width": float,
    "syscall_attention_weights": {str: float}, // {"rename": 0.38, "ftruncate": 0.27, ...}
    "top_syscall": str,
    "entropy_spike": {
        "timestep": int,
        "value_bits": float,
        "delta_from_baseline": float
    },
    "security_embedding": [float, ...], // [64] embedding vector for DCM input
    "inference_latency_ms": float
}
```

### DCM Server API (port 8003)

```
POST /dcm/correlate
Request body:
{
    "health_embedding": [float, ...],   // [128] from Health Model server
    "security_embedding": [float, ...], // [64] from Security Model server
    "health_assessment": dict,          // full health response (for causal chain)
    "security_event": dict              // full security response (for causal chain)
}

Response body:
{
    "correlation_score": float,         // [0, 1] how related are the two signals?
    "compound_flag": bool,              // true if correlation_score > 0.60
    "causal_chain": [str, ...],         // ordered list of events with timestamps
    "correlation_confidence": float,    // confidence in the correlation score itself
    "nl_summary": str | null            // NL summary from interpretation layer
                                        // null if API call is still in flight
}
```

---

## SECTION 14 — DEMO SCRIPT v4: UPDATED 15-MINUTE WALKTHROUGH

### Pre-Demo Checklist (run this before judges arrive)

```bash
# 1. Reset victim app to baseline
kubectl apply -f demo/victim-app.yaml -n demo
kubectl wait --for=condition=ready pod -l app=victim -n demo --timeout=60s

# 2. Clear all incident history
redis-cli -h $(kubectl get svc redis -n kubeheal -o jsonpath='{.spec.clusterIP}') DEL kubeheal.incidents

# 3. Verify all pods running
kubectl get pods -n kubeheal  # expect: all Running, no Pending/Error

# 4. Verify model servers responding
curl http://localhost:8001/health  # health model
curl http://localhost:8002/health  # security model
curl http://localhost:8003/health  # DCM

# 5. Open four windows:
#    Window 1: kubectl get pods -n kubeheal -w
#    Window 2: KubeHeal dashboard at localhost:5000
#    Window 3: Grafana at localhost:3000
#    Window 4: Terminal for running commands
```

### Minute 0–2: Architecture Introduction

Open the dashboard. Point to the three model cards: Health Model (showing green, risk=0.02), Security Model (showing green, risk=0.01), DCM (showing "No active correlation").

Say: "KubeHeal v4 has a fundamentally different architecture from any existing Kubernetes security tool. We run two specialized AI models in parallel — one focused exclusively on configuration drift, one focused exclusively on ransomware behavior. A third component, our Dependency Correlation Module, asks whether those two signals are causally related. Let me show you why that distinction matters."

### Minute 2–7: Config Drift Demo (Demo A)

Run the patch command:
```bash
kubectl patch deployment victim-app -n demo \
    --type=merge \
    -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"50m"}}}]}}}}'
```

Narrate while watching the dashboard:

- At T+0s: "The Health Agent just received a MODIFIED event. It sees that spec.template.spec.containers[0].resources.limits.cpu changed from 500m to 50m."
- At T+2s: "It's polling Prometheus for fresh metrics. Note: in v3, this was a hard-coded 15-second sleep that blocked other event processing. In v4, it polls with exponential backoff and shares a cache."
- At T+17s: "Health risk score just jumped to 0.79. Look at the field attribution panel — containers[0].resources.limits.cpu has 89% of the risk weight. The model knows exactly which field caused this."
- At T+17.5s: "Fusion Agent decision: health_risk=0.79 × tier_multiplier=1.2 = 0.948. Security model is calm at 0.11. DCM correlation = 0.09 — this is NOT a compound incident. Pure config drift. AUTO-PATCH."
- At T+18s: "The canary patch is applied to replica 1 of 3. Watch the CPU throttle drop from 82% to..."
- At T+80s: "11%. Canary passed. Full patch applied to all 3 replicas. MTTR: 80 seconds."
- Point to the NL summary panel: Read the generated summary. "This is KubeHeal v4's interpretation layer — the model's attention weights converted into plain English. An SRE on call gets this in their Slack message."

### Minute 7–13: Ransomware Demo (Demo B)

```bash
kubectl apply -f chaos/ransomware-simulator.yaml -n demo
```

Narrate:

- At T+2.3s: "First early signal — the Security Agent detected a rename burst. 12 renames per second is consistent with ransomware file-locking. The security model's risk score is 0.50. No action yet."
- At T+3.5s: "NetworkPolicy applied. ALL egress from this pod is blocked RIGHT NOW. If this ransomware was about to send the AES key to a command-and-control server, that channel is gone — before we've even confirmed it's ransomware."
- At T+3.3s: "Entropy crossed 7.76 bits. Security model inference complete: sec_risk=0.93, label=ransomware_active."
- At T+4.0s: "Fusion Agent — DCM correlation score: 0.71. The ransomware is causing CPU thrash that the health model is picking up as drift. This is a compound incident. Adjusted score: 0.93 × 1.2 (prod tier) × 1.15 (compound escalation) = 1.28. AUTO-KILL."
- At T+8s: "Pod deleted. PV quarantined. OS-level kill confirmed. 8 seconds."
- At T+8.5s: "Shadow PV promoted. The application is already in degraded read mode — users see slower responses, not a full outage."
- At T+4min: "Full restore complete. Let me show you the causal chain panel..."
- Point to dashboard: Read the causal chain. "This is the Dependency Correlation Module's output. It traced the sequence from the ransomware spawn through the CPU thrash to the health model's alert. Without the DCM, we'd see two independent events. With it, we understand the full incident."

### Minute 13–15: Results and Q&A Setup

Show the incident record. Point to:
- `compound_flag: true`
- `correlation_score: 0.71`
- `nl_summary` from interpretation layer
- `false_positive: false`
- `mttr_ms: 372000` (6.2 minutes)

Final statement: "KubeHeal v4 is the only system that detects, explains, and correlates Kubernetes configuration drift and container ransomware through two specialized AI models and a novel Dependency Correlation Module. The causal chain and natural language explanation make the AI's reasoning auditable — an SRE can read exactly why the system acted, not just that it acted."

---

## SECTION 15 — APPENDIX

### A.1 Complete Redis Stream Schema (v4)

The v4 streams add `compound_flag`, `correlation_score`, `nl_summary`, and `causal_chain` to the existing schema:

```
kubeheal.health.events fields (v4):
    event_id, namespace, pod_name, namespace_tier,
    health_risk, health_label, health_ci_lower, health_ci_upper, health_ci_width,
    field_attribution_json,   # JSON: {field_path: shap_value}
    top_field, top_metric,
    health_embedding_b64,     # base64-encoded [128] float32 tensor
    patch_proposal_json,      # proposed kubectl patch
    blast_radius, timestamp_ms

kubeheal.security.events fields (v4):
    event_id, namespace, pod_name, namespace_tier,
    sec_risk, sec_label, sec_ci_lower, sec_ci_upper, sec_ci_width,
    syscall_attribution_json, # JSON: {syscall_name: shap_value}
    top_syscall, entropy_spike_json,
    security_embedding_b64,   # base64-encoded [64] float32 tensor
    pid_target, kill_confidence,
    early_signals_json,       # JSON: {rename_burst, ftruncate, ransom_note, mmap}
    timestamp_ms

kubeheal.dcm.events fields (v4, NEW):
    event_id, namespace, pod_name,
    correlation_score, compound_flag,
    causal_chain_json,        # JSON: [str, ...] ordered event list
    correlation_confidence,
    nl_summary,               # generated by interpretation layer
    health_event_id,          # links to kubeheal.health.events
    security_event_id,        # links to kubeheal.security.events
    timestamp_ms

kubeheal.actions fields (UNCHANGED except action_type now includes compound_kill):
    action_type: "auto_kill" | "auto_patch" | "compound_kill" | 
                 "human_kill" | "human_patch" | "observe" | "benign"
    target, confidence, approved_by, circuit_breaker_state, nl_summary
```

### A.2 Environment Variables Required for v4

```bash
# Required in all model server pods:
ANTHROPIC_API_KEY=sk-ant-...     # for nl_summary_generator.py
                                  # must be in kubeheal-secrets K8s secret

# Required in Health Model server:
MODEL_PATH=/models/health_model_v4.onnx
ENABLE_SHAP=true                  # set false to skip SHAP (faster, less explainable)
SHAP_BACKGROUND_PATH=/models/shap_background_health.pt

# Required in Security Model server:
MODEL_PATH=/models/security_model_v4.onnx
ENABLE_SHAP=true
SHAP_BACKGROUND_PATH=/models/shap_background_security.pt

# Required in DCM server:
MODEL_PATH=/models/dcm_v4.onnx
HEALTH_MODEL_URL=http://kubeheal-health-model:8001
SECURITY_MODEL_URL=http://kubeheal-security-model:8002

# Required in all agents:
REDIS_URL=redis://redis:6379
REDIS_SENTINEL_MASTER=mymaster
HEALTH_MODEL_URL=http://kubeheal-health-model:8001
SECURITY_MODEL_URL=http://kubeheal-security-model:8002
DCM_URL=http://kubeheal-dcm:8003
```

### A.3 Known Failure Modes and Mitigations

| Failure Mode | Symptom | Root Cause | Mitigation |
|---|---|---|---|
| SHAP computation timeout | Health score returned but field_attribution empty | SHAP DeepExplainer takes >5s for large YAML graphs (>200 nodes) | Add a 3s timeout to SHAP computation. Return raw attention weights instead if SHAP times out. |
| GAT OOM on large specs | Health Model server OOM-killed | Very large Deployments (>50 containers, many env vars) produce graphs with >500 nodes | Add a node count limit (max 300 nodes). If graph exceeds limit, prune low-depth nodes (metadata labels, annotations with long values). |
| Interpretation API rate limit | nl_summary returns template | Anthropic API rate limit exceeded | Add exponential backoff (1s, 2s, 4s, 8s, max 3 retries). After 3 failures, return template summary and log the rate limit event. |
| DCM cold start | correlation_score stuck near 0.5 | DCM was not trained (no compound dataset available) | Initialize DCM with random weights and skip compound classification — Fusion Agent falls back to max(health_risk, sec_risk) without compound escalation. Add a warning to the dashboard. |
| cgroups detection failure | Security Agent maps all PIDs to None | Kernel version uses unusual cgroup hierarchy | Fall back to `/proc/{pid}/cmdline` parsing: look for "pause" container to identify pod sandbox, then enumerate sibling processes. |
| BiLSTM CUDA/CPU mismatch | "Expected all tensors on same device" | Mixed CPU/GPU tensors if model runs on GPU | Enforce all operations on CPU in Minikube. Add `device = torch.device("cpu")` at model initialization and move all inputs with `.to(device)`. |

### A.4 What to Tell Judges About the v4 Architecture

If judges ask "how is this different from ArgoCD + Falco + some ML model?":

1. **ArgoCD + Falco** detect independently and don't correlate. If ransomware causes CPU thrash (which looks like drift), ArgoCD tries to patch the CPU limit while Falco tries to kill the pod. These actions conflict. KubeHeal's DCM detects the compound incident and applies the correct unified response.

2. **The Dependency Correlation Module is novel.** No existing paper describes cross-modal attention between config-drift embeddings and security-behavioral embeddings for Kubernetes. This is a publishable contribution if you formalize it.

3. **The Interpretation Layer is production-ready.** Most ML security systems produce a score with no explanation. KubeHeal produces a natural language summary, a causal chain, and SHAP field attributions that an SRE can audit. This is what enterprise teams need to trust autonomous systems.

4. **The decision policy is formally specified.** Every threshold, every multiplier, every circuit breaker limit is a named constant in `decision_policy.py` — auditable, testable, changeable without touching the ML code. This is how production systems must be designed.

### A.5 PRD Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Initial | Team | v3 architecture (DIT-Sec monolith) |
| 2.0 | UIP Week 6 | Team | Added 10 loophole fixes |
| 3.0 | UIP Week 8 | Team | GNN+Mamba hybrid, Conformal Prediction |
| 4.0 | UIP Week 10 | LLM Council Review + Loki | Split model architecture, DCM, Interpretation Layer, Mamba→BiLSTM, cgroups v2 fix, Kafka removal |

---

*End of KubeHeal v4 PRD — Total specification length: ~35 pages*
*For Claude Code: Begin with Section 11 Phase 0. Do not skip sections.*
*For humans: The council's final recommendation is to prioritize the DCM and Interpretation Layer above all other changes — these are your demo moments and your novel contributions.*
