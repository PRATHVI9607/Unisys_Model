# KubeHeal — DIT-Sec v3 (GNN + Mamba) Architecture & Project Flow

This diagram shows two things at once:
1. **How the DIT-Sec v3 model works internally** (GNN + Mamba + Transformer + Conv1D → fusion → risk/label).
2. **How the model is used end-to-end in the KubeHeal project** (cluster signals → agents → model → decision → dashboard).

```mermaid
flowchart TD
    %% ============ DATA SOURCES ============
    subgraph CLUSTER["☸️ Kubernetes Cluster — live signals"]
        direction LR
        K1["📄 Deployment YAML<br/>baseline vs live spec"]
        K2["📈 Prometheus Metrics<br/>CPU · mem · latency · replicas"]
        K3["🔬 Falco eBPF Syscalls<br/>read · write · execve · …"]
        K4["🔥 File Entropy Series<br/>encryption fingerprint"]
    end

    %% ============ AGENTS ============
    subgraph AGENTS["🤖 KubeHeal Agents — collectors"]
        direction LR
        HA["💚 Health Agent"]
        SA["🛡️ Security Agent<br/>(DaemonSet)"]
    end

    K1 --> HA
    K2 --> HA
    K3 --> SA
    K4 --> SA

    %% ============ MODEL ============
    subgraph MODEL["🧠 DIT-Sec v3 — GNN + Mamba Hybrid Model"]
        direction TB
        subgraph ENC["Modality Encoders"]
            direction LR
            E1["🕸️ YAML → GAT<br/>3-layer GATConv · 4 heads<br/><b>128-dim</b>"]
            E2["🌊 Metrics → Mamba SSM<br/>2 layers · O(n) scan<br/><b>64-dim</b>"]
            E3["🔡 Events → Transformer<br/>4 heads × 2 layers<br/><b>64-dim</b>"]
            E4["📉 Entropy → Conv1D + SE<br/>squeeze-excitation<br/><b>64-dim</b>"]
        end
        FUSE["🔗 MHCA Fusion<br/>3-head cross-attention<br/>4 slots → <b>192-dim</b>"]
        subgraph HEAD["Output Head"]
            direction LR
            O1["⚠️ Risk Score<br/>0.0 – 1.0"]
            O2["🏷️ Class label<br/>benign · health-critical<br/>ransomware-critical<br/>sec-medium · perf-risk"]
        end
        E1 --> FUSE
        E2 --> FUSE
        E3 --> FUSE
        E4 --> FUSE
        FUSE --> O1
        FUSE --> O2
    end

    HA -->|"old_spec + new_spec"| E1
    HA -->|"60 × 15 metrics"| E2
    SA -->|"syscall sequence"| E3
    SA -->|"entropy window"| E4

    %% ============ DECISION ============
    subgraph FUSION["⚖️ Fusion Agent — decision layer"]
        D1{"risk ≥ threshold?"}
        D2["🛑 Circuit Breaker /<br/>Auto-Remediation"]
        D3["✅ Allow / keep monitoring"]
    end

    O1 --> D1
    O2 --> D1
    D1 -->|"yes"| D2
    D1 -->|"no"| D3

    DASH["📊 Dashboard<br/>live risk · labels · timeline"]
    D2 --> DASH
    D3 --> DASH
    O1 -.-> DASH

    %% ============ STYLES ============
    classDef cluster fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b;
    classDef agent fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#78350f;
    classDef gnn fill:#dbeafe,stroke:#2563eb,stroke-width:3px,color:#1e3a8a;
    classDef mamba fill:#dcfce7,stroke:#16a34a,stroke-width:3px,color:#14532d;
    classDef trans fill:#ffedd5,stroke:#ea580c,stroke-width:2px,color:#7c2d12;
    classDef conv fill:#f3e8ff,stroke:#9333ea,stroke-width:2px,color:#581c87;
    classDef fuse fill:#ccfbf1,stroke:#0d9488,stroke-width:3px,color:#134e4a;
    classDef head fill:#fef9c3,stroke:#ca8a04,stroke-width:2px,color:#713f12;
    classDef decision fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d;
    classDef dash fill:#e2e8f0,stroke:#475569,stroke-width:2px,color:#0f172a;

    class K1,K2,K3,K4 cluster;
    class HA,SA agent;
    class E1 gnn;
    class E2 mamba;
    class E3 trans;
    class E4 conv;
    class FUSE fuse;
    class O1,O2 head;
    class D1,D2,D3 decision;
    class DASH dash;
```

## Legend

| Color | Component | Role |
|-------|-----------|------|
| 🟦 Blue | **GNN (GAT)** | YAML diff → attributed graph → 3-layer Graph Attention Network → 128-dim |
| 🟩 Green | **Mamba SSM** | Prometheus metric time-series → O(n) state-space scan → 64-dim |
| 🟧 Orange | **Transformer** | Falco syscall sequence → 4-head × 2-layer encoder → 64-dim |
| 🟪 Purple | **Conv1D + SE** | File entropy series → conv + squeeze-excitation → 64-dim |
| 🟦‍🟩‍🟧‍🟪 → Teal | **MHCA Fusion** | Cross-attention over the 4 modality embeddings → 192-dim |
| 🟨 Gold | **Output Head** | Risk score (0–1) + 5-class label |
| 🟥 Red | **Fusion Agent** | Thresholds risk → circuit-breaker / auto-remediation or allow |

## Notes
- **Modality routing**: the health path uses YAML + metrics; the security path uses syscalls + entropy. Any missing modality is zero-filled, so the same single model serves both domains.
- **One model, two domains**: there is exactly one network (`DITSecV3`, ~436K params) with one shared fusion layer and one output head spanning all 5 classes.
- Source: [models/dit_sec_v3/dit_sec_v3_model.py](../models/dit_sec_v3/dit_sec_v3_model.py).
