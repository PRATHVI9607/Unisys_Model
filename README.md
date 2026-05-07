# KubeHeal v3.0

**Autonomous Configuration & Security Drift Correction in Kubernetes**

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              ARCHITECTURE                                      │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                       │
│   │   K8s API   │    │   Falco     │    │Prometheus  │                       │
│   │  (YAMLs)    │    │  (eBPF)    │    │(Metrics)   │                       │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                       │
│          │                 │                │                                 │
│   ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐                        │
│   │Health Agent │  │Security     │  │  Metrics    │                        │
│   │(Deployment)│  │Agent        │  │  Buffer    │                        │
│   └──────┬──────┘  │(DaemonSet) │  └──────┬──────┘                        │
│          │          └──────┬──────┘         │                                 │
│          │               │               │                                 │
│   ┌──────▼──────────────▼──────────────▼──────┐                            │
│   │              REDIS STREAMS                │                            │
│   │  • kubeheal.health.events              │                            │
│   │  • kubeheal.security.events          │                            │
│   │  • kubeheal.actions                 │                            │
│   │  • kubeheal.incidents              │                            │
│   └──────────────────┬───────────────────┘                            │
│                      │                                                 │
│              ┌───────▼───────┐                                      │
│              │ Fusion Agent │                                      │
│              │(Decision Pol)│                                      │
│              │ + Circuit   │                                      │
│              │   Breakers   │                                      │
│              └───────┬───────┘                                      │
│                      │                                             │
│    ┌─────────────────┼─────────────────┐                           │
│    │                 │                 │                           │
│ ┌──▼────┐    ┌─────▼────┐    ┌─────▼─────┐                          │
│ │KILL  │    │AUTO-PATCH│    │  HUMAN   │                          │
│ │NetworkPolicy│    │kubectl patch│  │  Slack   │                          │
│ │+Pod Del│    │+Canary   │    │ Webhook  │                          │
│ └───────┘    └──────────┘    └──────────┘                          │
│                                                                    │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Kill Time | <8s (PID terminate + PV quarantine) |
| Health MTTR | <80s (Detect → Patch → Verify) |
| DIT-Sec F1 | 93.2% (15K Chaos Mesh samples) |
| Year 1 ROI | 76× ($22K cost vs $1.68M savings) |

---

## Architecture

KubeHeal uses **3 autonomous agents** coordinated through **Redis Streams**, powered by **DIT-Sec** (Drift Impact Transformer - Security), a multi-modal causal transformer.

```
┌─────────────────────────────────────────────────────────────────┐
│                        KubeHeal System                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │Health Agent │    │Security Agent│    │Fusion Agent  │     │
│  │(Deployment) │    │(DaemonSet)   │    │(Deployment) │     │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘     │
│         │                  │                  │              │
│         │    Redis Streams │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                   │
│                   ┌────────▼────────┐                         │
│                   │  Fusion Agent  │                         │
│                   │ Decision Policy│                         │
│                   │ + Circuit Brkrs│                         │
│                   └────────┬────────┘                         │
│                            │                                   │
│              ┌────────────┼────────────┐                     │
│              │            │            │                          │
│       ┌──────▼─────┐ ┌────▼────┐ ┌────▼────┐                  │
│       │ AUTO-KILL │ │AUTO-PATCH│ │ HUMAN   │                  │
│       └───────────┘ └─────────┘ └─────────┘                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       DIT-Sec Model                            │
├─────────��───────────────────────────────────────────────────────┤
│                                                                 │
│  YAML Diffs ──► Graph Attention Network (GAT, 3 layers)        │
│  Prom Metrics ──► Mamba SSM Encoder (O(n) complexity)           │
│  Falco Events ──► Transformer Encoder (4 heads, 2 layers)    │
│  Entropy Series ──► Conv1D + Squeeze-Excitation               │
│                                                                 │
│  All 4 embeddings ──► MHCA Fusion ──► MLP ──► Output         │
│                         (3 heads × 64-dim)                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## DIT-Sec Model Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                        DIT-SEC MODEL v3.0                          │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                    │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────┐ │
│   │  YAML Diffs  │  │   Prom       │  │    Falco    │  │  Entropy  │ │
│   │             │  │   Metrics   │  │   Events    │  │  Series   │ │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘ │
│          │                │                 │              │        │
│   ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐  ┌───▼────┐  │
│   │    GAT      │  │   Mamba     │  │Transformer │  │ Conv1D │  │
│   │ (Graph      │  │   SSM      │  │ (Syscall   │  │ + SE   │  │
│   │  Attention)│  │   Encoder  │  │ Sequence) │  │       │  │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬────┘  │
│          │                │                 │              │        │
│   ┌──────▼────────────────▼─────────────────▼──────────────▼─────┐  │
│   │            Multi-Head Cross-Attention (MHCA)              │           │
│   │                    3 heads × 64-dim                     │           │
│   └──────────────────────┬──────────────────────────────┬──────────┘  │
│                         │                              │               │
│                    ┌─────▼─────┐            ┌─────▼─────┐          │
│                    │   MLP     │            │  Output   │          │
│                    │          │            │          │          │
│                    └─────┬─────┘            └─────┬─────┘          │
│                          │                        │               │
│                    ┌─────▼─────────────────────────▼─────┐       │
│                    │          Risk Score [0-1]            │       │
│                    │          + Label                   │       │
│                    │          + Confidence Interval     │       │
│                    │          + XAI Weights           │       │
│                    └─────────────────────���──────────────────┘       │
│                                                                    │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Components

| Component | Type | Description |
|-----------|------|-------------|
| Health Agent | Deployment | Watches YAML drift → DIT-Sec inference → publishes HealthAssessment |
| Security Agent | DaemonSet | eBPF entropy tracking + process tree analysis + early-warning signals |
| Fusion Agent | Deployment | Correlates events → makes decisions → enforces circuit breakers |
| DIT-Sec Model Server | Deployment + HPA | Serves GNN+Mamba inference at <50ms |
| Dashboard | Deployment | Real-time demo dashboard at port 5000 |

---

## Quick Start

### Prerequisites

- Ubuntu 22.04 LTS VM - minimum 4 vCPU, 8GB RAM, 40GB disk
- kubectl, minikube, helm installed

### Installation

```bash
# Run the installation script
aaaza

# Or manually:
kubectl create namespace kubeheal
kubectl apply -f k8s/rbac/
kubectl apply -f k8s/crds/
kubectl apply -f k8s/dit-sec-deployment.yaml
kubectl apply -f k8s/health-agent-deployment.yaml
kubectl apply -f k8s/security-agent-daemonset.yaml
kubectl apply -f k8s/fusion-agent-deployment.yaml
kubectl apply -f k8s/dashboard-deployment.yaml
```

### Running the Demo

```bash
# Terminal 1: Port-forward dashboard
kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n kubeheal

# Terminal 2: Port-forward Grafana
kubectl port-forward svc/monitoring-grafana 3000:80 -n monitoring

# Run demo script
./scripts/demo.sh
```

Demo A: Config Drift - Watch the system detect and auto-patch a CPU limit drift (~80s)

Demo B: Ransomware Attack - Watch the system kill the ransomware process in <8s and restore from backup (~4min)

---

## Project Structure

```
kubeheal/
├── agents/                    # Agent implementations
│   ├── health_agent/        # Health monitoring agent
│   ├── security_agent/     # Security/ransomware agent
│   └── fusion_agent/        # Decision engine agent
├── models/                   # ML model code
│   └── dit_sec_v3/         # DIT-Sec v3.0 model
│       ├── dit_sec_model.py    # Model architecture
│       ├── train_dit_sec_v3.py # Training script
│       └── export_onnx_v3.py  # ONNX export
├── k8s/                     # Kubernetes manifests
│   ├── rbac/               # RBAC + namespaces
│   ├── crds/               # CRDs
│   ├── dit-sec-deployment.yaml
│   ├── health-agent-deployment.yaml
│   ├── security-agent-daemonset.yaml
│   ├── fusion-agent-deployment.yaml
│   └── dashboard-deployment.yaml
├── dockerfiles/             # Docker build files
├── dashboard/               # Flask + Socket.IO dashboard
├── demo/                    # Victim app manifests
├── chaos/                   # Ransomware simulator
└── scripts/                 # Installation & demo scripts
```

---

## Decision Policy

| Adjusted Score | Label | Action | Circuit Breaker |
|--------------|-------|--------|-----------------|
| ≥0.98 | ransomware-critical | Direct kill (bypasses Fusion) | Counted |
| ≥0.85 | ransomware-critical / health-critical | AUTO-KILL / AUTO-PATCH | Max 3/hr/namespace |
| 0.65-0.84 | sec-medium / perf-risk | Human approval | N/A |
| 0.40-0.64 | sec-low / perf-mild | Observe (monitoring ×3) | N/A |
| <0.40 | benign | XACK and continue | N/A |

---

## Namespace Tiers

- **prod** × 1.20 multiplier
- **staging** × 1.00 multiplier
- **dev** × 0.70 multiplier

---

## Guardrails

- Auto-Kill Circuit Breaker - Max 3 auto-kills per namespace per hour
- Auto-Patch Circuit Breaker - Max 10 auto-patches per Deployment per hour
- Emergency Pause - `kubectl annotate namespace <ns> kubeheal.io/paused=true`
- Canary-First Patching - 60s validation window before full rollout
- Rollback Window - Automatic revert if no improvement in 60s
- Backup Integrity Gate - Entropy sampling + SHA-256 manifest check
- Conformal CI Gate - Any decision with CI width >0.15 escalates to human

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| REDIS_URL | redis://redis-master:6379 | Redis connection |
| DIT_SEC_URL | http://dit-sec-server:8000 | Model server URL |
| PROMETHEUS_URL | http://prometheus:9090 | Prometheus URL |
| NAMESPACE | kubeheal | Agent namespace |
| COOLDOWN_TTL | 300 | Cooldown period in seconds |
| LOG_LEVEL | INFO | Logging level |

### Namespace Labels

Apply to namespaces you want KubeHeal to monitor:

```yaml
metadata:
  labels:
    kubeheal.io/watch: "true"
    kubeheal.io/namespace-tier: "prod"  # prod/staging/dev
```

### Baseline Annotations

Apply to Deployments:

```yaml
metadata:
  annotations:
    kubeheal.io/baseline-sha: "abc123def456"
    kubeheal.io/baseline-date: "2025-01-01T00:00:00Z"
```

---

## API Endpoints

### DIT-Sec Model Server

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/score` | POST | Get risk score for an event |
| `/explain` | POST | Get XAI explanation |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |

### Dashboard

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/api/incidents` | GET | List incidents |
| `/api/risk-scores` | GET | Current risk scores |
| `/api/agent-status` | GET | Agent status |
| `/api/stats` | GET | Statistics |

---

## Troubleshooting

```bash
# Check pods
kubectl get pods -n kubeheal

# View logs
kubectl logs -n kubeheal -l app=health-agent
kubectl logs -n kubeheal -l app=security-agent
kubectl logs -n kubeheal -l app=fusion-agent

# Check Redis streams
redis-cli XREAD COUNT 10 STREAMS kubeheal.health.events 0
redis-cli XREAD COUNT 10 STREAMS kubeheal.security.events 0
redis-cli XREAD COUNT 10 STREAMS kubeheal.actions 0

# View incidents
redis-cli XREVRANGE kubeheal.incidents 0 + COUNT 10

# Check circuit breakers
redis-cli GET kubeheal:cb:default

# Pause namespace
kubectl annotate namespace demo kubeheal.io/paused=true
```

---

## Business Case

| Cost Item | Without KubeHeal | With KubeHeal | Annual Saving |
|----------|-------------------|---------------|------------|
| Health incident downtime | 47 min MTTR × $12K/hr | <2 min MTTR | ~$420K/yr |
| Ransomware recovery | $1.2M/incident × 1.4/yr | <$50K/incident | ~$1.61M/yr |
| SRE triage labor | 20+ min/incident | <2 min/incident | ~$95K/yr |
| Infrastructure overprovisioning | Undetected errors | Rightsizing | ~$55K/yr |
| **Total Annual Saving** | | | **~$2.18M/yr** |

KubeHeal Implementation Cost: ~$28K/yr

**Year 1 ROI: 76×**

---

## License

RVCE · Unisys UIP · Confidential

Team: Ryan Dave Fernandes · P Koti Darshan · Rakshak S