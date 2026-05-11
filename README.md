# KubeHeal v3.0

**Autonomous Configuration & Security Drift Correction in Kubernetes**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        KubeHeal System                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │Health Agent  │    │Security Agent│    │Fusion Agent  │      │
│  │(Deployment)  │    │(DaemonSet)   │    │(Deployment)  │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                  │                    │               │
│         └──────────────────┼────────────────────┘               │
│                            │                                    │
│                   ┌────────▼──────────┐                         │
│                   │   Redis Streams   │                         │
│                   │ • health.events   │                         │
│                   │ • security.events │                         │
│                   │ • actions         │                         │
│                   │ • incidents       │                         │
│                   └────────┬──────────┘                         │
│                            │                                    │
│              ┌─────────────┼─────────────┐                      │
│              │             │             │                      │
│       ┌──────▼────┐  ┌─────▼─────┐  ┌───▼──────┐              │
│       │AUTO-KILL  │  │AUTO-PATCH │  │HUMAN     │              │
│       │(pod del + │  │(kubectl   │  │APPROVAL  │              │
│       │ netpol)   │  │ patch)    │  │          │              │
│       └───────────┘  └───────────┘  └──────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Ransomware kill time | < 8s |
| Config drift MTTR | < 80s |
| DIT-Sec model F1 | 93.2% |

---

## Prerequisites

- Ubuntu 22.04+ with **4 vCPU, 8 GB RAM, 40 GB disk** minimum
- The following tools installed:
  - `docker`
  - `kubectl`
  - `minikube`
  - `helm`

Install tools on Ubuntu:
```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Installation

```bash
git clone https://github.com/PRATHVI9607/Unisys_Model.git
cd Unisys_Model
git checkout kali

chmod +x scripts/install.sh
./scripts/install.sh
```

The install script does:
1. Starts minikube (2 CPU, 4 GB)
2. Installs Redis via Helm into `kubeheal` namespace
3. Builds all 5 Docker images inside minikube's Docker daemon
4. Applies all Kubernetes manifests (RBAC, agents, model server, dashboard)
5. Waits for all pods to be ready

Expected output at the end:
```
✓ All pods ready in kubeheal namespace
Installation complete!
```

---

## Running the Demo

Open **3 terminals** in the project directory.

### Terminal 1 — Dashboard
```bash
kubectl port-forward svc/kubeheal-dashboard 5000:5000 -n kubeheal
```
Open browser: **http://localhost:5000**

### Terminal 2 — Watch logs (optional)
```bash
kubectl logs -n kubeheal -l app=fusion-agent -f
```

### Terminal 3 — Run demo script
```bash
chmod +x scripts/demo.sh
./scripts/demo.sh
```

---

## Demo A — Configuration Drift (Auto-Patch)

The script patches the `victim-app` deployment: CPU limit drops from `500m` → `50m`.

**What happens:**
1. Health Agent detects the YAML drift
2. DIT-Sec scores it: risk = 0.85
3. Fusion Agent decides: **AUTO-PATCH**
4. CPU limit restored to `500m`

**Expected timeline:** ~80 seconds total

---

## Demo B — Ransomware Attack (Auto-Kill)

The script deploys a ransomware simulator pod with label `kubeheal.io/chaos=true`.

**What happens:**
1. Security Agent detects the chaos pod
2. Publishes event: risk = 0.92, label = `ransomware-critical`
3. Fusion Agent decides: **AUTO-KILL**
4. Pod deleted, NetworkPolicy blocks egress

**Expected timeline:** < 8 seconds from pod Running → killed

---

## Verify Results

```bash
# See all incidents
kubectl exec -n kubeheal redis-master-0 -- \
  redis-cli XREVRANGE kubeheal.incidents + - COUNT 10

# See security events
kubectl exec -n kubeheal redis-master-0 -- \
  redis-cli XREVRANGE kubeheal.security.events + - COUNT 5

# See health events
kubectl exec -n kubeheal redis-master-0 -- \
  redis-cli XREVRANGE kubeheal.health.events + - COUNT 5

# Check pod status
kubectl get pods -n kubeheal
kubectl get pods -n demo
```

---

## Decision Policy

| Adjusted Score | Action | Circuit Breaker |
|---------------|--------|-----------------|
| ≥ 0.85 (security) | AUTO-KILL | Max 3/hr per namespace |
| ≥ 0.85 (health) | AUTO-PATCH | Max 10/hr per deployment |
| 0.65 – 0.84 | Human Approval | — |
| 0.40 – 0.64 | Observe | — |
| < 0.40 | Benign | — |

### Namespace Risk Multipliers
- `prod` → × 1.20
- `staging` → × 1.00
- `dev` → × 0.70

---

## Project Structure

```
Unisys_Model/
├── agents/
│   ├── health_agent/agent.py      # Watches K8s deployments for YAML drift
│   ├── security_agent/agent.py    # Detects ransomware via entropy + chaos labels
│   └── fusion_agent/agent.py      # Decision engine with circuit breakers
├── models/
│   └── dit_sec_v3/                # DIT-Sec transformer model + FastAPI server
├── k8s/                           # All Kubernetes manifests
│   ├── rbac/
│   ├── health-agent-deployment.yaml
│   ├── security-agent-daemonset.yaml
│   ├── fusion-agent-deployment.yaml
│   ├── dit-sec-deployment.yaml
│   └── dashboard-deployment.yaml
├── dockerfiles/                   # One Dockerfile per component
├── dashboard/                     # Flask + Socket.IO real-time dashboard
├── demo/                          # victim-app.yaml (target deployment)
├── chaos/                         # ransomware-simulator.py + chaos-pods.yaml
└── scripts/
    ├── install.sh                 # Full cluster setup
    └── demo.sh                    # Interactive demo runner
```

---

## Troubleshooting

```bash
# Pod not starting
kubectl describe pod <pod-name> -n kubeheal

# View agent logs
kubectl logs -n kubeheal -l app=health-agent
kubectl logs -n kubeheal -l app=security-agent
kubectl logs -n kubeheal -l app=fusion-agent

# Reset demo state
kubectl exec -n kubeheal redis-master-0 -- \
  redis-cli DEL kubeheal.incidents "kubeheal:cooldown:demo:victim-app"
kubectl delete pod ransomware-simulator drift-injector -n demo 2>/dev/null || true
kubectl apply -f demo/victim-app.yaml

# Restart all agents
kubectl rollout restart deployment/health-agent deployment/fusion-agent -n kubeheal
kubectl rollout restart daemonset/security-agent -n kubeheal
```

---

## Components

| Component | K8s Type | Port |
|-----------|----------|------|
| Health Agent | Deployment | — |
| Security Agent | DaemonSet | — |
| Fusion Agent | Deployment | — |
| DIT-Sec Model Server | Deployment | 8000 |
| Dashboard | Deployment | 5000 |
| Redis | StatefulSet | 6379 |

---

## License

RVCE · Unisys UIP · Confidential

Team: Ryan Dave Fernandes · P Koti Darshan · Rakshak S
