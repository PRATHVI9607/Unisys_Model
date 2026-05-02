# KubeHeal Usage Guide

## Next Steps to Continue Development

To continue developing and improving KubeHeal, here are the specific tasks that can be provided:

### 1. Train the DIT-Sec Model

**What's needed:**
- GPU machine (or cloud GPU) for training
- Real Kubernetes cluster with metrics collection
- Or: Provide annotated incident dataset

**What I'll create:**
- Training pipeline with real data
- Model fine-tuning scripts
- Conformal prediction calibration

### 2. Add More Test Coverage

**What's needed:**
- Test cases for edge cases
- Known problematic deployments

**What I'll create:**
- Unit tests for each agent
- Integration tests
- Chaos engineering tests

### 3. Integrate External Services

**What's needed:**
- Slack webhook URL (for human approval)
- PagerDuty API key (for alerting)
- AWS S3 credentials (for backup)

**What I'll create:**
- Slack integration for approvals
- PagerDuty alerting
- Velero backup configuration

### 4. Add ML Model Server API

**What's needed:**
- None (I can create this)

**What I'll create:**
- FastAPI model server with `/score` and `/explain` endpoints
- ONNX runtime integration
- Request validation

### 5. Create Dockerfiles for Production

**What's needed:**
- Build context understanding

**What I'll create:**
- Multi-stage Docker builds
- Production-ready configurations
- Health/liveness checks

### 6. Add Grafana Dashboards

**What's needed:**
- Dashboard JSON templates

**What I'll create:**
- Incident dashboard
- Agent performance dashboard
- System health dashboard

### 7. Implement Missing Features

**What's needed:**
- Feedback on prioritization

**What I'll create (in priority order):**

1. **Model Registry** - Versioned ONNX artifacts
2. **Burn-In Controller** - Graduated thresholds for new clusters
3. **WAL Backup** - Kasten K10 integration
4. **Falco Integration** - gRPC event consumer

### 8. Polish Dashboard UI

**What's needed:**
- Design preferences

**What I'll create:**
- Better visualization
- More interactive elements
- Dark/light mode

---

## Quick Win Tasks (Can Start Now)

If you'd like me to continue, pick one:

1. **Add `/score` endpoint to model server** - Basic inference API
2. **Add unit tests for Fusion Agent** - Decision policy tests
3. **Create Prometheus scrape config** - For 5s scrape interval
4. **Add README diagram** - Architecture visualization
5. **Create requirements.txt files** - For each component
6. **Add .dockerignore files** - Optimize builds

---

## What I Need From You

To continue, please provide:

1. **Preferred next task** from the list above
2. **Any specific requirements** (e.g., specific versions, integrations)
3. **Testing environment details** (if you have a K8s cluster)

---

## Current Project Status

| Component | Status |
|-----------|--------|
| DIT-Sec Model | Implemented (untrained) |
| Health Agent | Implemented |
| Security Agent | Implemented |
| Fusion Agent | Implemented |
| K8s Manifests | Complete |
| Dockerfiles | Complete |
| Dashboard | Functional |
| Demo Scripts | Complete |

**Ready for deployment on Minikube!**

---

## Recommended Next Steps

1. **Train the ML model** - This is critical for accuracy
2. **Add real-time /score API** - Missing endpoint
3. **Test on actual K8s cluster** - Validate functionality
4. **Add Slack/PagerDuty** - Complete the alerting loop

Let me know which task you'd like me to continue with!