# KubeHeal target specification (condensed from the synopsis)

Use this as the checklist when comparing the repository to the intended design.
Each item has an ID so reports can reference it (for example "S-POL-3: partial").

---

## 1. Components and interfaces

### S-HA: Health Agent (Deployment)
- S-HA-1 Watches Deployments through the Kubernetes Watch API; reconnects on watch timeout.
- S-HA-2 Stores a golden baseline per workload on first sight, written only if absent (never overwritten by persistent drift).
- S-HA-3 Computes a YAML diff between live spec and golden baseline.
- S-HA-4 Pulls a 60-step x 15-metric Prometheus window for the affected pod.
- S-HA-5 Shared cache so a burst of events for one pod costs one Prometheus query.
- S-HA-6 Read-only RBAC.

### S-SA: Security Agent (DaemonSet, hostPID)
- S-SA-1 Maps processes to pods through cgroups v1 and v2 (with LRU cache).
- S-SA-2 Reads per-process bytes written from `/proc/<pid>/io`.
- S-SA-3 Samples write entropy: 30 samples, 2 s apart.
- S-SA-4 Consumes Falco events (up to 256 syscalls per window).
- S-SA-5 Read-only RBAC.

### S-HM: Health Model server (FastAPI, port 8001)
- S-HM-1 Endpoint `POST /health/score`; `GET /health` for probes.
- S-HM-2 GATv2 (3 layers x 8 heads) over the YAML diff graph + BiLSTM (2 layers) over the metric window + cross-attention.
- S-HM-3 Output: risk, 4-class label (benign, low-risk drift, harmful degradation, critical error), label probabilities, field attribution, top field/metric, conformal CI, 128-dim embedding.
- S-HM-4 Loads trained checkpoint; behaviour when checkpoint is missing must be explicit (spec intent: fail closed, not random weights).

### S-SM: Security Model server (FastAPI, port 8002)
- S-SM-1 Endpoint `POST /security/score`; `GET /health`.
- S-SM-2 Transformer (4 heads x 2 layers, Pre-LN, CLS) over syscalls + Conv1D-SE (kernels 3, 7, 15) over entropy + cross-attention.
- S-SM-3 Output: risk, 5-class label (benign, suspicious, ransomware staging, ransomware active, exfiltration), syscall attribution, entropy spike flag, conformal CI, 64-dim embedding.
- S-SM-4 Same checkpoint rule as S-HM-4.

### S-DCM: Dependency Correlation Module server (FastAPI, port 8003)
- S-DCM-1 Endpoint `POST /dcm/correlate`; `GET /health`.
- S-DCM-2 Bidirectional cross-modal attention over the two embeddings.
- S-DCM-3 Output: correlation score, compound flag (score > 0.60), causal chain, NL summary.
- S-DCM-4 Trained after the base models, with base models frozen.

### S-INT: Interpretation layer
- S-INT-1 Field-name mapper (graph node index -> real YAML path).
- S-INT-2 SHAP attributions.
- S-INT-3 Causal chain builder, including attack onset time T0.
- S-INT-4 Template NL summary; optional LLM summary only for dev namespaces with pod names, paths and IPs redacted.

### S-MQ: Messaging
- S-MQ-1 Redis Streams between scoring and the Fusion Agent.
- S-MQ-2 One consumer group; each event delivered to exactly one Fusion replica.
- S-MQ-3 Pending-entry reclaim when a replica dies.
- S-MQ-4 Redis AOF on a PersistentVolume.

### S-FA: Fusion Agent (2 replicas)
- S-FA-1 Pairs health and security events per pod.
- S-FA-2 Calls DCM and interpretation layer.
- S-FA-3 Applies the decision policy (section 2).
- S-FA-4 Per-incident Redis lock: TTL 10 s, heartbeat every 3 s.

### S-EX: Remediation Executor
- S-EX-1 Only component with write permissions; scoped ServiceAccount; RoleBindings only in protected namespaces.
- S-EX-2 Drift path (section 3a).
- S-EX-3 Ransomware path (section 3b).
- S-EX-4 Writes every step to the audit ledger.

### S-DB: Dashboard
- S-DB-1 FastAPI behind Ingress.
- S-DB-2 Shows pending approvals with SHAP view and causal chain; approve/reject.

### S-REC: Record
- S-REC-1 Append-only ledger in MinIO with object lock, keyed by incident ID.
- S-REC-2 Prometheus counters for actions; Grafana dashboards.
- S-REC-3 MinIO also acts as model registry.

---

## 2. Decision policy (pure function, unit-tested)

- S-POL-1 If any model server failed to answer within the deadline -> HUMAN (fail closed).
- S-POL-2 adjusted = risk x tier x compound; tier prod 1.20, staging 1.00, dev 0.70; compound factor 1.15 when DCM > 0.60.
- S-POL-3 sec_adj >= 0.85 -> candidate CONTAIN (compound or security-only).
- S-POL-4 health_adj >= 0.85 and raw sec_risk < 0.4 -> candidate PATCH.
- S-POL-5 max(adj) >= 0.65 -> HUMAN approval; >= 0.40 -> OBSERVE (3x sampling); else BENIGN.
- S-POL-6 Guards for automatic action: both CI widths <= 0.15; circuit breaker closed (max 3 containments per namespace, 10 patches per Deployment, per hour); namespace not protected by label. Any guard fails -> HUMAN.
- S-POL-7 Burn-in until 2000 metric samples: automatic thresholds raised to 0.95 and 0.90.

---

## 3. Remediation

### 3a. Drift (canary patch)
- S-RD-1 Save live spec as rollback point.
- S-RD-2 Patch only the top-attributed field back to the golden baseline.
- S-RD-3 Rolling update with maxUnavailable 0.
- S-RD-4 Watch p99 latency and CPU throttling for 3 windows; keep if improved, else roll back and escalate.

### 3b. Ransomware (contain, then restore)
- S-RR-1 Rolling VolumeSnapshots every 5 min, keep last 12, for protected PVCs.
- S-RR-2 Quarantine: label pod `kubeheal/quarantine=true`; deny-all NetworkPolicy selects it.
- S-RR-3 On-demand forensic VolumeSnapshot.
- S-RR-4 Scale owning Deployment/StatefulSet to zero (not a bare pod delete).
- S-RR-5 Select newest rolling snapshot before T0.
- S-RR-6 Restore PVC from it; redeploy image pinned by digest.
- S-RR-7 Re-check entropy; lift quarantine if clean, else keep isolated and page.

---

## 4. Cloud and platform

- S-CL-1 Model servers: HPA min 2 max 8 on request queue depth via prometheus-adapter.
- S-CL-2 PodDisruptionBudget minAvailable 1 and topology spread for each model server.
- S-CL-3 Requests and limits set from measured profiles.
- S-CL-4 Namespaces prod / staging / dev with ResourceQuota and LimitRange; KubeHeal runs in `kubeheal` namespace and excludes itself from actions.
- S-CL-5 NetworkPolicy around the `kubeheal` namespace (only agents, dashboard, Prometheus reach model servers).
- S-CL-6 One Helm chart with dev / staging / prod values (replacing the Minikube shell installer).
- S-CL-7 Deployment model: private cloud (Minikube for dev, kubeadm lab cluster), validated on EKS/GKE/AKS. Demo now uses k3d.
- S-CL-8 Models exported to ONNX (FP16 where valid, else validated FP32 / torch bundle).

---

## 5. Kill switch (new, pending confirmation)

- S-KS-1 Modes `test` (dry run) and `enforce`.
- S-KS-2 ConfigMap `kubeheal-mode` in `kubeheal` namespace; per-namespace label override `kubeheal/mode`.
- S-KS-3 Checked in Fusion Agent and as a hard gate in the Executor before every write call.
- S-KS-4 Unreadable mode -> treat as `test`; fresh install default `test`.
- S-KS-5 Mid-action switch to `test` -> stop before next step, escalate.
- S-KS-6 Mode changes written to the ledger; only cluster admins may change it (RBAC).

---

## 6. Data and evaluation (for awareness, do not run)

- Drift dataset: 4,782 labelled samples (`models/health_model/dit-merged-complete.csv` or similar).
- Security traces: 14,000 generated + live Falco captures; tests on held-out variants only.
- Compound pairs: 5,000 generated.
- Reported so far in the synopsis: Health Model validation macro-F1 0.80; DCM AUROC 0.96; Security Model perfect on generated traces (generator judged too easy).
- Evaluation plan: detection vs Falco rules / fixed entropy threshold / diff-only drift; latency vs pods and replicas; detection continuity under chaos; RPO/RTO vs pod delete; end-to-end time to action (target < 8 s); FP32 vs FP16 cost.

---

## 7. Demo scope for 2026-11-11 (k3d)

Must have:
- D-1 k3d cluster from one script (1 server + 2 agents), demo app in `prod`.
- D-2 Three model servers running with **trained** checkpoints.
- D-3 Drift scenario end to end: inject 50m CPU limit -> detect -> score -> decide -> Executor patches back -> steps visible in logs/ledger.
- D-4 Kill switch live: flip to `test`, inject again, show "would have PATCHED", flip back.

Should have:
- D-5 Ransomware scored from replayed traces and contained via NetworkPolicy quarantine.
- D-6 Fail-closed moment: delete a model server pod mid-incident, show HUMAN escalation.

Only if already working:
- D-7 Snapshot restore (CSI hostpath + external-snapshotter).
- D-8 HPA scaling (CPU-based acceptable for demo).
- D-9 DCM compound case, dashboard UI, Grafana.
