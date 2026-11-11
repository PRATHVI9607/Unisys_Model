# Project specification status

This is a code review against `PROJECT_SPEC.md`, not a claim of production validation. “Implemented” means the behavior has code and relevant automated evidence. It does not imply that the behavior has been exercised against a production Kubernetes cluster. Live observations are identified separately.

## Components and interfaces

| ID | Status | Evidence and limits |
|---|---|---|
| S-HA-1 | Implemented | `agents/health_agent/agent.py`, `HealthAgent.watch_deployments`; reconnects and resumes by resource version. `tests/test_sense_health_window.py`; live Watch test in `tests/test_killswitch.py` covers ConfigMap watch, not all Deployment reconnect cases. |
| S-HA-2 | Implemented | `agents/health_agent/baseline.py`, `get_or_set_baseline`; Redis SET NX. `tests/test_golden_baseline.py`. |
| S-HA-3 | Implemented | `baseline.is_drifted` and `drift_view`; Health Agent compares live spec to stored golden spec. `tests/test_golden_baseline.py`, `tests/test_sense_health_window.py`. |
| S-HA-4 | Implemented | `agents/health_agent/prometheus_client.py`, `wait_for_fresh_metric_window`; 60 steps and 15 configured metrics. `tests/test_sense_health_window.py`. Live query check is recorded in `PROGRESS.md` under P10-V2. |
| S-HA-5 | Implemented | `agents/health_agent/prometheus_client.py` has a shared Redis cache for windows; `tests/test_prometheus_cache.py`. |
| S-HA-6 | Implemented | `deploy/helm/kubeheal/templates/rbac.yaml`, `k8s/rbac/rbac.yaml`; `tests/test_no_writes_outside_executor.py`, `tests/test_rbac_k3d.py`. The latter needs the configured cluster for live verification. |
| S-SA-1 | Implemented | `agents/security_agent/proc_scanner.py`; `tests/test_cgroups_compatibility.py`, `tests/test_proc_scanner_index.py`. |
| S-SA-2 | Implemented | `agents/security_agent/proc_scanner.py`; bounded `/proc/<pid>/io` reads. `tests/test_proc_scanner_index.py`. |
| S-SA-3 | Implemented | `agents/security_agent/entropy_sampler.py`; bounded entropy sampling. `tests/test_sense_entropy_sampler.py`. Live ransomware detection is unverified. |
| S-SA-4 | Implemented | `agents/security_agent/falco_client.py`, `syscall_window.py`; bounded event windows and explicit live/replay/off modes. `tests/test_sense_falco_replay.py`. Fixtures are hand-authored, not captures. |
| S-SA-5 | Implemented | `k8s/rbac/rbac.yaml`, Helm RBAC template; RBAC and no-writes tests listed above. |
| S-HM-1 | Implemented | `services/health_model_server/main.py`; `/health` and `/health/score`. `tests/test_model_servers_fail_closed.py`. |
| S-HM-2 | Implemented | `models/health_model/` encoder and fusion modules; `tests/test_encoders.py`. Checkpoint performance on live windows is not established. |
| S-HM-3 | Implemented | Health server response schema and output head in `services/health_model_server/main.py` and `models/health_model/`; contract and server tests. Attribution quality is not validated on live data. |
| S-HM-4 | Implemented | Health server rejects missing/incompatible required checkpoints and checks the preprocessing sidecar. `tests/test_model_servers_fail_closed.py`, `tests/test_health_preprocess_version.py`. |
| S-SM-1 | Implemented | `services/security_model_server/main.py`; `/health` and `/security/score`; server fail-closed tests. |
| S-SM-2 | Implemented | `models/security_model/` transformer, entropy encoder and fusion modules; `tests/test_encoders.py`. |
| S-SM-3 | Implemented | Security output head and service response; security model tests. Live attack classification is not established. |
| S-SM-4 | Implemented | Security server checkpoint validation; `tests/test_model_servers_fail_closed.py`. |
| S-DCM-1 | Implemented | `services/dcm_server/main.py`; `/health` and `/dcm/correlate`. |
| S-DCM-2 | Implemented | `models/dcm/cross_modal_attention.py`; `tests/test_encoders.py`. |
| S-DCM-3 | Implemented | DCM response and `models/dcm/causal_chain_builder.py`; DCM and interpretation tests. Content quality is not independently validated. |
| S-DCM-4 | Partial | Training and checkpoint artifacts/scripts exist under `models/`; evidence does not establish that the checked-in DCM checkpoint was trained with frozen base models as specified. |
| S-INT-1 | Implemented | `models/interpretation/field_name_mapper.py`; `tests/test_fusion_interpretation.py`. |
| S-INT-2 | Partial | SHAP helper exists in `models/interpretation/shap_explainer.py`; real KernelExplainer is not wired through the running scoring path and may fall back. See P6-D6 in `PROGRESS.md`. |
| S-INT-3 | Implemented | `models/dcm/causal_chain_builder.py` and Fusion interpretation client carry T0 where available; `tests/test_fusion_interpretation.py`, `tests/test_sense_falco_replay.py`. |
| S-INT-4 | Partial | Template summary exists in `models/interpretation/nl_summary_generator.py`. Optional LLM redaction and namespace restriction are not established as an active deployed path. |
| S-MQ-1 | Implemented | Redis streams connect agents and Fusion; `agents/fusion_agent/agent.py`; `tests/test_fusion_streams.py`, `tests/test_integration_full_pipeline.py`. |
| S-MQ-2 | Partial | Consumer groups route entries to group members; behavior is exercised in stream tests. Exactly-once delivery is not guaranteed; processing uses recovery and idempotency patterns. |
| S-MQ-3 | Implemented | `agents/common/stream_reliability.py`; pending claim recovery and dead-letter behavior; `tests/test_stream_reliability.py`, `tests/test_fusion_reliability.py`. |
| S-MQ-4 | Implemented | Redis persistence is configured in `deploy/helm/kubeheal/templates/redis.yaml`; chart tests cover rendered resources. Cluster durability has not been failure-tested. |
| S-FA-1 | Implemented | Fusion event pairing in `agents/fusion_agent/agent.py`; stream and integration tests. |
| S-FA-2 | Implemented | Fusion calls DCM and interpretation client; `tests/test_fusion_interpretation.py`, `tests/test_fusion_decide.py`. |
| S-FA-3 | Implemented | `agents/fusion_agent/decision_policy.py`; pure policy tests in `tests/test_decision_policy.py` and `tests/test_policy_rules.py`. |
| S-FA-4 | Implemented | `agents/fusion_agent/incident_lock.py`; lease and heartbeat tests in `tests/test_incident_lock.py`. |
| S-EX-1 | Implemented | Executor service account and namespace-scoped RBAC in `k8s/rbac/rbac.yaml` and Helm template; `tests/test_remediation_static.py`, `tests/test_rbac_k3d.py`. Live RBAC evidence is recorded in `PROGRESS.md`. |
| S-EX-2 | Implemented | `agents/executor/drift.py`; rollback point, guarded patch and canary checks. `tests/test_remediation_drift.py`. Real cluster patch behavior is demo-specific and remains limited by current model scores and kill-switch mode. |
| S-EX-3 | Partial | Quarantine, snapshots, restore and entropy probe code in `agents/executor/`; `tests/test_remediation_ransomware.py`, `tests/test_restore_entropy_probe.py`. Full CSI snapshot/restore path is not verified end to end. |
| S-EX-4 | Implemented | Executor records gated actions through the shared ledger; `tests/test_executor_ledger_policy.py`, `tests/test_record_pipeline.py`. MinIO transient startup failure and pending-stream drain are tracked in `PROGRESS.md`. |
| S-DB-1 | Partial | FastAPI dashboard and Helm Ingress resources exist (`dashboard/fastapi_app.py`, Helm templates). External TLS and production ingress behavior are not verified. |
| S-DB-2 | Partial | Approval and incident ledger views exist in `dashboard/`; dashboard tests cover routes and claims. A full SHAP review view and production authentication posture are not established. |
| S-REC-1 | Implemented | `agents/common/ledger.py` and `k8s/minio.yaml` configure append-only, object-lock writes. `tests/test_ledger.py`, `tests/test_ledger_guard.py`; see live check in `PROGRESS.md`. |
| S-REC-2 | Implemented | Metrics in `agents/common/metrics.py`, Prometheus config and Grafana dashboard in `deploy/`; `tests/test_metrics.py`, `tests/test_grafana_dashboard.py`. |
| S-REC-3 | Partial | Checkpoint registry helpers and upload code exist in `models/ckpt_registry.py` and `models/upload_to_registry.py`; registry lifecycle and promotion policy are not demonstrated. |

## Decision policy

| ID | Status | Evidence and limits |
|---|---|---|
| S-POL-1 | Implemented | Fusion marks unavailable model results and policy fails closed to HUMAN; `tests/test_decision_policy.py`, `tests/test_fusion_decide.py`. |
| S-POL-2 | Implemented | Tier and compound adjustment in `agents/fusion_agent/decision_policy.py`; boundary tests in `tests/test_decision_policy.py`. |
| S-POL-3 | Implemented | Containment threshold and tests in `decision_policy.py`, `tests/test_decision_policy.py`. |
| S-POL-4 | Implemented | Patch candidate threshold and tests in `decision_policy.py`, `tests/test_decision_policy.py`. |
| S-POL-5 | Implemented | HUMAN/OBSERVE/BENIGN thresholds in `decision_policy.py`; policy tests. OBSERVE requests are bounded by Redis TTL; Health Agent rescheduling is configurable with a documented default in `agents/health_agent/agent.py`. |
| S-POL-6 | Implemented | CI, breaker, protected namespace and mode guards are in policy/Fusion; tests in `tests/test_decision_policy.py`, `tests/test_policy_rules.py`, `tests/test_fusion_decide.py`. |
| S-POL-7 | Implemented | Burn-in counter and thresholds in Fusion/policy; `tests/test_fusion_decide.py`, `tests/test_decision_policy.py`. The sample-count interpretation is a chosen assumption documented in `PROGRESS.md`. |

## Remediation

| ID | Status | Evidence and limits |
|---|---|---|
| S-RD-1 | Implemented | Rollback record in `agents/executor/drift.py`; `tests/test_remediation_drift.py`. |
| S-RD-2 | Implemented | Field-level patch uses attributed field and golden baseline; `tests/test_remediation_drift.py`. |
| S-RD-3 | Implemented | Canary strategy configures zero unavailable replicas; drift tests. |
| S-RD-4 | Implemented | Three-window comparison and rollback/escalation in drift path; `tests/test_remediation_drift.py`; only fake-backed verification is claimed. |
| S-RR-1 | Partial | Rolling snapshot scanner and retention logic in `agents/executor/snapshots.py`; `tests/test_remediation_ransomware.py`. Scheduling and live CSI operation are not established across environments. |
| S-RR-2 | Implemented | Pod quarantine and deny policy in Executor; `tests/test_remediation_ransomware.py`, `tests/test_remediation_static.py`. NetworkPolicy enforcement is platform-dependent and not claimed here. |
| S-RR-3 | Implemented | Forensic snapshot action in `agents/executor/snapshots.py`; fake-backed remediation tests. |
| S-RR-4 | Implemented | Owning workload scale-down path in `agents/executor/restore.py`; remediation tests. |
| S-RR-5 | Implemented | Snapshot selection by timestamp before T0 in restore path; remediation tests. |
| S-RR-6 | Implemented | New PVC restore and digest validation in restore path; `tests/test_remediation_ransomware.py`, `tests/test_remediation_validation.py`. Live CSI restore remains unverified. |
| S-RR-7 | Partial | Entropy re-check hook exists in `agents/executor/restore_entropy.py`; `tests/test_restore_entropy_probe.py`. Deployment wiring and real post-restore signal validation are incomplete. |

## Cloud and platform

| ID | Status | Evidence and limits |
|---|---|---|
| S-CL-1 | Implemented | Queue-depth metrics and HPA templates in Helm; `tests/test_platform_inflight.py`, `tests/test_platform_chart.py`. k3d adapter observation is in P10-U7; scale-out under load is not measured. |
| S-CL-2 | Implemented | PDB and topology spread templates; `tests/test_platform_chart.py`. Scheduling behavior under disruption has not been tested. |
| S-CL-3 | Partial | Requests and limits are configured in chart values; profiles are chosen defaults, not measured workload profiles. `tests/test_platform_resource_profile.py`. |
| S-CL-4 | Implemented | Helm namespace, quotas, limits and self-exclusion labels; chart tests. |
| S-CL-5 | Implemented | Helm NetworkPolicy resources; `tests/test_platform_chart.py`. Effective network enforcement depends on the cluster CNI and has not been generalized. |
| S-CL-6 | Implemented | Helm chart and dev/staging/prod/lab/k3d values in `deploy/helm/kubeheal/`; `tests/test_platform_chart.py`. |
| S-CL-7 | Partial | Chart supports Kubernetes deployment; k3d demo configuration exists. EKS/GKE/AKS and kubeadm validation are not present. |
| S-CL-8 | Partial | Export scripts and parity checks exist in `models/export_*.py`; `tests/test_platform_onnx_switch.py`. Not every model format or target runtime has a validated export in this environment. |

## Kill switch

| ID | Status | Evidence and limits |
|---|---|---|
| S-KS-1 | Implemented | `agents/common/killswitch.py` and policy support `test`/`enforce`; `tests/test_killswitch.py`. |
| S-KS-2 | Implemented | `k8s/kill-switch.yaml` and Helm template define the ConfigMap and namespace labels; kill-switch tests. |
| S-KS-3 | Implemented | Fusion reads mode; Executor gates every write in `agents/executor/actions.py`; static and live Watch tests. |
| S-KS-4 | Implemented | Unreadable/missing mode normalizes to test; tests in `tests/test_killswitch.py`. |
| S-KS-5 | Implemented | Executor rechecks the mode before each write and escalates if it changes mid-action; `tests/test_killswitch.py`, `tests/test_executor.py`. |
| S-KS-6 | Partial | Mode changes are recorded and the dashboard role is scoped to the ConfigMap. Cluster-admin identity and production authentication configuration need deployment-specific verification. |

## Demo acceptance

| ID | Status | Evidence and limits |
|---|---|---|
| D-1 | Partial | k3d setup scripts and victim manifests are under `demo/k3d/`; repeatable acceptance is tracked as P10-U6. |
| D-2 | Partial | Checkpoints are present and model servers enforce checkpoint loading. The live model-pod checkpoint state and end-to-end trained-model acceptance are not established here. |
| D-3 | Partial | Drift is detected on k3d, but the observed decision was OBSERVE. Automatic patch acceptance has not been achieved; see P10 findings. |
| D-4 | Not verified | Requires a patch decision to demonstrate dry-run wording. Current drift scoring does not reach that path. |
| D-5 | Not verified | Replay and containment components exist; full demo acceptance is not recorded. |
| D-6 | Not verified | Fail-closed policy is unit-tested; the live model-server-loss scenario is not recorded as complete. |
| D-7 | Not verified | Snapshot/restore implementation exists, but a live victim PVC restore has not been recorded complete. |
| D-8 | Partial | Queue-depth HPA metric is observed by the adapter; scale-out under load is not measured. |
| D-9 | Not verified | DCM tests exist; no end-to-end demo result is recorded. |
