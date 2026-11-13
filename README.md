# KubeHeal

RVCE · Unisys "Agents Unleashed" · UIP · Mentor: Dr. Mohana
Team: Ryan Dave Fernandes · P Koti Darshan · Rakshak S

KubeHeal is an experimental Kubernetes control plane for detecting configuration drift and suspicious container activity. Its pipeline is Sense, Score, Decide, Act, and Record. The implementation is under active development; this repository does not establish production readiness.

## Current status

- Health Agent watches labeled Deployments, compares their specs with a first-seen Redis baseline, and requests Prometheus metric windows before scoring drift.
- Security Agent consumes Falco events and samples process write activity and entropy. Falco replay is available for controlled tests; fixtures are hand-written examples, not captured attacks.
- Health and Security scoring use the shipped LightGBM bundles, split-conformal prediction sets, and TreeSHAP factors. Fusion uses deterministic correlation because LightGBM does not expose the embeddings required by the old DCM. Automatic actions require exactly one conformal label and the policy's other safety gates. See [SPEC_VS_CODE](docs/kubeheal/SPEC_VS_CODE.md) for item-level status and evidence.
- The bundles' shipped security validation figures are based on synthetic classes and are not evidence of live model quality. Health live scores have not been validated on representative live metric windows. P12 retraining remains unapproved and was not run.
- **Verified on k3d:** on 2026-11-12, a scripted ransomware alert traversed Fusion, Executor intake, freeze, snapshots, quarantine, scale-to-zero, restore, entropy rescan, quarantine release, and ledger recording on a scratch Deployment in `staging`. The final enforce window lasted 45 seconds; its entropy scan read 5 clean files and found 0 high-entropy files. The alert was scripted using model fields from the D-5 replay. Falco was not installed, so this does not verify live detection or Sense. This is k3d evidence, not real-node validation. See the [F3 run evidence](docs/kubeheal/demo-evidence/F3/RUNBOOK_F3.md).
- The D-5 hand-written replay also ran on k3d: the Security Agent produced a model-scored ransomware event and Fusion recorded a dry-run action. It is replay evidence, not a live Falco capture or Executor containment. See [the replay output](docs/kubeheal/demo-evidence/F3/10_d5_rerun.txt) and [ledger](docs/kubeheal/demo-evidence/F3/11_d5_rerun_ledger.jsonl).
- One F11 synthetic load run used 32 VUs for 90 seconds: 121,088/121,088 checks passed, median latency 22.86 ms, p95 38.45 ms, HPA replicas 2 -> 7 -> 2, elapsed 7m14s. A post-merge repeat scaled 2 -> 8 -> 2 but had 12 connection refusals out of 99,431 checks; it is not a clean load result. Grafana's queue-depth and replica panels plus Prometheus data for the repeat are saved in `docs/kubeheal/demo-evidence/F11/grafana-hpa-api-2026-11-12.json`. The P11 E1 accepted benchmark and two-run U6 acceptance are **not measured**; see [P11 coverage](docs/kubeheal/results/p11/P11_COVERAGE.md).
- **Acceptance checkpoint, 2026-11-13:** F3 was rerun on the demo images in `staging`: scripted alert, 38-second enforce window, five restored files scanned, zero high-entropy files, and run-owned cleanup. This remains k3d-only and does not verify Falco detection. F4 test-mode HMAC smoke accepted the signed message and refused unsigned and tampered messages. F9's authenticated dashboard toggle recorded `test -> enforce -> test`; no enforcement action was generated during that interval. F10 observed live metrics and recorded a `human_patch` dry-run, then verified CPU restoration to 100m/500m; canary healing and bad-p99 rollback remain unverified. See the linked [F3](docs/kubeheal/demo-evidence/F3/README.md), [F4](docs/kubeheal/demo-evidence/F4/README.md), [F9](docs/kubeheal/demo-evidence/F9/README.md), and [F10](docs/kubeheal/demo-evidence/F10/F10_drift_walkthrough_2026-11-13.md) evidence.
- **Not fully live-verified:** F5 had no baseline candidate; F6 had no supported live request injector; F7's M2/D1/fresh-Security rollback path was not run; F8 pages/APIs responded but the full control walkthrough and screenshot were unavailable. U6's two full installs stopped at Helm repository DNS. F11's 2026-11-13 rerun had 12 first-timestamp refusals out of 72,328 checks (observed median 37.49 ms, p95 61.87 ms on that failed run); do not treat those latency values as accepted results. No Grafana screenshot was captured. P11 E1 had 12 first-timestamp refusals out of 66,819 requests and is not an accepted benchmark; P11 E2 measured one inference pod recovery at 1.25 seconds. P11 E3-E6 and V5-E1 are not measured. The end-to-end rehearsal from a fresh cluster is not complete. Details and reasons are in [the rehearsal record](docs/kubeheal/demo-evidence/REHEARSAL/rehearsal-2026-11-13.md) and [P11 coverage](docs/kubeheal/results/p11/P11_COVERAGE.md).
- The demo environment targets a local k3d cluster. Read `demo/README.md`, [the demo runbook](docs/kubeheal/DEMO_RUNBOOK.md), and `docs/kubeheal/NEXT_FOR_CODEX.md` before using it. The global source of truth is the `kubeheal-mode` ConfigMap, key `mode`; it defaults to `test`. In test mode, sensing, scoring, decisions, and ledger recording continue while remediation Kubernetes writes are blocked and recorded as "would have" actions. The Remediation Executor validates each request and is the only agent with remediation Kubernetes write permissions; it records intent before a corrective write and checks the kill switch before every write. The Security Agent separately verifies kill-switch mode before a node-local cgroup freeze. Containment runs in this order: freeze, forensic snapshot, quarantine, scale to zero, restore from the pre-T0 snapshot, entropy rescan, lift quarantine, and record the result. Freeze requests and results use HMAC-SHA256 with `CONTAIN_HMAC_KEY` from the chart-managed `kubeheal-containment-hmac` Secret, key `key`. Redis authentication uses a separate Secret, so a Redis credential alone cannot sign containment messages; an operator who can read the HMAC Secret can. The dashboard has a narrow permission to update the kill-switch ConfigMap with its admin token. A successful component or unit test does not by itself verify a full end-to-end workflow. Current findings are recorded in [PROGRESS](docs/kubeheal/PROGRESS.md).
- Training scripts are present, but no training should be inferred from their presence. Do not run training as part of setup.

## Local development

Use Python 3.11 and install the dependencies from `requirements.txt`. Some entries are pinned to an exact version (for example `torch==2.2.0`) and some are lower bounds or ranges (for example `torch-geometric>=2.5.0` and `numpy<2`), so installs are not fully reproducible. Then run the tests:

```powershell
$env:PYTHONPATH='.'
.venv\Scripts\python.exe -m pytest tests/ -q
```

Model servers require compatible checkpoint files and their preprocessing sidecars. They fail closed when required checkpoints are missing or incompatible, except when `ALLOW_RANDOM_WEIGHTS=true` is set explicitly (see `services/ckpt.py`): the server then serves random weights and its `/health` response reports `random_weights=true`. Check each server's `/health` response before relying on scores. Random weights are for development and unit tests only and are not suitable for operation.

## Kubernetes demo

The demo scripts and k3d configuration are under `demo/`. Read `demo/README.md` and `docs/kubeheal/NEXT_FOR_CODEX.md` before using them. The global kill switch defaults to `test`, which permits sensing, scoring, decisions, and audit recording but prevents Kubernetes remediation writes.

## Training and promotion gates (not approved: do not run without the owner's approval)

Training is not approved for this project. Do not run any command in this section unless the owner has explicitly asked for it. Training is slow and GPU-bound, and real ransomware traces need a live Falco cluster; the security generator synthesises samples for offline training. The health model trains on the real drift CSV in the repository (`models/health_model/dit-merged-complete.csv`). The commands are listed for reference only.

```bash
# 0. (Windows GPU) install CUDA torch first:
#    pip install torch==2.2.0 --index-url https://download.pytorch.org/whl/cu121
#    pip install torch-geometric torch-scatter torch-sparse -f https://data.pyg.org/whl/torch-2.2.0+cu121.html

# 1. Health Model, real data
PYTHONPATH=. python -u models/train_health_model.py \
    --epochs 30 --batch-size 16 --patience 6

# 2. Security training data (synthetic)
PYTHONPATH=. python models/generate_security_training_data.py \
    --output data/security_training.jsonl

# 3. Security Model
PYTHONPATH=. python -u models/train_security_model.py \
    --data data/security_training.jsonl --epochs 25 --batch-size 32 --patience 5

# 4. DCM, staged, AFTER 1 and 3 (freezes both base models)
PYTHONPATH=. python -u models/train_dcm.py --epochs 25 --batch-size 32

# 5. (optional) recalibrate conformal intervals on a held-out set
PYTHONPATH=. python models/calibrate_conformal.py --coverage 0.90

# 6. check the promotion gates
PYTHONPATH=. python models/validate_all_models.py

# 7. export for serving
PYTHONPATH=. python models/export_security_model.py --quantize fp16
PYTHONPATH=. python models/export_dcm.py --quantize fp16
PYTHONPATH=. python models/export_health_model.py

# 8. (optional) push to the MinIO model registry
PYTHONPATH=. python models/upload_to_registry.py --version v4.0.0
```

Outputs land in `models/<model>/checkpoints/` as `best_*.pt`, `*_conformal.json` and `*_report.json`, and the servers load the checkpoints on startup.

Promotion gates are defined in `models/validate_all_models.py`: an F1 gate for the Health and Security models, an AUROC gate for the DCM, and an advisory (non-blocking) latency check. The thresholds are in that script; this README does not restate them. Missing checkpoints are reported as SKIP, not as failures, so a SKIP is not evidence that a model passed.

## Documentation

- [Architecture](docs/kubeheal/ARCHITECTURE.md) describes the implemented flow and labels planned pieces.
- [Specification status](docs/kubeheal/SPEC_VS_CODE.md) maps the project specification IDs to code and evidence.
- [Implementation progress](docs/kubeheal/PROGRESS.md) records checked work, observed results, and deferred items.
- [Project specification](docs/kubeheal/PROJECT_SPEC.md) is the target design, not a claim that every item is implemented.
- [Architecture flow walkthrough](docs/architecture-flow.md) is a layer-by-layer description; the diagram is rendered in [architecture-flow.png](docs/architecture-flow.png).

![architecture flow](docs/architecture-flow.png)

To re-render the diagram from `docs/architecture-flow.mmd`:

```bash
npx -y @mermaid-js/mermaid-cli -i docs/architecture-flow.mmd -o docs/architecture-flow.png -s 2 -b transparent
```

## License

RVCE · Unisys UIP · Confidential
