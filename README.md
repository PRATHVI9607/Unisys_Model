# KubeHeal

KubeHeal is an experimental Kubernetes control plane for detecting configuration drift and suspicious container activity. Its pipeline is Sense, Score, Decide, Act, and Record. The implementation is under active development; this repository does not establish production readiness.

## Current status

- Health Agent watches labeled Deployments, compares their specs with a first-seen Redis baseline, and requests Prometheus metric windows before scoring drift.
- Security Agent consumes Falco events and samples process write activity and entropy. Falco replay is available for controlled tests; fixtures are hand-written examples, not captured attacks.
- Health Model, Security Model, DCM, Fusion Agent, Executor, dashboard, Redis streams, and an object-lock-compatible ledger have implementations and tests. See [SPEC_VS_CODE](docs/kubeheal/SPEC_VS_CODE.md) for item-level status and evidence.
- The Health Model checkpoint was trained on the repository's existing dataset. Its live scores have not been validated on real cluster metric windows. Drift detection currently relies mainly on the Kubernetes spec diff; metric evidence in the checkpoint is limited. P12-H retraining and recalibration on live windows has not been approved or run.
- The demo environment targets a local k3d cluster. A successful component or unit test does not by itself verify the full end-to-end workflow on a cluster. Current observed demo findings are recorded in [PROGRESS](docs/kubeheal/PROGRESS.md).
- Training scripts are present, but no training should be inferred from their presence. Do not run training as part of setup.

## Local development

Use Python 3.11 and install the pinned dependencies from `requirements.txt`. Then run the tests:

```powershell
$env:PYTHONPATH='.'
.venv\Scripts\python.exe -m pytest tests/ -q
```

Model servers require compatible checkpoint files and their preprocessing sidecars. They fail closed when required checkpoints are missing or incompatible; see each server's `/health` response before relying on scores. Do not assume random weights are suitable for operation.

## Kubernetes demo

The demo scripts and k3d configuration are under `demo/`. Read `demo/README.md` and `docs/kubeheal/NEXT_FOR_CODEX.md` before using them. The global kill switch defaults to `test`, which permits sensing, scoring, decisions, and audit recording but prevents Kubernetes remediation writes.

## Documentation

- [Architecture](docs/kubeheal/ARCHITECTURE.md) describes the implemented flow and labels planned pieces.
- [Specification status](docs/kubeheal/SPEC_VS_CODE.md) maps the project specification IDs to code and evidence.
- [Implementation progress](docs/kubeheal/PROGRESS.md) records checked work, observed results, and deferred items.
- [Project specification](docs/kubeheal/PROJECT_SPEC.md) is the target design, not a claim that every item is implemented.
