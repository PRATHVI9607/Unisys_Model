# KubeHeal demo guide

## Current status

This file describes the planned demo order and the behavior to look for. The demo setup and driver
scripts are not present yet, so the end-to-end demo is not runnable from this checkout. The cluster
has not been used for this guide. P10-U1 and the cluster acceptance tasks remain with the cluster
owner.

The victim application is in [`victim-app/`](victim-app/). It exports
`http_requests_total` and `http_request_duration_seconds`; local exporter tests pass. The app has
not been built into an image or scraped by Prometheus on k3d. P10-V2 must verify the Health Agent
queries against the running app.

## Planned run order

Once P10-U1 and P10-U4 provide the scripts, run these from the repository root in PowerShell:

1. `.\demo\k3d\up.ps1` creates the demo environment, installs its dependencies, and deploys KubeHeal.
2. `.\demo\scripts\demo.ps1` runs the numbered incident scenarios and prints their observations.
3. Review the dashboard, component logs, Prometheus, and the incident ledger for the outcomes listed below.
4. Use `.\demo\k3d\down.ps1` only when the demo environment is no longer needed.

These paths describe the planned interface. The scripts do not exist yet. Do not try to run these
commands until P10-U1 and P10-U4 are complete and the cluster owner has verified the environment.

## Expected behavior

- **Startup:** the demo reports the active kill-switch mode and the health of its components. Fresh
  installs default to `test` mode.
- **Drift in test mode:** the pipeline detects and scores the changed workload, makes a decision,
  and records a dry run. The ledger and Executor output should say that the patch would have happened;
  no Kubernetes write should occur.
- **Drift in enforce mode:** after an administrator enables `enforce`, the Executor applies the
  canary patch, watches the configured latency and CPU-throttling windows, and records whether it
  kept or rolled back the change. The configured window values are chosen defaults, not measured
  profiles.
- **Ransomware replay:** if live Falco is unavailable, the demo should say it is using recorded
  events. Containment should label only the affected pod and apply a NetworkPolicy that selects
  quarantined pods. Snapshot and restore behavior must be shown only after the cluster owner has
  verified the CSI snapshot setup. The P6 changes are merged into `work`; restore has not been run end to end on a cluster.
- **Human approval:** a HUMAN decision should appear as pending in the dashboard. An authorized
  approval or rejection should be reflected in the Executor stream and ledger.
- **Fail-closed check:** when a required model response is unavailable the expected result is a HUMAN
  escalation, not automatic remediation. The P6 policy and Fusion changes that implement this are merged
  into `work` and covered by unit tests; the scenario has not been run on a cluster, so do not present it
  as demonstrated end to end.

The actual console text, action sequence, and dashboard views must be confirmed by running the
finished scripts. This guide does not claim those end-to-end observations have happened.

## What to explain

KubeHeal follows Sense, Score, Decide, Act, and Record. The Health Agent supplies configuration
drift and a Prometheus window; the Security Agent supplies syscall and write-entropy evidence;
Fusion combines the assessments and applies the policy; the Executor is the only component that
performs Kubernetes writes; the ledger records decisions and action steps. The kill switch makes
`test` a dry run and `enforce` the write-enabled mode.

## Limitations to state

Drift pipeline complete; inputs now match training preprocessing; live Health Model scores are not yet validated on real cluster windows. Retraining on live cluster data (P12-H) is a future step, not approved yet. Drift detection currently relies mainly on the configuration diff; metric-based evidence is limited in the current checkpoint and is addressed by P12-H.

- The full setup and demo scripts are not implemented or tested yet.
- The victim-app image and Prometheus scrape have not been verified on a cluster. No result is recorded for the 15 Health Agent queries; P10-V2 owns that work.
- k3d VolumeSnapshot support needs the CSI hostpath driver, external snapshotter, and the expected `csi-hostpath-snapclass` class. Until the cluster owner verifies those pieces, do not claim snapshot restore works end to end.
- P6 is merged into `work` (merge commit 391b8ac). The Security Agent publishes the attack onset `t0_ms` (commit 3690c9f) from the Falco event time, and Fusion requests a restore only when `t0_ms` is known and otherwise escalates to a human. This is covered by unit tests only; automatic restore has not been demonstrated on a cluster, and an event whose Falco time is unknown carries no `t0_ms`, so it never restores automatically.
- A replayed Falco trace demonstrates the event pipeline, not live Falco operation on this Windows Docker Desktop setup.
- Health Model live scores, detection quality, latency, RPO, RTO, and resource usage have not been measured for this demo. Do not quote unrun metrics.
