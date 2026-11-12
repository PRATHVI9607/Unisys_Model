# KubeHeal k3d demo

The target cluster is `k3d-kubeheal`. Do not use `hybrid-demo`. The kill switch must be `test` outside a bounded scripted scenario. Read the [demo runbook](../docs/kubeheal/DEMO_RUNBOOK.md) and the current [handoff](../docs/kubeheal/NEXT_FOR_CODEX.md) before rehearsal.

## Verified state

On 2026-11-12, Helm revision 8 was deployed and the global mode was `test`. The Security Agent's cgroup freeze and the operator thaw were exercised on a scratch pod and read back on the k3d node. This check called the freeze helper directly. It did not exercise stream intake, Executor request parsing, or the complete containment order. It demonstrates k3d behavior only, not behavior on a real Linux node. See [the dated result](../docs/kubeheal/results/live_freeze_check_2026-11-12.md).

Earlier checks on 2026-11-11 observed all 15 Health Agent Prometheus queries with generated victim traffic and restored a CSI snapshot to a temporary PVC, reading the seeded records. These do not establish drift remediation or full ransomware recovery. Details and exact limits are recorded in [PROGRESS](../docs/kubeheal/PROGRESS.md).

On 2026-11-12, one queue-depth HPA scoring-load run passed on `k3d-kubeheal` in mode `test`: 32 VUs for 90 seconds, 121,088/121,088 HTTP checks passed, median 22.86 ms, p95 38.45 ms, and HPA replicas went 2 -> 7 -> 2. This single synthetic run is not a performance guarantee and does not measure the full incident pipeline. The raw summary and selected HPA samples are in [the F11 result](../docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md); full transcript/screenshots remain for the final rehearsal.

## Not yet verified end to end

- D-5 replay from the cluster to Fusion incident decision.
- Full alert-driven containment, restore, entropy rescan, and quarantine release.
- HMAC rejection for unsigned or modified containment messages.
- Baseline promotion and prod dashboard approval on the live cluster.
- Drift canary and bad-p99 rollback on the live cluster.
- Full Grafana screenshots and runbook rehearsal for F11; one successful synthetic load run is recorded, but no performance guarantee is claimed.
- Two complete clean-baseline acceptance runs.
- P11 baseline and scenario measurements.

Do not describe any of these as live-verified until the dated transcripts and screenshots are saved under [demo evidence](../docs/kubeheal/demo-evidence/).
