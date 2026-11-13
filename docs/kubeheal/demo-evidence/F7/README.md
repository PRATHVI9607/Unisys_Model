# F7 scripted Fusion policy evidence

Run on `k3d-kubeheal` on 2026-11-13. Inputs are labelled scripted in the runner and use the retained PVC-free
F5 dev Deployment as the run-owned target. Global mode stayed `test` throughout.

- M2: a model-shaped scripted Health event with prediction set `{degraded, benign}` reached `human_pending`.
- D1: the shipped posture policy emitted `policy:cpu_cut_10x` for 500m to 50m and
  `policy:memory_cut_10x` for 320Mi to 32Mi, including both inclusive edges.
- Q1: a scripted Health rule event paired with an unscored Security event reached `human_pending` because there
  was no fresh Security Model response. Replaying the rule with a fresh, explicitly scripted, model-scored
  Security response queued a rule-path `AUTO_PATCH` request with `dry_run: true`.
- No Kubernetes write was made by the policy run. The three run-owned human approvals were rejected through the
  dashboard; the ledger and stream history remain.

The Security response in this run was scripted and does not verify live Security Model scoring. Captured results:
[F7_scripted_run_2026-11-13.txt](F7_scripted_run_2026-11-13.txt) and
[F7_approval_resolution_2026-11-13.txt](F7_approval_resolution_2026-11-13.txt).
