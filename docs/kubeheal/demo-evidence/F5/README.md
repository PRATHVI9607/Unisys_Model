# F5 scripted live baseline promotion

Run on `k3d-kubeheal` on 2026-11-13, run ID `2a87df128d8848ceb2f800351f6a3620`.

`scripted_baseline_run.py` created two PVC-free, run-owned Deployments, changed their `F5_SCRIPTED_CONFIG` value
from `before` to `after`, and passed a clearly marked scripted benign/certain assessment to the deployed
Health Agent baseline module. The score was not produced by the model and this run does not verify model quality
or the Health Agent's live assessment path.

- Dev auto-promotion returned `promoted`; the new golden baseline pointed to the `baseline_promoted` ledger key.
- Prod stored a pending dashboard candidate. The run read it back as pending, then the dashboard approval endpoint
  promoted it in the bounded enforce window and returned `applied: true` with its ledger key.
- The independent dead-man logged start and end. The run restored global mode to `test`, and read it back.
- Both PVC-free scratch Deployments remain in their namespaces for review. They have no `kubeheal.io/watch=true`
  label and do not use PVCs.

Captured output: [F5_scripted_run_2026-11-13.txt](F5_scripted_run_2026-11-13.txt) and
[deadman_2a87df128d8848ceb2f800351f6a3620.txt](deadman_2a87df128d8848ceb2f800351f6a3620.txt).
