# KubeHeal next agent file (tool-neutral)

First resume point for any agent (Claude Code, Codex, a local model). Read, in this order: `AGENTS.md`,
`.ai/handoff.md` (short state), this file, the last sections of `docs/kubeheal/PROGRESS.md` (checklist, the section
"Claude session 2026-11-12" and the V5 lines), and section 11 of `docs/kubeheal/V5_INTEGRATION_PLAN.md` (every owner
decision, final). The filename is historical.

## State at the 2026-11-12 handoff (Claude Code)

Nothing is pushed. Never push, never set `ALLOW_PUSH`. `PROJECT_SPEC.md` is changed only with the owner.
Owner stop points: model training (P12 is NOT approved), `PROJECT_SPEC.md`, deleting user data, an irreversible decision.

- `work` (worktree `../Unisys_Model-wt-metric-query`) and `demo` (main checkout `C:/My_projects_1/cLOUD/Unisys_Model`) are in
  sync apart from demo-only files. Run `git log -1` in each for the tips. Last suites (Windows, Python 3.11.9, helm on PATH):
  work 2024 passed, 8 skipped, 1 deselected (`tests/test_rbac_k3d.py`; it passes against the cluster when run alone);
  demo about 5 more (demo-only files). Run the FULL suite including `tests/test_killswitch.py`: only `test_rbac_k3d.py`
  needs the cluster, and a blanket deselect of `test_killswitch.py` hid two stale tests for a day.
- Merged since Codex paused: V5-S2, D4 review fixes, chart cleanup, namespace tier map (`demo` to dev), V5-S1 (Falco rules),
  V5-D6 and D9 (Executor validation, candidate fields), V5-D5 (baseline promotion), V5-S5 (Executor freeze request,
  Security Agent freeze consumer, DaemonSet wiring, thaw script), V5-I3 (dashboard), image fix V5-IMG1, chart pieces CH1 to CH3.
- OPEN BRANCHES (committed, worktrees kept, NOT merged, NOT independently reviewed: the reviewer was stopped by the handoff):
  - `wave/V5-S5c` (`../Unisys_Model-wt-V5-S5c`, tip `6501c17`): fixes the Security Agent freeze for a private cgroup
    namespace (see "Facts from the cluster" below) and the pod to pid mapping in `proc_scanner.py`; 144 containment tests.
    Safety-critical (a host write): get an independent review (attack list: freezing the wrong cgroup, pid recycling,
    uuid strictness, symlinks, self pod, `parse_cgroup_line` mapping node processes to pods), then merge.
  - `wave/V5-CH4` (`../Unisys_Model-wt-V5-CH4`, tip `fb74a0a`): `POD_UID` and `POD_NAME` from the downward API on the
    Security Agent DaemonSet (chart and plain manifest). Needed by V5-S5c (without POD_UID every freeze is refused).
    Merge it together with V5-S5c.
- Cluster `k3d-kubeheal` (only this context, never `hybrid-demo`): `kubeheal-mode` is `test` (verified at the handoff).
  Helm release `kubeheal` is revision 6, `deployed`, with the LightGBM inference service, the new agents and the new RBAC.
  Images in use: executor `b20261112081307`; health-agent, security-agent, fusion-agent, dashboard and inference-server
  `b20261112075817` (built from `demo` before V5-S5c and CH4). The three neural model servers and the DCM are no longer
  deployed (`modelServers.legacy.enabled=false`).

## Facts from the cluster (2026-11-12, this machine, read-only checks unless stated)

- Inference service (called from the Health Agent pod): `/healthz` 200 `{"status":"ok"}`; `/readyz` 200
  `{"ready":true,"models":{"health":"health-5.0.0-a374e498","security":"security-5.0.0-c6fa12d8"}}`. The API-server proxy
  gives 502 because the NetworkPolicy only admits the agents and Prometheus: query it from an agent pod.
- Revision 5 of the upgrade failed because the Executor image lacked `kubeheal/` and `pydantic` (found only by the
  install); fixed in V5-IMG1; `tests/test_dockerfile_imports.py` now scans all five agent images. Revision 6 deployed.
- The Health Agent assesses through the inference service (log: `label=critical risk=0.51 set=[]` for the stale
  `prod/victim-app` baseline, whose image differs); an empty set is "not certain", so Fusion decides `observe` (no action,
  as rule M2 requires). `prod/victim-app` is a drift against an old golden baseline (its image tag changed on 2026-11-11).
- The Security Agent logged `containment consumer started on kubeheal.contain.req:<node>` and `KILL SWITCH mode None -> test`.
  Falco is not installed (`FALCO_MODE` resolves to `off`).
- cgroup layout seen from inside the Security Agent pod (cgroup v2, cgroupfs driver): its own `/proc/self/cgroup` is `0::/`
  (a private cgroup namespace); other pods show `0::/../../pod<uid>/<container>` (Guaranteed) and
  `0::/../../../burstable/pod<uid>/<container>`; node processes `0::/../../../../init` and `.../k3s`. `/host/cgroup` (the
  new read-write hostPath mount) shows the node root with a `kubepods` directory, `cgroup.freeze` mode 0644, write access
  true. The merged freeze code needs a `kubepods` path component and refuses `..`, so it refuses every freeze here (fails
  safe, never freezes): V5-S5c fixes it. The actual `cgroup.freeze` write has NOT been exercised on this cluster.

## Safety rules (unchanged, apply to every task)

Never push; no destructive git (`reset --hard`, `clean`, forced checkout, `branch -D`); no model training; no invented
numbers (write "not measured"; a number in a doc must come from a run you did, with date and machine); no em dashes in docs;
Python 3.11 only (no same-quote nesting in f-strings); no Kubernetes write outside `agents/executor/`
(`tests/test_no_writes_outside_executor.py`), and every write through `actions._write` and the kill-switch gate; ledger entry
BEFORE any corrective action; `decision_policy.py` stays pure and fails closed; every `kubectl` and `helm` command with
`--context k3d-kubeheal` / `--kube-context k3d-kubeheal`; `kubeheal-mode` stays `test` except during a scripted demo or
acceptance step, and is restored to `test` right after; core fixes go to `work` first and then to `demo`; never end with
uncommitted changes; update `.ai/handoff.md` and `PROGRESS.md` after every merge. Process per task: worktree
`../Unisys_Model-wt-<id>` on `wave/<id>`, small commits, full suite, independent review for reserved files (Executor,
Security Agent write paths, RBAC, `decision_policy.py`), `git merge --no-ff` into `work`, full suite, merge `work` into
`demo`, full suite, update the checklist. `git worktree remove` on Windows can fail with "Permission denied" while a shell
sits in the directory: `git worktree prune` and remove the empty folder.

## Verify commands

```powershell
cd C:\My_projects_1\cLOUD\Unisys_Model-wt-metric-query        # the work worktree
$env:Path += ";$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe\windows-amd64"
$env:PYTHONPATH='.'
C:\My_projects_1\cLOUD\Unisys_Model\.venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=$env:TEMP\kubeheal-t --deselect tests/test_rbac_k3d.py
C:\My_projects_1\cLOUD\Unisys_Model\.venv\Scripts\python.exe -m pytest tests/test_rbac_k3d.py -q -p no:warnings    # live, read-only
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
helm --kube-context k3d-kubeheal list -n kubeheal
git status; git worktree list; git log --oneline -8
```

Images: `.\demo\k3d\images.ps1 -Only <names>` from the `demo` checkout (it builds from the working tree there, tags
`b<timestamp>` in `demo/k3d/.image-tags.json`, writes `demo/k3d/.generated-values.yaml`). Install or upgrade:
`helm --kube-context k3d-kubeheal upgrade kubeheal deploy/helm/kubeheal -n kubeheal -f deploy/helm/kubeheal/values-k3d-demo.yaml -f demo/k3d/.generated-values.yaml --force-conflicts --wait --timeout 10m`
(`--force-conflicts` is needed after a `kubectl set image` on an object Helm owns).

## Pitfalls

- A shell heredoc with long Python and many quotes was rejected by the tool several times: write the script to a file with
  the Write tool and run it. Python on Windows cannot read `/c/...` paths from Git Bash: use `cygpath -w`.
- LightGBM refuses `model.txt` with CRLF (`models/bundles/** -text` in `.gitattributes`); read v5 files with
  `git show origin/main:<path>`; always pass features through `ModelBundle.restrict()`. The shipped security bundle's
  conformal and accuracy figures are not evidence (synthetic classes).
- Images are the only place missing packages show up (see V5-IMG1): after a change that adds an import, run
  `tests/test_dockerfile_imports.py` and, for a reserved image, a real build.
- Do not `git stash` (shared stack). The demo checkout holds demo-only files; merge `work` into it, never the reverse.
- `tests/test_cgroup_writes_static.py` fails if any file other than `agents/security_agent/containment.py` writes or builds
  a cgroup control file name (docs, tests and docstrings are exempt).

## Remaining tasks, in order

1. Review and merge `wave/V5-S5c` and `wave/V5-CH4` (above). Then rebuild the Security Agent image
   (`images.ps1 -Only security-agent`), `helm upgrade`, and check inside a Security Agent pod that a freeze request for a
   victim pod resolves its cgroup directory (use mode `test` first: the answer must be `dry_run` and nothing is written).
   A real freeze needs mode `enforce`: do it only as a scripted step on the `dev` victim (`demo/k3d` victim), thaw it with
   `scripts/thaw_pod.py`, restore the mode to `test`, and record the real outcome (frozen read back from `cgroup.events`,
   or the reason). Check whether Docker Desktop allows the write, whether a Redis password holder can forge a result
   (recommended hardening: an HMAC over the result, with V5-P3), and whether the hostPath can be narrowed to `kubepods`.
2. D-5 replay on the cluster (P10-D5 and P10-U2): mount the new hand-written trace
   `tests/fixtures/falco/ransomware_pv_encrypt_new_rules.jsonl`, adapted to the live `prod` victim pod identity, with
   `FALCO_MODE=replay` on the Security Agent, in mode `test`; record whether a `kubeheal.security.events` record is
   published and what Fusion decides (a heuristic-only event is human-only, a model-scored `ransomware` event with a
   one-label set is the automatic case); remove the temporary mount and restore `FALCO_MODE=auto`. The trace is hand-written
   and proves only that the pipeline scores events of this shape; live Falco is still unverified.
3. P10-U6: two complete `up.ps1` plus scenario plus reset runs on this machine; record the real output in
   `docs/kubeheal/results/`. The prod victim baseline is stale (see Facts): decide, with `scripts/baseline_tool.py` or a
   promotion in dev, how the demo gets a clean baseline; do not fake it.
4. P7-RR-11 (re-baseline after a restore), P7-RR-12 (resume of a partial restore), P7-RR-7 (RPO and RTO measurements),
   the ransomware restore path still scales to zero itself (design decision on the V5-S5 line of PROGRESS).
5. P11 runs (`eval/p11_harness.py`; every run in mode `test` unless a task says otherwise; results only from recorded runs):
   E1 to E7 and V5-E1 scripted lab scenarios. No training.
6. V5-DOC and P13: update `README.md`, `AGENTS.md` (the model sections still describe the neural models and the DCM),
   `docs/kubeheal/ARCHITECTURE.md`, `SPEC_VS_CODE.md`, `docs/architecture-flow.md`, `demo/README.md` to the LightGBM design
   with split-conformal prediction sets and TreeSHAP factors, the one-label gate (M2), the deterministic correlation, the
   rule rollback with the fresh Security response (Q1), baseline promotion (D3), the containment order and labels (D5, Q2),
   the kill-switch gates. Describe only what is merged and verified; mark the rest planned. Propose `PROJECT_SPEC.md`
   amendments to the owner instead of editing it.
7. V5-F1 (quarantine ownerReference and UID preconditions), V5-P1 (CI workflow), V5-P3 (Redis per-component ACL users,
   dashboard and Health Agent key access listed on the V5-D5 and V5-I3 lines), V5-M3 (needs the owner), V5-S4 (eBPF sensor,
   optional, last). Open owner items: M3 raw `collected/*.jsonl` from the teammate; the tag `demo-2026-11-11` after the demo.
8. When everything is merged: final suite on `work` and `demo`, `git status` clean, `.ai/handoff.md` current, stop. The owner pushes.
