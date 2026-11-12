# KubeHeal next agent handoff (one long autonomous Codex run that finishes the project)

This file is tool-neutral. It is the first resume point for Codex, Claude Code, or another repository agent.
Read `AGENTS.md`, `docs/kubeheal/PROGRESS.md` (checklist, section "V5 integration", and the execution records at its end),
`docs/kubeheal/V5_INTEGRATION_PLAN.md` (section 11 holds every owner decision) and `.ai/handoff.md` before changing files or using the cluster.

Codex may do EVERY task in this file, including `agents/fusion_agent/decision_policy.py`, the Executor write paths, RBAC (`k8s/rbac/`, the chart RBAC template),
chart changes and merges, provided it runs the full suite after each merge and keeps the safety rules below. Claude Code is unavailable; Codex will perform and record a self-review for each merge. A Claude review is not a prerequisite.

## Handoff state (2026-11-12, Codex)

Codex paused for handoff. No push is permitted. Get current `work` and `demo` tips with `git log -1` in each worktree. Active task is V5-S2, committed WIP, unreviewed and unmerged. Owner stop points are credentials/passwords, model training, deleting user data, or changing `PROJECT_SPEC.md`.

Owner decisions (all in `V5_INTEGRATION_PLAN.md` section 11): M1 option (b), M2, M3, D1, D2, D3, D5, D6, D7, plus the two latest answers Q1 and Q2.
In short: LightGBM health and security bundles (split-conformal sets, TreeSHAP) run inside OUR architecture; an automatic action needs a prediction set of exactly one label (M2);
correlation is the deterministic `compound_score` (no DCM); field attribution comes from the spec diff against the baseline; the 10x cut rule is inclusive (D1);
the rule-based rollback (failure reasons or posture violations) skips only the set gate and burn-in and the Health Model response, and needs a FRESH Security Model response (Q1: missing or late means escalate to HUMAN);
baseline promotion is automatic in dev and staging and needs dashboard approval in prod, every promotion is a ledger entry (D3);
containment (D5, Q2): automatic for `ransomware` and `exfiltration` (certain, adjusted risk at or above 0.85): freeze, forensic snapshot, quarantine, scale to 0; the restore step runs only for `ransomware`, after `exfiltration` a human follows up; `suspicious` is never automatic; the Executor requests the freeze, the node-local Security Agent does it;
the eBPF sensor is optional and last (D6).

### Branches and worktrees (nothing is pushed; never push)

| Branch | Worktree | Tip | State | What it needs |
|---|---|---|---|---|
| `work` | `../Unisys_Model-wt-metric-query` | `git log -1` | D4 merged; last suite 1363 passed, 3 skipped, 34 deselected. | Continue with S2 only after its full suite and review. |
| `demo` | main checkout `C:/My_projects_1/cLOUD/Unisys_Model` | `git log -1` | D4 merged; last demo suite 1368 passed, 2 skipped, 34 deselected. Includes demo-only I2 scripts. | Sync reviewed work changes after each task. |
| `wave/V5-D4` | `../Unisys_Model-wt-V5-D4` | `ad464f3` | Reviewed and merged into `work`; branch suite 1363 passed, 3 skipped, 34 deselected. Worktree clean. | Complete; keep branch. |
| `wave/V5-S2` | `../Unisys_Model-wt-V5-S2` | `c221832` | Codex WIP commit. Focused review-fix tests 49 passed; full suite not completed after fixes. Not reviewed or merged. | Rerun full suite, review all changes, resolve findings, then merge only if green. |
| `wave/P11` | none | `2240ec6` | Ancestor of work; P11 harness implementation merged and reviewed. | Run remaining P11 tasks below. |
| `wave/P5` | none | `8f1d8b6` | Ancestor of work; phase changes merged. | No branch action; follow open checklist items. |
| `wave/P6` | none | `7f95f6c` | Ancestor of work; phase changes merged. | No branch action; follow open checklist items. |
| `wave/P7` | none | `a294eb9` | Ancestor of work; phase changes merged. | Finish RR-7, RR-11 and RR-12 below. |
| `wave/P8` | none | `246b973` | Ancestor of work; phase changes merged. | No branch action; follow open checklist items. |
| `wave/P9` | none | `0451237` | Ancestor of work; phase changes merged. | No branch action; chart tasks below. |
| `wave/V5-M1` | none | `012f7ec` | Ancestor of work; reviewed and merged. | No action. |
| `wave/V5-D1` | none | `0d20936` | Ancestor of work; reviewed and merged. | No action. |
| `wave/V5-D2` | none | `0db2343` | Ancestor of work; reviewed and merged. | No action. |
| `wave/V5-D3` | none | `799028c` | Ancestor of work; reviewed and merged. | Executor field contract remains Task 7. |
| `wave/V5-D4a` | none | `8d307b2` | Ancestor of work; reviewed and merged. | No action. |
| `wave/V5-I2` | none | `0af66f1` | Ancestor of work; reviewed and merged. | Cluster deployment remains Task 4. |
| `wave/V5-I2-demo` | none | `982949e` | Ancestor of demo; demo-only scripts are in demo. | No action. |
| `wave/docs-p6d2` | none | `e611844` | Ancestor of work; merged. | No action. |
| `wip/docs-p6d2` | none | `b229491` | Ancestor of work; P6-D2 merged. | No action; cluster verification remains open in PROGRESS. |

Only four worktrees exist (listed above). All are clean at this handoff. Keep S2 and D4 worktrees for now; branches are retained.

The D4 worktree and S2 worktree are clean; S2 is WIP. Branches D4/S2 were cut from `work` at `96b1d08`; expect checklist/handoff conflicts and preserve current status when merging.

### Cluster and Helm state (k3d-kubeheal, checked by Claude on 2026-11-11, read-only)

**Handoff update 2026-11-12:** `kubectl --context k3d-kubeheal` and `helm --kube-context k3d-kubeheal` could not reach the recorded API endpoint `https://127.0.0.1:32201` (connection refused). The last known mode remains `test`, last known Helm release was revision 4 `deployed`; current mode, release revision/status and pod states are unknown. No upgrade, injection, or manifest application was run during this handoff. Once the cluster is reachable, first verify/set `kubeheal-mode=test`, then inspect release, pods and in-progress demo state before any changes.

- Context `k3d-kubeheal` only. Never `hybrid-demo`. `kubeheal-mode` ConfigMap value: `test`. Keep it `test` unless a step says otherwise.
- Helm release `kubeheal` in namespace `kubeheal`: revision 4, status `deployed`, chart `kubeheal-0.1.0`. History: rev 2 superseded, rev 3 FAILED (server-side-apply conflict with the field manager `kubectl-set` on the `health-agent` image because the live image had been changed with `kubectl set image`), rev 4 deployed.
- Values in use for rev 4: `deploy/helm/kubeheal/values-k3d-demo.yaml` plus the values returned by `helm get values kubeheal -n kubeheal -o yaml` (image repositories and tags, executor env, ingress `traefik`, `killSwitch.mode: test`), plus `--set healthAgent.image.tag=b20261111113631`. That last override pins the Health Agent to the LIVE tag, because the Helm values said `b20261111085903`. Any later `helm upgrade` must keep passing the live Health Agent tag (or must re-record it in the generated values) or the same conflict returns.
- Live images: executor `...:b20261111092120`, fusion-agent `...:b20261111092120`, health-agent `...:b20261111113631`, dashboard `...:b20261111090959`, dcm, health-model and security-model servers `...:b20261111085903`, MinIO `docker.io/pgsty/silo:RELEASE.2026-11-09T00-00-00Z`. All pods Running at the check. The rev 4 upgrade applied the new ClusterRole `kubeheal-health-agent-read` and the RoleBindings in prod, staging and dev; `tests/test_rbac_k3d.py` and `tests/test_killswitch.py` then gave 34 passed.
- The cluster does NOT yet run the LightGBM inference service: the chart on `work` renders it (`inference.enabled` default true, neural servers behind `modelServers.legacy.enabled` default false) but nothing was installed from it. Installing the current `work` chart takes the neural servers away; the agents on the cluster still call them. Install it only together with the new agent images (Tasks 1 to 3) or pass `--set modelServers.legacy.enabled=true` for a transition.
- The inference image was never built: Docker Desktop on this machine had no DNS for ghcr.io and Docker Hub during the I2 build. Check `docker pull python:3.11-slim` first; if there is no network, say so in `PROGRESS.md` and do the cluster steps later.
- Falco is not installed on the cluster (replay fallback). Prometheus (kube-prometheus-stack) and prometheus-adapter run in `monitoring`.

## Safety rules (unchanged, apply to every task)

Never push, never set `ALLOW_PUSH`, never restore the push URL, no destructive git commands (`reset --hard`, `clean`, forced checkout, branch -D), no training (`models/train_*.py`, `training/`), no invented numbers (write "not measured"; a number in a doc must come from a run you did, with date and machine), plain text without em dashes, Python 3.11 only (no same-quote nesting in f-strings), no Kubernetes write outside `agents/executor/` (`tests/test_no_writes_outside_executor.py`), every write through `actions._write` and the kill-switch gate, ledger entry BEFORE any corrective action request, global mode `test` unless a step says otherwise, every kubectl and helm command with `--context k3d-kubeheal` / `--kube-context k3d-kubeheal`, never touch `hybrid-demo`, `decision_policy.py` stays pure and fails closed, core fixes go to `work` first and then to `demo`, never end with uncommitted changes, update `.ai/handoff.md` and `PROGRESS.md` after every merge.

Process per task: worktree `../Unisys_Model-wt-<id>` on branch `wave/<id>` (or `wip/<id>` if unfinished), small commits, full suite, `git merge --no-ff` into `work`, full suite again, merge `work` into `demo`, update the checklist. If an independent reviewer (another agent) is available, use it for reserved files; otherwise write a self-review into `PROGRESS.md` listing what you checked.

## Verify commands

```powershell
cd C:\My_projects_1\cLOUD\Unisys_Model-wt-metric-query     # the work worktree
$env:Path += ";$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe\windows-amd64"   # helm; without it 48 chart tests skip and prove nothing
$env:PYTHONPATH='.'
New-Item -ItemType Directory -Force $env:TEMP\kubeheal-t | Out-Null
C:\My_projects_1\cLOUD\Unisys_Model\.venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=$env:TEMP\kubeheal-t --deselect tests/test_rbac_k3d.py --deselect tests/test_killswitch.py
# live read-only files (need the cluster): tests/test_rbac_k3d.py tests/test_killswitch.py
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
helm --kube-context k3d-kubeheal list -n kubeheal
git status; git branch -v; git worktree list; git log --oneline -8
```

Last known results: `work` 1304 passed, 3 skipped, 34 deselected; `demo` 1309 passed, 2 skipped, 34 deselected (the demo checkout has the demo-only files). The 3 skips on `work` are the symlink and FIFO tests on Windows and the k6 body test that needs `demo/`.

## Pitfalls (learned the hard way)

- Windows venv at `C:\My_projects_1\cLOUD\Unisys_Model\.venv` (Python 3.11.9, numpy 1.26.4, pydantic 2.6.0, lightgbm 4.7.0). v5 targets Python 3.13: rewrite nested same-type quotes in f-strings.
- LightGBM refuses `model.txt` with CRLF. `.gitattributes` has `models/bundles/** -text`. Never extract bundles with `git archive` on Windows. Read v5 files with `git show origin/main:<path>` (run `git fetch origin` first; fetch works, push does not).
- Always pass feature dicts through `ModelBundle.restrict()` (the inference service does it). The shipped security bundle lists 40 features while the code emits 45; its conformal and accuracy figures are not evidence (synthetic classes, `conformal_q` about 3.87e-6, the serving floor 0.05 does the work). The health bundle's `field_attribution` of the old neural model was flat; patch fields now come from the spec diff.
- `git worktree` branches: `git worktree remove ../Unisys_Model-wt-<id>` removes only the checkout, the branch stays. Do not `git stash` (shared stack).
- Multi-line Python edits through a shell heredoc mangled backslash escapes twice. Write the script to a file with the Write tool and run it.
- Python on Windows cannot read `/c/...` paths from Git Bash: use `cygpath -w`.
- `helm upgrade` against objects touched by `kubectl set image` fails with a field-manager conflict (see Cluster state). Pass the live image tags, or `--force-conflicts`, knowingly.
- `deploy/helm/kubeheal/templates/agents.yaml` still sets `HEALTH_MODEL_URL`, `SECURITY_MODEL_URL` and `DCM_URL` (on the Fusion Agent too). The agents no longer read the first two, and a set `DCM_URL` switches the Fusion Agent onto the legacy DCM path, which needs embeddings the LightGBM events do not carry (every paired incident would go to a human). Remove all three when the agents are merged (Task 3).
- The new Health Agent defaults `WATCH_NAMESPACES` to `prod,staging,dev` (a cluster-wide HPA list is a 403 under our RBAC). The demo workload (`demo/victim-app.yaml`) runs in namespace `demo`; the chart sets no `WATCH_NAMESPACES`. Decide and set it (and the RBAC RoleBindings for any extra namespace) before the demo.
- Fusion treats a security `model_scored` of false or a missing prediction set as "not certain": until the Health Agent (D4) and Security Agent (S2) are merged and deployed, NO automatic action can happen (fail closed). That is expected, not a bug.

## Remaining tasks, in order

**Resume order:** (1) finish/review `wave/V5-S2`; (2) chart/agent contract cleanup; (3) cluster install and readiness if registry/network is available; (4) V5-S1 Falco rules and D-5 replay; (5) V5-D5 baseline promotion; (6) V5-D6/D9 Executor validation; (7) V5-S5 containment; (8) V5-I3 dashboard; (9) P10 acceptance and remaining P7/P11 measurements; (10) P13 and V5-DOC; (11) Later tasks V5-F1, V5-P1, V5-P3, V5-E1, V5-S4, V5-M3. Keep phase tasks in PROGRESS order and run the full non-cluster suite after each task/merge. No cluster task may start until its state is reachable and mode is verified.

For each task use its listed implementation/tests and full-suite command. Files not listed for that task are out of scope; never touch `PROJECT_SPEC.md` without the owner, never train, and keep `decision_policy.py`, Executor write paths and RBAC within the explicitly assigned D3/D6/S5 tasks. For k3d verification use only the context-qualified commands below. Use `helm lint` and `helm template` for chart changes; use `PYTHONPATH=. .venv\Scripts\python.exe -m pytest tests/ -q` (with Helm on PATH and live cluster tests deselected for local suites).

### Task 0. Orient

`git status`, `git branch -v`, `git worktree list`, `git log --oneline -8` on `work` and `demo`. Run the full suite on `work` (command above); expect all green. Mark the first task you start `[~] Codex` in `PROGRESS.md`.

### Task 1. Review fixes and merge of `wave/V5-D4` (Health Agent, `agents/health_agent/agent.py`, `inference_client.py`)

Independent review verdict was merge after the demo-namespace item. The findings below were fixed on `wave/V5-D4`, reviewed by Codex, and the branch was merged into `work` as `501dea6`, then into `demo` as `e377d6a`. Branch and work suites each passed (1363 passed, 3 skipped, 34 deselected); demo suite passed (1368 passed, 2 skipped, 34 deselected). Helm was on PATH. No Kubernetes write was used. The eleven findings and their fixes are recorded on the V5-D4 line in `PROGRESS.md`.

1. Demo namespace: set `WATCH_NAMESPACES` in the chart/demo values (include `demo` if the demo workload stays there) and add the matching RoleBindings for `kubeheal-health-agent-read` in that namespace (RBAC test parity in `tests/test_rbac_*` and `k8s/rbac/rbac.yaml`).
2. `_first_sight` (agent.py about 412): a Redis error pops `seen_hash` and nothing retries, so a quiet drifted workload is never assessed until its spec changes. Add a retry (scheduler retry set or periodic re-list).
3. When no metric exists, the agent publishes the service's prediction set verbatim with `health_uncertain=true`, but Fusion gates only on the set. Fail closed: publish an empty (or full) set when there are no metrics, or make Fusion/the policy treat `health_uncertain=true` as uncertain (decision_policy.py is yours to edit; keep it pure and add table tests).
4. `_publish_event` does `xadd` then `hset`/`expire`; a failing `hset` retries the `xadd` with a new `event_id` and opens a duplicate incident. Write the hash first or do not retry the `xadd`.
5. Rule-evidence event published with inference down is never re-scored after recovery (acceptable; write that down as intended or add a re-score).
6. `assess` does not re-check after acquiring the semaphore that `p.hash` still equals `seen_hash[key]`; drop a superseded pending assessment.
7. Missing golden key inside `_assess` (for example a Redis flush) is re-created from the current drifted spec: treat as a failed assessment and tell a human instead.
8. Module docstring says a `PostureError` "publishes nothing"; the code publishes a no-score notice with `assessment_error`. Fix the doc.
9. Early assessment (posture violation or failed rollout) queries a window of a few seconds, so the model effectively sees only the spec diff: widen the window or mark such events uncertain.
10. `watch_loop`: no minimum interval between watch attempts or after a 410 (hot loop risk). Add about 1 s minimum.
11. OBSERVE with inference down publishes a no-score notice per sample (Fusion's SET NX contains it); add per-spec dedup if cheap.
Also: `field_attribution_json` is no longer published but `dashboard/fastapi_app.py`, `dashboard/incident_view.py` and `agents/fusion_agent/interpretation_client.py` still read it (handled in Task 9, make sure nothing crashes meanwhile). Status 2026-11-12 (Claude review): findings 2 (scheduler retry), 10 (minimum interval also after a normal stream end) and the demo-namespace item (chart no longer renders extra Namespace objects; k3d victim apps run in prod and dev; `namespaceTierMap` maps `demo` to dev) were only partly fixed by Codex and are fixed on `wave/V5-D4` (`f81a380`) and `wave/V5-T1`; the Health Agent image also lacked `COPY kubeheal/` and could not start. Task 1 is complete once those branches are merged.

### Task 2. Review fixes and merge of `wave/V5-S2` (Security Agent)

Independent review verdict: do NOT merge as is. 176 touched tests pass; no Kubernetes write; contract with Fusion matches; entropy hardening is correct. Codex is fixing the following findings in `../Unisys_Model-wt-V5-S2`; do not merge until the full suite passes and the diff is reviewed:

1. BUG (detection): `agents/security_agent/agent.py` about line 555 `risk_score = pred["risk"] if pred else heuristic_risk` plus the publish test at about line 563. With the shipped bundle the ransomware trigger window of the current `k8s/` Falco rules scores `benign` (0.05 to 0.15) even with entropy near 7.9, so NO event is published during an attack and the score hash says `model_scored=true, sec_risk` about 0.05, which Fusion's rule path reads as "security risk confirmed below 0.4". Fix: always compute the heuristic; when `heuristic_risk >= SECURITY_PUBLISH_RISK` and the model risk is below it (or absent), publish a heuristic-only event with `model_scored=false`, label `suspicious`, empty prediction set, `sec_uncertain=true` (it reaches a human only, never an automatic action), carry the model risk in a `model_risk` or `model_issue` field, and write the score hash with `model_scored=false` (or `sec_risk=max(model, heuristic)`) in that conflict so the rule rollback escalates. Land Task 5 (V5-S1) as soon as possible: it makes the model see the right features.
2. BUG: `_record_score` is only called when scorable events exist, so an unscorable window (only mmap/msync, no Falco window on the /proc path, an exception in feature building) leaves an earlier "true, low" hash in place. Whenever an assessment runs and the model did not answer for it, write the hash with `model_scored=false`; wrap feature building in try/except that writes "false".
3. BUG (deploy): `dockerfiles/Dockerfile.security` copies only `agents/`; the agent now imports `kubeheal.contracts` and `kubeheal.features.security`. Add `COPY kubeheal/ /app/kubeheal/` (as `Dockerfile.fusion` does) and a test that every top-level package the agent imports is copied (use `tests/test_dockerfiles*.py` if one exists).
4. Frozen trigger snapshot: `_trigger_entropy_check` passes `list(trigger.events)` so the "initial" and "complete" assessments (60 s apart) score the same 15 events. Re-read `tracker.window(pid)` at each assessment.
5. Hash is last-writer-wins across nodes and replicas and per-PID: do the max in Redis (Lua or WATCH/MULTI: keep the higher risk while the stored one is within TTL), one `ts_ms`, `hset` plus `expire` in one pipeline (a cancel between them leaves a hash with no TTL).
6. Quiet workloads never get a hash, so the Q1 rule rollback of an idle drifted workload (the main case) always escalates to a human. Score each pod periodically with a real (possibly near-empty) window and real counters, only with a real inference answer.
7. Tracker: prune events older than `WINDOW_S` before counting bursts, cap tracked pids (LRU), evict `_falco_first_ts` when a check ends (15 writes an hour apart currently fire a trigger).
8. Pid reuse: key counters and the entropy sampler by `(pid, /proc/<pid>/stat starttime)`.
9. `written_files` scans all fds before applying `max_files`: stop after N.
Nits: pod missing from the pod index gives a pod-name workload for the first event (fail closed, fixed on the next assessment). Then full suite, merge, mark V5-S2 `[x]`, record the cause of D-5 as the builder wrote it in `PROGRESS.md` (the replay trace had no rename source and no open flags, so the model scored it benign; a hand-written trace shaped like the V5-S1 rules scores `ransomware` 0.95).

### Task 3. Chart and agents consistency after D4 and S2

Remove `HEALTH_MODEL_URL`, `SECURITY_MODEL_URL` and `DCM_URL` from `deploy/helm/kubeheal/templates/agents.yaml` (and `k8s/fusion-agent-deployment.yaml` `DCM_URL` and `CI_WIDTH_THRESHOLD`); set `WATCH_NAMESPACES`; keep `modelServers.legacy.enabled: false`; update `tests/test_agent_fusion_contract.py` so both agents are pinned on the new fields (`health_prediction_set`, `sec_prediction_set`, `failure_reasons_json`, `changed_fields_json`, `spec_changed`, `has_baseline`, `model_unavailable`, the Redis hash `kubeheal:security:score:*`) instead of the old ci_width and embeddings. `helm lint` and `helm template` for every values file, `tests/test_platform_chart.py` green with helm on PATH.

### Task 4. Install the new stack on k3d-kubeheal (needs registry network; mode stays `test`)

`demo/k3d/up.ps1 -Stage images` (builds `inference-server`, health-agent, security-agent, fusion-agent images; check the exit codes), then `-Stage install` (or a manual `helm upgrade` with the generated values; keep the pinning lesson above). Verify: `kubectl --context k3d-kubeheal -n kubeheal get pods`, the inference Service `/readyz` returns 200 (record the real output), `tests/test_rbac_k3d.py` and `tests/test_killswitch.py` pass, mode still `test`. Record the exact image tags and the Helm revision in `PROGRESS.md`. If the registry has no network, record that and continue with the offline tasks.

### Task 5. V5-S1 Falco rules and replay traces (moved up: the model needs these fields)

Compare v5's Falco rules and values (`git show origin/main:<path>`, find them with `git ls-tree -r origin/main --name-only | grep -i falco`) with `k8s/` and the chart; make our rules emit open flags and BOTH rename paths (source and target) and the fields `falco_client._normalise` reads; add a sync test between the rules and the captured syscall traces; refresh the recorded replay traces (`tests/fixtures/falco`, see its README) so the replay produces a model-visible ransomware window; re-run the D-5 replay on the cluster in mode `test` and record whether a Security event is published (true or false, with the log lines).

### Task 6. V5-D5 baseline promotion (owner D3), Health Agent plus ledger plus dashboard hook

Promote the baseline when the assessment is benign, certain (one-label set), rollout complete (`failure_reasons.rollout_complete`), no `failure_reasons`, no posture violation: automatically in dev and staging; in prod write a candidate key and require approval (dashboard, Task 8). Every promotion, automatic or approved, is a ledger entry that keeps the previous baseline. The golden-baseline rule changes from "never overwritten" to "overwritten only by these two paths and `scripts/baseline_tool.py`": update `agents/health_agent/baseline.py` docs and tests. Keep P7-RR-11 in mind (re-baseline after restore).

### Task 7. V5-D6 and V5-D9 Executor validation and candidate fields (reserved files, tests required)

Before any patch: pod-template labels match the Deployment selector (`matchExpressions` always escalates) and `kubeheal.posture.weakens_posture(live_template, baseline_template)` is empty (a `PostureError` escalates). Replace model attribution with the candidate fields from the request's `patch_fields` (the spec diff against the baseline): patch the drifted fields the Executor can verify differ, escalate only when the diff is empty, keep canary and rollback. Remove the `no_drift_at_field` dependence on model attribution and the `health_field_top` remnants in `decision_policy.py` (V5-D9). The Executor must also accept and ledger the new request fields Fusion already sends (`patch_fields`, `rule_path`, `rule_reasons`, `containment_label`, `restore_after`, `human_followup`). Add Executor tests; every write stays behind `actions._write`.

### Task 8. V5-S5 containment (reserved: Executor, Security Agent, RBAC; owner D5 and Q2)

The Executor, behind the kill-switch gate and with a ledger entry first, publishes a contain request; the node-local Security Agent re-checks the mode, freezes the pod cgroup (`cgroup.freeze`) and answers on a result stream; the Executor waits a bounded time, then forensic snapshot, quarantine, scale to 0, and (only when `restore_after` is true, that is `ransomware`) restore using the existing P7 code. After an `exfiltration` containment the Executor does not restore and escalates to HUMAN (Fusion already escalates once). The Executor never writes the cgroup itself. Needs a host cgroup mount on the Security Agent DaemonSet, RBAC and chart changes (security review: write the review into `PROGRESS.md`), tests with fakes (no real cgroup in CI), fail safe when the freeze is not acknowledged (escalate, do not continue). Use cgroup `io.stat` for the write-bytes counter when you have the mount (replaces the per-process counters, S2 finding 8).

### Task 9. V5-I3 dashboard

Prod promotion approvals (Task 6), TreeSHAP `top_factors` view, prediction-set display replacing the CI width, containment label and follow-up display, no reads of removed fields (`field_attribution_json`, `*_ci_width`, embeddings). Update `dashboard/` tests.

### Task 10. Cluster acceptance and the open P10 and P11 items

- P10-U6 acceptance twice (see `docs/kubeheal/PROGRESS.md` P10 and `docs/kubeheal/results/p10-k3d-2026-11-11.md` for what was confirmed and what was only reported). Record real numbers only.
- P10 D-5 replay (Task 5) and the real `/readyz` output (Task 4).
- P7-RR-7, RR-11, RR-12 and P11-E1 to E7 (`eval/p11_harness.py`, the harness allow-lists and `assert_test_mode` stay; every run in mode `test` unless the task says enforce on a scratch namespace; results only from recorded runs).
- Rebuild and deploy the Health Agent image (done as part of Task 4) and verify the `ApiClient` fix on the cluster.
- P13 documentation: the phase table in `PROGRESS.md` lists P11 and P13 as not started; open their checklist lines (and the P11-E1 to E7 lines) and finish them with real numbers only.

### Task 11. V5-DOC (after the code runs, not before)

Update `README.md`, `AGENTS.md`, `docs/kubeheal/ARCHITECTURE.md`, `SPEC_VS_CODE.md`, `PROJECT_SPEC.md` amendments, `docs/architecture-flow.md` and `demo/README.md` so they describe LightGBM health and security models with split-conformal prediction sets and TreeSHAP factors, the one-label gate (M2), the deterministic correlation, the rule-based rollback with its Security-freshness requirement (Q1), the baseline promotion rule (D3), and the containment order and labels (D5, Q2: freeze, forensic snapshot, quarantine, scale to 0, restore only for ransomware, human follow-up after exfiltration, suspicious never automatic). Describe only what is merged and verified; mark anything not running as planned. The neural models and DCM stay documented as legacy (off by default).

### Task 12. Later, in this order

V5-F1 (quarantine ownerReference and UID preconditions, protected-owner and unknown-controller handling), V5-P1 (CI workflow: pytest, `helm lint`, `helm template`, image builds), V5-P3 (Redis per-component ACL users), V5-E1 (scripted lab scenarios on k3d in mode `test`; collection through our agents is allowed, training is not), V5-S4 (eBPF sensor as an optional event source, not verifiable on this machine), V5-M3 (option c, stretch; training needs the owner's go). When everything above is merged: final suite on `work` and `demo`, `git status` clean, `.ai/handoff.md` current, then stop. The owner pushes.

## Open owner items (do not block)

- M3: the owner asks the teammate for the raw `collected/*.jsonl` files and collection scripts.
- The tag `demo-2026-11-11` is created by the owner after the demo (AGENTS.md branch plan).
