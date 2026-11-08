# Models and data

KubeHeal runs two LightGBM classifiers behind one inference service: **health**, which scores a
Deployment spec change together with its post-change metrics, and **security**, which scores one
pod's syscall and entropy window. This document covers their features, the model bundle, training,
the datasets, and how to retrain.

## The parity-by-construction rule

A model is only as good as the match between the inputs it was trained on and the inputs it gets
at serve time. KubeHeal enforces that match structurally, so it does not depend on review:

- **One feature module.** All feature code lives in `kubeheal/features/`. Training, the lab collectors and the live agents import the same functions. There is no second implementation anywhere.
- **Collectors record what the agents computed.** The lab collectors never compute features: health rows carry the features of the `HealthEvent` the live agent published, and security rows carry the features the live agent captured. `train.py --collected` fails if a recorded feature set differs from the current feature list.
- **One metric window.** The health agent and `training/collect/drift_lab.py` both call `agents/health_agent/prometheus.fetch_window` over `[change seen, assess time]` (`ASSESS_DELAY_S` = 60 s by default, shorter when the agent assesses early; `drift_lab.py` records `assess_delay_s`) at `METRIC_STEP_S` = 15 s, which is also Prometheus' scrape interval.
- **Synthetic windows match what Falco can see.** The synthetic security windows are cut down to the agent's view: `CAPTURED_GROUPS` syscalls on the data volume only, at most 512 events, at most `MAX_ENTROPY_SAMPLES` = 8 entropy samples of the first 16 KiB, and the same `window_seconds()` = max(event span, 5 s) capped at 60 s for every per-second rate, defined once in `kubeheal/features/security.py`. A test keeps the Falco rule and `CAPTURED_GROUPS` in sync.
- **Unknown is `None`, never 0.** LightGBM handles missing values natively, and the inference API rejects unknown feature names with a 422.

## Training and data pipeline

```mermaid
flowchart TD
  subgraph lab["Lab cluster · training/collect/run_lab.sh --hours N"]
    direction LR
    DL["drift_lab.py<br/>podinfo slots · 19 change families"] -- "spec changes" --> HAG["live health-agent"]
    SL["security_lab.py<br/>benign workloads + detection-test pods"] -- "file I/O → Falco" --> SAG["live security-agent<br/>KUBEHEAL_CAPTURE=1"]
    HAG -- "HealthEvent" --> RED[("Redis<br/>kubeheal.health.events<br/>kubeheal.security.capture")]
    SAG -- "every scored window" --> RED
  end
  RED -- "agent features + observed-impact label" --> HJ["collected/health.jsonl"]
  RED -- "agent features + before/after-overwrite label" --> SJ["collected/security.jsonl"]
  HJ --> EXP["training.datasets.collected export"]
  SJ --> EXP
  EXP --> GZ["training/data/*_lab.jsonl.gz<br/>+ dataset card README.md"]

  CSV["health_drift.csv<br/>legacy runs"] --> TR
  SYN["synth_security.py<br/>synthetic windows"] --> TR
  GZ -- "--collected<br/>(raw JSONL preferred when present)" --> TR
  TR["training.train --task health | security<br/>grouped 80/10/10 split · 5-fold grouped CV<br/>conformal q · held-out families"] --> GATE
  GATE{"GATES floors/ceilings, no regression,<br/>None-safe splits?"}
  GATE -- no --> FAIL["exit 1, nothing written"]
  GATE -- yes --> BUN["models/{task}/model.txt + meta.json"]
  BUN -- "COPY in Dockerfile.inference" --> INF["inference :8000"]
```

## Features

### Health: 36 features (`kubeheal/features/health.py`)

**Raw metrics**, in raw SI units, one PromQL each (`agents/health_agent/prometheus.build_queries`):
`cpu_usage_cores`, `cpu_limit_cores`, `cpu_throttled_ratio`, `memory_working_set_bytes`,
`memory_limit_bytes`, `request_rate_rps`, `error_rate_rps`, `latency_p99_s`, `restarts_total`,
`replicas_desired`, `replicas_ready`.

**24 spec-diff features** are computed on canonical camelCase DeploymentSpecs and summed over containers:

| Group | Features |
|---|---|
| Resources | `cpu_limit_ratio`, `cpu_request_ratio`, `mem_limit_ratio`, `mem_request_ratio` (new/old, `None` if either side is missing), `cpu_limit_removed`, `mem_limit_removed` |
| Scale | `replicas_ratio`, `replicas_to_zero` |
| Image | `image_changed`, `image_unpinned` (no tag, or `:latest`) |
| Security posture | `privileged_added`, `root_user_added`, `capabilities_added`, `host_namespace_added`, `host_path_added` |
| Probes, env, command | `probe_changed`, `probe_removed`, `env_count_delta`, `env_values_changed`, `volume_mounts_removed`, `containers_delta`, `command_changed` |
| Size | `n_changed_fields`, `spec_changed` |

**12 metric features** are computed from the window:

| Features | Definition |
|---|---|
| `cpu_util_mean`, `cpu_util_max` | Usage / limit |
| `cpu_throttle_mean` | Mean throttled ratio |
| `mem_util_mean`, `mem_util_max` | Working set / limit |
| `latency_p99_mean_s`, `latency_p99_max_s` | Mean and max p99 latency |
| `latency_trend` | Slope of p99 latency per minute |
| `error_ratio` | Σ 5xx / Σ requests |
| `request_rate_log` | log1p of the mean request rate |
| `restarts_delta` | Last minus first restart count |
| `ready_ratio` | Last ready / desired |

`failure_reasons` (container waiting reasons and `OOMKilled` in pods created after the change, plus
`ProgressDeadlineExceeded`) is **not** a model feature, so the model's inputs stay identical to the
collected training data. It travels on the `HealthEvent` and drives fusion's rule-based rollback
(see [architecture.md](architecture.md#decision-policy-agentsfusion_agentdecision_policypy)). The model
is left to judge subtle drift such as throttling, latency and memory pressure.

### Security: 45 features (`kubeheal/features/security.py`)

The input is a list of Falco events (`syscall`, `path`, `new_path`, `ts_ms`), the entropy samples of
files the pod wrote, the window length, and two byte counters.

| Group | Features |
|---|---|
| Volume | `n_events`, `events_per_s` |
| Syscall mix | `frac_read` and `frac_write` (per-file opens by intent, via `open_syscall`: the live capture has no `read()`/`write()`), `frac_open` (always 0 live), `frac_rename`, `frac_unlink`, `frac_truncate`, `frac_network`, `frac_mmap`, `frac_exec`, `frac_chmod`. Network, mmap and exec are never captured live, so these are always 0 at serve time. |
| Paths | `unique_paths`, `unique_dirs`, `files_written_per_s`, `suspicious_ext_ratio` (27 known ransomware extensions), `ransom_note` (a name like `README_DECRYPT.txt`) |
| Rename kind (`rename_kinds()`, first match wins per rename) | `frac_rename_rotate` (new = old plus a 1-2 digit suffix, `x.log` to `x.log.1`, `x.log.1.gz` to `x.log.2.gz`), `frac_rename_suffix_added` (new = old + `.ext`, `file.txt` to `file.txt.locked`: the encryption style), `frac_rename_temp_replace` (old looks temporary: leading `.`, `.tmp` `.swp` `.part` `.new` `.lock` `.dpkg-new`, `~`, or a mktemp-style suffix of 5+ alphanumerics with a digit; or the target was already opened, written or renamed onto earlier in the window), fractions of all renames, `None` without renames. `rename_ext_added_ratio` = suffix_added renames whose added extension is not compression (`.gz .bz2 .xz .zst`). Replaces `rename_ext_change_ratio` and `recent_ext_change_frac` (extension compared with the original name: any atomic write or rotation counted as a change). Other renames (plain moves, extension swaps) are in none of the three fractions. |
| Transforms of read originals (`transforms()`) | Ransomware rewrites the files it has just read; backup tools (restic, borg) read originals and write new content-addressed files elsewhere, package managers and git write fresh trees, atomic writes rename an unread temp file. An event *transforms* an original X opened for read earlier in the window when it opens X for write or truncates it (in place), renames X within its directory (`X` to `X.locked`, `X.dat` to `X.locked`), or writes `X` + suffix (copy). Rotation (`.1`), compression (`.gz .bz2 .xz .zst`) and temp/backup suffixes (`~ .tmp .part .new .swp .bak .orig .old .copy .lock .dpkg-new`) never transform; renames into another directory are moves. `frac_write_from_read` = written files (opens for write, truncates, rename targets) that transform an original / all written files; `frac_read_destroyed` = files read that are later overwritten in place, renamed away or unlinked / all files read (gzip and restic prune score here too, transform nothing); `n_files_transformed` = distinct originals transformed (a count, so a slow attack shows after 2 files). The fractions are `None` without writes / reads. |
| Entropy (bits/byte, first 16 KiB) | `entropy_mean`, `entropy_max`, `entropy_p90`, `entropy_high_frac` (> 7.5), `entropy_slope`, `n_entropy_samples`. All `None` when no samples. |
| Byte counters | `write_bytes_per_s` (pod cgroup v2 `io.stat` `wbytes`, counted at writeback), `net_out_bytes_per_s` (TX bytes of every non-loopback interface in the pod netns, `/proc/{pid}/net/dev`). Both are the counter increase across the window divided by its length, and `None` on a pod's first evaluation or after a reset. |
| Short horizon (last `RECENT_EVENTS` = 64 events, so a burst stands out from the setup phase) | `recent_frac_write` (open for write + truncate), `recent_frac_rename`, `recent_frac_unlink`, `recent_frac_chmod` (fractions of the 64), `recent_unique_files` (distinct paths), `recent_frac_rename_suffix_added`, `recent_frac_rename_temp_replace`, `recent_ext_added_frac` (the rename-kind features over the last 64 events, classified against the whole window; `None` without renames), `recent_entropy_mean` / `recent_entropy_high_frac` (entropy samples of the files written in those 64 events; `None` without samples), `recent_events_per_s` (64 / max(span, 0.5 s)), `recent_frac_write_from_read` / `recent_frac_read_destroyed` (the transform fractions over the last 64 events; originals read before them still count, so the tail of an attack that follows a setup phase scores near 1). Computed by `recent_features()` for the agent and the generator alike; an older bundle without them, or one that leaves some out (the shipped bundle omits `recent_frac_rename`), keeps serving because the inference service ignores feature names it does not list, and a name the bundle lists but the agent no longer sends (`rename_ext_change_ratio`, `recent_ext_change_frac`) is read as missing. |

The two byte counters are filled at serve time. They are the agent's only network signal, because
the Falco rule captures file syscalls only. The synthetic generator produces them too: they are
`None` on a first evaluation and in 10 % of windows, as live, and include background traffic.

## The model bundle (`kubeheal/ml/`)

A bundle is a directory with `model.txt` (the LightGBM booster) and `meta.json`, which holds `task`,
`version`, `labels`, `class_risk`, `features`, `alpha`, `conformal_q`, `metrics` (the full training
report), `data` (`source`, `rows`, `groups`, `synthetic`, `sha256`, plus `class_source` for security),
and `created_at`. `ModelBundle.load` refuses a `model.txt` whose feature names or class count do not
match `meta.json`.

`ModelBundle.predict(features)` returns a `Prediction` and works as follows:

- **Inputs:** unknown keys raise an error, missing or non-finite values become NaN, and prediction runs with `num_threads=1`.
- **Label:** the argmax class.
- **Risk:** `risk = Σ p(class) · class_risk`, clipped to [0, 1]. Health class risks are 0.05, 0.60 and 0.95. Security class risks are 0.05, 0.45, 0.95 and 0.85.
- **Conformal set:** `{c : 1 − p_c ≤ max(q, 0.05)}` (the floor admits any label with p ≥ 0.95). `uncertain = len(set) != 1`, so an empty set is uncertain.
- **Top factors:** the 5 largest non-zero |TreeSHAP| contributions to the predicted class, from LightGBM `pred_contrib=True`. These are exact for trees, and the `shap` package is not needed.

### Split-conformal uncertainty (`kubeheal/ml/conformal.py`)

The non-conformity score is `1 − p(true class)`. The threshold `q` is the ⌈(n+1)(1−α)⌉-th smallest
calibration score. If there are too few points for that rank, q = 1 and every label is in the set.
With α = 0.1, the set contains the true label at least 90 % of the time, provided the serve-time data
is exchangeable with the calibration data. Fusion uses the set as a gate: a model-driven AUTO_* action
requires a single-label set.

## Training (`training/train.py`)

```bash
uv run --all-extras python -m training.train --task health                        # legacy CSV
uv run --all-extras python -m training.train --task security                      # synthetic windows
uv run --all-extras python -m training.train --task health --collected            # lab data (+ --with-legacy for the CSV too)
uv run --all-extras python -m training.train --task security --collected --drop-features recent_frac_rename   # shipped bundle: lab data + synthetic suspicious/exfiltration/hard negatives
```

| Flag | Default | Meaning |
|---|---|---|
| `--task` | required | `health` or `security` |
| `--collected` | off | Train on lab data. Security adds synthetic rows only for `suspicious` and `exfiltration`. |
| `--with-legacy` | off | Health with `--collected`: also add the legacy CSV given by `--data` |
| `--data` | `training/data/health_drift.csv` | Legacy health CSV |
| `--n-scenarios` | `3000` | Number of synthetic security scenario instances |
| `--drop-features` | none | Comma-separated features left out of the bundle (the agents still compute them; inference ignores unknown `recent_*`). The shipped security bundle uses `--drop-features recent_frac_rename`. |
| `--alpha` | `0.1` | Conformal miscoverage |
| `--gate PATH=VALUE` | `GATES` in `train.py` | Override one gate threshold (repeatable) |
| `--regression-tol` | `0.02` | Max drop of a gated metric vs the bundle being replaced |
| `--allow-regression` | off | Skip the no-regression check (say why in the commit) |
| `--seed` | `7` | Seed for splits, LightGBM and the generator |
| `--out` | `models/<task>` | Bundle directory |

### Procedure

1. **Grouped split.** Data is split 80/10/10 into train, validation and test **by group** (a scenario run, a lab base spec, a pod, or a synthetic scenario instance), stratified on each group's most severe label. No run lands on two sides of the split.
2. **Final model.** The LightGBM multiclass model uses `num_leaves=15`, `learning_rate=0.05`, `min_data_in_leaf=20`, feature and bagging fraction 0.8, `lambda_l2=1` and class-balanced weights. It stops early on the validation set (patience 50, up to 2000 rounds).
3. **5-fold grouped cross-validation** over all non-test groups at the chosen round count. The out-of-fold probabilities feed both the CV report and the conformal calibration. For health, only rows with a real spec change are used, because those are the only inputs the agent ever sends.
4. **Held-out families.** With `--collected`, each lab scenario family is held out in turn. No row involving it trains: health families come from each record's `params.ops` (`collected.heldout_key`), so combined changes and reverts (which carry the forward ops) leave training with every family they touch. The test rows are those involving only that family, so the pooled metric is a partition of them. Detection-test runs are split by variant: rename or in-place, and full or partial overwrite.
5. **Report.** The report contains per-class precision, recall and F1, macro and weighted F1, the confusion matrix, empirical coverage and mean set size for CV and test (health also on spec-changed rows), and single-row latency p50 and p99 including TreeSHAP.
6. **Missing values.** Health training appends blanked copies of every row (`missing_dropout`), one per `MISSING_GROUPS` group: all metrics (Prometheus down), app metrics (latency, errors, request rate: the app exports no HTTP metrics) and resources (the 4 limit/request ratios plus CPU/memory utilisation: no limits or requests). Every lab base spec sets limits and requests, so without these copies LightGBM saw no NaN there and scored a live `None` as 0: a Deployment without limits read as "limit cut to 0", and 1,765 of 2,044 benign lab rows flipped to critical. Copies keep label, group and family, so every split keeps them on their source's side; they are fit-only (not in calibration, reports or gates).
7. **Gate.** The bundle is written only if (a) every `GATES` threshold holds, (b) no gated metric is worse than in the `meta.json` being replaced by more than `--regression-tol` (unless `--allow-regression`), and (c) no feature in `kubeheal.ml.bundle.LIVE_NONE` (can be `None` live) is split with a missing type other than NaN. `ModelBundle.load` logs an error for (c) too. Otherwise the script exits 1 and writes nothing. The result is stored in `metrics.gate`.

| Task | Gated metric (report path) | Threshold | Seeds 1 / 2 / 7 |
|---|---|---|---|
| health | `cv5_grouped_spec_changed.macro_f1` | >= 0.90 | 0.939 / 0.930 / 0.939 |
| health | `cv5_grouped_spec_changed.per_class.critical.recall` | >= 0.85 | 0.898 / 0.877 / 0.904 |
| health | `cv5_grouped_spec_changed.per_class.degradation.recall` | >= 0.92 | 0.955 / 0.983 / 0.965 |
| health | `heldout_family.pooled.macro_f1` | >= 0.62 | 0.669 / 0.647 / 0.661 |
| security | `cv5_grouped.macro_f1` | >= 0.80 | |
| security | `cv5_grouped_lab.per_class.ransomware.recall` (lab rows only) | >= 0.95 | |
| security | `cv5_grouped_lab.false_kill_rate` (lab benign predicted ransomware) | <= 0.01 | |
| security | `heldout_family.pooled.per_class.ransomware.recall` | >= 0.90 | |

Security macro-F1 alone is inflated by the synthetic-only classes, hence the lab-only rows.

## Datasets

| Dataset | Path | Used for | Notes |
|---|---|---|---|
| Legacy drift CSV | `training/data/health_drift.csv` | health (default, or `--with-legacy`) | Real metric samples of earlier drift-lab runs. Group = `collection_run_id` (48 runs, only about 9 with a harmful label). |
| Health lab data | `training/data/collected/health.jsonl` (raw, git-ignored), exported to `training/data/health_lab.jsonl.gz` | health `--collected` | Features from the live health agent, labelled by observed impact |
| Security lab data | `training/data/collected/security.jsonl` (raw), exported to `training/data/security_lab.jsonl.gz` | security `--collected` | Captured windows of benign workloads and the detection-test workload. Captures from before the byte counters existed (`collected/pre-telemetry/`) are never used. Rows collected with raw events (see below) are recomputed with the current feature code on load; older rows keep the agent's features and have `None` for features added later (the transform features). |
| Synthetic security | generated by `training/synth_security.py` | security (default), and `suspicious`/`exfiltration` with `--collected` | Hard positives and hard negatives, cut to the agent's view. `meta.json` marks it `synthetic`. With `--collected` it also supplies the benign hard-negative families `atomic_rename` (temp file + rename, editor saves), `logrotate_gz`, `dpkg_install`, `git_npm`, `backup_repo` (restic/borg/kopia-like encrypted repos) and `package_tree` (npm/pip installs), at 20 to 400 files/s with setup phases, and the hard positive `ransomware_trickle` (1 to 5 files/s, 2 to 12 files); `meta.json` reports `synthetic_fraction_by_class`, `synthetic_hard_negatives` and `synthetic_hard_positives`. |

`training/data/README.md` is the dataset card, generated by the export command with row counts, label
counts, scenario families and label reasons. Do not edit it by hand.

Health relabels on load (`collected.read`, deterministic, raw file untouched, flagged `relabeled`):
`readiness_break_replicas1` (forward change breaking the readiness probe with a wrong path or port, `obs.desired == 1`,
not stuck → `obs.stuck = true` and `drift_lab.impact_label` re-run; the collector's rollout check passed at 1 replica
while only the old pod was available, but every such change at 2-3 replicas was stuck; 23 rows, 20 benign → critical,
3 already critical gain `rollout_stuck`), then
`p99>=2x_robust_pre` (benign → degradation against the run's median pre-change p99).

### Legacy CSV cleaning (`training/datasets/health.py`)

- **Label mapping:** `Benign_Or_Subtle` → benign, `Harmful_Performance_Degradation` → degradation, any other `Harmful_*` → critical.
- **Pre-drift rows:** `phase == "pre"` rows become benign, because the drift was not applied yet.
- **Dropped rows:** 506 `Synthetic*` augmentation rows, and post-drift rows whose recorded spec did not change.
- **Windows:** each window starts at the change, like the agent's.
- **Units:** `cpu_limit` and `cpu_usage_cores` are in cores, `memory_limit` in MiB, `latency_p99` in seconds.

### Lab collection (`training/collect/`)

`run_lab.sh --hours N` runs both collectors against a lab cluster. It never targets production.
Operational details are in [operations.md](operations.md#lab-data-collection).

**Health** (`drift_lab.py`) runs podinfo "slots" in the namespace `kubeheal-lab`. The namespace is
prod tier (the label is reconciled on every start); the lab Deployments and pods, not the namespace, carry
`kubeheal.io/protected=true`, so fusion never acts on a sample mid-measurement.
Each slot runs a load generator on a random base spec, and the collector applies changes from 21
weighted families with random magnitudes (`FAMILIES` = generators, `WEIGHTS` = the mix, one table in
`drift_lab.py`):

- CPU and memory limits, up and down (ratio-based cuts)
- `cpu_throttle`: an absolute 5–22m CPU limit, and `mem_pressure`: an absolute 30–34 Mi memory limit
  (podinfo's working set is ~21–30 Mi). These target subtle slowdowns: the first lab run produced only
  ~5% degradation, nearly all from CPU limits under ~20m or `--stress-cpu`. Expected non-revert mix
  with the current weights: ~52% benign / ~22% degradation / ~26% critical.
- CPU requests
- replicas: up, down, to zero
- a valid image or a missing image
- probes: break, tweak, remove
- env, args (break or stress), volume-mount removal
- metadata-only changes
- security-posture changes

The label comes from the **observed** impact, never from the scenario name:

| Label | Observed impact |
|---|---|
| `critical` | A posture change (policy), scaled to zero, ready ratio < 0.5, rollout not complete, a pod waiting in a failure state, any restart or OOMKill, or 5xx ratio > 5 % |
| `degradation` | p99 latency ≥ 2× the minute before the change (and at least 10 ms more), CPU throttling > 25 %, or memory > 90 % of the limit |
| `benign` | otherwise |

Restores of the base spec are recorded as `revert` rows, labelled the same way.

**Security** (`security_lab.py`) runs short-lived pods. Each runs an ordinary file workload (backups,
log rotation, databases, compiles, copies, atomic writes, and a `backup_upload` that streams an
archive to an in-cluster TCP sink, `lab-sink:9000`), labelled `benign`, or the
sandboxed `deploy/chaos/detection-test-workload.py`. The detection-test workload creates plain files, waits,
then overwrites them with random bytes and optionally renames them. Windows that end before the
overwrite are `benign`, windows that start after it are `ransomware`, and straddling windows are
dropped. The security agent's capture mode (`KUBEHEAL_CAPTURE=1`) supplies every scored window.

Benign profiles also run **real tools** on `/data`, weighted up because they were the nearest false kills live
([evaluation.md](evaluation.md)): `restic_backup` (`restic/restic` image: init, backups of a generated tree after
edits, `forget --prune`, random compression), `npm_install` (2 to 4 packages, sometimes after `npm cache clean`),
`pip_install` (a venv on `/data`, 2 to 4 packages, with or without the pip cache) and `git_repo` (a local repo with
tagged commits, checkouts across the tags, `gc`, local clones; no network). npm and pip need network access from
the cluster. **Held out for evaluation, never collected or generated by name:** borg, kopia, duplicity, yarn and
pnpm, so the live soak measures tools the model has not seen. 30 % of detection-test pods run at 1 to 5 files/s
(slow attacks, killed only after about 10 files live).

**Raw events.** When the capture entry carries them, a lab row also stores the window's raw events and entropy
samples, so feature changes need no re-collection. Capture fields (strings, next to the SecurityEvent fields):
`events_json` = JSON list of `{"syscall", "path", "new_path", "ts_ms"}`, the exact events passed to
`security_features()`, oldest first, at most 512; `entropy_json` = JSON list of the entropy samples passed to it
(floats or `null`). Either may be absent. Consecutive windows of a pod overlap, so the collector stores one
`events_log` per pod (rows `[ts_ms, syscall, path, new_path]`, on the pod's first row with events) and an
`events_range` `[lo, hi)` plus `entropy` per row (`pack_events()` in `training/datasets/collected.py`). On load,
`recompute_security()` recomputes every such row's features (byte-counter features are kept from the capture:
they come from the pod's cgroup and netns, not from events).

### Synthetic security (`training/synth_security.py`)

The generator has 28 scenario generators across 4 labels:

- **Benign:** web serving, databases, compressed or encrypted backups, media transcoding, log rotation, atomic writes, package installs, backup uploads, maintenance scripts, encrypted-at-rest stores, encrypted dedup backup repos (`backup_repo`), npm/pip install trees (`package_tree`).
- **Suspicious:** reconnaissance, file enumeration, permission tampering.
- **Ransomware:** rename, in-place, copy-then-delete, intermittent or partial, slow, trickle (1 to 5 files/s caught early).
- **Exfiltration.**

Paths, extensions and window lengths are randomised, and 0 to 80 % background noise is added before
the window is cut to the agent's view. Each scenario instance yields 1 to 4 windows sharing one group.

## Retrain and ship

```bash
training/collect/run_lab.sh --hours 12                        # optional: more lab data
uv run --all-extras python -m training.datasets.collected export           # gz exports + training/data/README.md
uv run --all-extras python -m training.train --task health --collected     # writes models/health/ only if it passes the gate
uv run --all-extras python -m training.train --task security --collected
uv run --all-extras pytest tests/test_bundle.py tests/test_inference_api.py
./deploy/scripts/install.sh                                          # rebuilds kubeheal/inference:v5 with the new bundles
```

The bundles are baked into the inference image (`COPY models/...`). To pick up new bundles, rebuild
the image and roll out `kubeheal-inference`.

## Metrics

Values from `models/{health,security}/meta.json`, plus my own nested evaluation for the security rows marked
"eval" (scripts are not in the repo). Health numbers use real, spec-changed rows only (missing-dropout copies are fit-only).

| | Health | Security |
|---|---|---|
| Bundle version | `health-5.0.0-a374e498` | `security-5.0.0-c6fa12d8` |
| Rows / groups / sources | 2,998 / 277 / lab (`collected/health.jsonl`) | 49,964 / 1,954 / lab 46,606 (benign + ransomware) + synthetic 3,358 (6.7 %): suspicious and exfiltration (1,296, 100 % of those classes) and benign hard negatives (2,062, 4.6 % of benign); ransomware is 0 % synthetic. `meta.json` has `synthetic_fraction_by_class` |
| Grouped-CV macro-F1 (gate) | 0.939 | 0.9994 |
| Test macro-F1 | 0.902 (n = 304) | 1.000 (n = 4,512) |
| Held-out-family macro-F1 (pooled) | 0.661 (21 op families; every row involving the family held out. The old 0.858 kept combined/revert rows of the family in training) | 0.999 over benign + ransomware (meta.json: 0.50, because exfiltration and suspicious do not occur in lab families) |
| Per-class F1 (grouped CV) | benign 0.969, critical 0.901, degradation 0.946 | benign 1.000, ransomware 0.9995, suspicious 0.9993, exfiltration 0.9990 |
| Conformal q / coverage / mean set size | 0.312 / 0.901 / 0.92 | 3.9e-6 (serving floors it at 0.05) / 1.000 / 1.00 |
| Latency p50 / p99 (ms) | 6.3 / 8.8 (measured with other training jobs running) | 13.0 / 15.7 |
| Eval: pod-level ransomware recall, prod tier (5-fold by pod, bundle q) | | 177 / 178 (one partial in-place run missed; same in leave-one-family-out) |
| Eval: benign pods falsely killed (418 pods; prod and dev) | | 0 / 418 in 5-fold CV and 0 / 418 leaving each benign family out; dev never kills, its 0.7 multiplier caps risk at 0.7 < 0.85 |
| Eval: first overwrite to first kill-eligible window, median / p90 (CV latency proxy, floor about 2 s) | | 2.21 s / 2.72 s |
| Eval: health, same grouped held-out groups, 5 seeds | 0.926 +/- 0.014 on all 2,998 rows, 0.920 +/- 0.017 on the 2,519 rows the previous bundle saw | |

Health: against the previous bundle (`health-5.0.0-37c9309f`, 2,519 rows), the extra 479 rows leave macro-F1 within
noise (0.926 +/- 0.014 vs 0.920 +/- 0.017, same held-out groups, 5 seeds; recall benign / critical / degradation
0.962 / 0.930 / 0.900 vs 0.960 / 0.936 / 0.893). The previous bundle as shipped scores 0.929 macro-F1 on those 479 rows, which it
had not seen. Promoted because the gate passes (0.933) and it is not worse.

Security: `recent_*` features carry about 5 % of the gain. They did not change in-distribution results (the interim bundle, which
ignores them, scores the same). What they buy is speed at 180 files/s, and what one of them costs is generalisation, see below.

Hardening against unseen benign write patterns (security). Each variant retrained on the same lab data (variant 1 with the synthetic rows redrawn, so not byte-identical to the shipped `a49c7ed8`) and
evaluated by pod at prod tier (kill rule: kill label, singleton conformal set, `min(1, risk * 1.2) >= 0.85`).
"LOFO" holds one lab family out of training in turn; "latency" is first ransomware window start to first
kill-eligible window end in 5-fold grouped CV by pod. Ransomware recall is 217 / 217 pods in every variant, in
5-fold CV and in LOFO over the four `detection_test` variants.

| Variant | Benign pods killed, LOFO (305 pods; worst family) | 5-fold CV: benign kills / latency median, p90 | Live kill, 180 files/s / 20 files/s | Live benign atomic-write pods |
|---|---|---|---|---|
| 1. `a49c7ed8`: all `recent_*`, no hard negatives | 23 (`atomic_config_writes` 23 / 30) | 0 / 0.23 s, 0.65 s | 0.65 to 0.72 s / 2.1 to 2.3 s | killed (replay of the live windows) |
| 2. no `recent_*`, hard negatives | 1 (`redis_snapshots`) | 0 / 0.23 s, 0.65 s | as 3 (replay) | not killed (replay) |
| 3. all `recent_*`, hard negatives | 0 | 0 / 0.23 s, 0.65 s | 1.15 to 1.27 s / 8.7 to 8.9 s | not killed (replay) |
| 4. `recent_*` minus `recent_frac_rename`, hard negatives: **`ca2438d3`, shipped** | 0 | 0 / 0.23 s, 0.65 s | 1.17 to 1.34 s / 8.7 to 9.0 s | 3 / 3 not killed |
| 5. `recent_*` minus `recent_frac_rename`, no hard negatives: `d1eb7c81` | 0 | 0 / 0.23 s, 0.65 s | 0.64 to 0.81 s / 2.2 to 2.3 s | 3 / 3 killed |

Findings. (a) `recent_frac_rename` is the feature that drives the false kills: dropping it alone takes the
`atomic_config_writes` hold-out from 23 to 0 kills, dropping `recent_ext_change_frac` does not. Dropping more
`recent_*` features is not more robust (one such model killed 13 of 30 again). (b) The lab-only CV and LOFO
numbers do not separate the variants. Live they do: the hard-negative families (`atomic_rename`,
`logrotate_gz`, `dpkg_install`, `git_npm` in `training/synth_security.py`) are what stop the model killing a
live atomic-write workload (variant 5 kills it: its decision rests on `unique_dirs` and `files_written_per_s`
with unknown entropy), but any amount of them (down to 5 % weight, any single family) moves the first
confident window of the back-to-back detection workload later. The lab data has a 65 to 80 s gap between
setup and encryption, so it cannot show this. (c) Hold-out results of models trained without hard negatives
flip with the LightGBM seed or thread count (a 0 / 30 result became 13 / 30), so a clean number there is thin evidence.

### Rename-kind features (variants A to D)

New lab data (46,606 security windows; ransomware runs with quiet gaps of 0 to 3 s, 5 to 20 s and 30 to 80 s, append or swap rename; benign
families now include `atomic_config_writes` with varied temp names and `log_rotation`), features from `rename_kinds()`, and four retrains
(same recipe, 3,000 synthetic scenarios, seed 7). Scripts are not in the repo. Pods: 418 benign and 178 ransomware (lab only).
"LOFO" holds one family out of training in turn; "CV" is 5-fold by pod (rounds from the bundle, serving q floor 0.05, prod tier,
kill rule: kill label, singleton set, `min(1, risk * 1.2) >= 0.85`). The latency proxy is the end of the first kill-eligible window minus
the attack start (end of the setup-phase windows plus `params.delay`); the lab only labels a back-to-back window ransomware after 2 s of
attack, so about 2 s is the floor of this proxy.

| Variant (version) | LOFO benign pods killed (of 418) | LOFO / CV ransomware pods killed | CV benign pods killed, uncertain rate | CV latency median, p90 |
|---|---|---|---|---|
| A. hard negatives, all features (`064782d7`) | 0 | 177 / 178, 177 / 178 | 0, 0.06 % | 2.21 s, 2.72 s |
| B. no hard negatives, all features (`b83ec6da`) | 30 (`log_rotation` 25 / 39, `tar_gzip_backup` 4 / 25, `archive_extract` 1 / 47) | 177 / 178, 177 / 178 | 1 | 2.21 s, 2.72 s |
| C. A minus `recent_frac_rename` (`2166de62`) | 1 (`tar_gzip_backup` 1 / 25) | 177 / 178, 177 / 178 | 0, 0.05 % | 2.21 s, 2.72 s |
| D. B minus `recent_frac_rename` (`e9e00ee1`) | 14 (`tar_gzip_backup` 13 / 25, `archive_extract` 1 / 47) | 177 / 178, 178 / 178 | 1 | not re-measured |

Ransomware (A; B and C identical): append 93 / 93, swap 37 / 37, in place 47 / 48; gap 0 to 3 s 79 / 79, 4 to 20 s 52 / 53, 21 s and more 46 / 46.
The one missed pod is a partial in-place run. CV latency by gap (median / p90): 0 to 3 s 2.35 / 2.90 s, 4 to 20 s 2.21 / 2.68 s, 21 s and more 1.03 / 2.50 s.
The CV latencies do not separate the variants: kill eligibility is set by the labels, not the variant. Gain share of the rename-kind features (A):
`recent_frac_rename_temp_replace` 6.2 %, `frac_rename_temp_replace` 0.5 %, `frac_rename_suffix_added` 0.25 %, `rename_ext_added_ratio` 0.03 %,
`frac_rename_rotate`, `recent_frac_rename_suffix_added` and `recent_ext_added_frac` 0 %; in C `frac_rename_temp_replace` takes 3.3 %.

Live (only the candidate that passed LOFO and CV, A; B to D fail LOFO with 1 to 30 benign pods, so they were not deployed):

| | `064782d7` (A) | `ca2438d3` (shipped) |
|---|---|---|
| Kill time, 180 files/s (3 runs) | 0.53, 0.58, 0.70 s | 1.17 to 1.34 s |
| Kill time, 20 files/s back-to-back (5 runs) | 0.53, 0.64, 0.69, 0.76, 1.04 s | 8.73 to 8.96 s |
| 3 benign atomic-write pods (about 80 renames per second, 60 s) | 0 killed | 0 killed |
| 3 benign gzip-rotation pods (60 s) | **3 killed** | 0 killed |
| E. A plus start-up burst negatives, without directory/read/entropy variety (`3cdb205c`) | 3 gzip-rotation pods killed again (0.97) | |
| F. A plus start-up burst negatives (`c6fa12d8`, **shipped**) | kills 0.46 to 0.70 s (20 files/s, 5 runs), 0.55 to 0.75 s (180 files/s, 3 runs); atomic-write pods 0 killed; gzip-rotation pods 0 killed | |

Outcome. The rename-kind features and the new gap mix deliver the speed (kills at 20 files/s drop from 8.9 s to 0.7 s) and keep the
atomic-write result with hard negatives, but the model does not use `frac_rename_rotate`, and gzip rotation in a pod's first window is
classified `ransomware`. `064782d7` was not promoted. Variant F adds small-window start-up bursts (see Known limitations) and replaces it: same lab results as A (LOFO 0 / 418 benign pods killed, 177 / 178 ransomware; CV the same), live 0 benign pods killed. The first try, E, still killed the rotation pods: the real window had two directories, reads and a mix of low-entropy `.log` and `.gz` entropy samples, which the first generator lacked. Removing the hard negatives (B, D) breaks the lab hold-outs, so
they are needed, and dropping `recent_frac_rename` (C) is no longer a clear gain with the new data.

## Known limitations

- **Exfiltration rests entirely on synthetic data.** The serve-time byte counters are real measurements, but `exfiltration` and `suspicious` are trained only on synthetic windows. Treat `exfiltration` predictions as unvalidated until real labelled windows exist.
- **Narrow health data.** There is one workload type (podinfo) on a single minikube node. The legacy CSV has only about 9 harmful runs, so health quality depends on lab data.
- **One ransomware simulator.** It is non-destructive and randomised (rate, size, rename, partial overwrite), but it is not real malware.
- **Short window.** Health labels and features cover the first 60 s after a change (the assess delay; shorter on an early assessment). Slow leaks are judged by what was visible within that time.
- **Conformal assumptions.** The coverage guarantee assumes exchangeability. A shift from the lab to production weakens it, and the set size is the signal to watch.
- **Safety rests on synthetic hard negatives (security).** The shipped bundle holds out every benign lab family with 0 pod kills, and live pods that rewrite config through temp-file + rename (about 80 per second) or rotate logs with gzip were not touched. Without the synthetic hard-negative families the model kills those workloads (variants B and D). A rename-heavy benign family unlike `atomic_rename`, `logrotate_gz`, `dpkg_install`, `git_npm`, `logrotate_start`, `archive_burst` and the lab families may still be killed. Kills stay behind the protected namespaces, the `kubeheal.io/protected` label, the circuit breakers and the prod-only 0.85 gate.
- **Gap mix and one simulator.** The new lab runs use gaps of 0 to 3 s, 5 to 20 s and 30 to 80 s from the same simulator (`deploy/chaos/`; append rename in 70 % of runs, swap in 30 %). A ransomware that renames in a way the simulator never does, or that encrypts slowly without renames, is not covered. The per-gap and per-style recalls below come from this one tool.
- **Synthetic parts of the security data.** `suspicious` and `exfiltration` (all rows) and the benign hard negatives (`atomic_rename`, `logrotate_gz`, `dpkg_install`, `git_npm`, `logrotate_start`, `archive_burst`) are generated.
- **Start-up bursts rest on synthetic negatives.** Benign windows of 64 events or fewer with `frac_rename_rotate >= 0.5` (a pod's first window of gzip log rotation, or tar/zip creation) are covered by synthetic `logrotate_start` and `archive_burst` windows (about 820 of the 2,062 hard-negative rows; 60 % are a pod's first 20 to 64 events); the lab has none. Live, three gzip-rotation pods and three atomic-write pods are left alone. A different benign start-up pattern may still be killed on its first window; `frac_rename_rotate` has little gain (0.2 %), the model keys on the surrounding features.
