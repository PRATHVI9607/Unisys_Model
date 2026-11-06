"""Lab-collected data (training/collect/) → training rows, and the committed gz export + dataset card.

Rows are `{features, label, group, family, source}`. `features` are the ones the live agents
computed (HealthEvent / captured SecurityEvent), so there is nothing to recompute. `family` is the
scenario family used for the held-out-family evaluation in training/train.py ("" = always train).

Reads training/data/collected/<task>.jsonl (raw collector output, git-ignored) when present, else
the committed export training/data/<task>_lab.jsonl.gz.

    uv run python -m training.datasets.collected export [--out-dir DIR]   # gz files + README.md (default training/data)
"""

from __future__ import annotations

import gzip
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
COLLECTED = DATA / "collected"
# Classes the security lab cannot produce: these come from training/synth_security.py.
SYNTH_ONLY = ("suspicious", "exfiltration")
ROBUST_P99 = "p99>=2x_robust_pre"


def source_path(task: str) -> Path:
    live = COLLECTED / f"{task}.jsonl"
    return live if live.exists() else DATA / f"{task}_lab.jsonl.gz"


def _rel(path: Path) -> str:
    return os.path.relpath(path, DATA.parents[1])


def read(task: str, path: Path | None = None) -> list[dict]:
    """Collector records; a torn last line (collector killed mid-write) is skipped, not fatal."""
    path = path or source_path(task)
    if not path.exists():
        raise FileNotFoundError(f"no collected {task} data: run training/collect/run_lab.sh or restore {path}")
    out, bad = [], 0
    with gzip.open(path, "rt") if path.suffix == ".gz" else open(path) as fh:
        for line in fh:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    if bad:
        print(f"warning: {path}: skipped {bad} unparseable line(s)", file=sys.stderr)
    if task == "health" and (n := relabel_health(out)):
        print(f"note: {path}: {n} benign record(s) relabelled degradation ({ROBUST_P99})", file=sys.stderr)
    return out


def relabel_health(recs: list[dict]) -> int:
    """Re-check latency degradation against a robust "before" p99, in place; returns the upgrade count.

    Early lab records measured `pre_p99_s` right after the previous revert rolled out, which can inflate it and
    hide a degradation. Baseline = median `pre_p99_s` of the (run_id, slot)'s forward changes (all share the base
    spec); drift_lab.impact_label's p99 rule decides. Only benign → degradation, flagged `relabeled`. Revert records
    are skipped: their "before" is the changed spec, which their own `pre_p99_s` measures correctly.
    """
    from training.collect.drift_lab import impact_label

    pres = defaultdict(list)
    for r in recs:
        if not r.get("revert") and r.get("pre_p99_s") is not None:
            pres[(r.get("run_id"), r.get("slot"))].append(r["pre_p99_s"])
    base = {k: statistics.median(v) for k, v in pres.items()}
    n = 0
    for r in recs:
        b = base.get((r.get("run_id"), r.get("slot")))
        if r.get("revert") or r["label"] != "benign" or b is None:
            continue
        if impact_label({"latency_p99_mean_s": r["features"].get("latency_p99_mean_s")}, {}, b, [])[0] == "degradation":
            r.update(label="degradation", label_reasons=[*r.get("label_reasons", []), ROBUST_P99], relabeled=ROBUST_P99,
                     robust_pre_p99_s=b)
            n += 1
    return n


def family(task: str, rec: dict) -> str:
    """Scenario family for held-out evaluation; detection-test runs split by variant."""
    if task == "health":
        return rec["family"]
    if rec["scenario"] != "detection_test":
        return rec["scenario"]
    p = rec["params"]
    return "detection_test:" + ("rename" if p["rename"] else "inplace") + ("_partial" if p["partial"] < 1 else "")


def lab_rows(task: str, path: Path | None = None) -> list[dict]:
    return [{"features": r["features"], "label": r["label"], "group": f"lab:{r['group']}",
             "family": family(task, r), "source": "lab"} for r in read(task, path)]


def health_rows(legacy_csv: str | None = None) -> tuple[list[dict], dict]:
    rows = lab_rows("health")
    src = {"lab": _rel(source_path("health"))}
    if legacy_csv:
        from kubeheal.features.health import health_features
        from training.datasets.health import load_records

        rows += [{"features": health_features(r["old"], r["new"], r["window"]), "label": r["label"],
                  "group": f"legacy:{r['group']}", "family": "", "source": "legacy_csv"}
                 for r in load_records(legacy_csv)]
        src["legacy_csv"] = legacy_csv
    return rows, {"sources": src, "legacy_csv": bool(legacy_csv), "synthetic": False}


def security_rows(n_scenarios: int, seed: int) -> tuple[list[dict], dict]:
    from kubeheal.features.security import security_features
    from training.synth_security import generate

    rows = [r for r in lab_rows("security") if r["label"] not in SYNTH_ONLY]
    # Pre-telemetry captures (training/data/collected/pre-telemetry/) have no byte counters at all; never train on them.
    if rows and all(r["features"].get("write_bytes_per_s") is None for r in rows):
        raise ValueError(f"{source_path('security')}: no byte telemetry in any window (pre-telemetry data?)")
    synth = [r for r in generate(n_scenarios, seed) if r["label"] in SYNTH_ONLY]
    rows += [{"features": security_features(r["events"], r["entropy"], r["window_s"], r["bytes_written"],
                                            r["net_bytes_out"]),
              "label": r["label"], "group": f"synth:{r['group']}", "family": "", "source": "synthetic"}
             for r in synth]
    class_source = {lbl: sorted({r["source"] for r in rows if r["label"] == lbl}) for lbl in
                    dict.fromkeys(r["label"] for r in rows)}
    return rows, {"sources": {"lab": _rel(source_path("security")),
                              "synthetic": f"training/synth_security.py n_scenarios={n_scenarios} seed={seed}"
                                           f" ({', '.join(SYNTH_ONLY)} only)"},
                  "class_source": class_source, "synthetic": bool(synth)}


# ── export ───────────────────────────────────────────────────────────────────
CARD = """# KubeHeal lab datasets

Generated by `uv run python -m training.datasets.collected export` from the raw collector output in
`training/data/collected/` (git-ignored). Training reads the raw files when present, else these exports:
`uv run python -m training.train --task health|security --collected`.

| file | rows | groups |
|---|---|---|
{files}

## Labels

{labels}

## How labels are assigned

**Health** (`training/collect/drift_lab.py`): podinfo Deployments in namespace `kubeheal-lab` (prod tier,
`kubeheal.io/protected=true` so fusion never acts on them) get random base specs and random spec changes
(19 families, 1-3 changes each). Features are those of the HealthEvent the live health agent published for the
change (same Prometheus window, same code). The label comes from the *observed* impact, never the scenario name:
`critical` = security-posture change (policy), scaled to zero, ready ratio < 0.5, rollout stuck, a pod waiting in
ImagePullBackOff/CrashLoopBackOff/…, a restart or OOMKill, or 5xx ratio > 5 %; `degradation` = p99 ≥ 2× the
pre-change minute (and ≥ +10 ms), CPU throttling > 25 % or memory > 90 % of the limit; `benign` otherwise.
At load/export a benign forward change is also re-checked against the median pre-change p99 of its run
(`relabeled: p99>=2x_robust_pre`), because early records could measure the pre-change minute while the
previous revert was still rolling out.
`revert` rows are the agent's assessment of restoring the base spec. Group = one random base spec (run).

**Security** (`training/collect/security_lab.py`): short-lived pods run either an ordinary file workload (backups,
log rotation, databases, compiles, copies, …) → every window `benign`, or the sandboxed non-destructive
`deploy/chaos/detection-test-workload.py` (creates plain files, waits, then overwrites them with high-entropy data,
optionally renaming). The security agent's capture mode records every window it scored from real Falco events.
Detection-test windows that end before the overwrite starts are `benign`, windows that start after it are
`ransomware`, straddling windows are dropped. Group = one pod.

## Scenario families

{families}

## Known limits

- Per-pod egress and write rates are measured (`net_out_bytes_per_s` from the pod netns `/proc/<pid>/net/dev`,
  `write_bytes_per_s` from the pod cgroup v2 `io.stat`), and real benign high-egress windows (`backup_upload`
  profile) are collected. But the lab runs no exfiltration workloads, so the `exfiltration` and `suspicious`
  classes are trained on synthetic rows from `training/synth_security.py` only (`class_source` in
  `models/security/meta.json`).
- One workload type for health (podinfo on a single minikube node); latency/throughput effects of a change on a
  real multi-node cluster under real traffic can differ.
- Ransomware windows come from one simulator with randomised rate/size/rename/partial-overwrite parameters, not
  from real malware families.
- Health labels are thresholds on observed impact; changes whose harm shows only after the 120 s window
  (slow leaks) are labelled by what was visible within it.
"""


def _table(counter: Counter, head: str) -> str:
    return "\n".join([f"| {head} | rows |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(counter.items())])


def export(out: Path = DATA) -> None:
    out.mkdir(parents=True, exist_ok=True)
    files, labels, fams = [], [], []
    for task in ("health", "security"):
        src = COLLECTED / f"{task}.jsonl"
        if not src.exists():
            print(f"skip {task}: {src} missing")
            continue
        recs = read(task, src)
        dst = out / f"{task}_lab.jsonl.gz"
        with gzip.open(dst, "wt", compresslevel=9) as fh:
            fh.writelines(json.dumps(r, separators=(",", ":")) + "\n" for r in recs)
        files.append(f"| `{dst.name}` | {len(recs)} | {len({r['group'] for r in recs})} |")
        labels.append(f"### {task}\n\n" + _table(Counter(r["label"] for r in recs), "label"))
        fam = Counter(f"{family(task, r)} / {r['label']}" for r in recs)
        reasons = Counter(x for r in recs for x in r.get("label_reasons") or ["(none)"])
        fams.append(f"### {task}\n\n" + _table(fam, "family / label") + "\n\nLabel reasons:\n\n" + _table(reasons, "reason"))
        print(f"wrote {dst} ({len(recs)} rows)")
    (out / "README.md").write_text(CARD.format(files="\n".join(files), labels="\n\n".join(labels),
                                               families="\n\n".join(fams)))
    print(f"wrote {out / 'README.md'}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] != ["export"] or args[1:] and (len(args) != 3 or args[1] != "--out-dir"):
        sys.exit(__doc__)
    export(Path(args[2]) if args[1:] else DATA)
