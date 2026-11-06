"""Legacy drift-lab CSV → raw health records `{old, new, window, label, group}`.

Each CSV row is one metric sample of one app's scenario run. A post-drift
record's window is that sample plus up to 19 earlier post-drift samples of the
same run/scenario/app: like the agent's window, it starts at the change.
(CSV samples are ~5-8 s apart, not METRIC_STEP_S, so latency_trend is only
approximate on these rows.) A pre-drift record's window holds pre samples only.

Label cleaning (documented because it changes the class balance):
- Benign_Or_Subtle → benign, Harmful_Performance_Degradation → degradation,
  any other Harmful_* → critical (the old "low_risk_drift" class never occurred).
- phase == "pre" → benign: the drift was not applied yet (baseline == live).
- rows whose notes start with "Synthetic" (506 augmentation rows, each its own
  collection_run_id) are dropped: they are not measurements, and 452 of them
  are post-drift rows with baseline_json == live_json, i.e. a harmful label on
  a spec that did not change.
- remaining post-drift rows with baseline_json == live_json (29) are dropped
  for the same reason: the recorded spec does not show the drift the label
  describes, and the health agent only assesses real spec changes.

CSV units: cpu_limit / cpu_usage_cores cores, memory_limit MiB, latency_p99
seconds, memory_working_set_bytes bytes, request_rate rps.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_CSV = Path(__file__).resolve().parents[1] / "data" / "health_drift.csv"
LABEL_MAP = {"Benign_Or_Subtle": "benign", "Harmful_Performance_Degradation": "degradation"}
MIB = 2.0**20
WINDOW_SAMPLES = 20


def _label(row: dict) -> str:
    if row["phase"] == "pre":
        return "benign"
    return LABEL_MAP.get(row["operational_label"], "critical")


def _sample(row: dict) -> dict[str, float]:
    return {
        "cpu_usage_cores": float(row["cpu_usage_cores"]),
        "cpu_limit_cores": float(row["cpu_limit"]),
        "memory_working_set_bytes": float(row["memory_working_set_bytes"]),
        "memory_limit_bytes": float(row["memory_limit"]) * MIB,
        "request_rate_rps": float(row["request_rate"]),
        "error_rate_rps": float(row["error_rate_5xx"]),
        "latency_p99_s": float(row["latency_p99"]),
        "restarts_total": float(row["restart_count"]),
        "replicas_desired": float(row["desired_replicas"]),
        "replicas_ready": float(row["ready_replicas"]),
    }


def load_records(path: str | Path = DEFAULT_CSV) -> list[dict]:
    csv.field_size_limit(sys.maxsize)
    with open(path, newline="") as fh:
        rows = [r for r in csv.DictReader(fh)
                if not r["notes"].startswith("Synthetic")
                and (r["phase"] == "pre" or r["baseline_json"] != r["live_json"])]

    # One collection run executes each scenario once per app (cpu/db/api/cache), interleaved in sample_index.
    runs: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        runs[(r["collection_run_id"], r["scenario_name"], r["app_name"])].append(r)

    records = []
    for run_rows in runs.values():
        run_rows.sort(key=lambda r: int(r["sample_index"]))
        window: dict[str, list[float]] = defaultdict(list)
        pre = True
        for r in run_rows:
            if pre and r["phase"] != "pre":   # drift applied: the agent's window starts here
                window.clear()
            pre = r["phase"] == "pre"
            for k, v in _sample(r).items():
                window[k].append(v)
            records.append({
                "old": json.loads(r["baseline_json"]),
                "new": json.loads(r["live_json"]),
                "window": {k: v[-WINDOW_SAMPLES:] for k, v in window.items()},
                "label": _label(r),
                "group": r["collection_run_id"],
            })
    return records
