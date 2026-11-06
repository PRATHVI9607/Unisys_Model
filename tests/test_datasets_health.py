import csv
import json

from training.datasets.health import load_records

SPEC = {"replicas": 1, "template": {"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "1"}}}]}}}
DRIFT = {"replicas": 1, "template": {"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "0.1"}}}]}}}


def test_windows_are_per_app_and_start_at_the_change(tmp_path):
    path = tmp_path / "drift.csv"
    cols = ["collection_run_id", "scenario_name", "app_name", "sample_index", "phase", "operational_label", "notes",
            "baseline_json", "live_json", "cpu_usage_cores", "cpu_limit", "memory_working_set_bytes", "memory_limit",
            "request_rate", "error_rate_5xx", "latency_p99", "restart_count", "desired_replicas", "ready_replicas"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, cols)
        w.writeheader()
        for app, latency in (("cpu_app", 0.1), ("db_app", 9.0)):   # same run + scenario, interleaved indices
            for i, phase in enumerate(["pre", "pre", "steady", "steady"]):
                w.writerow({"collection_run_id": "run1", "scenario_name": "cpu_cut", "app_name": app,
                            "sample_index": i, "phase": phase, "operational_label": "Benign_Or_Subtle", "notes": "",
                            "baseline_json": json.dumps(SPEC), "live_json": json.dumps(SPEC if phase == "pre" else DRIFT),
                            "cpu_usage_cores": 0.1, "cpu_limit": 1, "memory_working_set_bytes": 1, "memory_limit": 1,
                            "request_rate": 1, "error_rate_5xx": 0, "latency_p99": latency + i,
                            "restart_count": 0, "desired_replicas": 1, "ready_replicas": 1})
    recs = load_records(path)
    assert len(recs) == 8
    last_cpu_app = [r for r in recs if r["new"] == DRIFT and r["window"]["latency_p99_s"][0] < 5][-1]
    assert last_cpu_app["window"]["latency_p99_s"] == [2.1, 3.1]   # post-change samples of cpu_app only
