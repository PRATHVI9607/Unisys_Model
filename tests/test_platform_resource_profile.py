"""P9-H4: parsing and statistics of eval/resource_profile.py, with in-test fixtures (no cluster)."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("resource_profile", ROOT / "eval" / "resource_profile.py")
rp = importlib.util.module_from_spec(_spec)
sys.modules["resource_profile"] = rp
_spec.loader.exec_module(rp)


def matrix(*series):
    return {"status": "success", "data": {"resultType": "matrix", "result": [
        {"metric": m, "values": [[1000 + i, str(v)] for i, v in enumerate(vals)]} for m, vals in series]}}


def test_quantities():
    assert rp.parse_cpu_quantity("250m") == pytest.approx(0.25)
    assert rp.parse_cpu_quantity("12500000n") == pytest.approx(0.0125)
    assert rp.parse_cpu_quantity("2") == 2.0
    assert rp.parse_memory_quantity("512Mi") == 512 * 2**20
    assert rp.parse_memory_quantity("2048Ki") == 2048 * 1024
    assert rp.parse_memory_quantity("1G") == 1e9
    assert rp.parse_memory_quantity("12345") == 12345


def test_component_mapping_longest_prefix():
    assert rp.component_for_pod("kubeheal-health-model-7d9f-abcde") == "health-model"
    assert rp.component_for_pod("health-agent-6c8-xyz") == "health-agent"
    assert rp.component_for_pod("security-agent-zk2lm") == "security-agent"
    assert rp.component_for_pod("redis-0") == "redis"
    assert rp.component_for_pod("some-other-pod") is None


def test_parse_query_range_skips_nan_and_pod_less_series():
    payload = matrix(({"pod": "executor-1", "container": "executor"}, ["0.1", "NaN", "0.3"]),
                     ({"container": "x"}, [1]))
    out = rp.parse_query_range(payload)
    assert out == {("executor-1", "executor"): [0.1, 0.3]}


def test_parse_query_range_errors():
    with pytest.raises(ValueError):
        rp.parse_query_range({"status": "error", "error": "bad query"})
    with pytest.raises(ValueError):
        rp.parse_query_range({"status": "success", "data": {"resultType": "vector", "result": []}})


def test_statistics_nearest_rank():
    s = [5, 1, 4, 2, 3]
    assert rp.statistic(s, "min") == 1 and rp.statistic(s, "max") == 5
    assert rp.statistic(s, "mean") == pytest.approx(3)
    assert rp.statistic(s, "p50") == 3
    assert rp.statistic(s, "p99") == 5
    with pytest.raises(ValueError):
        rp.statistic([], "max")
    with pytest.raises(Exception):
        rp.validate_stat("median")


def test_rows_and_csv(tmp_path):
    cpu = rp.parse_query_range(matrix(({"pod": "kubeheal-dcm-aa-b", "container": "dcm-server"}, [0.1, 0.2, 0.4])))
    mem = rp.parse_query_range(matrix(({"pod": "kubeheal-dcm-aa-b", "container": "dcm-server"}, [100e6, 120e6])))
    rows = rp.build_rows(cpu, mem)
    assert {r["metric"] for r in rows} == {rp.CPU, rp.MEM}
    assert all(r["component"] == "dcm" for r in rows)
    path = tmp_path / "p.csv"
    rp.write_csv(rows, path)
    header = path.read_text(encoding="utf-8").splitlines()[0].split(",")
    assert header[:5] == ["component", "pod", "container", "metric", "samples"]


def test_values_snippet_uses_highest_pod_and_chosen_stats():
    cpu = {("kubeheal-health-model-a-1", "s"): [0.1, 0.2, 0.3], ("kubeheal-health-model-a-2", "s"): [0.1, 0.5]}
    mem = {("kubeheal-health-model-a-1", "s"): [100 * 2**20, 200 * 2**20],
           ("kubeheal-health-model-a-2", "s"): [50 * 2**20, 60 * 2**20]}
    values = rp.build_values(cpu, mem, request_stat="p50", limit_stat="max")
    assert values[("modelServers", "health")] == {
        "requests": {"cpu": "200m", "memory": "100Mi"},     # p50 nearest rank: pod-1 cpu 0.2, mem 100Mi
        "limits": {"cpu": "500m", "memory": "200Mi"}}
    text = rp.render_values_yaml(values, "header line")
    assert text.startswith("# header line")
    assert 'modelServers:\n  health:\n    resources:\n      limits:\n        cpu: "500m"' in text


def test_metrics_server_parse_and_polling():
    payload = {"items": [{"metadata": {"name": "executor-abc"},
                          "containers": [{"name": "executor", "usage": {"cpu": "25000000n", "memory": "64Mi"}}]}]}
    assert rp.parse_metrics_api(payload) == {("executor-abc", "executor"): (pytest.approx(0.025), 64 * 2**20)}
    t = {"now": 0.0}
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        t["now"] += s

    cpu, mem = rp.measure_metrics_server(lambda: payload, window_s=20, step_s=10, sleep=sleep,
                                         clock=lambda: t["now"])
    assert len(cpu[("executor-abc", "executor")]) == 3 and sleeps == [10, 10]


def test_prometheus_fetch_builds_query_range_url():
    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(matrix(({"pod": "executor-1", "container": "executor"}, [0.1]))).encode()

    def opener(url, timeout=None):
        seen.setdefault("urls", []).append(url)
        return Resp()

    cpu, mem = rp.measure_prometheus("http://prom:9090/", "kubeheal", window_s=60, step_s=5, rate_window_s=30,
                                     end=2000.0, opener=opener)
    assert len(seen["urls"]) == 2 and all("/api/v1/query_range?" in u for u in seen["urls"])
    assert "step=5s" in seen["urls"][0] and "start=1940.000" in seen["urls"][0]
    assert "container_cpu_usage_seconds_total" in rp.prometheus_queries("kubeheal", 30)[rp.CPU]


def test_cli_refuses_to_guess(capsys):
    with pytest.raises(SystemExit):   # no defaults for window, step, statistics
        rp.main(["--source", "prometheus", "--namespace", "kubeheal"])
    assert rp.main(["--source", "metrics-server", "--namespace", "kubeheal", "--window-s", "10", "--step-s", "5",
                    "--request-stat", "p95", "--limit-stat", "max", "--out-dir", "x"]) == 2   # needs --context
