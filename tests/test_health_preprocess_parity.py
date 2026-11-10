"""P5-Q2a: the Health Model input preprocessing is ONE definition for training and serving.

The reference below is a frozen, verbatim copy of the training code as it was BEFORE the shared module
(`build_metric_window` and its constants in models/train_health_model.py), with the noise left out. The
new path must give bit-identical float32 windows on every real CSV row, so the checkpoint's training
distribution is unchanged and live windows can be mapped onto it.
"""
import csv
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from models.health_model.metric_schema import INPUT_SEQUENCE_LENGTH, METRIC_COLUMNS, NUM_METRICS
from models.health_model import preprocess as pp

CSV_PATH = ROOT / "models" / "health_model" / "dit-merged-complete.csv"

# ---- frozen legacy reference (do not edit: it documents what the checkpoint was trained on) ------------
LEGACY_CSV_METRIC_MAP = {
    "request_rate": "http_request_rate",
    "error_rate_5xx": "http_error_rate",
    "latency_p99": "http_p99_latency_ms",
    "cpu_usage_cores": "cpu_usage_millicores",
    "memory_working_set_bytes": "memory_working_set_bytes",
    "cpu_limit": "cpu_limit_millicores",
    "memory_limit": "memory_limit_bytes",
    "restart_count": "pod_restarts_total",
    "app_instance_count": "http_request_rate",
}
LEGACY_NORM = {
    "http_request_rate": 100.0, "http_error_rate": 10.0, "http_p99_latency_ms": 2000.0,
    "cpu_usage_millicores": 2000.0, "memory_working_set_bytes": 1e9,
    "cpu_limit_millicores": 2000.0, "memory_limit_bytes": 2e9,
    "pod_restarts_total": 10.0,
}


def _lf(row, key, default=0.0):
    try:
        return float(row.get(key) or default)
    except Exception:
        return default


def legacy_window_no_noise(row):
    base = np.zeros(NUM_METRICS, dtype=np.float32)
    for csv_col, metric in LEGACY_CSV_METRIC_MAP.items():
        if metric in METRIC_COLUMNS:
            idx = METRIC_COLUMNS.index(metric)
            base[idx] = _lf(row, csv_col) / LEGACY_NORM.get(metric, 1.0)
    ti = METRIC_COLUMNS.index("cpu_throttle_percent")
    usage = _lf(row, "cpu_usage_cores")
    limit = _lf(row, "cpu_limit") or 1.0
    base[ti] = min(1.0, usage / max(limit, 1e-6))
    return np.tile(base, (INPUT_SEQUENCE_LENGTH, 1)).astype(np.float32)


@pytest.fixture(scope="module")
def rows():
    return list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))


def live_window_for(row):
    """The same sample expressed the way the Health Agent delivers it (live units), built here
    independently of preprocess.csv_row_to_raw."""
    raw = np.zeros((INPUT_SEQUENCE_LENGTH, NUM_METRICS))
    c = {n: i for i, n in enumerate(METRIC_COLUMNS)}
    raw[:, c["http_error_rate"]] = _lf(row, "error_rate_5xx")
    raw[:, c["http_p99_latency_ms"]] = _lf(row, "latency_p99") * 1000.0            # s -> ms
    raw[:, c["cpu_usage_millicores"]] = _lf(row, "cpu_usage_cores") * 1000.0       # cores -> m
    raw[:, c["memory_working_set_bytes"]] = _lf(row, "memory_working_set_bytes")
    raw[:, c["cpu_limit_millicores"]] = _lf(row, "cpu_limit") * 1000.0
    raw[:, c["memory_limit_bytes"]] = _lf(row, "memory_limit") * 1024 * 1024        # MiB -> bytes
    raw[:, c["pod_restarts_total"]] = _lf(row, "restart_count")
    # channels that carried no signal in training may hold ANY live value: they must be ignored
    for name in ("memory_rss_bytes", "http_p50_latency_ms", "http_p999_latency_ms",
                 "network_receive_bytes", "network_transmit_bytes", "disk_io_bytes"):
        raw[:, c[name]] = 123456.789
    raw[:, c["cpu_throttle_percent"]] = 87.0       # the real CFS ratio is not a model input
    raw[:, c["http_request_rate"]] = 55.0          # live request rate is not what the channel held in training
    return raw


def test_training_path_matches_the_frozen_legacy_code_bit_for_bit_on_every_csv_row(rows):
    assert len(rows) > 4000
    for i, row in enumerate(rows):
        raw, replicas = pp.csv_row_to_raw(row)
        new = pp.preprocess_window(raw, replicas)
        assert new.dtype == np.float32
        assert np.array_equal(new, legacy_window_no_noise(row)), f"row {i} differs"


def test_serving_path_gives_the_identical_tensor_for_the_same_sample(rows):
    for i, row in enumerate(rows):
        served = pp.preprocess_window(live_window_for(row), replicas=_lf(row, "app_instance_count"))
        assert np.array_equal(served, legacy_window_no_noise(row)), f"row {i} differs"


def test_the_trainer_uses_the_shared_module(rows):
    pytest.importorskip("torch")
    from models import train_health_model as t
    row = rows[17]
    np.random.seed(1234)
    got = t.build_metric_window(row)
    np.random.seed(1234)
    ref = legacy_window_no_noise(row)
    ref = ref + np.random.randn(*ref.shape).astype(np.float32) * 0.02       # the legacy noise step
    assert np.array_equal(got, ref.astype(np.float32))


def test_real_cfs_throttle_ratio_is_logged_separately_and_is_not_a_model_input():
    raw = np.zeros((4, NUM_METRICS))
    raw[:, 0] = [10.0, 20.0, 30.0, 99.0]                       # real CFS ratio x 100
    raw[:, METRIC_COLUMNS.index("cpu_usage_millicores")] = 250.0
    raw[:, METRIC_COLUMNS.index("cpu_limit_millicores")] = 500.0
    out = pp.preprocess_window(raw)
    assert np.allclose(out[:, 0], 0.5)                          # usage/limit proxy, whatever the CFS ratio is
    assert np.allclose(pp.cfs_throttle_percent(raw), [10.0, 20.0, 30.0, 99.0])


def test_missing_limit_counts_as_one_core_like_training_and_nan_is_zero():
    raw = np.zeros((2, NUM_METRICS))
    raw[:, METRIC_COLUMNS.index("cpu_usage_millicores")] = [500.0, np.nan]
    out = pp.preprocess_window(raw)
    assert np.allclose(out[:, 0], [0.5, 0.0])                   # 0.5 core over the default 1 core; NaN -> 0


def test_channels_without_a_training_signal_are_zero_and_request_rate_channel_is_replicas():
    raw = np.full((3, NUM_METRICS), 777.0)
    out = pp.preprocess_window(raw, replicas=3)
    for name in ("memory_rss_bytes", "http_p50_latency_ms", "http_p999_latency_ms",
                 "network_receive_bytes", "network_transmit_bytes", "disk_io_bytes"):
        assert not out[:, METRIC_COLUMNS.index(name)].any(), name
    assert np.allclose(out[:, METRIC_COLUMNS.index("http_request_rate")], 0.03)
    assert not pp.preprocess_window(raw)[:, METRIC_COLUMNS.index("http_request_rate")].any()   # no replicas -> 0


def test_bad_shape_is_rejected():
    with pytest.raises(ValueError):
        pp.preprocess_window(np.zeros((60, 14)))


def test_health_model_server_scales_the_raw_window_with_the_shared_preprocessing(rows):
    """End to end through the real server: the tensor the model receives equals the training-path tensor
    for the same sample, whatever raw values arrive in the channels training never used."""
    pytest.importorskip("torch")
    import torch
    from fastapi.testclient import TestClient
    from services.health_model_server import main as srv

    srv._load_model()
    seen = []
    model = srv.STATE["model"]
    orig = model.forward

    def spy(graph, metrics):
        seen.append(metrics.detach().clone())
        return orig(graph, metrics)
    model.forward = spy
    try:
        row = rows[321]
        raw = live_window_for(row)
        r = TestClient(srv.app).post("/health/score", json={
            "old_spec": {}, "new_spec": {}, "metrics": raw.tolist(),
            "replicas": _lf(row, "app_instance_count")})
        assert r.status_code == 200, r.text
        assert len(seen) == 1
        assert torch.equal(seen[0], torch.tensor(legacy_window_no_noise(row)))
        bad = TestClient(srv.app).post("/health/score", json={"old_spec": {}, "new_spec": {},
                                                               "metrics": [[0.0] * 14] * 60})
        assert bad.status_code == 422
    finally:
        model.forward = orig
