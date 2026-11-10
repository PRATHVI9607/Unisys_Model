"""
Health Model metric preprocessing: ONE definition for training and serving (P5-Q2a).
====================================================================================
Torch-free (numpy only) so the slim agent images can import it. Used by

  * training:  `models/train_health_model.py` `build_metric_window` (CSV row -> raw window -> here),
  * serving:   `services/health_model_server` (raw Prometheus window -> here, then the model),
  * the Health Agent, which sends the RAW window plus the replica count and logs the real CFS
    throttle ratio separately (`cfs_throttle_percent`), because that ratio is NOT a model input.

Why this exists. The checkpoint was trained on windows built from 9 scalar CSV columns, scaled by
constants and with a usage/limit proxy in the throttle channel (see `NORM` below). Serving used to
pass raw Prometheus values (bytes, millicores, milliseconds), which is outside that distribution.
This module reproduces the training scaling EXACTLY, so a live window lands where the training
windows were. It does NOT make the model validated on live data: the training windows were scalar
CSV values broadcast over time, not real time series, and the model has not been evaluated on real
cluster windows. Retraining on live cluster data (P12-H) is a future step, not approved.

Raw input (what `agents/health_agent/metric_queries.py` returns, one row per 5 s step, 15 columns in
`METRIC_COLUMNS` order, live units):

    cpu_usage_millicores, cpu_limit_millicores     millicores
    memory_working_set_bytes, memory_limit_bytes   bytes
    http_p99_latency_ms                            milliseconds
    http_error_rate                                5xx responses per second
    pod_restarts_total                             count
    cpu_throttle_percent                           real CFS throttle ratio x 100 (logged, not used)
    the other columns                              not used (see below)

Model input, per channel, as the training windows contained it (CSV units in brackets):

    cpu_throttle_percent      min(1, usage_cores / max(limit_cores, 1e-6)); a missing or zero limit
                              counts as 1 core (training: `limit or 1.0`). A USAGE/LIMIT PROXY IN 0..1,
                              not a throttle percentage.
    cpu_usage_millicores      cores / 2000          [CSV cpu_usage_cores, in cores]
    cpu_limit_millicores      cores / 2000          [CSV cpu_limit, in cores]
    memory_working_set_bytes  bytes / 1e9
    memory_limit_bytes        MiB / 2e9             [CSV memory_limit, in MiB]
    http_error_rate           rate / 10
    http_p99_latency_ms       seconds / 2000        [CSV latency_p99, in seconds]
    pod_restarts_total        count / 10
    http_request_rate         REPLICA COUNT / 100. In training the CSV map listed `request_rate` and then
                              `app_instance_count` for this channel, so the second one overwrote the first:
                              the channel holds app_instance_count (the replica count, 2 to 3 in the CSV),
                              not a request rate. Reproduced here on purpose; a retraining should fix it.
    all other channels        0 in training (memory_rss_bytes, http_p50_latency_ms,
                              http_p999_latency_ms, network_receive_bytes, network_transmit_bytes,
                              disk_io_bytes): the model never saw a signal there, so they are zeroed.

The constants in `NORM` are the training constants. Several of them do not match the CSV units
(for example latency in seconds is divided by a number meant for milliseconds, so those channels sit
near zero in training); they are kept as they are because the checkpoint depends on them.
"""

import json
from pathlib import Path
from typing import Mapping, Optional, Tuple, Union

import numpy as np

from models.health_model.metric_schema import INPUT_SEQUENCE_LENGTH, METRIC_COLUMNS, NUM_METRICS

# Version of THIS preprocessing. "v1-legacy" is the quirk-preserving behaviour the current checkpoint was
# trained with (see the module docstring). A checkpoint records the version it expects in a sidecar file next
# to it (`<checkpoint stem>.preprocess.json`); the Health Model server refuses to start when that version and
# this one differ, so a retrained checkpoint (new preprocessing, new version) cannot be served with the old
# code, and the old checkpoint cannot be served with new code.
PREPROCESS_VERSION = "v1-legacy"
SIDECAR_SUFFIX = ".preprocess.json"


class PreprocessVersionMismatch(RuntimeError):
    """The checkpoint's expected preprocessing version is missing or differs from the code's."""


def sidecar_path(checkpoint_path) -> Path:
    p = Path(checkpoint_path)
    return p.with_name(p.stem + SIDECAR_SUFFIX)


def sidecar_object_name(checkpoint_object: str) -> str:
    """Registry object name of the sidecar that belongs to a checkpoint object."""
    head, _, tail = checkpoint_object.rpartition("/")
    stem = tail.rsplit(".", 1)[0] if "." in tail else tail
    return (head + "/" if head else "") + stem + SIDECAR_SUFFIX


def write_sidecar(checkpoint_path, version: str = PREPROCESS_VERSION) -> Path:
    """Record the preprocessing version a checkpoint was trained with (call after saving it)."""
    out = sidecar_path(checkpoint_path)
    out.write_text(json.dumps({"preprocess_version": version, "checkpoint": Path(checkpoint_path).name},
                              indent=2) + "\n", encoding="utf-8")
    return out


def parse_sidecar(text) -> Optional[str]:
    """Version string from sidecar content, or None when absent or unreadable."""
    try:
        v = json.loads(text).get("preprocess_version")
    except Exception:
        return None
    return v if isinstance(v, str) and v.strip() else None


def read_sidecar_version(checkpoint_path) -> Optional[str]:
    p = sidecar_path(checkpoint_path)
    return parse_sidecar(p.read_text(encoding="utf-8")) if p.exists() else None


def check_version(expected: Optional[str], code_version: str = PREPROCESS_VERSION) -> None:
    """Fail closed: raise unless the checkpoint expects exactly the code's preprocessing version."""
    if expected is None:
        raise PreprocessVersionMismatch(
            f"checkpoint has no preprocessing version sidecar (code is {code_version!r}); refusing to start")
    if expected != code_version:
        raise PreprocessVersionMismatch(
            f"checkpoint expects preprocessing {expected!r} but the code is {code_version!r}; refusing to start")


# Training constants (models/train_health_model.py before P5-Q2a).
NORM = {
    "http_request_rate": 100.0, "http_error_rate": 10.0, "http_p99_latency_ms": 2000.0,
    "cpu_usage_millicores": 2000.0, "memory_working_set_bytes": 1e9,
    "cpu_limit_millicores": 2000.0, "memory_limit_bytes": 2e9,
    "pod_restarts_total": 10.0,
}
BYTES_PER_MIB = 1024 * 1024
COL = {name: i for i, name in enumerate(METRIC_COLUMNS)}


def _f(x, default=0.0) -> float:
    """Training's `_f`: a missing, empty, zero or unparsable value becomes the default."""
    try:
        return float(x or default)
    except Exception:
        return default


def cfs_throttle_percent(raw: np.ndarray) -> np.ndarray:
    """The real CFS throttle ratio x 100 from the raw window (channel 0). Logged, never a model input."""
    return np.asarray(raw, dtype=np.float64)[:, COL["cpu_throttle_percent"]]


def preprocess_window(raw, replicas: Optional[Union[float, np.ndarray]] = None) -> np.ndarray:
    """Raw live-unit window [T,15] -> model input [T,15] float32. Deterministic, no noise.
    NaN (a missing sample) is treated as 0 like a missing CSV value. `replicas` is the Deployment's
    replica count (scalar or length-T); None counts as 0 for the http_request_rate channel."""
    raw = np.nan_to_num(np.asarray(raw, dtype=np.float64), nan=0.0, posinf=0.0, neginf=0.0)
    if raw.ndim != 2 or raw.shape[1] != NUM_METRICS:
        raise ValueError(f"raw metric window must be [T,{NUM_METRICS}], got {raw.shape}")
    out = np.zeros(raw.shape, dtype=np.float64)

    usage_cores = raw[:, COL["cpu_usage_millicores"]] / 1000.0
    limit_cores = raw[:, COL["cpu_limit_millicores"]] / 1000.0
    limit_cores = np.where(limit_cores == 0.0, 1.0, limit_cores)           # training: `limit or 1.0`
    out[:, COL["cpu_throttle_percent"]] = np.minimum(1.0, usage_cores / np.maximum(limit_cores, 1e-6))
    out[:, COL["cpu_usage_millicores"]] = usage_cores / NORM["cpu_usage_millicores"]
    out[:, COL["cpu_limit_millicores"]] = raw[:, COL["cpu_limit_millicores"]] / 1000.0 / NORM["cpu_limit_millicores"]
    out[:, COL["memory_working_set_bytes"]] = raw[:, COL["memory_working_set_bytes"]] / NORM["memory_working_set_bytes"]
    out[:, COL["memory_limit_bytes"]] = (
        raw[:, COL["memory_limit_bytes"]] / BYTES_PER_MIB / NORM["memory_limit_bytes"])
    out[:, COL["http_error_rate"]] = raw[:, COL["http_error_rate"]] / NORM["http_error_rate"]
    out[:, COL["http_p99_latency_ms"]] = raw[:, COL["http_p99_latency_ms"]] / 1000.0 / NORM["http_p99_latency_ms"]
    out[:, COL["pod_restarts_total"]] = raw[:, COL["pod_restarts_total"]] / NORM["pod_restarts_total"]
    rep = np.zeros(raw.shape[0]) if replicas is None else np.broadcast_to(
        np.asarray(replicas, dtype=np.float64), (raw.shape[0],))
    out[:, COL["http_request_rate"]] = rep / NORM["http_request_rate"]
    return out.astype(np.float32)


def csv_row_to_raw(row: Mapping, steps: int = INPUT_SEQUENCE_LENGTH) -> Tuple[np.ndarray, float]:
    """Training side: a CSV row (CSV units) -> raw live-unit window [steps,15] and the replica count,
    so that `preprocess_window` is the only place that scales."""
    raw = np.zeros((steps, NUM_METRICS), dtype=np.float64)
    raw[:, COL["http_request_rate"]] = _f(row.get("request_rate"))          # present in the CSV; unused by the model
    raw[:, COL["http_error_rate"]] = _f(row.get("error_rate_5xx"))
    raw[:, COL["http_p99_latency_ms"]] = _f(row.get("latency_p99")) * 1000.0           # seconds -> ms
    raw[:, COL["cpu_usage_millicores"]] = _f(row.get("cpu_usage_cores")) * 1000.0      # cores -> millicores
    raw[:, COL["memory_working_set_bytes"]] = _f(row.get("memory_working_set_bytes"))
    raw[:, COL["cpu_limit_millicores"]] = _f(row.get("cpu_limit")) * 1000.0            # cores -> millicores
    raw[:, COL["memory_limit_bytes"]] = _f(row.get("memory_limit")) * BYTES_PER_MIB    # MiB -> bytes
    raw[:, COL["pod_restarts_total"]] = _f(row.get("restart_count"))
    return raw, _f(row.get("app_instance_count"))
