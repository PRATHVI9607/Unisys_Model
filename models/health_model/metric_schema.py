"""
Metric schema — KubeHeal v4 Health Model
========================================
Torch-free single source of truth for the Prometheus metric window layout.
Lives apart from metric_bilstm_encoder.py so the slim agent images (which ship
no torch) can import the column order / window size without pulling the model.
Both the encoder and the health agent's prometheus_client import from here.
"""

from typing import List

METRIC_COLUMNS: List[str] = [
    "cpu_throttle_percent",
    "cpu_usage_millicores",
    "memory_rss_bytes",
    "memory_working_set_bytes",
    "memory_limit_bytes",
    "cpu_limit_millicores",
    "http_request_rate",
    "http_error_rate",
    "http_p50_latency_ms",
    "http_p99_latency_ms",
    "http_p999_latency_ms",
    "pod_restarts_total",
    "network_receive_bytes",
    "network_transmit_bytes",
    "disk_io_bytes",
]
NUM_METRICS = len(METRIC_COLUMNS)          # 15
INPUT_SEQUENCE_LENGTH = 60                 # 5 min @ 5s resolution
