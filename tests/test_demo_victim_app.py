"""demo/victim-app probe endpoints: /fail, /cpu and the bounded, fsync-backed /disk counter."""

import importlib.util
import pathlib

import pytest
from fastapi.testclient import TestClient

APP = pathlib.Path(__file__).resolve().parents[1] / "demo" / "victim-app" / "app.py"


@pytest.fixture()
def app_module():
    spec = importlib.util.spec_from_file_location("victim_app_under_test", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sample(client, name):
    for line in client.get("/metrics").text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"):
            return float(line.rsplit(" ", 1)[1])
    return None


def test_fail_endpoint_is_a_counted_5xx(app_module):
    client = TestClient(app_module.create_app())
    assert client.get("/fail").status_code == 500
    text = client.get("/metrics").text
    assert 'http_requests_total{method="GET",path="/fail",status="500"} 1.0' in text


def test_cpu_endpoint_is_bounded(app_module):
    client = TestClient(app_module.create_app())
    assert client.get("/cpu?milliseconds=1").status_code == 200
    assert client.get("/cpu?milliseconds=100000").status_code == 422


def test_disk_endpoint_counts_bytes_and_stays_bounded(app_module, tmp_path, monkeypatch):
    probe = tmp_path / "probe"
    monkeypatch.setenv("KUBEHEAL_DISK_IO_PATH", str(probe))
    monkeypatch.setattr(app_module, "DISK_PROBE_MAX_BYTES", 100)
    client = TestClient(app_module.create_app())
    payload_len = len(b"kubeheal-demo-disk-metric\n")
    for _ in range(10):
        assert client.get("/disk").json() == {"bytes_written": payload_len}
    assert probe.stat().st_size <= 100 + payload_len
    assert _sample(client, "kubeheal_victim_disk_io_bytes_total") == 10 * payload_len


def test_disk_endpoint_reports_503_when_the_path_is_not_writable(app_module, tmp_path, monkeypatch):
    monkeypatch.setenv("KUBEHEAL_DISK_IO_PATH", str(tmp_path / "missing-dir" / "probe"))
    client = TestClient(app_module.create_app())
    assert client.get("/disk").status_code == 503
    assert _sample(client, "kubeheal_victim_disk_io_bytes_total") in (None, 0.0)
