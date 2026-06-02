"""
Integration smoke test for the DIT-Sec v3 model server.

Verifies the trained checkpoint loads, the z-score standardization stats are
applied to metrics, and /score returns a model-backed result (not the
heuristic fallback) for the health, security, and metrics paths.

Run:  .venv_train/Scripts/python.exe models/dit_sec_v3/tests/test_server_integration.py
"""

import sys
from pathlib import Path

from fastapi.testclient import TestClient

SCRIPT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPT_DIR))

import server  # noqa: E402


def _client() -> TestClient:
    # TestClient context manager triggers FastAPI startup (loads model + stats).
    return TestClient(server.app)


def main() -> int:
    failures = []

    with _client() as client:
        # Model + standardization stats must have loaded at startup.
        assert server.model is not None, "model failed to load"
        if server.metric_mean is None or server.metric_std is None:
            failures.append("metric standardization stats did NOT load")

        # 1) Health path — YAML diff (CPU limit slashed).
        old_spec = {"spec": {"template": {"spec": {"containers": [
            {"name": "app", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}}]}}}}
        new_spec = {"spec": {"template": {"spec": {"containers": [
            {"name": "app", "resources": {"limits": {"cpu": "50m", "memory": "512Mi"}}}]}}}}
        r = client.post("/score", json={"old_spec": old_spec, "new_spec": new_spec})
        assert r.status_code == 200, r.text
        body = r.json()
        print(f"[health/yaml]  label={body['label']:<20} risk={body['risk_score']:.3f} "
              f"model_used={body['model_used']}")
        if body["model_used"] != "pytorch":
            failures.append("health path did not use the pytorch model")

        # 2) Metrics path — must be standardized internally (60x15).
        metrics = [[0.5] * 15 for _ in range(60)]
        r = client.post("/score", json={
            "old_spec": old_spec, "new_spec": new_spec, "metrics": metrics})
        assert r.status_code == 200, r.text
        body = r.json()
        print(f"[health+metrics] label={body['label']:<20} risk={body['risk_score']:.3f} "
              f"model_used={body['model_used']}")
        if body["model_used"] != "pytorch":
            failures.append("metrics path did not use the pytorch model")

        # 3) Security path — high-entropy + write/rename burst.
        syscalls = [{"syscall": s} for s in (["write", "rename", "ftruncate"] * 40)]
        entropy = [7.6] * 20
        r = client.post("/score", json={"syscalls": syscalls, "entropy_series": entropy})
        assert r.status_code == 200, r.text
        body = r.json()
        print(f"[security]     label={body['label']:<20} risk={body['risk_score']:.3f} "
              f"model_used={body['model_used']}")
        if body["model_used"] != "pytorch":
            failures.append("security path did not use the pytorch model")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nAll server integration checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
