import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient

def test_full_v4_pipeline():
    from services.health_model_server.main import app as h_app, _load_model as h_start
    from services.security_model_server.main import app as s_app, _load_model as s_start
    from services.dcm_server.main import app as d_app, _load_model as d_start
    h_start(); s_start(); d_start()
    h = TestClient(h_app); s = TestClient(s_app); d = TestClient(d_app)

    assert h.get("/health").json()["status"] == "ok"
    assert s.get("/health").json()["status"] == "ok"
    assert d.get("/health").json()["status"] == "ok"

    hr = h.post("/health/score", json={
        "old_spec": {"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"500m"}}}]}}}},
        "new_spec": {"spec":{"template":{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"50m"}}}]}}}},
        "metrics": [[0.0]*15]*60,
    }).json()
    assert 0.0 <= hr["risk_score"] <= 1.0
    assert len(hr["health_embedding"]) == 128
    assert "ci_width" in hr and "top_field" in hr

    sr = s.post("/security/score", json={
        "events": [{"syscall":"open","fd_path":"/data/f"},{"syscall":"write","fd_path":"/data/f"},
                   {"syscall":"rename","fd_path":"/data/f.locked"}]*20,
        "entropy_series": [2.0,3.0,5.0,7.2,7.6,7.8]*5,
        "early_signals": {"rename_burst": True},
    }).json()
    assert 0.0 <= sr["risk_score"] <= 1.0
    assert len(sr["security_embedding"]) == 64

    dr = d.post("/dcm/correlate", json={
        "health_embedding": hr["health_embedding"],
        "security_embedding": sr["security_embedding"],
        "health_assessment": {"risk_score": hr["risk_score"], "top_field": hr["top_field"]},
        "security_event": {"risk_score": sr["risk_score"], "top_syscall": sr["top_syscall"],
                           "entropy_spike": sr["entropy_spike"], "early_signals": {"rename_burst": True}},
        "want_nl_summary": True,
    }).json()
    assert 0.0 <= dr["correlation_score"] <= 1.0
    assert isinstance(dr["causal_chain"], list) and len(dr["causal_chain"]) > 0
    assert dr["nl_summary"]  # template fallback at minimum
