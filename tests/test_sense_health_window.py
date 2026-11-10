"""P5-H1 / P5-H2: Health Agent builds a real 60-step Prometheus range window and flags missing metrics."""
import asyncio
import json
from pathlib import Path

import numpy as np
import pytest

from agents.health_agent import prometheus_client as pc
from agents.health_agent.metric_queries import METRIC_SPECS, build_queries
from models.health_model.metric_schema import METRIC_COLUMNS, INPUT_SEQUENCE_LENGTH

FIX = Path(__file__).parent / "fixtures" / "prometheus"
NOW = 1_700_000_000.0


def _load(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))["metrics"]


class FakeProm:
    """Fake Prometheus query_range: answers each PromQL from a fixture and records the calls."""

    def __init__(self, metrics, fail=None):
        self.by_query = {q: c for c, q in build_queries("shop", "web").items()}
        self.metrics = metrics
        self.fail = fail or set()
        self.calls = []

    async def __call__(self, promql, start, end, step):
        self.calls.append((promql, start, end, step))
        col = self.by_query[promql]
        if col in self.fail:
            raise RuntimeError("boom")
        spec = self.metrics.get(col, {"absent": True})
        if spec.get("absent"):
            result = []
        elif spec.get("nan_only"):
            result = [{"metric": {}, "values": [[start + i * step, "NaN"] for i in range(60)]}]
        else:
            result = [{"metric": {}, "values": [[start + i * step, str(v)] for i, v in spec["points"]]}]
        return {"status": "success", "data": {"resultType": "matrix", "result": result}}


def run(coro):
    return asyncio.run(coro)


def fetch(metrics, **kw):
    prom = FakeProm(metrics, **kw)
    win = run(pc.fetch_metric_window("shop", "web", now=NOW, query_fn=prom))
    return win, prom


def test_mapping_table_covers_the_model_columns_in_order():
    assert [s.column for s in METRIC_SPECS] == METRIC_COLUMNS
    assert all(s.basis in ("standard", "demo-victim-app contract") for s in METRIC_SPECS)
    # every query is a distinct PromQL string for this workload
    assert len(set(build_queries("shop", "web").values())) == 15


def test_http_queries_match_the_demo_victim_app_exporter_contract():
    queries = build_queries("prod", "victim-app-abc")
    app_specs = {s.column: s for s in METRIC_SPECS if s.column.startswith("http_")}
    assert set(app_specs) == {
        "http_request_rate", "http_error_rate", "http_p50_latency_ms",
        "http_p99_latency_ms", "http_p999_latency_ms",
    }
    assert all(s.basis == "demo-victim-app contract" for s in app_specs.values())
    assert all('namespace="prod",pod=~"victim-app-abc.*"' in queries[name]
               for name in app_specs)
    assert "http_requests_total" in queries["http_request_rate"]
    assert 'status=~"5.."' in queries["http_error_rate"]
    assert "http_request_duration_seconds_bucket" in queries["http_p99_latency_ms"]


def test_full_window_uses_range_queries_5s_step_60_points():
    win, prom = fetch(_load("window_full"))
    assert len(prom.calls) == 15                      # one query_range per metric
    for _, start, end, step in prom.calls:
        assert step == 5
        assert end == NOW
        assert end - start == 59 * 5                  # 60 evaluation steps
    assert win.values.shape == (INPUT_SEQUENCE_LENGTH, 15)
    assert win.values.dtype == np.float32
    assert win.missing == [] and win.short == [] and win.complete
    assert win.mask.all()
    assert all(n == 60 for n in win.observed.values())
    # real series, not a broadcast of one instant value: values change across the window
    assert win.values[0, 0] != win.values[59, 0]
    # metric k (1-based) at step i is 10*k + 0.5*i in the fixture
    assert win.values[7, 2] == pytest.approx(10 * 3 + 0.5 * 7)


def test_missing_metrics_are_flagged_not_silently_zero():
    win, _ = fetch(_load("window_missing"))
    assert set(win.missing) == {"http_request_rate", "http_error_rate", "http_p50_latency_ms",
                                "http_p99_latency_ms", "http_p999_latency_ms"}
    assert not win.complete
    for c in win.missing:
        i = METRIC_COLUMNS.index(c)
        assert not win.mask[i]
        assert win.observed[c] == 0
    # metrics that exist keep real values
    assert win.mask.sum() == 10
    assert win.values[:, METRIC_COLUMNS.index("cpu_usage_millicores")].min() > 0
    assert "memory_rss_bytes" not in win.missing


def test_short_window_forward_and_back_fill_with_counts():
    win, _ = fetch(_load("window_short"))
    assert win.missing == []
    assert set(win.short) == {"cpu_usage_millicores", "memory_rss_bytes"}
    assert win.observed["cpu_usage_millicores"] == 40
    assert win.observed["memory_rss_bytes"] == 55
    cpu = win.values[:, METRIC_COLUMNS.index("cpu_usage_millicores")]
    assert cpu[0] == cpu[19] == pytest.approx(20 + 0.5 * 20)       # leading gap back-filled from first real
    rss = win.values[:, METRIC_COLUMNS.index("memory_rss_bytes")]
    assert rss[30] == rss[34] == pytest.approx(30 + 0.5 * 29)      # inner gap forward-filled
    assert rss[35] == pytest.approx(30 + 0.5 * 35)


def test_one_failing_query_flags_only_that_metric():
    win, _ = fetch(_load("window_full"), fail={"memory_rss_bytes"})
    assert win.missing == ["memory_rss_bytes"]


def test_no_data_at_all_raises_instead_of_returning_zeros():
    with pytest.raises(pc.PrometheusUnavailable):
        fetch({})                                    # every query returns an empty result
    with pytest.raises(pc.PrometheusUnavailable):
        fetch(_load("window_full"), fail=set(METRIC_COLUMNS))


def test_multi_series_reduce_rules():
    # latency and throttle take the worst series, sum-type queries are already one series
    spec = {s.column: s for s in METRIC_SPECS}
    assert spec["http_p99_latency_ms"].agg == "max" and spec["cpu_throttle_percent"].agg == "max"
    grid = pc._series_to_grid(
        [{"values": [[NOW, "1"]]}, {"values": [[NOW, "3"]]}], NOW, 5, "max")
    assert grid == {0: 3.0}


def test_wait_for_fresh_metric_window_polls_then_succeeds_and_caches():
    pc._prometheus_cache.clear()
    state = {"t": NOW, "calls": 0}
    full = FakeProm(_load("window_full"))

    async def flaky(promql, start, end, step):
        state["calls"] += 1
        if state["calls"] <= 15:                     # whole first attempt fails
            raise RuntimeError("down")
        return await full(promql, start, end, step)

    async def fake_sleep(s):
        state["t"] += s

    win = run(pc.wait_for_fresh_metric_window(
        "shop", "web", query_fn=flaky, clock=lambda: state["t"], sleep=fake_sleep, timeout_s=30))
    assert win.complete and state["t"] == NOW + 2
    calls_after = state["calls"]
    again = run(pc.wait_for_fresh_metric_window(
        "shop", "web", query_fn=flaky, clock=lambda: state["t"], sleep=fake_sleep))
    assert again is win and state["calls"] == calls_after       # served from the shared cache


def test_wait_times_out_with_unavailable_not_zeros():
    pc._prometheus_cache.clear()
    state = {"t": NOW}

    async def down(*a):
        raise RuntimeError("down")

    async def fake_sleep(s):
        state["t"] += s

    with pytest.raises(pc.PrometheusUnavailable):
        run(pc.wait_for_fresh_metric_window("shop", "web", query_fn=down,
                                            clock=lambda: state["t"], sleep=fake_sleep, timeout_s=6))
    assert state["t"] >= NOW + 6


def test_wait_for_fresh_metrics_keeps_ndarray_contract(monkeypatch):
    pc._prometheus_cache.clear()
    prom = FakeProm(_load("window_full"))
    orig = pc.fetch_metric_window

    async def patched(ns, pod, url, *, now=None, query_fn=None):
        return await orig(ns, pod, url, now=NOW, query_fn=prom)

    monkeypatch.setattr(pc, "fetch_metric_window", patched)
    arr = run(pc.wait_for_fresh_metrics("shop", "web", "http://unused"))
    assert isinstance(arr, np.ndarray) and arr.shape == (60, 15)


def test_assess_health_sends_missing_flags_and_publishes_them(monkeypatch):
    """The agent passes the window values plus the missing list to the model server and puts the list in
    the published assessment."""
    from agents.health_agent import agent as ha

    win, _ = fetch(_load("window_missing"))
    seen = {}

    class Resp:
        status = 200
        async def json(self): return {"risk_score": 0.7, "label": "drift", "ci_width": 0.1,
                                      "top_field": "limits.cpu"}
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def post(self, url, json=None, timeout=None):
            seen["payload"] = json
            return Resp()

    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: Session())
    agent = ha.HealthAgent(redis_url="redis://unused")
    out = run(agent._assess_health("shop", "web", {"a": 1}, {"a": 2}, win, "Low"))
    assert out["metrics_missing"] == win.missing
    assert seen["payload"]["metrics_missing"] == win.missing
    assert np.array(seen["payload"]["metrics"]).shape == (60, 15)

    published = {}

    class R:
        async def xadd(self, stream, payload): published.update(payload)
        async def hset(self, *a, **k): pass
        async def expire(self, *a, **k): pass

    agent.redis = R()
    run(agent._publish_assessment(out))
    assert json.loads(published["metrics_missing_json"]) == win.missing
    assert json.loads(published["metrics_observed_json"])["http_request_rate"] == 0


def test_health_model_unavailable_still_fails_closed(monkeypatch):
    from agents.health_agent import agent as ha
    import aiohttp

    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def post(self, *a, **k): raise RuntimeError("connection refused")

    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: Session())
    win, _ = fetch(_load("window_full"))
    agent = ha.HealthAgent(redis_url="redis://unused")
    assert run(agent._assess_health("shop", "web", {}, {}, win, "Low")) is None


def _assess_and_publish(monkeypatch, window):
    from agents.health_agent import agent as ha
    import aiohttp

    class Resp:
        status = 200
        async def json(self): return {"risk_score": 0.7, "label": "drift", "ci_width": 0.08,
                                      "top_field": "limits.cpu"}
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def post(self, url, json=None, timeout=None): return Resp()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: Session())
    agent = ha.HealthAgent(redis_url="redis://unused")
    out = run(agent._assess_health("shop", "web", {"a": 1}, {"a": 2}, window, "Low"))
    published = {}

    class R:
        async def xadd(self, stream, payload): published.update(payload)
        async def hset(self, *a, **k): pass
        async def expire(self, *a, **k): pass

    agent.redis = R()
    run(agent._publish_assessment(out))
    return out, published


def test_missing_metrics_publish_max_ci_width_but_keep_the_assessment(monkeypatch):
    from agents.fusion_agent.decision_policy import make_decision, DecisionInput, Decision
    win, _ = fetch(_load("window_missing"))
    out, pub = _assess_and_publish(monkeypatch, win)
    assert out is not None                                      # the assessment is not dropped
    assert float(pub["health_ci_width"]) == 1.0
    assert json.loads(pub["metrics_missing_json"]) == win.missing
    assert float(pub["health_risk"]) == pytest.approx(0.7)
    # the policy cannot auto-patch on it
    d = make_decision(DecisionInput(health_risk=0.99, health_ci_width=float(pub["health_ci_width"]),
                                    namespace_tier="prod", mode="enforce"))
    assert d.decision == Decision.HUMAN_PATCH


def test_complete_window_keeps_the_models_ci_width(monkeypatch):
    win, _ = fetch(_load("window_full"))
    _, pub = _assess_and_publish(monkeypatch, win)
    assert float(pub["health_ci_width"]) == pytest.approx(0.08)
    assert json.loads(pub["metrics_missing_json"]) == []


def test_agent_sends_replicas_and_logs_the_real_cfs_ratio_separately(monkeypatch):
    """P5-Q2a: the model server scales the RAW window (shared preprocessing); the agent sends the replica
    count and publishes the real CFS throttle ratio on its own, not as a model input."""
    from agents.health_agent import agent as ha

    win, _ = fetch(_load("window_full"))
    seen = {}

    class Resp:
        status = 200
        async def json(self): return {"risk_score": 0.7, "label": "drift", "ci_width": 0.1}
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def post(self, url, json=None, timeout=None):
            seen["payload"] = json
            return Resp()

    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: Session())
    agent = ha.HealthAgent(redis_url="redis://unused")
    out = run(agent._assess_health("shop", "web", {"a": 1}, {"a": 2}, win, "Low", replicas=3))
    assert seen["payload"]["replicas"] == 3
    # raw values are sent unscaled
    assert np.allclose(np.array(seen["payload"]["metrics"]), win.values)
    assert out["cfs_throttle_percent"] == pytest.approx(float(win.values[-1, 0]))

    published = {}

    class R:
        async def xadd(self, stream, payload): published.update(payload)
        async def hset(self, *a, **k): pass
        async def expire(self, *a, **k): pass

    agent.redis = R()
    run(agent._publish_assessment(out))
    assert float(published["cfs_throttle_percent"]) == pytest.approx(float(win.values[-1, 0]), abs=1e-3)
