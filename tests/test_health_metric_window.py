"""V5-D4a: the Health Agent's Prometheus window for the LightGBM health model (offline)."""
import asyncio
import json
import logging
import re

import aiohttp

from agents.health_agent import metric_window as mw
from kubeheal.features.health import METRIC_STEP_S, RAW_METRICS, health_features


def _rx(deployment: str) -> re.Pattern:
    # The query text is inside a PromQL double-quoted string: `\\` there is one backslash in the regex.
    return re.compile(mw.pod_regex(deployment).replace("\\\\", "\\"))


def _ok(values):
    return {"status": "success", "data": {"resultType": "matrix",
                                          "result": [{"metric": {}, "values": values}]}}


EMPTY = {"status": "success", "data": {"resultType": "matrix", "result": []}}


class FakeResp:
    def __init__(self, body, status=200):
        self.body, self.status = body, status
        self.request_info = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self.body

    async def text(self):
        return json.dumps(self.body)


class FakeSession:
    """Answers per query by matching a PromQL substring; 'boom' raises, an int is an HTTP status."""

    def __init__(self, answers):
        self.answers, self.urls, self.params, self.timeouts = answers, [], [], []

    def get(self, url, params, timeout):
        self.urls.append(url)
        self.params.append(params)
        self.timeouts.append(timeout)
        for needle, ans in self.answers.items():
            if needle in params["query"]:
                if ans == "boom":
                    raise aiohttp.ClientConnectionError("refused")
                if isinstance(ans, int):
                    return FakeResp({"status": "error"}, status=ans)
                return FakeResp(ans)
        return FakeResp(EMPTY)


def run(coro):
    return asyncio.run(coro)


# -- pod_regex ---------------------------------------------------------------
def test_pod_regex_matches_own_pods_only():
    rx = _rx("web")
    assert rx.fullmatch("web-5d9f7c6b4-x7k2p")
    for sibling in ("web-migrate-x7k2p", "web-db-0", "web-agent-k8s2z"):
        assert not rx.fullmatch(sibling), sibling


def test_pod_regex_escapes_dots():
    raw = mw.pod_regex("my.app")
    assert raw.startswith("my\\\\.app-")             # PromQL string escape of the regex `\.`
    rx = _rx("my.app")
    assert rx.fullmatch("my.app-5d9f7c6b4-x7k2p")
    assert not rx.fullmatch("myXapp-5d9f7c6b4-x7k2p")


# -- build_queries -----------------------------------------------------------
def test_query_names_equal_raw_metrics_plus_extras():
    q = mw.build_queries("shop", "web")
    assert list(q)[:len(RAW_METRICS)] == RAW_METRICS
    assert set(q) == set(RAW_METRICS) | {"replicas_updated", "replicas_unavailable"}
    assert set(q) == set(RAW_METRICS) | set(mw.EXTRA_METRICS)
    assert len(q) == len(RAW_METRICS) + 2
    assert not set(mw.EXTRA_METRICS) & set(RAW_METRICS)     # the extras are not model features


def test_every_query_is_scoped_to_the_namespace_and_deployment():
    q = mw.build_queries("shop", "web")
    for name, promql in q.items():
        assert 'namespace="shop"' in promql, name
        assert 'pod=~"' in promql or 'deployment="web"' in promql, name
    assert 'deployment="web"' in q["replicas_desired"]
    assert 'resource="cpu"' in q["cpu_limit_cores"] and 'resource="memory"' in q["memory_limit_bytes"]
    assert "*100" not in q["cpu_throttled_ratio"].replace(" ", "")      # a ratio, not a percent
    assert 'container!="POD"' in q["cpu_usage_cores"]


def test_queries_use_victim_app_and_exporter_series():
    q = mw.build_queries("prod", "victim-app")
    assert "http_requests_total" in q["request_rate_rps"]
    assert 'status=~"5.."' in q["error_rate_rps"]
    assert "http_request_duration_seconds_bucket" in q["latency_p99_s"]
    assert "kube_pod_container_status_restarts_total" in q["restarts_total"]
    assert "kube_deployment_status_replicas_ready" in q["replicas_ready"]
    assert not any("container_fs_" in p for p in q.values())


# -- parse_range -------------------------------------------------------------
def test_parse_range_empty_nan_inf_and_errors():
    assert mw.parse_range(_ok([[1, "0.5"], [2, "NaN"], [3, "+Inf"], [4, "-Inf"], [5, "0.25"]])) == [0.5, 0.25]
    assert mw.parse_range(EMPTY) is None
    assert mw.parse_range({"status": "success", "data": {}}) is None
    assert mw.parse_range({"status": "error", "error": "bad"}) is None
    assert mw.parse_range(_ok([[1, "NaN"], [2, "+Inf"]])) is None
    assert mw.parse_range(_ok([[1, "abc"], [2, None]])) is None
    assert mw.parse_range(_ok([[1, "0"]])) == [0.0]          # a real zero is data, not missing


def test_parse_range_uses_first_series_only():
    body = {"status": "success", "data": {"result": [
        {"metric": {"pod": "a"}, "values": [[1, "1"], [2, "2"]]},
        {"metric": {"pod": "b"}, "values": [[1, "9"], [2, "9"]]}]}}
    assert mw.parse_range(body) == [1.0, 2.0]


# -- fetch_window ------------------------------------------------------------
def test_fetch_window_marks_failed_and_empty_as_none_never_zero(caplog):
    session = FakeSession({"container_cpu_usage_seconds_total": _ok([[1, "0.2"], [2, "0.4"]]),
                           "container_memory_working_set_bytes": "boom",
                           "kube_deployment_spec_replicas": 500})
    with caplog.at_level(logging.WARNING):
        w = run(mw.fetch_window(session, "http://prom:9090", "shop", "web", 1000.0, 1120.0))
    assert w["cpu_usage_cores"] == [0.2, 0.4]
    assert w["memory_working_set_bytes"] is None             # connection error
    assert w["replicas_desired"] is None                     # HTTP 500
    assert w["cpu_limit_cores"] is None                      # empty result
    assert set(w) == set(mw.build_queries("shop", "web"))
    assert [k for k, v in w.items() if v is not None] == ["cpu_usage_cores"]
    assert not any(v == [0.0] or v == 0 for v in w.values())
    assert any("queries failed" in r.message for r in caplog.records)


def test_one_failing_query_does_not_discard_the_others():
    answers = {"container_cpu_usage_seconds_total": "boom",
               "kube_deployment_status_replicas_ready": _ok([[1, "2"]]),
               "kube_deployment_spec_replicas": _ok([[1, "2"]])}
    w = run(mw.fetch_window(FakeSession(answers), "http://prom:9090", "shop", "web", 1.0, 61.0))
    assert w["cpu_usage_cores"] is None
    assert w["replicas_ready"] == [2.0] and w["replicas_desired"] == [2.0]


def test_window_and_step_are_forwarded():
    session = FakeSession({})
    run(mw.fetch_window(session, "http://prom:9090", "shop", "web", 1000.0, 1120.5))
    assert len(session.urls) == len(mw.build_queries("shop", "web"))
    assert all(u == "http://prom:9090/api/v1/query_range" for u in session.urls)
    assert {(p["start"], p["end"], p["step"]) for p in session.params} == {
        ("1000.000", "1120.500", str(METRIC_STEP_S))}
    assert METRIC_STEP_S == 15
    assert {p["query"] for p in session.params} == set(mw.build_queries("shop", "web").values())
    assert all(t.total == mw.QUERY_TIMEOUT_S for t in session.timeouts)

    session = FakeSession({})
    run(mw.fetch_window(session, "http://prom:9090", "shop", "web", 10.0, 70.0, step_s=30))
    assert {p["step"] for p in session.params} == {"30"}


def test_missing_metrics_and_health_features_accept_the_result():
    session = FakeSession({"container_cpu_usage_seconds_total": _ok([[1, "0.1"], [2, "0.2"]]),
                           "kube_pod_container_resource_limits{namespace=\"shop\",pod=~\"web-[bcdfghjklmnpqrstvwxz2456789]{1,10}"
                           "-[bcdfghjklmnpqrstvwxz2456789]{5}\",resource=\"cpu\"}": _ok([[1, "0.5"], [2, "0.5"]])})
    w = run(mw.fetch_window(session, "http://prom:9090", "shop", "web", 1.0, 31.0))
    miss = mw.missing_metrics(w)
    assert "cpu_usage_cores" not in miss and "cpu_limit_cores" not in miss
    assert set(miss) == set(RAW_METRICS) - {"cpu_usage_cores", "cpu_limit_cores"}
    assert "replicas_updated" not in miss                     # extras never reported as model gaps
    health_features({}, {}, w)                                # None entries are accepted, no exception
