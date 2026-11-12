"""Review fixes B, F, G, H for the sensing agents: unknown tier, explicit model_scored and a model outage event
from the Health Agent, protobuf Falco time and a first-seen T0, and a model answer that is NaN or incomplete."""
import asyncio
import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

from agents.security_agent import falco_client as fc
from agents.security_agent.agent import falco_t0_ms
from agents.security_agent.syscall_window import FalcoWindowTracker

BENIGN = Path(__file__).parent / "fixtures" / "falco" / "benign_sensitive_read.jsonl"


def run(coro):
    return asyncio.run(coro)


# ---- B: tier names ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("namespace,tier", [
    ("prod", "prod"), ("production", "prod"), ("shop-prod", "prod"), ("staging", "staging"), ("stage-1", "staging"),
    ("dev", "dev"), ("team-dev", "dev"),
    ("default", "unknown"), ("kube-system", "unknown"), ("payments", "unknown"), ("", "unknown"), (None, "unknown"),
])
def test_both_agents_emit_unknown_for_a_namespace_that_matches_no_known_name(namespace, tier):
    from agents.health_agent.agent import namespace_tier as health_tier
    from agents.security_agent.agent import namespace_tier as sec_tier
    assert sec_tier(namespace) == tier and health_tier(namespace) == tier


def test_security_event_of_an_unnamed_namespace_carries_tier_unknown():
    from agents.security_agent import agent as sa
    ag = sa.SecurityAgent(redis_url="redis://unused")
    ag.redis = _Redis()
    run(ag._publish_security_event({"pod": "p", "namespace": "payments", "pid": 7}, 0.9, {}))
    assert ag.redis.streams[0][1]["namespace_tier"] == "unknown"


# ---- F: shared fakes (the Health Agent tests moved, see below) --------------------------------------------
class _HealthResp:
    status = 200

    async def json(self):
        return {"risk_score": 0.7, "label": "drift", "ci_width": 0.08, "top_field": "limits.cpu"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, fail=False):
        self.fail = fail

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, *a, **k):
        if self.fail:
            raise RuntimeError("connection refused")
        return _HealthResp()


class _Redis:
    def __init__(self):
        self.streams, self.hashes, self.kv = [], {}, {}

    async def xadd(self, stream, payload):
        self.streams.append((stream, dict(payload)))

    async def hset(self, key, mapping=None, **kw):
        self.hashes[key] = dict(mapping or {})

    async def expire(self, *a):
        pass

    async def eval(self, script, numkeys, key, model_scored, risk, ts_ms, ttl, publish):
        if "kubeheal:record_security_score" in script:
            self.hashes[key] = {"model_scored": model_scored, "sec_risk": risk, "ts_ms": ts_ms}
            return risk
        raise AssertionError("unexpected Lua script")

    async def setex(self, k, ttl, v):
        self.kv[k] = v

    async def get(self, k):
        return self.kv.get(k)


# The Health Agent tests that lived here (model_scored, outage notice, Fusion contract) moved to
# tests/test_health_agent_contract.py with the V5-D4 rewrite; the helpers above stay for the Security Agent tests.


# ---- G: Falco time from gRPC, first-seen T0 ---------------------------------------------------------------
class _Ts:
    def __init__(self, seconds, nanos):
        self.seconds, self.nanos = seconds, nanos

    def __str__(self):
        return f"seconds: {self.seconds}\nnanos: {self.nanos}\n"


def test_protobuf_timestamp_becomes_a_timezone_aware_iso_string():
    iso = fc.timestamp_to_iso(_Ts(1794303000, 250_000_000))
    assert iso == "2026-11-10T09:30:00.250000Z"
    assert datetime.fromisoformat(iso.replace("Z", "+00:00")).tzinfo is not None
    assert falco_t0_ms([{"ts": iso}]) == 1794303000250


def test_real_protobuf_timestamp_message():
    pb = pytest.importorskip("google.protobuf.timestamp_pb2")
    ts = pb.Timestamp(seconds=1794303000, nanos=5_000_000)
    assert falco_t0_ms([{"ts": str(ts)}]) is None                     # the old behaviour: protobuf text, no T0
    assert falco_t0_ms([{"ts": fc.timestamp_to_iso(ts)}]) == 1794303000005


@pytest.mark.parametrize("value", [None, _Ts(0, 0), _Ts(-5, 0), _Ts(1, 2_000_000_000), "seconds: 1", ""])
def test_unusable_timestamps_are_unknown_not_guessed(value):
    assert fc.timestamp_to_iso(value) == ""


def test_an_iso_string_with_a_timezone_passes_through():
    assert fc.timestamp_to_iso("2026-11-10T09:30:00Z") == "2026-11-10T09:30:00Z"
    assert fc.timestamp_to_iso("2026-11-10T09:30:00") == ""            # no timezone: unknown


def test_grpc_response_time_gives_t0():
    class Resp:
        rule = "KubeHeal Ransom Note Dropped"
        priority = 2
        time = _Ts(1794303000, 0)
        output_fields = {"evt.type": "openat", "proc.pid": "4242", "k8s.pod.name": "p", "k8s.ns.name": "demo"}
    evt = fc._event_from_grpc_response(Resp())
    assert evt["ts"] == "2026-11-10T09:30:00Z" and falco_t0_ms([evt]) == 1794303000000


def _ticking_clock():
    t = [0.0]

    def clock():
        t[0] += 1.0
        return t[0]
    return clock


def _write_event(i, pid=4242):
    sec = 1794303000 + i
    return {"syscall": "write", "pid": pid, "fd_path": f"/data/f{i}", "rule": "", "priority": "warning",
            "pod": "p", "namespace": "demo",
            "ts": datetime.fromtimestamp(sec, tz=timezone.utc).isoformat().replace("+00:00", "Z")}


def test_t0_is_the_first_seen_time_even_when_the_window_dropped_the_first_events():
    tracker = FalcoWindowTracker(burst_threshold=3, cooldown_s=0, max_events=5, clock=_ticking_clock())
    trigger = None
    for i in range(40):                                             # a long attack: 40 events, window keeps 5
        trigger = tracker.add(_write_event(i)) or trigger
    assert len(trigger.events) == 5
    assert falco_t0_ms(trigger.events) == (1794303000 + 35) * 1000           # drifted later: unsafe
    assert falco_t0_ms(trigger.events + [{"ts": trigger.first_ts}]) == 1794303000 * 1000
    assert trigger.first_ts == tracker.first_seen(4242) == _write_event(0)["ts"]


def test_first_seen_keeps_the_earliest_time_for_out_of_order_events_and_is_bounded(monkeypatch):
    import agents.security_agent.syscall_window as sw
    tracker = FalcoWindowTracker(burst_threshold=100, clock=lambda: 0.0)
    for i in (5, 2, 9):
        tracker.add(_write_event(i))
    assert tracker.first_seen(4242) == _write_event(2)["ts"]
    monkeypatch.setattr(sw, "MAX_TRACKED_PIDS", 3)
    for pid in range(1, 10):
        tracker.add(_write_event(0, pid=pid))
    assert len(tracker._first_seen) == 3


def test_an_event_without_a_usable_time_never_sets_first_seen():
    tracker = FalcoWindowTracker(burst_threshold=100, clock=lambda: 0.0)
    tracker.add({**_write_event(1), "ts": ""})
    tracker.add({**_write_event(1), "ts": "not a time"})
    tracker.add({**_write_event(1), "ts": "2026-11-10T09:30:00"})            # no timezone
    assert tracker.first_seen(4242) == ""


def _service_body(risk=0.9, label="ransomware", **kw):
    """The JSON the inference service answers (kubeheal.contracts.Prediction)."""
    body = {"model_version": "security-test", "label": label, "risk": risk, "probabilities": {label: 1.0},
            "prediction_set": [label], "uncertain": False, "top_factors": [], "latency_ms": 1.0}
    body.update(kw)
    return body


def _security_agent(monkeypatch, body, status=200):
    """An agent whose inference client talks to a fake service: `body` is the JSON it answers (None: the service
    cannot be reached)."""
    from agents.security_agent import agent as sa
    from agents.security_agent.entropy_sampler import EntropySampler, ProcFdReader
    from agents.security_agent.inference import InferenceClient
    ag = sa.SecurityAgent(redis_url="redis://unused", sampler=EntropySampler(ProcFdReader("/nonexistent-proc")))
    ag.redis, ag.running = _Redis(), True
    ag.redis.kv["kubeheal:pid:4242"] = json.dumps({"pid": 4242, "pod": "p", "namespace": "prod"})

    async def poster(url, payload, timeout_s):
        if body is None:
            raise ConnectionError("refused")
        return status, body
    ag.inference = InferenceClient("http://inference.invalid", poster=poster)

    async def no_mmap(pid):
        return False
    monkeypatch.setattr(ag, "_check_mmap_entropy", no_mmap)
    return ag


def test_published_t0_is_the_first_seen_time_of_a_long_attack(monkeypatch):
    ag = _security_agent(monkeypatch, _service_body())
    tracker = FalcoWindowTracker(burst_threshold=3, cooldown_s=0, max_events=5, clock=_ticking_clock())
    captured = []

    async def capture(pid, events, source="none", **kwargs):
        captured.append((pid, events, source))
    monkeypatch.setattr(ag, "_trigger_entropy_check", capture)

    async def go():
        for i in range(40):
            await ag._ingest_falco_event(_write_event(i), tracker, "replay")
        pid, events, source = captured[-1]
        assert len(events) == 5                                         # the window really was capped
        await ag._run_entropy_check(pid, events, source)
    run(go())
    p = ag.redis.streams[-1][1]
    assert p["t0_ms"] == str(1794303000 * 1000)


# ---- H: a service answer that is NaN, incomplete or out of range -----------------------------------------
def _publish_with_model(monkeypatch, body, status=200):
    ag = _security_agent(monkeypatch, body, status)
    ag.inotify_watcher.check_rename_burst = lambda events=None: 0.5          # heuristic floor 0.60
    evs = [{"syscall": "write", "fd_path": "/data/a", "ts": "2026-11-10T09:30:00Z"}] * 3
    run(ag._run_entropy_check(4242, evs, "replay"))
    return ag


@pytest.mark.parametrize("body,status,issue", [
    (None, 200, "inference_unreachable"),                                     # service down or timeout
    (_service_body(), 503, "inference_http_503"),                             # no bundle loaded
    (_service_body(), 500, "inference_http_500"),
    (_service_body(risk=float("nan")), 200, "inference_invalid_response"),
    (_service_body(risk=float("inf")), 200, "inference_invalid_response"),
    (_service_body(risk=1.5), 200, "inference_invalid_response"),
    (_service_body(risk="0.9"), 200, "inference_invalid_response"),
    (_service_body(label="ransomware_active"), 200, "inference_invalid_response"),   # not a security label
    (_service_body(prediction_set="ransomware"), 200, "inference_invalid_response"),
    (_service_body(prediction_set=["other"]), 200, "inference_invalid_response"),
    (_service_body(uncertain="false"), 200, "inference_invalid_response"),
    ({"detail": "x"}, 200, "inference_invalid_response"),
    ([], 200, "inference_invalid_response"),
])
def test_an_unusable_service_answer_gives_no_score_and_falls_back_to_the_heuristic(monkeypatch, body, status,
                                                                                    issue, caplog):
    with caplog.at_level(logging.WARNING):
        ag = _publish_with_model(monkeypatch, body, status)
    streams = [p for _, p in ag.redis.streams]
    assert len(streams) >= 1                                           # not suppressed, no KeyError, no dead task
    p = streams[-1]
    assert float(p["sec_risk"]) == pytest.approx(0.60) and not math.isnan(float(p["sec_risk"]))
    assert p["model_scored"] == "false" and p["sec_uncertain"] == "true" and p["sec_prediction_set"] == "[]"
    assert p["model_issue"] == issue
    assert ag.redis.hashes["kubeheal:security:score:prod:p"]["model_scored"] == "false"
    assert "not usable" in caplog.text or issue == "inference_unreachable"


def test_a_valid_service_answer_is_used(monkeypatch):
    ag = _publish_with_model(monkeypatch, _service_body(risk=0.91))
    p = ag.redis.streams[-1][1]
    assert p["model_scored"] == "true" and float(p["sec_risk"]) == pytest.approx(0.91)
    assert "model_issue" not in p and ag.inference.rejected == {}
    assert ag.redis.hashes["kubeheal:security:score:prod:p"]["model_scored"] == "true"


def test_nan_service_risk_is_not_suppressed_below_the_heuristic_threshold_behaviour(monkeypatch):
    """The old code: max(nan, 0.95) is nan and nan >= 0.40 is False, so a clear ransomware heuristic was
    dropped. Now the heuristic score is published."""
    ag = _security_agent(monkeypatch, _service_body(risk=float("nan")))
    ag.inotify_watcher.check_rename_burst = lambda events=None: 0.5
    run(ag._run_entropy_check(4242, [{"syscall": "write", "fd_path": "/x", "ts": ""}], "replay"))
    assert float(ag.redis.streams[-1][1]["sec_risk"]) == pytest.approx(0.60)


def test_an_expired_pid_cache_is_counted_and_logged_not_silent(monkeypatch, caplog):
    ag = _security_agent(monkeypatch, None)
    ag.redis.kv.clear()
    with caplog.at_level(logging.WARNING):
        run(ag._run_entropy_check(4242, [], "none"))
    assert ag.dropped_checks == {"pid_cache_expired": 1}
    assert "dropped" in caplog.text and ag.redis.streams == []


def test_a_failing_check_task_is_counted(monkeypatch):
    ag = _security_agent(monkeypatch, None)

    async def boom(pid, events, source, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(ag, "_run_entropy_check", boom)

    async def go():
        await ag._trigger_entropy_check(4242, [], "none")
        await asyncio.gather(*list(ag._checks.values()), return_exceptions=True)
        await asyncio.sleep(0)
    run(go())
    assert ag.dropped_checks.get("check_failed") == 1

