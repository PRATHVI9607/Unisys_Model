"""V5-S2: the Security Agent scores through the LightGBM inference service.

Offline: fakes for Redis and for the service (and, where a test says so, the real shipped bundle through the real
FastAPI app); the v5 feature code is the real one. Covers the window mapping, fail closed, the publish threshold,
the per-workload score hash Fusion reads, the contract with the Fusion mapping, D-5 and the process counters."""
import asyncio
import json
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_redis import FakeRedis                                    # noqa: E402
from fusion_helpers import make_agent, security_score_key, stream as stream_of  # noqa: E402

from agents.security_agent import agent as sa                       # noqa: E402
from agents.security_agent import counters as ct                    # noqa: E402
from agents.security_agent import entropy_sampler as entropy_mod     # noqa: E402
from agents.security_agent import falco_client as fc               # noqa: E402
from agents.security_agent import v5_window as vw                  # noqa: E402
from agents.security_agent.entropy_sampler import EntropyResult, EntropySampler, ProcFdReader  # noqa: E402
from agents.security_agent.inference import (                      # noqa: E402
    InferenceClient, clean_features, validate_prediction,
)
from agents.security_agent.proc_scanner import PodIndex, PodInfo    # noqa: E402
from agents.security_agent.syscall_window import FalcoWindowTracker  # noqa: E402
from kubeheal.contracts import SECURITY_PUBLISH_RISK               # noqa: E402
from kubeheal.features.security import SECURITY_FEATURES, security_features  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "falco"
RANSOM = FIX / "ransomware_pv_encrypt.jsonl"
RANSOM_CURRENT = FIX / "ransomware_pv_encrypt_current_rules.jsonl"
NOW_S = 1_000_000.0                                                  # the Fusion test clock


def run(coro):
    return asyncio.run(coro)


class AgentRedis(FakeRedis):
    async def setex(self, key, ttl, value):
        self.store[key] = value


def body(risk=0.91, label="ransomware", pset=None, uncertain=False, factors=None):
    """What the service answers (kubeheal.contracts.Prediction)."""
    return {"model_version": "security-test", "label": label, "risk": risk, "probabilities": {label: 1.0},
            "prediction_set": [label] if pset is None else pset, "uncertain": uncertain,
            "top_factors": [{"feature": "frac_rename", "value": 0.47, "contribution": 1.2}]
            if factors is None else factors, "latency_ms": 1.0}


class FakeService:
    """The inference service as a client poster: records requests, answers `answers` in turn (the last repeats)."""

    def __init__(self, *answers):
        self.answers = list(answers) or [(200, body())]
        self.requests = []

    async def __call__(self, url, payload, timeout_s):
        self.requests.append((url, payload, timeout_s))
        ans = self.answers[min(len(self.requests), len(self.answers)) - 1]
        if isinstance(ans, Exception):
            raise ans
        return ans


def make_agent_sec(service=None, redis=None, sampler=None, mmap=False):
    ag = sa.SecurityAgent(redis_url="redis://unused",
                          sampler=sampler or EntropySampler(ProcFdReader("/nonexistent-proc")))
    ag.redis, ag.running = redis or AgentRedis(), True
    ag.service = service or FakeService()
    ag.inference = InferenceClient("http://inference.invalid", poster=ag.service)
    ag._wall = lambda: NOW_S
    ag._mono = lambda: 5000.0

    async def no_mmap(pid):
        return mmap
    ag._check_mmap_entropy = no_mmap
    ag.redis.store["kubeheal:pid:4242"] = json.dumps({"pid": 4242, "pod": "victim-app-7d9f8b6c5-x2k4q",
                                                      "namespace": "demo"})
    return ag


def trace_events(path):
    return list(fc.iter_trace_events(str(path)))


def burst_window(path=RANSOM):
    """The window the tracker hands the agent for the first burst of a trace."""
    tracker = FalcoWindowTracker(max_events=sa.MAX_WINDOW_EVENTS, clock=lambda: 0.0, wall=lambda: NOW_S)
    for e in trace_events(path):
        trig = tracker.add(e)
        if trig:
            return trig.events
    raise AssertionError("no trigger")


def check(ag, events, source="replay", pid=4242):
    run(ag._run_entropy_check(pid, events, source))


def published(ag):
    return [f for s, f in ag.redis.added if s == "kubeheal.security.events"]


def score_hash(ag, key="kubeheal:security:score:demo:victim-app-7d9f8b6c5-x2k4q"):
    return ag.redis.hashes.get(key)


# ---- the mapping of windows to v5 feature input ---------------------------------------------------------

def norm(syscall, fd_path="", ts="2026-11-10T09:30:00Z", **kw):
    return {"syscall": syscall, "fd_path": fd_path, "ts": ts, **kw}


def test_opens_map_to_open_w_or_open_r_by_flags_and_an_open_without_flags_is_a_read():
    f = vw.to_v5_event
    assert f(norm("openat", "/d/a", flags="O_WRONLY|O_CREAT"))["syscall"] == "open_w"
    assert f(norm("openat", "/d/a", flags="O_RDWR"))["syscall"] == "open_w"
    assert f(norm("openat", "/d/a", flags="O_RDONLY"))["syscall"] == "open_r"
    assert f(norm("openat", "/d/a"))["syscall"] == "open_r"
    assert f(norm("creat", "/d/a"))["syscall"] == "open_w"
    assert f(norm("openat2", "/d/a", flags="O_TRUNC"))["syscall"] == "open_w"
    assert f(norm("openat", "/d/a", flags="2"))["syscall"] == "open_w"          # PPM-encoded number


def test_mapping_choice_raw_writes_become_open_w_one_event_each():
    for name in ("write", "pwrite", "pwritev"):
        assert vw.to_v5_event(norm(name, "/data/a"))["syscall"] == "open_w"
    window, *_ = vw.window_from_normalised([norm("write", "/data/a")] * 3)
    feats = security_features(window, [], 5.0)
    assert feats["frac_write"] == 1.0 and feats["n_events"] == 3.0


def test_syscalls_outside_the_captured_groups_are_dropped():
    for name in ("mmap", "msync", "connect", "execve", "madeup", ""):
        assert vw.to_v5_event(norm(name, "/data/a")) is None
    for name in ("unlink", "unlinkat", "truncate", "ftruncate", "chmod", "fchmod", "fchmodat", "rename"):
        assert vw.to_v5_event(norm(name, "/data/a")) is not None


def test_a_rename_keeps_its_two_paths_and_never_derives_a_source():
    both = vw.to_v5_event(norm("renameat2", fs_source="/d/a", fs_target="/d/a.locked"))
    assert (both["path"], both["new_path"]) == ("/d/a", "/d/a.locked")
    only_fd = vw.to_v5_event(norm("rename", "/d/a.locked"))             # what the rules in k8s/ emit today
    assert (only_fd["path"], only_fd["new_path"]) == ("", "/d/a.locked")
    only_source = vw.to_v5_event(norm("rename", "/d/a.locked", fs_source="/d/a"))
    assert (only_source["path"], only_source["new_path"]) == ("/d/a", "")
    window, *_ = vw.window_from_normalised([norm("rename", "/d/a.locked")])
    feats = security_features(window, [], 5.0)
    assert feats["frac_rename"] == 1.0
    assert feats["frac_rename_suffix_added"] is None and feats["rename_ext_added_ratio"] is None


def test_paths_come_from_fd_name_then_the_path_fields():
    assert vw.to_v5_event(norm("unlink", fs_name="/d/x"))["path"] == "/d/x"
    assert vw.to_v5_event(norm("openat", "/d/y", fs_name="/d/x"))["path"] == "/d/y"


def test_time_is_the_falco_time_else_the_arrival_time_else_the_event_is_dropped():
    assert vw.to_v5_event(norm("write", "/d/a"))["ts_ms"] == 1794303000000
    assert vw.to_v5_event(norm("write", "/d/a", ts="", seen_ms=1234))["ts_ms"] == 1234
    assert vw.to_v5_event(norm("write", "/d/a", ts="no", seen_ms=1234))["ts_ms"] == 1234
    assert vw.to_v5_event(norm("write", "/d/a", ts="2026-11-10T09:30:00")) is None     # no timezone, no arrival time
    assert vw.to_v5_event(norm("write", "/d/a", ts="", seen_ms=0)) is None
    assert vw.to_v5_event(norm("write", "/d/a", ts="")) is None


def test_window_cut_is_60_s_before_the_newest_and_at_most_512_events():
    evs = [{"syscall": "open_w", "path": f"/d/{i}", "new_path": "", "ts_ms": 1_000_000 + i * 1000}
           for i in range(100)]
    cut, start, newest, window_s = vw.cut_window(evs)
    assert newest == 1_099_000 and start == 1_039_000 and len(cut) == 61 and window_s == 60.0
    many = [{"syscall": "open_w", "path": "/d/a", "new_path": "", "ts_ms": 5_000_000 + i} for i in range(700)]
    cut, *_ = vw.cut_window(many)
    assert len(cut) == 512 and cut[-1] is many[-1]
    assert vw.cut_window([]) == ([], 0, 0, 0.0)
    one, start, newest, window_s = vw.cut_window(evs[:1])
    assert window_s == 5.0                                              # MIN_WINDOW_S floor


def test_top_syscall_is_the_most_frequent_observed_name():
    assert vw.top_syscall([norm("write"), norm("rename"), norm("write")]) == "write"
    assert vw.top_syscall([]) == ""


def test_the_replayed_trace_maps_to_the_full_feature_dict_with_json_safe_values():
    window, *_ = vw.window_from_normalised(burst_window())
    feats = security_features(window, [7.9, 7.8], 5.0, 1000.0, None)
    assert list(feats) == SECURITY_FEATURES and len(feats) == 45
    clean = clean_features({**feats, "nan": float("nan"), "inf": float("inf"), "b": True})
    assert clean["nan"] is None and clean["inf"] is None and clean["b"] is None
    json.dumps(clean, allow_nan=False)                                   # strict JSON: no NaN literal


def test_the_tracker_keeps_what_the_mapping_needs_and_counts_open_w_towards_the_burst():
    tracker = FalcoWindowTracker(burst_threshold=3, cooldown_s=0, clock=lambda: 0.0, wall=lambda: 7.0)
    fired = [tracker.add({"syscall": "openat", "pid": 5, "flags": "O_WRONLY|O_CREAT", "fd_path": f"/d/{i}",
                          "ts": ""}) for i in range(3)]
    assert fired[:2] == [None, None] and fired[2] is not None
    kept = fired[2].events[0]
    assert kept["flags"] == "O_WRONLY|O_CREAT" and kept["seen_ms"] == 7000 and "fs_target" in kept


def test_tracker_prunes_old_events_bounds_lru_and_resets_on_pid_reuse(monkeypatch):
    monkeypatch.setattr("agents.security_agent.syscall_window.MAX_TRACKED_PIDS", 2)
    tracker = FalcoWindowTracker(burst_threshold=999, cooldown_s=0, wall=lambda: 1.0)

    def event(pid, start, seen):
        return {"syscall": "write", "pid": pid, "proc_starttime": start, "seen_ms": seen, "ts": ""}

    tracker.add(event(1, 10, 1_000))
    tracker.add(event(2, 20, 1_000))
    tracker.add(event(1, 10, 2_000))  # touch PID 1 so PID 2 is least recently used
    tracker.add(event(3, 30, 2_000))
    assert tracker.window(1) and tracker.window(2) == [] and tracker.window(3)

    # A changed /proc starttime is a different process even when Linux reused the numeric PID.
    tracker.add(event(1, 11, 3_000))
    assert len(tracker.window(1)) == 1 and tracker.window(1)[0]["proc_starttime"] == 11

    # Entries older than the event-time window are discarded before a new event is retained.
    tracker.add(event(1, 11, 3_001 + sa.WINDOW_S * 1_000))
    assert len(tracker.window(1)) == 1


def test_entropy_assessments_use_a_fresh_tracker_window_for_initial_and_complete_phases():
    ag = make_agent_sec()
    current = [norm("write", "/data/a")]
    observed = []

    class DynamicSampler:
        config = type("Config", (), {"samples": 2, "interval_s": 0.0})()

        async def collect(self, pid, on_sample=None, **kwargs):
            await on_sample(EntropyResult(pid, [None]), 0)
            current.append(norm("write", "/data/b"))
            return EntropyResult(pid, [None, None])

    async def get_pid_info(pid):
        return {"pid": pid, "pod": "victim-app-7d9f8b6c5-x2k4q", "namespace": "demo"}

    async def counters(pid, info):
        return ct.CounterSamples()

    async def assess(pid, info, result, events, source, mmap, phase):
        observed.append((phase, len(events)))

    ag.sampler = DynamicSampler()
    ag._get_pid_info = get_pid_info
    ag._sample_counters = counters
    ag._assess_and_publish = assess
    run(ag._run_entropy_check(4242, list(current), "replay", window_provider=lambda: list(current)))
    assert observed == [("initial", 1), ("complete", 2)]


def test_normalise_carries_flags_and_path_fields_and_new_syscalls_are_tracked():
    evt = fc._normalise({"rule": "KubeHeal Data File Activity", "priority": "Notice", "time": "2026-11-10T09:30:00Z",
                         "output_fields": {"evt.type": "renameat2", "proc.pid": 9, "fd.name": "<NA>",
                                           "evt.arg.flags": "<NA>", "fs.path.source": "/data/a",
                                           "fs.path.target": "/data/a.locked", "k8s.pod.name": "p",
                                           "k8s.ns.name": "demo", "k8s.pod.uid": "uid-1", "container.id": "c1"}})
    assert (evt["fs_source"], evt["fs_target"], evt["pod_uid"], evt["container_id"]) == (
        "/data/a", "/data/a.locked", "uid-1", "c1")
    assert evt["flags"] == "" and evt["fs_name"] == ""
    for name in ("creat", "openat2", "chmod", "fchmod", "fchmodat"):
        assert name in fc.RANSOMWARE_SYSCALLS


# ---- the real service: the full dict is accepted ------------------------------------------------------------

@pytest.fixture(scope="module")
def real_service():
    pytest.importorskip("lightgbm")
    from fastapi.testclient import TestClient
    from services.inference_server.main import create_app
    with TestClient(create_app()) as client:
        yield client


def real_poster(client):
    async def post(url, payload, timeout_s):
        r = client.post("/v1/security/predict", json=payload)
        return r.status_code, r.json()
    return post


def test_the_real_service_accepts_the_full_45_name_dict_and_answers_a_prediction_set(real_service):
    window, *_ = vw.window_from_normalised(burst_window())
    feats = security_features(window, [], 5.0)
    assert len(feats) == 45
    status, out = run(real_poster(real_service)("", {"features": clean_features(feats)}, 5))
    assert status == 200                                                 # restrict drops the 5 unlisted names
    assert isinstance(out["prediction_set"], list) and out["model_version"]
    assert validate_prediction(out) is not None


# ---- the client fails closed -------------------------------------------------------------------------------

def test_client_posts_the_feature_dict_to_the_security_route():
    svc = FakeService((200, body()))
    client = InferenceClient("http://kubeheal-inference:8000/", poster=svc)
    out = run(client.predict({"n_events": 3, "x": float("nan"), "y": None}))
    url, payload, timeout = svc.requests[0]
    assert url == "http://kubeheal-inference:8000/v1/security/predict"
    assert payload == {"features": {"n_events": 3.0, "x": None, "y": None}} and timeout == 5.0
    assert out["label"] == "ransomware" and out["top_factors"][0]["feature"] == "frac_rename"
    assert client.last_issue == ""


def test_client_url_comes_from_the_environment(monkeypatch):
    monkeypatch.delenv("INFERENCE_URL", raising=False)
    assert InferenceClient().url == "http://kubeheal-inference:8000"
    monkeypatch.setenv("INFERENCE_URL", "http://svc:9/")
    assert InferenceClient().url == "http://svc:9"


@pytest.mark.parametrize("answer,issue", [
    (asyncio.TimeoutError(), "unreachable"), (ConnectionRefusedError(), "unreachable"),
    ((503, {"detail": "security model not loaded"}), "http_503"), ((422, {}), "http_422"),
    ((200, None), "invalid_response"), ((200, "text"), "invalid_response"),
])
def test_client_returns_none_and_names_the_issue(answer, issue):
    client = InferenceClient("http://x", poster=FakeService(answer))
    assert run(client.predict({})) is None and client.last_issue == issue
    assert client.rejected[issue] == 1


# ---- the score hash ----------------------------------------------------------------------------------------

def test_every_window_writes_the_score_hash_even_below_the_publish_threshold():
    ag = make_agent_sec(FakeService((200, body(risk=0.05, label="benign"))))
    check(ag, burst_window())
    h = score_hash(ag)
    ts = str(int(NOW_S * 1000))
    assert h == {"sec_risk": "0.0500", "ts_ms": ts, "model_scored": "true", "high_risk": "0.0500", "high_ts_ms": ts}
    assert published(ag) == []                                           # below SECURITY_PUBLISH_RISK


def test_the_hash_is_written_in_both_entropy_phases_and_expires():
    writes = []

    class Counting(AgentRedis):
        async def eval(self, script, n, key, model_scored, risk, ts_ms, ttl, publish):
            if "kubeheal:record_security_score" in script:
                writes.append({"model_scored": model_scored, "sec_risk": risk, "ts_ms": ts_ms})
            return await super().eval(script, n, key, model_scored, risk, ts_ms, ttl, publish)

    ag = make_agent_sec(redis=Counting())
    check(ag, burst_window())
    # nothing is sampled (no such process): the sample loop ends at once, so the early report never fires and
    # only the complete assessment scores. Drive the initial one directly as well.
    run(ag._assess_and_publish(4242, {"pid": 4242, "pod": "victim-app-7d9f8b6c5-x2k4q", "namespace": "demo"},
                               EntropyResult(4242, []), burst_window(), "replay", False, "initial"))
    assert len(writes) == 2 and all(w["model_scored"] == "true" for w in writes)
    key = "kubeheal:security:score:demo:victim-app-7d9f8b6c5-x2k4q"
    assert ag.redis.expiry[key] - ag.redis.now == 60                      # SECURITY_SCORE_TTL_S default


def test_the_ttl_is_configurable_and_a_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("SECURITY_SCORE_TTL_S", "45")
    ag = make_agent_sec()
    check(ag, burst_window())
    assert ag.redis.expiry["kubeheal:security:score:demo:victim-app-7d9f8b6c5-x2k4q"] - ag.redis.now == 45
    for bad in ("0", "-3", "nan", "abc", ""):
        monkeypatch.setenv("SECURITY_SCORE_TTL_S", bad)
        assert make_agent_sec().score_ttl_s == 60.0


@pytest.mark.parametrize("answer", [ConnectionRefusedError(), (503, {}), (200, {"risk": 5})])
def test_a_down_service_writes_model_scored_false_and_overwrites_an_earlier_true(answer):
    svc = FakeService((200, body(risk=0.2, label="suspicious", pset=["suspicious"])), answer)
    ag = make_agent_sec(svc)
    check(ag, burst_window())
    assert score_hash(ag)["model_scored"] == "true"
    check(ag, burst_window())                                            # same pod, the service is now down
    h = score_hash(ag)
    assert h["model_scored"] == "false" and h["sec_risk"] == ""          # never a fabricated score
    assert h["ts_ms"] == str(int(NOW_S * 1000))


def test_an_unscorable_assessment_without_a_falco_window_clears_stale_score():
    ag = make_agent_sec(FakeService((200, body(risk=0.15, label="benign"))))
    check(ag, burst_window())
    assert score_hash(ag)["model_scored"] == "true"
    run(ag._assess_and_publish(4242, {"pid": 4242, "pod": "victim-app-7d9f8b6c5-x2k4q", "namespace": "demo"},
                               EntropyResult(4242, []), [], "none", False, "quiet"))
    assert score_hash(ag)["model_scored"] == "false" and score_hash(ag)["sec_risk"] == ""


def test_high_heuristic_conflict_is_human_only_and_clears_the_low_model_hash():
    ag = make_agent_sec(FakeService((200, body(risk=0.15, label="benign"))))
    run(ag._assess_and_publish(4242, {"pid": 4242, "pod": "victim-app-7d9f8b6c5-x2k4q", "namespace": "demo"},
                               EntropyResult(4242, [7.9]), burst_window(RANSOM_CURRENT), "replay", False, "complete"))
    event = published(ag)[0]
    assert event["model_scored"] == "false" and event["sec_label"] == "suspicious"
    assert event["sec_prediction_set"] == "[]" and event["sec_uncertain"] == "true"
    assert float(event["sec_risk"]) >= SECURITY_PUBLISH_RISK and event["model_risk"] == "0.1500"
    assert score_hash(ag)["model_scored"] == "false" and score_hash(ag)["sec_risk"] == ""


def test_score_hash_maximum_is_atomic_across_agent_instances_with_shared_redis():
    shared = AgentRedis()
    one = make_agent_sec(FakeService((200, body(risk=0.91))), redis=shared)
    two = make_agent_sec(FakeService((200, body(risk=0.12, label="benign"))), redis=shared)
    check(one, burst_window())
    check(two, burst_window())
    assert score_hash(one)["sec_risk"] == "0.9100"
    assert shared.expiry["kubeheal:security:score:demo:victim-app-7d9f8b6c5-x2k4q"] == shared.now + 60


def test_quiet_pod_scoring_uses_real_counters_and_writes_only_an_inference_answer(monkeypatch):
    ag = make_agent_sec(FakeService((200, body(risk=0.12, label="benign"))))
    ag._pid_map = {4242: {"pid": 4242, "pod": "victim-app-7d9f8b6c5-x2k4q", "namespace": "demo"}}
    samples = ct.CounterSamples()
    samples.add(1.0, 10.0, 20.0)
    samples.add(3.0, 30.0, 80.0, force=True)

    async def counters(_pid, _info):
        return samples
    monkeypatch.setattr(ag, "_sample_counters", counters)
    run(ag._score_quiet_workloads_once())
    assert ag.service.requests
    features = ag.service.requests[0][1]["features"]
    # The shipped model schema omits n_events; these rates prove the quiet score used live counters.
    assert features["write_bytes_per_s"] == pytest.approx(30.0)
    assert features["net_out_bytes_per_s"] == pytest.approx(10.0)
    assert score_hash(ag)["model_scored"] == "true"
    assert score_hash(ag)["sec_risk"] == "0.1200"


def test_quiet_scoring_failure_clears_a_stale_model_score(monkeypatch):
    ag = make_agent_sec(FakeService((503, None)))
    ag._pid_map = {4242: {"pid": 4242, "pod": "victim-app-7d9f8b6c5-x2k4q", "namespace": "demo"}}
    key = f"{sa.SCORE_KEY_PREFIX}:demo:victim-app-7d9f8b6c5-x2k4q"
    ag.redis.hashes[key] = {"model_scored": "true", "sec_risk": "0.9900", "ts_ms": "1"}

    async def counters(_pid, _info):
        samples = ct.CounterSamples()
        samples.add(1.0, 1.0, 1.0)
        samples.add(3.0, 3.0, 3.0, force=True)
        return samples
    monkeypatch.setattr(ag, "_sample_counters", counters)
    run(ag._score_quiet_workloads_once())
    assert ag.service.requests and score_hash(ag)["model_scored"] == "false"
    assert score_hash(ag)["sec_risk"] == ""


def test_the_hash_holds_the_highest_model_risk_of_the_workload_within_the_ttl():
    svc = FakeService((200, body(risk=0.9)), (200, body(risk=0.1, label="benign")))
    ag = make_agent_sec(svc)
    check(ag, burst_window())
    check(ag, burst_window())                                            # a quiet process of the same workload
    assert score_hash(ag)["sec_risk"] == "0.9000"
    now = [NOW_S]
    ag._wall = lambda: now[0]
    now[0] = NOW_S + 61                                                  # the 0.9 window is older than the TTL
    ag.redis.advance(61)                                                  # expire the fake Redis key as real Redis would
    ag.service.answers = [(200, body(risk=0.1, label="benign"))]
    ag.service.requests.clear()
    check(ag, burst_window())
    assert score_hash(ag)["sec_risk"] == "0.1000"


def test_no_hash_and_no_service_call_without_a_syscall_window():
    ag = make_agent_sec()
    check(ag, [], source="none")
    assert ag.service.requests == []
    assert score_hash(ag)["model_scored"] == "false"
    # events the v5 features do not count (mmap only) are not scored either
    check(ag, [norm("mmap", "/x"), norm("msync", "/x")])
    assert ag.service.requests == [] and score_hash(ag)["model_scored"] == "false"


def test_a_redis_error_on_the_hash_does_not_stop_the_check_or_the_event():
    class Broken(AgentRedis):
        async def eval(self, script, n, key, *args):
            if key.startswith(sa.SCORE_KEY_PREFIX):
                raise ConnectionError("redis down")
            return await super().eval(script, n, key, *args)
    ag = make_agent_sec(redis=Broken())
    check(ag, burst_window())
    assert ag.score_write_errors >= 1 and len(published(ag)) == 1


def test_the_hash_is_keyed_by_the_workload_the_pod_index_knows_not_the_pod_name():
    """The Falco-written pid record has no workload; the pod index supplies the Deployment name."""
    ag = make_agent_sec()
    ag.pod_index.update_from([], {})
    ag.pod_index.by_pod[("demo", "victim-app-7d9f8b6c5-x2k4q")] = PodInfo(
        "demo", "victim-app-7d9f8b6c5-x2k4q", "app", "Deployment", "victim-app", "uid-9")

    async def go():
        tracker = FalcoWindowTracker(max_events=512, clock=lambda: 0.0, wall=lambda: NOW_S)
        for e in trace_events(RANSOM):
            await ag._ingest_falco_event(e, tracker, "replay")
        await asyncio.gather(*list(ag._checks.values()))
    run(go())
    rec = json.loads(ag.redis.store["kubeheal:pid:4242"])
    assert rec["workload"] == "victim-app" and rec["pod_uid"] == "uid-9"
    assert score_hash(ag, "kubeheal:security:score:demo:victim-app")["model_scored"] == "true"
    ev = published(ag)[0]
    assert ev["deployment"] == "victim-app" and ev["pod_name"] == "victim-app-7d9f8b6c5-x2k4q"
    assert ev["workload_kind"] == "Deployment" and ev["pod_uid"] == "uid-9"
    assert not [k for k in ag.redis.hashes if k.endswith("x2k4q") and k.startswith(sa.SCORE_KEY_PREFIX)]


def test_pod_index_finds_a_pod_by_namespace_and_name():
    idx = PodIndex()

    class Md:
        namespace, name, uid, owner_references = "prod", "web-abc-1", "u1", None

    class Pod:
        metadata = Md
        spec = None
    idx.update_from([Pod], {})
    assert idx.lookup_pod("prod", "web-abc-1").uid == "u1" and idx.lookup_pod("prod", "other") is None


# ---- publish threshold -------------------------------------------------------------------------------------

@pytest.mark.parametrize("risk,label,expect", [
    (0.05, "benign", 0), (SECURITY_PUBLISH_RISK - 0.001, "suspicious", 0),
    (SECURITY_PUBLISH_RISK, "suspicious", 1), (0.95, "ransomware", 1)])
def test_an_event_is_published_only_at_or_above_the_publish_risk(risk, label, expect):
    ag = make_agent_sec(FakeService((200, body(risk=risk, label=label))))
    check(ag, burst_window())
    assert len(published(ag)) == expect
    assert score_hash(ag)["model_scored"] == "true"                      # scored either way


def test_a_scored_event_carries_exactly_what_fusion_reads():
    ag = make_agent_sec(FakeService((200, body(risk=0.95, label="ransomware", pset=["ransomware", "exfiltration"],
                                               uncertain=True))))
    check(ag, burst_window())
    p = published(ag)[0]
    for name in ("sec_label", "sec_risk", "sec_prediction_set", "sec_uncertain", "top_factors_json", "model_scored",
                 "model_version", "pod_name", "deployment", "namespace", "namespace_tier", "timestamp_ms",
                 "workload_kind", "window_start_ms", "window_end_ms", "pid_target", "top_syscall", "event_id"):
        assert name in p, name
    assert (p["sec_risk"], p["sec_label"], p["model_scored"], p["model_version"]) == (
        "0.9500", "ransomware", "true", "security-test")
    assert json.loads(p["sec_prediction_set"]) == ["ransomware", "exfiltration"] and p["sec_uncertain"] == "true"
    assert json.loads(p["top_factors_json"])[0] == {"feature": "frac_rename", "value": 0.47, "contribution": 1.2}
    assert p["namespace_tier"] == "unknown" and p["window_start_ms"] == "1794303000000"
    assert int(p["window_end_ms"]) >= int(p["window_start_ms"]) and p["n_events"] == "15"
    for gone in ("sec_ci_width", "security_embedding_b64"):
        assert gone not in p


def test_cooldown_one_trigger_per_burst_and_one_check_per_pid():
    t = {"now": 0.0}
    ag = make_agent_sec()
    tracker = FalcoWindowTracker(cooldown_s=5, max_events=512, clock=lambda: t["now"], wall=lambda: NOW_S)
    calls = []

    async def spy(pid, events, source="none", **kwargs):
        calls.append((pid, len(events)))
    ag._trigger_entropy_check = spy

    async def go():
        for e in trace_events(RANSOM)[:-1]:
            await ag._ingest_falco_event(e, tracker, "replay")
    run(go())
    assert calls == [(4242, 15)]                                         # cooldown: one trigger, not one per event


# ---- contract with the Fusion mapping and its security score hash -------------------------------------------

def test_published_fields_map_through_fusions_to_security_event():
    from agents.fusion_agent import event_mapping as em
    ag = make_agent_sec(FakeService((200, body(risk=0.95, label="ransomware"))))
    check(ag, burst_window())
    ev = em.to_security_event(published(ag)[0], "demo", "victim-app")
    assert ev is not None
    assert ev.label == "ransomware" and ev.risk == pytest.approx(0.95) and ev.uncertain is False
    assert ev.top_factors[0].feature == "frac_rename" and ev.model_version == "security-test"
    assert ev.window_start_ms == 1794303000000 and ev.window_end_ms >= ev.window_start_ms
    assert em.prediction_set(published(ag)[0], "sec_prediction_set") == ["ransomware"]


def test_an_unscored_event_maps_but_is_uncertain_for_fusion():
    from agents.fusion_agent import event_mapping as em
    ag = make_agent_sec(FakeService(ConnectionRefusedError()), mmap=True)        # heuristic 0.85
    check(ag, burst_window())
    p = published(ag)[0]
    assert p["model_scored"] == "false"
    ev = em.to_security_event(p, "demo", "victim-app")
    assert ev is not None and ev.uncertain is True and em.prediction_set(p, "sec_prediction_set") == []


def test_fusion_reads_the_hash_the_agent_wrote_as_a_fresh_security_response():
    ag = make_agent_sec(FakeService((200, body(risk=0.12, label="benign"))))
    check(ag, burst_window())
    fusion = make_agent()
    fusion.redis = ag.redis
    assert security_score_key("demo", "victim-app-7d9f8b6c5-x2k4q") == \
        "kubeheal:security:score:demo:victim-app-7d9f8b6c5-x2k4q"
    fresh, risk = run(fusion._security_score("demo", "victim-app-7d9f8b6c5-x2k4q"))
    assert fresh is True and risk == pytest.approx(0.12)
    fusion.clock = lambda: NOW_S + fusion.cfg.security_fresh_s + 1             # older than SECURITY_FRESH_S
    assert run(fusion._security_score("demo", "victim-app-7d9f8b6c5-x2k4q")) == (False, None)


def test_fusion_does_not_trust_a_hash_written_while_the_service_was_down():
    ag = make_agent_sec(FakeService(ConnectionRefusedError()))
    check(ag, burst_window())
    fusion = make_agent()
    fusion.redis = ag.redis
    assert run(fusion._security_score("demo", "victim-app-7d9f8b6c5-x2k4q")) == (False, None)


def test_fusion_handles_a_published_security_event_end_to_end():
    from agents.fusion_agent import agent as fusion_mod
    ag = make_agent_sec(FakeService((200, body(risk=0.95, label="ransomware"))))
    ag.pod_index.by_pod[("prod", "payments-abc-1")] = PodInfo("prod", "payments-abc-1", "c", "Deployment",
                                                              "payments", "u")
    ag.redis.store["kubeheal:pid:4242"] = json.dumps({"pid": 4242, "pod": "payments-abc-1", "namespace": "prod"})
    check(ag, burst_window())
    fields = published(ag)[0]
    assert fields["deployment"] == "payments"
    fusion = make_agent()
    assert run(fusion._handle_entry(fusion_mod.SEC_STREAM, "1-0", dict(fields))) is True


# ---- D-5: why the replay emitted no Security event -------------------------------------------------------------

def test_d5_a_trace_that_scores_below_the_publish_risk_emits_no_event_but_the_hash_shows_it_was_scored():
    """The cause made visible: the hand-written trace was consumed and scored; the window scored below
    SECURITY_PUBLISH_RISK, so nothing was published. Before V5-S2 nothing recorded that a score happened."""
    ag = make_agent_sec(FakeService((200, body(risk=0.06, label="benign"))))
    events = trace_events(RANSOM_CURRENT)
    assert len(events) == 21
    tracker = FalcoWindowTracker(max_events=512, clock=lambda: 0.0, wall=lambda: NOW_S)

    async def go():
        for e in events:
            await ag._ingest_falco_event(e, tracker, "replay")
        await asyncio.gather(*list(ag._checks.values()))
    run(go())
    assert len(ag.service.requests) == 1                                 # the model was called once
    assert published(ag) == []                                           # below the threshold: no event
    assert score_hash(ag)["model_scored"] == "true" and float(score_hash(ag)["sec_risk"]) < SECURITY_PUBLISH_RISK


def test_d5_the_real_bundle_scores_the_current_rules_trace_below_the_publish_risk(real_service):
    """The root cause, with the shipped bundle: renames carry only the new name (no `fs.path.source`) and the
    replayed process has no readable files, so the suffix-added rename and entropy features are None and the
    window looks benign. Hand-written fixture, not a capture."""
    ag = make_agent_sec()
    ag.inference = InferenceClient("http://x", poster=real_poster(real_service))
    check(ag, burst_window(RANSOM_CURRENT))
    h = score_hash(ag)
    assert h["model_scored"] == "true" and float(h["sec_risk"]) < SECURITY_PUBLISH_RISK
    assert published(ag) == []


def _locked_trace(path, files=12):
    """Hand-written Falco lines the way the V5-S1 rules will emit them: opens with flags, renames with both paths."""
    lines, t = [], 1794304000_000_000_000

    def line(evt_type, **fields):
        nonlocal t
        t += 40_000_000
        out = {"evt.time": t, "evt.type": evt_type, "proc.pid": 4242, "k8s.ns.name": "demo",
               "k8s.pod.name": "victim-app-7d9f8b6c5-x2k4q", "container.id": "5f3a9c1d2b7e", **fields}
        lines.append(json.dumps({"rule": "KubeHeal Data File Activity", "priority": "Notice",
                                 "output_fields": out}))
    for i in range(files):
        f = f"/data/doc_{i:02d}.txt"
        line("openat", **{"evt.arg.flags": "O_RDONLY", "fd.name": f})
        line("openat", **{"evt.arg.flags": "O_WRONLY|O_CREAT|O_TRUNC", "fd.name": f})
        line("renameat2", **{"fs.path.source": f, "fs.path.target": f + ".locked"})
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_d5_a_trace_with_both_rename_paths_and_open_flags_publishes_through_the_real_bundle(real_service, tmp_path):
    """Same attack, emitted the way the V5-S1 rules will: the real bundle then answers ransomware at or above
    the publish risk and the event reaches the stream. Hand-written, not a capture."""
    trace = _locked_trace(tmp_path / "locked.jsonl")
    ag = make_agent_sec()
    ag.inference = InferenceClient("http://x", poster=real_poster(real_service))
    tracker = FalcoWindowTracker(max_events=512, clock=lambda: 0.0, wall=lambda: NOW_S)

    async def go():
        for e in fc.iter_trace_events(str(trace)):
            await ag._ingest_falco_event(e, tracker, "replay")
        await asyncio.gather(*list(ag._checks.values()))
    run(go())
    h = score_hash(ag)
    assert h["model_scored"] == "true"
    ev = published(ag)
    assert ev and ev[0]["model_scored"] == "true" and float(ev[0]["sec_risk"]) >= SECURITY_PUBLISH_RISK
    assert ev[0]["sec_label"] in ("ransomware", "exfiltration", "suspicious")


# ---- write-bytes and net-out counters (V5-S3) -----------------------------------------------------------------

def test_the_shipped_bundle_lists_both_counters():
    meta = json.loads((Path(__file__).resolve().parents[1] / "models/bundles/security/meta.json").read_text())
    assert "write_bytes_per_s" in meta["features"] and "net_out_bytes_per_s" in meta["features"]


def _proc(tmp_path, pid, write_bytes=None, tx=None):
    d = tmp_path / str(pid)
    (d / "net").mkdir(parents=True, exist_ok=True)
    (d / "ns").mkdir(exist_ok=True)
    (d / "ns" / "net").write_text(f"netns-{pid}")
    if write_bytes is not None:
        (d / "io").write_text(f"rchar: 1\nwchar: 2\nwrite_bytes: {write_bytes}\ncancelled_write_bytes: 0\n")
    if tx is not None:
        (d / "net" / "dev").write_text(
            "Inter-|   Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n"
            f"    lo: 99 1 0 0 0 0 0 0 {tx * 7} 1 0 0 0 0 0 0\n  eth0: 5 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n")


def test_process_counters_read_io_and_net_dev_and_never_report_zero_for_unknown(tmp_path):
    _proc(tmp_path, 10, write_bytes=4096, tx=500)
    _proc(tmp_path, 11, write_bytes=1000)
    (tmp_path / "1" / "ns").mkdir(parents=True)
    (tmp_path / "1" / "ns" / "net").write_text("host")
    net, wb = ct.read_pod_counters(str(tmp_path), [10, 11])
    assert wb == 5096.0 and net == 500.0                                  # lo excluded, eth0 only
    assert ct.read_pod_counters(str(tmp_path), [11])[0] is None           # no net table: unknown, not 0
    assert ct.read_pod_counters(str(tmp_path), [10, 12]) == (500.0, None)  # one unreadable pid: no partial sum
    assert ct.read_pod_counters(str(tmp_path), []) == (None, None)


def test_a_host_network_process_has_no_net_counter(tmp_path, monkeypatch):
    _proc(tmp_path, 10, write_bytes=1, tx=500)
    (tmp_path / "1" / "ns").mkdir(parents=True)
    (tmp_path / "1" / "ns" / "net").write_text("host")
    real_stat = ct.os.stat

    class S:
        def __init__(self, ino):
            self.st_ino = ino

    monkeypatch.setattr(ct.os, "stat", lambda p, *a, **k: S(7) if "ns" in str(p) else real_stat(p, *a, **k))
    try:
        assert ct.net_tx_bytes(str(tmp_path), 10) is None
    finally:
        monkeypatch.undo()


def test_counter_total_is_the_increase_rescaled_to_the_window_like_v5():
    s = ct.CounterSamples()
    s.add(100.0, 1000.0, 10_000.0)
    assert s.total(1, 60.0) is None and s.total(2, 60.0) is None          # one sample: unknown
    s.add(100.5, 1500.0, 20_000.0)                                         # closer than 1 s: not added
    assert len(s.samples) == 1
    s.add(110.0, 2000.0, 60_000.0)
    assert s.total(2, 60.0) == pytest.approx(50_000.0 * 60.0 / 10.0)       # rate 5000 B/s over the 10 s span
    assert s.total(1, 60.0) == pytest.approx(1000.0 * 60.0 / 10.0)
    s.add(120.0, 1.0, None)                                                # a reset and an unreadable counter
    assert s.total(1, 60.0) is None and s.total(2, 60.0) is None


def test_a_span_shorter_than_the_minimum_is_unknown():
    s = ct.CounterSamples()
    s.add(100.0, 0.0, 0.0)
    s.add(100.4, 10.0, 10.0, force=True)
    assert s.total(2, 60.0) is None


def test_the_agent_feeds_the_counter_rates_into_the_features(monkeypatch):
    seen = []
    values = iter([(0.0, 0.0), (2000.0, 10_000.0)])
    monkeypatch.setattr(sa, "read_pod_counters", lambda root, pids: next(values))
    ag = make_agent_sec()
    now = [5000.0]
    ag._mono = lambda: now[0]
    orig = ag._predict

    async def spy(features):
        seen.append(features)
        return await orig(features)
    ag._predict = spy
    info = {"pid": 4242, "pod": "p", "namespace": "demo"}

    async def go():
        await ag._sample_counters(4242, ag._with_workload(info))              # baseline when the check starts
        now[0] += 5.0
        await ag._assess_and_publish(4242, info, EntropyResult(4242, []), burst_window(), "replay", False,
                                     "complete")
    run(go())
    assert seen[0]["write_bytes_per_s"] == pytest.approx(10_000.0 / 5.0)       # window_s is 5 (floor)
    assert seen[0]["net_out_bytes_per_s"] == pytest.approx(2000.0 / 5.0)


def test_write_byte_samples_are_keyed_by_pid_and_proc_starttime(tmp_path):
    proc = tmp_path / "4242"
    proc.mkdir()
    (proc / "stat").write_text("4242 (worker) " + " ".join(["S"] + ["0"] * 18 + ["123"]) + "\n")
    (proc / "cgroup").write_text("0::/kubepods/burstable/pod123/container\n")
    (proc / "io").write_text("write_bytes: 2048\n")
    ag = make_agent_sec()
    ag.proc_root = str(tmp_path)
    assert ag._sample_write_bytes() == {(4242, 123): 2048}

    # Reusing the numeric PID starts a new counter identity; a prior instance's delta cannot carry over.
    (proc / "stat").write_text("4242 (worker) " + " ".join(["S"] + ["0"] * 18 + ["456"]) + "\n")
    assert ag._sample_write_bytes() == {(4242, 456): 2048}


def test_entropy_sampling_stops_when_the_pid_starttime_changes(monkeypatch):
    class EmptyReader:
        proc_root = "/proc/fake"
        def written_files(self, pid):
            return []

    observed = iter([123, 456])
    monkeypatch.setattr(entropy_mod, "process_start_time", lambda pid, root: next(observed))
    sampler = EntropySampler(EmptyReader(), config=entropy_mod.SamplerConfig(samples=3, interval_s=0.0),
                             sleep=lambda _: asyncio.sleep(0))
    result = run(sampler.collect(4242, expected_start_time=123))
    assert result.ended_early and result.series == [None]


def test_without_counters_the_features_are_none_not_zero():
    ag = make_agent_sec()
    seen = []

    async def spy(features):
        seen.append(features)
        return None
    ag._predict = spy
    check(ag, burst_window())
    assert seen[0]["write_bytes_per_s"] is None and seen[0]["net_out_bytes_per_s"] is None


def test_the_agent_has_no_kubernetes_write_in_the_new_modules():
    root = Path(__file__).resolve().parents[1] / "agents" / "security_agent"
    for name in ("v5_window.py", "inference.py", "counters.py"):
        src = (root / name).read_text(encoding="utf-8")
        for needle in ("create_namespaced", "patch_namespaced", "delete_namespaced", "replace_namespaced",
                       "os.kill", "kubectl", "subprocess"):
            assert needle not in src, (name, needle)
    assert chr(0x2014) not in (root / "agent.py").read_text(encoding="utf-8")


def test_the_pod_index_wins_over_a_pod_name_fallback_stored_before_it_knew_the_pod():
    ag = make_agent_sec()
    pod = "victim-app-7d9f8b6c5-x2k4q"
    ag.redis.store["kubeheal:pid:4242"] = json.dumps({"pid": 4242, "pod": pod, "namespace": "demo",
                                                      "workload": pod})          # the fallback, stored early
    ag.pod_index.by_pod[("demo", pod)] = PodInfo("demo", pod, "app", "Deployment", "victim-app", "uid-9")
    check(ag, burst_window())
    assert score_hash(ag, "kubeheal:security:score:demo:victim-app")["model_scored"] == "true"
    assert score_hash(ag) is None and published(ag)[0]["deployment"] == "victim-app"


def test_the_event_timestamp_is_epoch_milliseconds_of_the_agent_clock():
    ag = make_agent_sec()
    ag._wall = lambda: 1_794_303_000.25
    check(ag, burst_window())
    assert published(ag)[0]["timestamp_ms"] == "1794303000250"


# ---- review fixes D1 to D3: hash semantics across writes, and T0 after an activity gap ---------------------

POD_WORKLOAD = "victim-app-7d9f8b6c5-x2k4q"


def record(ag, risk):
    """One _record_score call: a model answer with `risk`, or no answer (None)."""
    pred = None if risk is None else {"risk": risk}
    run(ag._record_score("demo", POD_WORKLOAD, pred))


def test_a_later_low_answer_does_not_flip_a_heuristic_conflict_false_to_confirmed_low():
    ag = make_agent_sec(FakeService((200, body(risk=0.15, label="benign"))))
    run(ag._assess_and_publish(4242, {"pid": 4242, "pod": POD_WORKLOAD, "namespace": "demo"},
                               EntropyResult(4242, [7.9]), burst_window(RANSOM_CURRENT), "replay", False, "complete"))
    assert score_hash(ag)["model_scored"] == "false"
    record(ag, 0.05)                                                     # the idle-pod scorer, one tick later
    assert score_hash(ag)["model_scored"] == "false" and score_hash(ag)["sec_risk"] == ""
    record(ag, 0.93)                                                     # a high answer is accepted as evidence
    assert score_hash(ag)["model_scored"] == "true" and score_hash(ag)["sec_risk"] == "0.9300"


def test_a_false_hash_gives_way_to_a_low_answer_after_one_hold_period():
    ag = make_agent_sec()
    now = [NOW_S]
    ag._wall = lambda: now[0]
    record(ag, None)
    now[0] = NOW_S + 61
    ag.redis.advance(61)
    record(ag, 0.05)
    assert score_hash(ag)["model_scored"] == "true" and score_hash(ag)["sec_risk"] == "0.0500"


def test_a_high_risk_does_not_stay_forever_while_the_pod_keeps_being_scored():
    ag = make_agent_sec()
    now = [NOW_S]
    ag._wall = lambda: now[0]
    record(ag, 0.9)
    for offset in (20, 40, 59):                                          # low answers inside the hold period
        now[0] = NOW_S + offset
        ag.redis.advance(20 if offset < 59 else 19)
        record(ag, 0.1)
        assert score_hash(ag)["sec_risk"] == "0.9000"                    # the high value is held
    now[0] = NOW_S + 61                                                  # but its own age, not later writes, decides
    ag.redis.advance(2)
    record(ag, 0.1)
    assert score_hash(ag)["sec_risk"] == "0.1000"


def test_t0_starts_again_after_an_activity_gap_longer_than_the_window():
    tracker = FalcoWindowTracker(burst_threshold=15, clock=lambda: 0.0, wall=lambda: NOW_S)
    base_ms = int(NOW_S * 1000)

    def rename(i, ts, seen_ms):
        return {"pid": 4242, "syscall": "rename", "fd_path": f"/d/f{i}", "ts": ts, "seen_ms": seen_ms,
                "fs_source": f"/d/f{i}", "fs_target": f"/d/f{i}.enc"}
    assert tracker.add(rename(0, "2026-11-10T10:00:00Z", base_ms)) is None
    trigger = None
    for i in range(1, 16):                                               # 15 renames an hour later
        trigger = tracker.add(rename(i, "2026-11-10T11:00:00Z", base_ms + 3_600_000 + i)) or trigger
    assert trigger is not None and trigger.first_ts == "2026-11-10T11:00:00Z"


def test_mmap_heuristic_uses_the_mapping_length_under_the_configured_proc_root(tmp_path):
    ag = make_agent_sec()
    ag.proc_root = str(tmp_path)
    ag.mmap_size_threshold = 1 << 20
    (tmp_path / "7").mkdir()
    maps = tmp_path / "7" / "maps"
    # a small file mapping at a high address: its END address is huge, its length is one page
    maps.write_text("7f0000000000-7f0000001000 rw-p 00000000 08:01 12 /data/small.bin\n", encoding="utf-8")
    assert run(sa.SecurityAgent._check_mmap_entropy(ag, 7)) is False
    maps.write_text("7f0000000000-7f0000400000 rw-p 00000000 08:01 12 /data/big.bin\n", encoding="utf-8")
    assert run(sa.SecurityAgent._check_mmap_entropy(ag, 7)) is True
    assert run(sa.SecurityAgent._check_mmap_entropy(ag, 8)) is False        # no such process
