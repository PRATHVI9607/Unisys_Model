"""P5-S2 / P5-S3: Falco replay (hand-written fixtures, see tests/fixtures/falco/README.md) feeds the same
pipeline as live Falco, down to the Security Model input. No model server and no cluster needed."""
import asyncio
import json
from pathlib import Path

import pytest

from agents.security_agent import falco_client as fc
from agents.security_agent.syscall_window import (
    FalcoWindowTracker, build_model_input, MODEL_MAX_EVENTS, MODEL_ENTROPY_LENGTH,
)

FIX = Path(__file__).parent / "fixtures" / "falco"
RANSOM = FIX / "ransomware_pv_encrypt.jsonl"
RANSOM_CURRENT = FIX / "ransomware_pv_encrypt_current_rules.jsonl"
BENIGN = FIX / "benign_sensitive_read.jsonl"


def events(path):
    return list(fc.iter_trace_events(str(path)))


def test_replay_normalises_real_format_lines():
    evs = events(RANSOM)
    assert len(evs) == 25                      # 12 writes + 12 renames + 1 note
    first = evs[0]
    assert first["syscall"] == "write" and first["pid"] == 4242
    assert first["pod"] == "victim-app-7d9f8b6c5-x2k4q" and first["namespace"] == "demo"
    assert first["fd_path"] == "/data/file_0000.txt" and first["priority"] == "warning"
    assert first["syscall_inferred"] is False
    assert evs[-1]["syscall"] == "openat" and evs[-1]["priority"] == "critical"


def test_events_of_current_rules_have_inferred_syscall_family():
    evs = events(RANSOM_CURRENT)
    assert len(evs) == 21
    assert [e["syscall"] for e in evs[:2]] == ["write", "rename"]
    assert all(e["syscall_inferred"] for e in evs)
    assert evs[-1]["syscall"] == "open"


def test_earliest_falco_event_time_is_normalized_to_epoch_ms_without_publish_time_fallback():
    from agents.security_agent.agent import falco_t0_ms
    first = events(RANSOM)[0]
    assert first["ts"].endswith("Z")
    assert falco_t0_ms([{"ts": "2026-11-10T09:30:02Z"}, first]) == 1794303000000
    assert falco_t0_ms([{"timestamp_ms": "1794303000000"}, {"ts": "not-a-time"}]) is None


def test_directory_replay_reads_all_files_in_name_order():
    evs = events(FIX)
    # 3 benign + 21 current-rules + 25 hand-written (old rules) + 37 hand-written (new rules, V5-S1)
    assert len(evs) == 3 + 21 + 25 + 37
    assert evs[0]["pid"] == 5150               # benign file sorts first


def test_malformed_and_unusable_lines_are_skipped_and_logged(tmp_path, caplog):
    f = tmp_path / "t.jsonl"
    good = RANSOM.read_text(encoding="utf-8").splitlines()[1]
    f.write_text("# c\n\nnot json\n" + json.dumps({"rule": "Other rule", "output_fields": {}}) + "\n" + good + "\n",
                 encoding="utf-8")
    with caplog.at_level("WARNING"):
        evs = events(f)
    assert len(evs) == 1
    assert "1 malformed" in caplog.text and "1 event(s) without a syscall" in caplog.text


def test_replay_stream_is_async_finite_and_paced_by_injected_sleep():
    slept = []

    async def sleep(s):
        slept.append(s)

    async def run():
        return [e async for e in fc.replay_stream(str(BENIGN), delay_s=0.5, sleep=sleep)]

    out = asyncio.run(run())
    assert len(out) == 3 and slept == [0.5, 0.5, 0.5]


def test_tracker_triggers_on_burst_with_the_real_window():
    t = {"now": 100.0}
    tracker = FalcoWindowTracker(clock=lambda: t["now"])
    triggers = [tr for tr in (tracker.add(e) for e in events(RANSOM)) if tr]
    assert len(triggers) == 1                              # cooldown: one trigger for the whole attack
    tr = triggers[0]
    assert tr.pid == 4242 and tr.reason == "burst"
    assert len(tr.events) == 15                            # default burst threshold
    assert tr.events[0]["syscall"] == "write" and tr.events[0]["fd_path"] == "/data/file_0000.txt"
    assert tr.events[0]["ts"].startswith("2026-11-10T09:30:00")
    assert all(e["fd_path"].startswith("/data/") for e in tr.events)


def test_tracker_cooldown_then_critical_note_rule_triggers_again():
    t = {"now": 0.0}
    tracker = FalcoWindowTracker(clock=lambda: t["now"])
    evs = events(RANSOM)
    fired = [tracker.add(e) for e in evs[:-1]]
    assert sum(1 for f in fired if f) == 1
    t["now"] = 10.0                                         # past the 5 s cooldown
    note = tracker.add(evs[-1])
    assert note is not None and note.reason == "falco_rule"
    assert note.events[-1]["fd_path"] == "/data/DECRYPT_FILES.txt"


def test_benign_trace_never_triggers():
    tracker = FalcoWindowTracker()
    assert [tracker.add(e) for e in events(BENIGN)] == [None, None, None]


def test_warning_ransomware_rule_alone_does_not_trigger_a_one_event_window():
    tracker = FalcoWindowTracker()
    assert tracker.add(events(RANSOM)[0]) is None


def test_replay_output_builds_a_valid_security_model_input():
    """Replay -> window tracker -> model input builder -> the model's own encoders (no server)."""
    torch = pytest.importorskip("torch")
    from models.security_model.security_model import (
        encode_syscall_window, pad_entropy, SYSCALL_BASE, SecurityModel,
    )
    from models.security_model.falco_transformer_encoder import MAX_SEQUENCE_LENGTH
    from models.security_model.entropy_conv1d_encoder import ENTROPY_WINDOW_LENGTH

    assert MODEL_MAX_EVENTS == MAX_SEQUENCE_LENGTH and MODEL_ENTROPY_LENGTH == ENTROPY_WINDOW_LENGTH

    tracker = FalcoWindowTracker(clock=lambda: 0.0)
    trigger = next(tr for tr in (tracker.add(e) for e in events(RANSOM)) if tr)
    entropy = [7.9, 7.95, 7.9]                            # as if sampled; the replay itself has no entropy
    body = build_model_input(trigger.events, entropy,
                             {"rename_burst": True, "high_entropy": True, "mmap_detected": False})
    json.dumps(body)                                      # JSON-serialisable request body
    assert set(body) == {"events", "entropy_series", "early_signals"}
    assert [e["syscall"] for e in body["events"][:2]] == ["write", "rename"]

    sid, pid, mask = encode_syscall_window(body["events"])
    n = len(body["events"])
    assert sid.shape == (1, MAX_SEQUENCE_LENGTH) and int((~mask).sum()) == n == 15
    assert int(sid[0, 0]) == SYSCALL_BASE["write"] and int(sid[0, 1]) == SYSCALL_BASE["rename"]
    assert int((pid[0, :n] > 0).sum()) == n               # every event carries a real path id
    ent = pad_entropy(body["entropy_series"])
    assert ent.shape == (1, ENTROPY_WINDOW_LENGTH) and float(ent[0, 0]) == pytest.approx(7.9)

    model = SecurityModel().eval()                        # random weights: shape check only, no score claim
    with torch.no_grad():
        out = model(sid, pid, mask, ent)
    assert out["risk_score"].numel() == 1 and bool(torch.isfinite(out["risk_score"]).all())


def test_builder_keeps_most_recent_events_and_caps_entropy():
    evs = [{"syscall": "write", "fd_path": f"/data/{i}"} for i in range(MODEL_MAX_EVENTS + 10)]
    body = build_model_input(evs, [1.0] * (MODEL_ENTROPY_LENGTH + 5), {})
    assert len(body["events"]) == MODEL_MAX_EVENTS
    assert body["events"][-1]["fd_path"] == f"/data/{MODEL_MAX_EVENTS + 9}"
    assert len(body["entropy_series"]) == MODEL_ENTROPY_LENGTH


@pytest.mark.parametrize("env,exists,expected", [
    ({"FALCO_MODE": "off"}, set(), "off"),
    ({"FALCO_MODE": "live"}, set(), "live"),
    ({"FALCO_MODE": "replay", "FALCO_REPLAY_PATH": "/t"}, set(), "replay"),
    ({"FALCO_MODE": "replay"}, set(), "off"),                                   # no path: say off
    ({}, {"/var/run/falco/events.jsonl"}, "live"),                              # auto, file present
    ({"FALCO_GRPC_ADDR": "unix:///run/falco/falco.sock"}, {"/run/falco/falco.sock"}, "live"),
    ({"FALCO_REPLAY_PATH": "/t"}, {"/t"}, "off"),                               # auto never picks replay
    ({"FALCO_MODE": "auto", "FALCO_REPLAY_PATH": "/t"}, {"/t"}, "off"),
    ({"FALCO_REPLAY_PATH": "/t"}, set(), "off"),
    ({}, set(), "off"),
    ({"FALCO_ENABLED": "true"}, set(), "live"),                                 # legacy flag forces live
    ({"FALCO_ENABLED": "false"}, {"/var/run/falco/events.jsonl"}, "live"),      # legacy false = auto
    ({"FALCO_ENABLED": "true", "FALCO_MODE": "off"}, set(), "off"),             # FALCO_MODE wins
    ({"FALCO_MODE": "bogus"}, set(), "off"),
])
def test_resolve_falco_mode(env, exists, expected):
    mode, reason = fc.resolve_falco_mode(env, exists=lambda p: p in exists)
    assert mode == expected and reason


# ---- end to end through the agent: replay -> pipeline -> model call -> published event -------------------

class FakeRedis:
    def __init__(self):
        self.kv, self.streams, self.hashes, self.ttl = {}, [], {}, {}

    async def setex(self, k, ttl, v): self.kv[k] = v
    async def get(self, k): return self.kv.get(k)
    async def xadd(self, stream, payload): self.streams.append((stream, dict(payload)))
    async def hset(self, k, mapping=None, **kw): self.hashes.setdefault(k, {}).update(mapping or {})
    async def expire(self, k, seconds): self.ttl[k] = seconds
    async def eval(self, script, n, key, model_scored, risk, ts_ms, ttl):
        self.hashes[key] = {"model_scored": model_scored, "sec_risk": risk, "ts_ms": ts_ms}
        self.ttl[key] = int(ttl)
        return risk


def pred(risk=0.91, label="ransomware", pset=None, uncertain=False, version="security-test"):
    """What the inference client returns for a valid service answer."""
    return {"risk": risk, "label": label, "prediction_set": [label] if pset is None else pset,
            "uncertain": uncertain, "model_version": version,
            "top_factors": [{"feature": "frac_rename", "value": 0.47, "contribution": 1.2}]}


def _agent(monkeypatch, tmp_path, trace, sampler=None):
    from agents.security_agent import agent as sa
    monkeypatch.setenv("FALCO_MODE", "replay")
    monkeypatch.setenv("FALCO_REPLAY_PATH", str(trace))
    monkeypatch.setenv("FALCO_TRIGGER_COOLDOWN_S", "5")
    ag = sa.SecurityAgent(redis_url="redis://unused", sampler=sampler)
    ag.redis, ag.running = FakeRedis(), True
    calls = []

    async def fake_predict(features):
        calls.append(features)
        return pred()

    async def no_mmap(pid): return False
    monkeypatch.setattr(ag, "_predict", fake_predict)
    monkeypatch.setattr(ag, "_check_mmap_entropy", no_mmap)
    return ag, calls


def _run_replay(ag):
    async def go():
        await ag._handle_falco_events()
        await asyncio.gather(*list(ag._checks.values()))
    asyncio.run(go())


def test_agent_replay_publishes_event_scored_from_the_features_of_the_trace(monkeypatch, tmp_path):
    from agents.security_agent.entropy_sampler import EntropySampler, ProcFdReader
    sampler = EntropySampler(ProcFdReader(str(tmp_path)))          # pid 4242 does not exist here: no entropy
    ag, calls = _agent(monkeypatch, tmp_path, RANSOM, sampler)
    _run_replay(ag)

    assert ag.falco_mode == "replay"
    assert len(calls) == 1                                          # one trigger, sampling ended at once
    f = calls[0]
    # The live replay may append more events while the first assessment is running; both
    # snapshots must remain bounded by this fixture and carry real write/rename signals.
    assert 0 < f["n_events"] <= len(events(RANSOM))
    assert f["frac_write"] > 0 and f["frac_rename"] > 0
    assert f["n_entropy_samples"] == 0.0 and f["entropy_mean"] is None          # entropy unavailable, not zeros

    assert len(ag.redis.streams) == 1
    stream, p = ag.redis.streams[0]
    assert stream == "kubeheal.security.events"
    assert p["pod_name"] == "victim-app-7d9f8b6c5-x2k4q" and p["namespace"] == "demo"
    assert p["syscall_source"] == "replay" and p["model_scored"] == "true"
    assert p["t0_ms"] == "1794303000000" and p["window_start_ms"] == "1794303000000"
    assert p["entropy"] == "" and p["entropy_valid_samples"] == "0" and p["entropy_phase"] == "complete"
    assert float(p["sec_risk"]) == pytest.approx(0.91) and p["sec_label"] == "ransomware"
    assert p["sec_prediction_set"] == '["ransomware"]' and p["sec_uncertain"] == "false"
    assert p["top_syscall"] == "write"


def test_security_agent_reads_observe_request_before_its_next_entropy_sample(monkeypatch):
    import json
    import time
    from types import SimpleNamespace
    from agents.security_agent import agent as sa

    agent = sa.SecurityAgent(redis_url="redis://unused")
    agent.redis = FakeRedis()
    agent.redis.kv["kubeheal:sampling:prod:pod:victim-abc"] = json.dumps({
        "factor": 3, "until_ms": int(time.time() * 1000) + 30_000,
    })
    intervals = []

    class Sampler:
        config = SimpleNamespace(samples=2, interval_s=2.0)

        async def collect(self, pid, on_sample=None, interval_provider=None):
            intervals.append(await interval_provider())
            return SimpleNamespace(pid=pid, series=[0.5], valid_samples=1, files=[], ended_early=False)

    agent.sampler = Sampler()
    async def pid_info(_pid):
        return {"namespace": "prod", "pod": "victim-abc"}
    async def no_mmap(_pid):
        return False
    async def no_assess(*_args, **_kwargs):
        return None
    monkeypatch.setattr(agent, "_get_pid_info", pid_info)
    monkeypatch.setattr(agent, "_check_mmap_entropy", no_mmap)
    monkeypatch.setattr(agent, "_assess_and_publish", no_assess)

    asyncio.run(agent._run_entropy_check(4242, [], "falco"))
    assert intervals == pytest.approx([2.0 / 3.0])


def test_agent_replay_of_benign_trace_publishes_nothing_and_never_calls_the_model(monkeypatch, tmp_path):
    ag, calls = _agent(monkeypatch, tmp_path, BENIGN)
    _run_replay(ag)
    assert calls == [] and ag.redis.streams == []


def test_agent_without_syscall_window_does_not_call_the_model_or_fabricate_events(monkeypatch, tmp_path):
    """/proc write-tracker path: no Falco, no replay. The model is skipped; a heuristic-only event says so."""
    from agents.security_agent.entropy_sampler import EntropySampler, ProcFdReader
    ag, calls = _agent(monkeypatch, tmp_path, BENIGN, EntropySampler(ProcFdReader(str(tmp_path))))
    ag.redis.kv["kubeheal:pid:99"] = json.dumps({"pid": 99, "pod": "p", "namespace": "n"})
    ag.inotify_watcher.check_rename_burst = lambda events=None: 0.5      # heuristic floor 0.60

    async def go():
        await ag._trigger_entropy_check(99)
        await asyncio.gather(*list(ag._checks.values()))
    asyncio.run(go())
    assert calls == []
    _, p = ag.redis.streams[0]
    assert p["syscall_source"] == "none" and p["model_scored"] == "false"
    assert float(p["sec_risk"]) == pytest.approx(0.60)


def test_agent_entropy_checks_do_not_block_and_are_deduplicated_per_pid(monkeypatch, tmp_path):
    ag, _ = _agent(monkeypatch, tmp_path, BENIGN)
    ag.redis.kv["kubeheal:pid:5"] = json.dumps({"pid": 5, "pod": "p", "namespace": "n"})
    gate = {}

    async def go():
        gate["ev"] = asyncio.Event()
        started = []

        async def slow_check(pid, events, source, **kwargs):
            started.append(pid)
            await gate["ev"].wait()

        monkeypatch.setattr(ag, "_run_entropy_check", slow_check)
        await ag._trigger_entropy_check(5)
        await ag._trigger_entropy_check(5)                          # already running: ignored
        await asyncio.sleep(0)
        assert started == [5] and len(ag._checks) == 1
        gate["ev"].set()
        await asyncio.gather(*list(ag._checks.values()))
        await asyncio.sleep(0)
        assert ag._checks == {}
    asyncio.run(go())


def test_replay_is_only_reachable_with_explicit_mode():
    env = {"FALCO_REPLAY_PATH": str(RANSOM)}
    for mode_env in ({}, {"FALCO_MODE": "auto"}, {"FALCO_ENABLED": "false"}, {"FALCO_ENABLED": "true"}):
        mode, _ = fc.resolve_falco_mode({**env, **mode_env}, exists=lambda p: p == str(RANSOM))
        assert mode != "replay", mode_env
    assert fc.resolve_falco_mode({**env, "FALCO_MODE": "replay"})[0] == "replay"


# ---- gRPC priority mapping ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("Critical", "critical"), ("CRITICAL", "critical"), ("Warning", "warning"), ("", ""),
    (2, "critical"), ("2", "critical"), (4, "warning"), (0, "emergency"), (7, "debug"),
    (99, ""), (None, ""),
])
def test_priority_name_accepts_name_or_number(value, expected):
    assert fc.priority_name(value) == expected


def test_priority_name_prefers_the_protobuf_enum_descriptor():
    class V:                      # stands in for an EnumValueDescriptor
        def __init__(self, name): self.name = name

    class Enum:
        values_by_number = {3: V("CRITICAL")}     # deliberately differs from the fallback table

    assert fc.priority_name(3, Enum) == "critical"
    assert fc.priority_name(2, Enum) == "critical"        # not in the descriptor: falls back to the table


def _grpc_resp(priority, with_descriptor=False):
    class Resp:
        rule = "KubeHeal Ransom Note Dropped"
        time = "2026-11-10T09:30:00Z"
        output_fields = {"evt.type": "openat", "proc.pid": "4242", "fd.name": "/data/DECRYPT_FILES.txt",
                         "k8s.pod.name": "p", "k8s.ns.name": "demo"}
    r = Resp()
    r.priority = priority
    if with_descriptor:
        class V:
            def __init__(self, name): self.name = name

        class Enum:
            values_by_number = {5: V("CRITICAL")}

        class Field:
            enum_type = Enum

        class Desc:
            fields_by_name = {"priority": Field}
        r.DESCRIPTOR = Desc
    return r


@pytest.mark.parametrize("priority", [2, "CRITICAL", "Critical", "2"])
def test_grpc_response_priority_is_the_enum_name_and_triggers_the_note_rule(priority):
    evt = fc._event_from_grpc_response(_grpc_resp(priority))
    assert evt["priority"] == "critical" and evt["pid"] == 4242
    assert FalcoWindowTracker(clock=lambda: 0.0).add(evt) is not None   # critical rule fires on its own


def test_grpc_response_uses_its_own_descriptor_when_present():
    assert fc._event_from_grpc_response(_grpc_resp(5, with_descriptor=True))["priority"] == "critical"


def test_grpc_numeric_priority_is_not_compared_as_str_of_a_number():
    evt = fc._event_from_grpc_response(_grpc_resp(4))      # 4 = warning, must not trigger alone
    assert evt["priority"] == "warning"
    assert FalcoWindowTracker(clock=lambda: 0.0).add(evt) is None


# ---- uncertainty of events without a model score -----------------------------------------------------

def _publish_heuristic_only(monkeypatch, tmp_path, events_present, model_up):
    from agents.security_agent.entropy_sampler import EntropySampler, ProcFdReader
    ag, calls = _agent(monkeypatch, tmp_path, BENIGN, EntropySampler(ProcFdReader(str(tmp_path))))
    ag.redis.kv["kubeheal:pid:99"] = json.dumps({"pid": 99, "pod": "p", "namespace": "prod"})
    ag.inotify_watcher.check_rename_burst = lambda events=None: 0.5      # heuristic floor 0.60 >= observe

    async def down(features):
        return None
    if not model_up:
        monkeypatch.setattr(ag, "_predict", down)

    async def go():
        evs = events(RANSOM)[:15] if events_present else None
        await ag._trigger_entropy_check(99, evs, "replay" if events_present else "none")
        await asyncio.gather(*list(ag._checks.values()))
    asyncio.run(go())
    return ag.redis.streams[0][1]


def test_heuristic_only_event_is_uncertain_and_cannot_auto_contain(monkeypatch, tmp_path):
    from agents.fusion_agent.decision_policy import make_decision, DecisionInput, Decision
    p = _publish_heuristic_only(monkeypatch, tmp_path, events_present=False, model_up=True)
    assert p["model_scored"] == "false" and p["syscall_source"] == "none"
    assert p["sec_prediction_set"] == "[]" and p["sec_uncertain"] == "true" and p["sec_label"] == "suspicious"
    assert p["model_version"] == "" and p["top_factors_json"] == "[]"
    # even at the highest risk the policy sees an unscored event: human, never AUTO_CONTAIN
    out = make_decision(DecisionInput(sec_risk=0.99, sec_label="ransomware", sec_prediction_set=[],
                                      models_ok=p["model_scored"] == "true",
                                      namespace_tier="prod", mode="enforce"))
    assert out.decision != Decision.AUTO_CONTAIN and out.decision == Decision.HUMAN_CONTAIN
    assert out.dry_run is False


def test_event_with_unreachable_service_is_not_model_scored_and_says_why(monkeypatch, tmp_path):
    p = _publish_heuristic_only(monkeypatch, tmp_path, events_present=True, model_up=False)
    assert p["model_scored"] == "false" and p["syscall_source"] == "replay"
    assert p["sec_uncertain"] == "true" and p["sec_prediction_set"] == "[]"
    assert p["model_issue"].startswith("inference_")
    assert float(p["sec_risk"]) == pytest.approx(0.60)            # the heuristic, never reported as the model's


def test_model_scored_event_carries_the_services_risk_label_and_set(monkeypatch, tmp_path):
    p = _publish_heuristic_only(monkeypatch, tmp_path, events_present=True, model_up=True)
    assert p["model_scored"] == "true" and float(p["sec_risk"]) == pytest.approx(0.91)   # not max() with 0.60
    assert p["sec_label"] == "ransomware" and p["model_version"] == "security-test"
    assert json.loads(p["top_factors_json"])[0]["feature"] == "frac_rename"
    for gone in ("sec_ci_width", "security_embedding_b64"):
        assert gone not in p


def test_falco_priority_table_matches_the_official_enum():
    """falcosecurity/client-go pkg/api/schema Priority: EMERGENCY=0 ... DEBUG=7."""
    from agents.security_agent.falco_client import FALCO_PRIORITY_BY_NUMBER, priority_name
    assert FALCO_PRIORITY_BY_NUMBER == {
        0: "emergency", 1: "alert", 2: "critical", 3: "error",
        4: "warning", 5: "notice", 6: "informational", 7: "debug"}
    assert [priority_name(i) for i in range(8)] == [
        "emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]
    assert priority_name("2") == "critical" and priority_name("Critical") == "critical"
    assert priority_name(8) == "" and priority_name(None) == ""
