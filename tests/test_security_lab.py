import random
import subprocess

import pytest

from kubeheal.contracts import SecurityEvent
from training.collect import security_lab as lab


def window(start_ms: int, end_ms: int) -> SecurityEvent:
    return SecurityEvent(event_id="c", namespace=lab.NS, workload="w", pod="p", label="benign", risk=0.1,
                         window_start_ms=start_ms, window_end_ms=end_ms)


def test_overwrite_start_from_log_line():
    log = "2026-10-17T07:01:00.000000001Z starting\n2026-10-17T07:01:02.500000000Z created 50 files in /data\n"
    assert lab.overwrite_start_ms(log, delay_s=12) == 1792220462500 + 12_000
    assert lab.overwrite_start_ms("2026-10-17T07:01:00Z nothing\n", 12) is None


def test_detection_windows_split_by_phase_and_straddlers_dropped():
    t = 1_000_000
    assert lab.label_window(window(t - 10_000, t - 5_000), "ransomware", t) == "benign"      # setup phase
    assert lab.label_window(window(t, t + 5_000), "ransomware", t) == "ransomware"
    assert lab.label_window(window(t - 2_000, t + 3_000), "ransomware", t) is None           # straddles
    assert lab.label_window(window(t, t + 5_000), "ransomware", None) is None                # never overwrote
    assert lab.label_window(window(t, t + 5_000), "benign", None) == "benign"


def test_every_profile_builds_valid_commands_and_lab_pod():
    r = random.Random(0)
    for name, (image, make) in lab.BENIGN.items():
        cmd, params = make(r)
        if cmd[0] == "sh":
            assert subprocess.run(["sh", "-n", "-c", cmd[2]]).returncode == 0, name
        else:
            compile(cmd[2], name, "exec")
        pod = lab.pod_manifest(f"sec-{name}", name, "benign", image, cmd, params)
        assert pod["metadata"]["labels"]["kubeheal.io/protected"] == "true"      # fusion must never act mid-sample
        assert pod["metadata"]["labels"][lab.SCENARIO_LABEL] == "benign"
    cmd, params = lab.detection_profile(r)
    assert "--sandbox /data" in cmd[2] and params["delay"] >= 0


def test_detection_gap_mix():
    r = random.Random(1)
    gaps = [lab.draw_gap(r) for _ in range(4000)]
    share = lambda lo, hi: sum(lo <= g <= hi for g in gaps) / len(gaps)   # noqa: E731
    assert share(0, 3) == pytest.approx(0.4, abs=0.04) and share(5, 20) == pytest.approx(0.3, abs=0.04)
    assert share(30, 80) == pytest.approx(0.3, abs=0.04) and share(0, 80) == 1.0
    assert all(lab.detection_profile(r)[1]["delay"] <= 80 for _ in range(50))


def test_back_to_back_windows_that_hold_the_attack_are_ransomware():
    t = 1_000_000
    w = window(t - 20_000, t + 4_000)                                       # setup still in the window, 4 s of attack
    assert lab.label_window(w, "ransomware", t, delay_s=1) == "ransomware"
    assert lab.label_window(window(t - 20_000, t + 500), "ransomware", t, delay_s=1) is None   # too little attack
    assert lab.label_window(w, "ransomware", t, delay_s=70) is None        # long gap: straddlers stay dropped
    assert lab.label_window(window(t - 20_000, t - 1), "ransomware", t, delay_s=1) == "benign"


def test_benign_families_cover_atomic_writes_and_rotation_with_gzip():
    r = random.Random(2)
    assert {"atomic_config_writes", "log_rotation"} <= set(lab.BENIGN)
    assert "gzip" in lab.BENIGN["log_rotation"][1](r)[0][2]
    tmps = {lab.BENIGN["atomic_config_writes"][1](r)[0][2].split("mv /data/")[1].split()[0] for _ in range(60)}
    assert len(tmps) > 2 and all(t.startswith((".", "conf.json")) or t == "conf.next" for t in tmps)


def test_caught_up_waits_for_the_lagging_agent(monkeypatch):
    import asyncio
    import types
    monkeypatch.setattr(lab, "TRAILING_S", 0)
    real_sleep = asyncio.sleep
    lb = lab.Lab(types.SimpleNamespace(seed=0), None, None, None, None)

    async def go():
        async def agent_catches_up():
            await real_sleep(0.05)
            lb.watermark_ms = 2_000
        monkeypatch.setattr(lab.asyncio, "sleep", lambda s: real_sleep(0.01))
        task = asyncio.create_task(agent_catches_up())
        await lb.caught_up(1_000)
        assert lb.watermark_ms == 2_000
        await task
    asyncio.run(go())


def test_read_capture_retries_dropped_connection_and_keeps_position(monkeypatch):
    import asyncio

    from redis.exceptions import ConnectionError as RedisConnectionError

    class FakeRedis:
        def __init__(self):
            self.calls = []

        async def xread(self, streams, block, count):
            self.calls.append(dict(streams))
            if len(self.calls) == 1:
                raise RedisConnectionError("port-forward dropped")
            if len(self.calls) == 2:
                return [(lab.STREAM_CAPTURE, [("5-0", window(1, 2).to_fields())])]
            raise asyncio.CancelledError

    async def no_sleep(_):
        pass

    monkeypatch.setattr(lab.asyncio, "sleep", no_sleep)
    r = FakeRedis()
    L = lab.Lab(type("A", (), {"seed": 0}), None, None, r, None)
    try:
        asyncio.run(L.read_capture())
    except asyncio.CancelledError:
        pass
    assert [c[lab.STREAM_CAPTURE] for c in r.calls] == ["$", "$", "5-0"] and L.watermark_ms == 2


def test_real_tool_families_present_and_holdouts_absent():
    assert {"restic_backup", "npm_install", "pip_install", "git_repo"} <= set(lab.BENIGN)
    cmds = " ".join(lab.BENIGN[n][1](random.Random(i))[0][2] for i, n in enumerate(sorted(lab.BENIGN)))
    assert not any(tool in cmds for tool in ("borg", "kopia", "duplicity", "yarn", "pnpm"))   # held out for evaluation
    r = random.Random(3)
    rates = [lab.detection_profile(r)[1]["rate"] for _ in range(1000)]
    assert sum(x <= 5 and x != 5 for x in rates) / len(rates) == pytest.approx(lab.SLOW_SHARE * 0.75, abs=0.05)


def test_raw_window_tolerates_absent_and_bad_fields():
    assert lab.raw_window({}) == (None, None)
    assert lab.raw_window({"events_json": "{bad", "entropy_json": "[7.9, null]"}) == (None, [7.9, None])
    assert lab.raw_window({"events_json": '[{"syscall":"open_r","path":"/data/a","ts_ms":1}]', "entropy_json": ""})[0] \
        == [{"syscall": "open_r", "path": "/data/a", "ts_ms": 1}]


def test_raw_events_round_trip_and_recompute(tmp_path):
    from kubeheal.features.security import security_features, window_seconds
    from training.datasets import collected

    stream = []
    for i in range(300):   # one pod: create, then read + overwrite + rename (the detection-test pattern)
        x = f"/data/f{i % 100}.dat"
        stream += [{"syscall": "open_r", "path": x, "ts_ms": 1000 + 30 * i},
                   {"syscall": "open_w", "path": x, "ts_ms": 1010 + 30 * i},
                   {"syscall": "rename", "path": x, "new_path": x + ".khlocked", "ts_ms": 1020 + 30 * i}]
    windows = [stream[max(0, end - 512):end] for end in range(100, len(stream) + 1, 150)]   # overlapping, ≤512
    windows.append(stream[-40:])                                                              # a gap (agent restart)
    kept = [(window(w[0]["ts_ms"], w[-1]["ts_ms"]), w, [7.9, None, 7.95], "ransomware") for w in windows]
    kept.insert(1, (window(0, 1), None, None, "benign"))                                   # a window without raw events
    recs = lab.window_records(kept, "detection_test", "ransomware", {"rename": True}, "sec-x", "Succeeded")
    assert sum("events_log" in r for r in recs) == 1 and "events_range" not in recs[1]
    log = recs[0]["events_log"]
    assert len(log) == 850 + 40              # overlapping windows stored once (events 0-849), the gap window appended
    path = tmp_path / "security.jsonl"
    path.write_text("".join(__import__("json").dumps(r) + "\n" for r in recs))
    back = collected.read("security", path)                                                 # recomputed on load
    with_raw = [r for r in back if "events_range" in r]
    assert len(with_raw) == len(windows)
    for r, w in zip(with_raw, windows, strict=True):
        assert collected.unpack_events(log[slice(*r["events_range"])]) == w
        want = security_features(w, [7.9, None, 7.95], window_seconds(w[0]["ts_ms"], w[-1]["ts_ms"]))
        assert r["features"] == want | {k: None for k in collected.BYTE_FEATURES}
        assert r["features"]["frac_read_destroyed"] > 0.95
    assert back[1]["features"] == {}                                                        # no raw events: untouched
