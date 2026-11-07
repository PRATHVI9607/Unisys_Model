import random
import subprocess

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
    assert "--sandbox /data" in cmd[2] and params["delay"] >= 10   # ≥ 2 agent eval intervals between phases


def test_detection_delay_outlasts_the_agents_window():
    from agents.security_agent.agent import WINDOW_S
    r = random.Random(1)
    assert all(lab.detection_profile(r)[1]["delay"] > WINDOW_S for _ in range(50))   # no setup event in an overwrite window


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
