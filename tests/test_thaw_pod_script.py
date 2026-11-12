"""scripts/thaw_pod.py: the operator thaw request and its protocol agreement with the Executor's freeze module."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load():
    spec = importlib.util.spec_from_file_location("thaw_pod_script", ROOT / "scripts" / "thaw_pod.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeRedis:
    def __init__(self, answer=None):
        self.added, self.hashes, self.answer = [], {}, answer

    def xadd(self, stream, fields):
        self.added.append((stream, fields))
        if self.answer is not None:
            self.hashes[f"kubeheal:contain:result:{fields['request_id']}"] = dict(self.answer)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


def test_constants_match_the_executor_freeze_module():
    from agents.executor import freeze
    mod = load()
    assert mod.STREAM_PREFIX == freeze.STREAM_PREFIX and mod.RESULT_PREFIX == freeze.RESULT_PREFIX


def test_the_request_is_an_operator_thaw_without_a_label_on_the_nodes_stream():
    mod, redis = load(), FakeRedis()
    req = mod.build_request("prod", "web-1", "uid-1", "node-a", "inc-1", now_ms=1234, request_id="a" * 32)
    mod.thaw(redis, req, wait_s=0, sleep=lambda s: None)
    (stream, fields), = redis.added
    assert stream == "kubeheal.contain.req:node-a"
    assert fields["action"] == "thaw" and fields["requested_by"] == "operator" and fields["label"] == ""
    assert fields["timestamp_ms"] == "1234" and len(fields["request_id"]) == 32


def test_success_only_for_a_verified_thaw():
    mod = load()
    ok, msg, _ = mod.thaw(FakeRedis({"status": "thawed", "frozen": "0"}),
                          mod.build_request("prod", "p", "u", "n", "i"), wait_s=1, sleep=lambda s: None)
    assert ok and "thawed" in msg
    for answer in ({"status": "failed", "frozen": "1", "reason": "thaw_not_confirmed"},
                   {"status": "refused", "frozen": "0", "reason": "bad_requested_by"},
                   {"status": "thawed", "frozen": "1"}):
        ok, msg, _ = mod.thaw(FakeRedis(answer), mod.build_request("prod", "p", "u", "n", "i"), wait_s=1,
                              sleep=lambda s: None)
        assert not ok


def test_no_answer_in_time_is_not_a_success():
    mod, now = load(), [0.0]

    def clock():
        return now[0]

    def sleep(s):
        now[0] += s
    ok, msg, result = mod.thaw(FakeRedis(None), mod.build_request("prod", "p", "u", "n", "i"), wait_s=2,
                               poll_s=0.5, sleep=sleep, clock=clock)
    assert not ok and result == {} and "no answer" in msg


def test_a_clock_problem_gets_a_hint_and_control_characters_are_not_echoed_raw():
    mod = load()
    ok, msg, _ = mod.thaw(FakeRedis({"status": "refused", "frozen": "0", "reason": "expired\x1b[31m"}),
                          mod.build_request("prod", "p", "u", "n", "i"), wait_s=1, sleep=lambda s: None)
    assert not ok and "clocks" in msg and "\x1b" in msg and "\x1b[31m" not in msg

