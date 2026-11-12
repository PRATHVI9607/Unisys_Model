"""Offline tests for the live HMAC runner. No kubectl, Redis, MinIO, or cluster is contacted."""
import contextlib
import io
import json
import sys
import time
import types

import pytest

from agents.common.containment_auth import sign_fields, verify_fields
from scripts import containment_hmac_smoke as smoke


KEY = "offline-only-containment-test-key"
UID = "11111111-2222-4333-8444-555555555555"
VICTIM = {"metadata": {"name": "victim-app-dev-0", "namespace": "dev", "uid": UID,
                        "labels": {"app.kubernetes.io/name": "victim-app"}},
          "spec": {"nodeName": "k3d-kubeheal-agent-0"}, "status": {"phase": "Running"}}
AGENT = {"metadata": {"name": "security-agent-0", "uid": "22222222-2222-4333-8444-555555555555",
                        "labels": {"app": "security-agent"}},
         "spec": {"nodeName": "k3d-kubeheal-agent-0"}, "status": {"phase": "Running"}}


class FakeRedis:
    instance = None

    def __init__(self, key=KEY, bad_result_hmac=False):
        self.key, self.bad_result_hmac = key, bad_result_hmac
        self.stream, self.results, self.requests, self.cleaned = {}, {}, [], []
        self.next_id = 0

    @classmethod
    def from_url(cls, *_args, **_kwargs):
        return cls.instance

    def xadd(self, stream, fields):
        self.next_id += 1
        message_id = f"{self.next_id}-0"
        fields = dict(fields)
        self.requests.append((stream, fields, message_id))
        self.stream[message_id] = fields
        if verify_fields(fields, self.key):
            status, reason, mode = "dry_run", "mode_test: nothing was written", "test"
        else:
            status, reason, mode = "refused", "invalid_hmac", ""
        result = sign_fields({
            "request_id": fields["request_id"], "incident_id": fields["incident_id"],
            "namespace": fields["namespace"], "pod": fields["pod"], "pod_uid": fields["pod_uid"],
            "node": fields["node"], "action": "freeze", "status": status,
            "reason": reason, "frozen": "0", "mode_seen": mode, "ts_ms": str(int(time.time() * 1000)),
        }, self.key)
        if self.bad_result_hmac:
            result["reason"] += " changed"
        self.results[fields["request_id"]] = result
        return message_id

    def hgetall(self, key):
        request_id = key.rsplit(":", 1)[-1]
        return dict(self.results.get(request_id, {}))

    def eval(self, _script, numkeys, *args):
        stream_name, *result_keys = args[:numkeys]
        _group, *message_ids = args[numkeys:]
        for message_id in message_ids:
            self.stream.pop(message_id, None)
        for key in result_keys:
            self.results.pop(key.rsplit(":", 1)[-1], None)
        self.cleaned.append((stream_name, tuple(message_ids), tuple(result_keys)))
        return b"clean"


class FakeKubectl:
    def __init__(self, mode_reads=("test", "test"), victims=(VICTIM,), agents=(AGENT,), redis=None):
        self.mode_reads, self.read_index = list(mode_reads), 0
        self.victims, self.agents = list(victims), list(agents)
        self.redis = redis or FakeRedis()
        FakeRedis.instance = self.redis
        self.calls = []

    def __call__(self, *args, input_text=None, timeout_s=30.0):
        self.calls.append((args, input_text, timeout_s))
        if args[:4] == ("-n", "kubeheal", "get", "configmap"):
            mode = self.mode_reads[min(self.read_index, len(self.mode_reads) - 1)]
            self.read_index += 1
            return json.dumps({"data": {"mode": mode}})
        if args[:4] == ("-n", "dev", "get", "pods"):
            return json.dumps({"items": self.victims})
        if args[:4] == ("-n", "kubeheal", "get", "pods"):
            return json.dumps({"items": self.agents})
        if args[:3] == ("-n", "kubeheal", "exec"):
            return execute_remote(args[args.index("-c") + 5], input_text, self.redis)
        raise AssertionError(f"unexpected kubectl call: {args}")


def execute_remote(source, input_text, fake_redis):
    redis_module = types.SimpleNamespace(Redis=types.SimpleNamespace(from_url=FakeRedis.from_url))
    old_stdin, old_stdout = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(input_text), io.StringIO()
    sys.modules["redis"] = redis_module
    try:
        exec(compile(source, "remote-containment-hmac-smoke.py", "exec"), {})
        return sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_stdin, old_stdout
        sys.modules.pop("redis", None)


def test_remote_smoke_signs_three_cases_verifies_results_and_cleans_exact_records(monkeypatch, capsys):
    monkeypatch.setenv("REDIS_URL", "redis://offline.invalid")
    monkeypatch.setenv("CONTAIN_HMAC_KEY", KEY)
    fake = FakeKubectl()
    evidence = smoke.run(fake, timeout_s=30)

    assert [(r["case"], r["status"], r["reason"], r["result_hmac"]) for r in evidence["checks"]] == [
        ("signed", "dry_run", "mode_test: nothing was written", "valid"),
        ("unsigned", "refused", "invalid_hmac", "valid"),
        ("tampered", "refused", "invalid_hmac", "valid"),
    ]
    assert len(fake.redis.requests) == 3
    assert len({fields["request_id"] for _, fields, _ in fake.redis.requests}) == 3
    assert len({fields["incident_id"] for _, fields, _ in fake.redis.requests}) == 3
    assert all(stream == "kubeheal.contain.req:" + AGENT["spec"]["nodeName"]
               for stream, _, _ in fake.redis.requests)
    signed, unsigned, tampered = [fields for _, fields, _ in fake.redis.requests]
    assert verify_fields(signed, KEY)
    assert "hmac_sha256" not in unsigned
    assert not verify_fields(tampered, KEY)
    assert (int(tampered["timestamp_ms"]) - int(signed["timestamp_ms"])) in range(-1000, 1001)
    assert fake.redis.stream == {} and fake.redis.results == {} and len(fake.redis.cleaned) == 1
    output = capsys.readouterr().out
    assert KEY not in output and "mode=test" in output and "Cleanup verified" in output
    assert not any("patch" in args or "create" in args or "delete" in args for args, _, _ in fake.calls)
    assert all(timeout <= 30 for _, _, timeout in fake.calls)


def test_non_test_mode_refuses_before_pod_discovery_or_exec():
    fake = FakeKubectl(mode_reads=("enforce",))
    with pytest.raises(RuntimeError, match="already test"):
        smoke.run(fake, timeout_s=30)
    assert len(fake.calls) == 1 and not fake.redis.requests


def test_mode_is_checked_again_before_any_message_is_sent():
    fake = FakeKubectl(mode_reads=("test", "enforce"))
    with pytest.raises(RuntimeError, match="changed before requests"):
        smoke.run(fake, timeout_s=30)
    assert len(fake.calls) == 4 and not fake.redis.requests


def test_mode_is_checked_after_results_too(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://offline.invalid")
    monkeypatch.setenv("CONTAIN_HMAC_KEY", KEY)
    fake = FakeKubectl(mode_reads=("test", "test", "enforce"))
    with pytest.raises(RuntimeError, match="changed during HMAC smoke"):
        smoke.run(fake, timeout_s=30)
    assert len(fake.redis.requests) == 3 and fake.redis.stream == {} and fake.redis.results == {}


def test_invalid_result_hmac_fails_closed_and_still_cleans_run_records(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://offline.invalid")
    monkeypatch.setenv("CONTAIN_HMAC_KEY", KEY)
    fake = FakeKubectl(redis=FakeRedis(bad_result_hmac=True))
    with pytest.raises(RuntimeError, match="invalid HMAC"):
        smoke.run(fake, timeout_s=30)
    assert len(fake.redis.requests) == 3
    assert fake.redis.stream == {} and fake.redis.results == {} and len(fake.redis.cleaned) == 1


def test_pod_and_matching_agent_must_be_running_on_the_same_node():
    other_agent = {**AGENT, "spec": {"nodeName": "other-node"}}
    fake = FakeKubectl(agents=(other_agent,))
    with pytest.raises(RuntimeError, match="no Running dev victim-app"):
        smoke.run(fake, timeout_s=30)
    assert not fake.redis.requests


def test_all_kubectl_commands_are_context_pinned_and_have_a_hard_timeout(monkeypatch):
    captured = {}

    class Proc:
        returncode, stdout, stderr = 0, "ok", ""

    def fake_run(command, **kwargs):
        captured["command"], captured["kwargs"] = command, kwargs
        return Proc()

    monkeypatch.setattr(smoke.subprocess, "run", fake_run)
    assert smoke._kubectl("get", "pods", timeout_s=4.5) == "ok"
    assert captured["command"][:3] == ["kubectl", "--context", "k3d-kubeheal"]
    assert captured["kwargs"]["timeout"] == 4.5


def test_live_runner_routes_every_kubectl_call_through_the_pinned_wrapper(monkeypatch):
    commands = []

    class Proc:
        returncode, stderr = 0, ""

        def __init__(self, stdout):
            self.stdout = stdout

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        if "configmap" in command:
            output = json.dumps({"data": {"mode": "test"}})
        elif "-n" in command and command[command.index("-n") + 1] == "dev":
            output = json.dumps({"items": [VICTIM]})
        elif "-l" in command and "app=security-agent" in command:
            output = json.dumps({"items": [AGENT]})
        else:
            output = json.dumps({"checks": [
                {"case": "signed", "status": "dry_run", "reason": "mode_test: nothing was written",
                 "mode_seen": "test", "result_hmac": "valid"},
                {"case": "unsigned", "status": "refused", "reason": "invalid_hmac",
                 "mode_seen": "", "result_hmac": "valid"},
                {"case": "tampered", "status": "refused", "reason": "invalid_hmac",
                 "mode_seen": "", "result_hmac": "valid"}],
                "cleanup": "run-owned messages and results removed"})
        return Proc(output)

    monkeypatch.setattr(smoke.subprocess, "run", fake_run)
    smoke.run(timeout_s=30)
    assert len(commands) == 6
    assert all(command[:3] == ["kubectl", "--context", "k3d-kubeheal"] for command, _ in commands)
    assert all(0 < kwargs["timeout"] <= 30 for _, kwargs in commands)
    assert all(KEY not in " ".join(command) for command, _ in commands)


def test_remote_runner_source_never_prints_or_serializes_hmac_key():
    assert "json.dumps({\"checks\": checks" in smoke.REMOTE_SMOKE
    assert "print(key" not in smoke.REMOTE_SMOKE
    assert "CONTAIN_HMAC_KEY" in smoke.REMOTE_SMOKE
