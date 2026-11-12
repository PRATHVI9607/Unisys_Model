"""The D-5 runner is tested against a fake kubectl transport; these tests never touch a cluster."""
import json
import time
from pathlib import Path

import pytest

from scripts import d5_replay_runner as runner


POD = {"metadata": {"namespace": "prod", "name": "victim-app-live-123", "uid": "11111111-2222-3333-4444-555555555555"},
       "spec": {"nodeName": "k3d-kubeheal-agent-0"}, "status": {"phase": "Running",
       "containerStatuses": [{"containerID": "containerd://abcdef1234567890"}]}}
DS = {"spec": {"template": {"spec": {
    "volumes": [{"name": "host"}],
    "containers": [{"name": "agent", "env": [{"name": "FALCO_MODE", "value": "auto"},
                                                   {"name": "FALCO_EVENTS_PATH", "value": "/var/run/falco/events.jsonl"}],
                    "volumeMounts": [{"name": "host", "mountPath": "/sys"}]}],
}}}}


class FakeKubectl:
    def __init__(self, event=True, mode="test"):
        self.calls, self.event, self.mode = [], event, mode
        self.pod = dict(POD)

    def __call__(self, *args, input_text=None):
        self.calls.append((args, input_text))
        if "--ignore-not-found=true" in args:
            return ""
        if args[:4] == ("-n", "kubeheal", "get", "configmap"):
            return json.dumps({"data": {"mode": self.mode}})
        if args[:4] == ("-n", "prod", "get", "pods"):
            return json.dumps({"items": [self.pod]})
        if args[:4] == ("-n", "kubeheal", "get", "daemonset"):
            return json.dumps(DS)
        if args[:4] == ("-n", "kubeheal", "create", "configmap"):
            return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: temporary\n"
        if args[:3] == ("-n", "kubeheal", "get") and args[3] == "pods":
            return json.dumps({"items": [{"metadata": {"name": "security-agent-0"}, "spec": {
                "nodeName": "k3d-kubeheal-agent-0"}, "status": {"phase": "Running"}}]})
        if args[:3] == ("-n", "kubeheal", "exec"):
            security = []
            actions = []
            if self.event:
                now = str(int(time.time() * 1000))
                security = [{"namespace": "prod", "pod_name": POD["metadata"]["name"],
                             "syscall_source": "replay", "timestamp_ms": now, "model_scored": "true"}]
                actions = [{"target": json.dumps({"namespace": "prod", "pod": POD["metadata"]["name"]}),
                            "timestamp_ms": now, "dry_run": "true", "action_type": "HUMAN_CONTAIN"}]
            return json.dumps({"security": security, "actions": actions})
        return ""


def test_adapt_trace_rewrites_only_target_identity():
    line = '{"hostname":"old-node","output_fields":{"k8s.ns.name":"demo","k8s.pod.name":"old",' \
           '"k8s.pod.uid":"old-uid","container.id":"old-container","evt.type":"renameat2"}}'
    adapted = runner.adapt_trace(line, "prod", "victim-live", "uid-live", "node-live", "container-live")
    event = json.loads(adapted)
    assert event["hostname"] == "node-live"
    assert event["output_fields"] == {"k8s.ns.name": "prod", "k8s.pod.name": "victim-live",
                                      "k8s.pod.uid": "uid-live", "container.id": "container-live",
                                      "evt.type": "renameat2"}


def test_runner_emits_fusion_evidence_and_restores_daemonset_without_changing_mode(tmp_path):
    fake = FakeKubectl()
    fixture = tmp_path / "trace.jsonl"
    fixture.write_text('# handmade\n{"output_fields":{"k8s.ns.name":"demo"}}\n', encoding="utf-8")
    result = runner.run(fake, sleep=lambda _s: None, fixture=fixture, timeout_s=2)
    assert result["security_event"]["syscall_source"] == "replay"
    assert result["fusion_action"]["dry_run"] == "true"
    patches = [json.loads(args[args.index("-p") + 1]) for args, _ in fake.calls if "patch" in args]
    assert patches[0]["spec"]["template"]["spec"]["containers"][0]["env"][-1] == {
        "name": "FALCO_REPLAY_NODE", "value": "k3d-kubeheal-agent-0"}
    restore = patches[-1]["spec"]["template"]["spec"]
    assert restore["volumes"] == [{"name": runner.VOLUME, "$patch": "delete"}]
    assert restore["containers"][0]["volumeMounts"] == [{"name": runner.VOLUME, "$patch": "delete"}]
    restored_env = restore["containers"][0]["env"]
    assert restored_env[0] == {"name": "FALCO_MODE", "value": "auto"}
    assert any("$patch" in item for item in restored_env)
    assert any(args[:3] == ("-n", "kubeheal", "delete") and "configmap" in args for args, _ in fake.calls)


def test_real_kubectl_wrapper_always_pins_context(monkeypatch):
    captured = {}

    class Proc:
        returncode, stdout, stderr = 0, "ok", ""

    def fake_run(command, **kwargs):
        captured["command"] = command
        return Proc()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner._kubectl("get", "pods") == "ok"
    assert captured["command"][:3] == ["kubectl", "--context", "k3d-kubeheal"]


def test_timeout_still_restores_replay_mount_and_deletes_configmap(tmp_path):
    fake = FakeKubectl(event=False)
    fixture = tmp_path / "trace.jsonl"
    fixture.write_text('{"output_fields":{"k8s.ns.name":"demo"}}\n', encoding="utf-8")
    ticks = iter([0, 0, 0, 0, 2, 2, 2])
    with pytest.raises(TimeoutError):
        runner.run(fake, sleep=lambda _s: None, clock=lambda: next(ticks), timeout_s=1, fixture=fixture)
    patch_calls = [args for args, _ in fake.calls if "patch" in args]
    assert len(patch_calls) == 2
    assert any("delete" in args and "configmap" in args for args in patch_calls + [c[0] for c in fake.calls])


def test_runner_refuses_non_test_mode_before_creating_temporary_resources(tmp_path):
    fake = FakeKubectl(mode="enforce")
    with pytest.raises(RuntimeError, match="already test"):
        runner.run(fake, fixture=tmp_path / "unused.jsonl")
    assert not any("create" in args or "patch" in args or "apply" in args for args, _ in fake.calls)
