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
    def __init__(self, event=True, mode="test", second_mode=None, fail_restore=False, fail_create_after=False):
        self.calls, self.event, self.mode = [], event, mode
        self.second_mode, self.mode_reads = second_mode, 0
        self.fail_restore, self.patch_count = fail_restore, 0
        self.fail_create_after, self.created_cm = fail_create_after, None
        self.pod = dict(POD)

    def __call__(self, *args, input_text=None, timeout_s=30.0):
        self.calls.append((args, input_text, timeout_s))
        if args[:4] == ("-n", "kubeheal", "get", "configmap") and args[4] != "kubeheal-mode":
            if self.created_cm and self.created_cm["metadata"]["name"] == args[4]:
                return json.dumps(self.created_cm)
            return ""
        if args[:4] == ("-n", "kubeheal", "delete", "configmap"):
            if self.created_cm and self.created_cm["metadata"]["name"] == args[4]:
                self.created_cm = None
            return "deleted"
        if "--ignore-not-found=true" in args:
            return ""
        if args[:4] == ("-n", "kubeheal", "get", "configmap"):
            self.mode_reads += 1
            mode = self.second_mode if self.second_mode and self.mode_reads >= 2 else self.mode
            return json.dumps({"data": {"mode": mode}})
        if args[:4] == ("-n", "prod", "get", "pods"):
            return json.dumps({"items": [self.pod]})
        if args[:4] == ("-n", "kubeheal", "get", "daemonset"):
            return json.dumps(DS)
        if args[:4] == ("-n", "kubeheal", "create", "configmap"):
            return json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": args[4]},
                               "data": {"trace.jsonl": "{}"}})
        if args[:4] == ("-n", "kubeheal", "create", "-f"):
            self.created_cm = json.loads(input_text)
            if self.fail_create_after:
                raise TimeoutError("injected client timeout after API create")
            return "created"
        if args[:3] == ("-n", "kubeheal", "patch"):
            self.patch_count += 1
            if self.fail_restore and self.patch_count > 1:
                raise RuntimeError("injected restore failure")
            return "patched"
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
    result = runner.run(fake, sleep=lambda _s: None, fixture=fixture, timeout_s=20)
    assert result["security_event"]["syscall_source"] == "replay"
    assert result["fusion_action"]["dry_run"] == "true"
    target_query = next(args for args, _, _ in fake.calls if args[:4] == ("-n", "prod", "get", "pods"))
    assert target_query[target_query.index("-l") + 1] == (
        "app.kubernetes.io/name=victim-app,kubeheal.io/watch=true"
    )
    patches = [json.loads(args[args.index("-p") + 1]) for args, _, _ in fake.calls if "patch" in args]
    assert patches[0]["spec"]["template"]["spec"]["containers"][0]["env"][-1] == {
        "name": "FALCO_REPLAY_NODE", "value": "k3d-kubeheal-agent-0"}
    restore = patches[-1]["spec"]["template"]["spec"]
    assert restore["volumes"] == [{"name": runner.VOLUME, "$patch": "delete"}]
    assert restore["containers"][0]["volumeMounts"] == [{"name": runner.VOLUME,
                                                            "mountPath": runner.MOUNT_PATH,
                                                            "$patch": "delete"}]
    restored_env = restore["containers"][0]["env"]
    assert restored_env[0] == {"name": "FALCO_MODE", "value": "auto"}
    assert any("$patch" in item for item in restored_env)
    assert any(args[:3] == ("-n", "kubeheal", "delete") and "configmap" in args
               for args, _, _ in fake.calls)
    cm_create = next((args, body) for args, body, _ in fake.calls if "create" in args and "-f" in args)
    cm = json.loads(cm_create[1])
    assert len(cm["metadata"]["name"].removeprefix("kubeheal-d5-replay-")) == 32
    assert cm["metadata"]["labels"]["kubeheal.io/d5-replay-id"] in cm["metadata"]["name"]
    assert not any("apply" in args for args, _, _ in fake.calls)
    assert all(timeout <= 20 for _, _, timeout in fake.calls)


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
    class Clock:
        now = 0.0

        def __call__(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    clock = Clock()
    with pytest.raises(TimeoutError):
        runner.run(fake, sleep=clock.sleep, clock=clock, timeout_s=20, fixture=fixture)
    patch_calls = [args for args, _, _ in fake.calls if "patch" in args]
    assert len(patch_calls) == 2
    assert any("delete" in args and "configmap" in args for args, _, _ in fake.calls)


def test_runner_refuses_non_test_mode_before_creating_temporary_resources(tmp_path):
    fake = FakeKubectl(mode="enforce")
    with pytest.raises(RuntimeError, match="already test"):
        runner.run(fake, fixture=tmp_path / "unused.jsonl")
    assert not any("create" in args or "patch" in args or "apply" in args for args, _, _ in fake.calls)


def test_second_mode_check_refuses_before_patch_and_deletes_unmounted_configmap(tmp_path):
    fake = FakeKubectl(second_mode="enforce")
    fixture = tmp_path / "trace.jsonl"
    fixture.write_text('{"output_fields":{"k8s.ns.name":"demo"}}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="no longer test"):
        runner.run(fake, fixture=fixture)
    assert not any("patch" in args for args, _, _ in fake.calls)
    assert any("delete" in args and "configmap" in args for args, _, _ in fake.calls)


def test_restore_failure_preserves_configmap_and_reports_manual_recovery(tmp_path):
    fake = FakeKubectl(fail_restore=True)
    fixture = tmp_path / "trace.jsonl"
    fixture.write_text('{"output_fields":{"k8s.ns.name":"demo"}}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="preserved mounted ConfigMap") as err:
        runner.run(fake, fixture=fixture)
    assert "Manual recovery" in str(err.value) and "rollout status" in str(err.value)
    assert not any("delete" in args and "configmap" in args for args, _, _ in fake.calls)


def test_ambiguous_create_timeout_deletes_only_the_run_owned_configmap(tmp_path):
    fake = FakeKubectl(fail_create_after=True)
    fixture = tmp_path / "trace.jsonl"
    fixture.write_text('{"output_fields":{"k8s.ns.name":"demo"}}\n', encoding="utf-8")
    with pytest.raises(TimeoutError, match="injected client timeout"):
        runner.run(fake, fixture=fixture, timeout_s=20)
    created_cm = next(json.loads(body) for args, body, _ in fake.calls if args[:4] == ("-n", "kubeheal", "create", "-f"))
    name = created_cm["metadata"]["name"]
    assert created_cm["metadata"]["labels"]["kubeheal.io/d5-replay-id"] == \
        name.removeprefix("kubeheal-d5-replay-")
    assert any(args[:4] == ("-n", "kubeheal", "delete", "configmap") and
               args[4] == name for args, _, _ in fake.calls)


def test_second_mode_read_is_immediately_before_replay_patch(tmp_path):
    fake = FakeKubectl()
    fixture = tmp_path / "trace.jsonl"
    fixture.write_text('{"output_fields":{"k8s.ns.name":"demo"}}\n', encoding="utf-8")
    runner.run(fake, sleep=lambda _s: None, fixture=fixture, timeout_s=20)
    mode_reads = [i for i, (args, _, _) in enumerate(fake.calls)
                  if args[:4] == ("-n", "kubeheal", "get", "configmap")]
    patch_index = next(i for i, (args, _, _) in enumerate(fake.calls) if "patch" in args)
    assert len(mode_reads) >= 2 and mode_reads[1] < patch_index
    assert patch_index == mode_reads[1] + 1
