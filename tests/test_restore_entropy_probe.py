import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

from agents.executor.entropy_probe import scan_roots
from agents.executor.restore_entropy import job_body


def test_probe_reports_clean_only_after_scanning_readable_regular_files(tmp_path):
    volume = tmp_path / "volume"
    volume.mkdir()
    (volume / "data.txt").write_bytes(b"A" * 128)
    result = scan_roots([str(volume)])
    assert result["verdict"] == "clean"
    assert result["files_scanned"] == 1 and result["unreadable"] == 0


def test_probe_flags_high_entropy_file(tmp_path):
    volume = tmp_path / "volume"
    volume.mkdir()
    (volume / "encrypted.bin").write_bytes(bytes(range(256)) * 8)
    result = scan_roots([str(volume)])
    assert result["verdict"] == "high_entropy"
    assert result["high_entropy_files"] == 1


def test_probe_returns_unknown_for_missing_or_symlinked_content(tmp_path):
    missing = scan_roots([str(tmp_path / "missing")])
    assert missing["verdict"] == "unknown"

    volume = tmp_path / "volume"
    volume.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("A" * 32, encoding="utf-8")
    try:
        os.symlink(target, volume / "linked.txt")
    except (OSError, NotImplementedError):
        return
    result = scan_roots([str(volume)])
    assert result["verdict"] == "unknown" and result["unreadable"] == 1


def test_probe_does_not_report_clean_when_symlinked_directory_is_skipped(tmp_path):
    volume = tmp_path / "volume"
    volume.mkdir()
    target = tmp_path / "outside"
    target.mkdir()
    (target / "data.txt").write_text("A" * 32, encoding="utf-8")
    try:
        os.symlink(target, volume / "linked-dir", target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    result = scan_roots([str(volume)])
    assert result["verdict"] == "unknown" and result["unreadable"] == 1


def test_scanner_job_mounts_every_restore_pvc_read_only_without_api_token():
    job = job_body("scan-1", "inc-1", "kubeheal/executor:v4", ["data-restore-inc-1"], 180)
    pod = job["spec"]["template"]["spec"]
    scanner = pod["containers"][0]
    assert pod["automountServiceAccountToken"] is False
    assert pod["volumes"][0]["persistentVolumeClaim"]["readOnly"] is True
    assert scanner["volumeMounts"][0]["readOnly"] is True
    assert scanner["command"][-1] == "/restore/0"
    assert scanner["securityContext"]["readOnlyRootFilesystem"] is True
    assert job["spec"]["activeDeadlineSeconds"] == 180


# ---- scan Job node pinning (review fix 10) ------------------------------------------------------------------

def _pod(name, node, claims=(), labels=None, phase="Running", deleting=False):
    meta = {"name": name, "labels": labels or {"app": name}}
    if deleting:
        meta["deletionTimestamp"] = "2026-11-11T00:00:00Z"
    spec = {"volumes": [{"name": f"v{i}", "persistentVolumeClaim": {"claimName": c}} for i, c in enumerate(claims)]}
    if node:
        spec["nodeName"] = node
    return {"metadata": meta, "spec": spec, "status": {"phase": phase}}


class _Core:
    def __init__(self, pods=None, fail=False):
        self.pods, self.fail, self.calls = pods or [], fail, []

    async def list_namespaced_pod(self, namespace, label_selector=None):
        self.calls.append((namespace, label_selector))
        if self.fail:
            raise RuntimeError("forbidden")
        if label_selector:                        # the scan pod of the Job
            return {"items": [_pod("scan-pod", None, labels={"app": "kubeheal-restore-entropy"})]}
        return {"items": self.pods}

    async def read_namespaced_pod_log(self, name, namespace, container=None):
        return '{"verdict": "clean", "files_scanned": 3, "unreadable": 0}\n'


class _Batch:
    def __init__(self):
        self.created, self.deleted = [], []

    async def create_namespaced_job(self, namespace, body):
        self.created.append(body)

    async def read_namespaced_job(self, name, namespace):
        return {"status": {"succeeded": 1}}

    async def delete_namespaced_job(self, name, namespace, propagation_policy=None):
        self.deleted.append(name)


def _node(pods, pvcs):
    import asyncio
    from agents.executor.restore_entropy import scan_node
    return asyncio.run(scan_node(_Core(pods), "prod", pvcs))


def test_job_pod_spec_gets_the_node_name_only_when_one_is_given():
    plain = job_body("scan-1", "inc-1", "img", ["c"], 60)["spec"]["template"]["spec"]
    pinned = job_body("scan-1", "inc-1", "img", ["c"], 60, node_name="k3d-kubeheal-agent-1")["spec"]["template"]["spec"]
    assert "nodeName" not in plain and pinned["nodeName"] == "k3d-kubeheal-agent-1"


def test_scan_node_follows_the_pod_that_mounts_the_pvc():
    pods = [_pod("web", "node-a"), _pod("db-1", "node-b", ["db-restore"]), _pod("other", "node-c", ["x"])]
    assert _node(pods, ["db-restore"]) == "node-b"


def test_scan_node_needs_every_pvc_on_the_same_node():
    same = [_pod("a", "node-b", ["p1"]), _pod("b", "node-b", ["p2"])]
    assert _node(same, ["p1", "p2"]) == "node-b"
    split = [_pod("a", "node-b", ["p1"]), _pod("b", "node-c", ["p2"])]
    assert _node(split, ["p1", "p2"]) is None                      # different nodes: no pin
    assert _node([_pod("a", "node-b", ["p1"])], ["p1", "p2"]) is None      # p2 has no pod: no pin
    assert _node([], ["p1"]) is None and _node([_pod("a", "node-b", ["p1"])], []) is None


def test_scan_node_ignores_unscheduled_finished_deleting_and_earlier_scan_pods():
    pods = [_pod("pending", None, ["p1"]), _pod("done", "node-x", ["p1"], phase="Succeeded"),
            _pod("gone", "node-y", ["p1"], deleting=True),
            _pod("old-scan", "node-z", ["p1"], labels={"app": "kubeheal-restore-entropy"})]
    assert _node(pods, ["p1"]) is None
    assert _node(pods + [_pod("live", "node-b", ["p1"])], ["p1"]) == "node-b"


def test_scan_node_failure_means_no_pin_not_an_error():
    import asyncio
    from agents.executor.restore_entropy import scan_node
    assert asyncio.run(scan_node(_Core(fail=True), "prod", ["p1"])) is None


def test_the_created_scan_job_is_pinned_to_the_restored_pods_node():
    import asyncio
    import remediation_fakes as fk
    from agents.executor.restore_entropy import check_restored_pvcs
    batch = _Batch()
    core = _Core([_pod("db-9", "k3d-kubeheal-agent-0", ["db-data-restore-inc-1"])])
    verdict = asyncio.run(check_restored_pvcs(core, batch, fk.Gate(), "prod", "inc-1", ["db-data-restore-inc-1"],
                                              "kubeheal/executor:v4", 30, 1, sleep=fk.Clock().sleep))
    assert verdict["clean"] is True
    spec = batch.created[0]["spec"]["template"]["spec"]
    assert spec["nodeName"] == "k3d-kubeheal-agent-0"
    assert ("prod", None) in core.calls                              # a plain namespace listing, read only
    # no pod found: the Job is created without a pin, as before
    batch2 = _Batch()
    asyncio.run(check_restored_pvcs(_Core([]), batch2, fk.Gate(), "prod", "inc-1", ["db-data-restore-inc-1"],
                                    "kubeheal/executor:v4", 30, 1, sleep=fk.Clock().sleep))
    assert "nodeName" not in batch2.created[0]["spec"]["template"]["spec"]


def test_list_pods_read_access_already_exists_for_the_executor_and_no_write_verb_was_added():
    import pathlib
    import yaml
    docs = list(yaml.safe_load_all((pathlib.Path(__file__).resolve().parents[1] / "k8s/rbac/rbac.yaml").read_text(encoding="utf-8")))
    read = next(d for d in docs if d and d.get("metadata", {}).get("name") == "kubeheal-executor-read")
    rule = next(r for r in read["rules"] if "pods" in r["resources"])
    assert "list" in rule["verbs"] and not {"create", "update", "patch", "delete"} & set(rule["verbs"])
