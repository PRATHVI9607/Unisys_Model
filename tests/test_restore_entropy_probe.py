import os

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
