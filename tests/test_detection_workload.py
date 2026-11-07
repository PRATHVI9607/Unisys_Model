"""deploy/chaos/detection-test-workload.py must never write through a planted symlink or delete unlisted files."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "detection_workload", Path(__file__).parent.parent / "deploy/chaos/detection-test-workload.py")
dw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dw)


def _sandbox(tmp_path):
    sb = tmp_path / "sb"
    sb.mkdir()
    (sb / dw.MARKER).touch()
    return sb


def _run(sb):
    return dw.run(sb, 3, 3, 10, 0, rename=False)


def test_planted_symlink_skipped_target_untouched(tmp_path):
    sb = _sandbox(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    (sb / "khtest_0000.dat").symlink_to("../victim.txt")
    (sb / dw.NOTE_NAME).symlink_to("../victim.txt")
    assert _run(sb) == 2
    assert victim.read_text() == "precious"
    assert (sb / "khtest_0000.dat").is_symlink()


def test_existing_file_not_overwritten(tmp_path):
    sb = _sandbox(tmp_path)
    (sb / "khtest_0001.dat").write_text("mine")
    _run(sb)
    assert (sb / "khtest_0001.dat").read_text() == "mine"


def test_cleanup_only_removes_ledgered_files(tmp_path):
    sb = _sandbox(tmp_path)
    _run(sb)
    (sb / "khtest_report.dat").write_text("keep")
    assert dw.cleanup(sb) == 4  # 3 files + note
    assert (sb / "khtest_report.dat").read_text() == "keep"
    assert not (sb / "khtest_0000.dat").exists()
    assert not (sb / dw.LEDGER).exists()


def test_cleanup_ignores_ledger_symlink_and_traversal(tmp_path):
    sb = _sandbox(tmp_path)
    keep = tmp_path / "keep.txt"
    keep.write_text("x")
    (sb / "link").symlink_to(keep)
    (sb / dw.LEDGER).write_text("link\n../keep.txt\n")
    assert dw.cleanup(sb) == 0
    assert keep.exists() and (sb / "link").is_symlink()
