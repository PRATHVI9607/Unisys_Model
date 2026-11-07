"""Sensor fixture lines must parse with the unchanged Falco parser into the expected events."""
import pathlib
import subprocess

import pytest

from agents.security_agent.falco import parse_line

BIN = pathlib.Path(__file__).parents[1] / "target/release/kubeheal-sensor"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build first: cd sensor && cargo build --release")


def events():
    out = subprocess.run([BIN, "--selftest-json"], check=True, capture_output=True, text=True).stdout  # noqa: S603
    return [parse_line(line) for line in out.splitlines()]


def test_every_line_parses_with_identity_and_time():
    evs = events()
    assert len(evs) == 14 and all(evs)
    for e in evs:
        assert (e["namespace"], e["pod"], e["pid"]) == ("demo", "web-0", 42)
        assert e["pod_uid"] == "11111111-2222-3333-4444-555555555555" and e["container_id"] == "c" * 64
        assert e["ts_ms"] == 1_700_000_000_000


def test_syscall_groups_and_paths():
    by = [(e["syscall"], e["path"], e["new_path"]) for e in events()]
    assert by == [
        ("open_r", "/data/f.txt", ""), ("open_r", "/data/f.txt", ""),   # open, openat O_RDONLY
        ("open_w", "/data/f.txt", ""), ("open_w", "/data/f.txt", ""),   # openat O_WRONLY|O_CREAT, openat2 O_RDWR
        ("open_w", "/data/f.txt", ""),                                  # creat
        ("rename", "/data/f.txt", "/data/f.txt.locked"), ("renameat", "/data/f.txt", "/data/f.txt.locked"),
        ("renameat2", "/data/f.txt", "/data/f.txt.locked"),
        ("unlink", "/data/f.txt", ""), ("unlinkat", "/data/f.txt", ""), ("truncate", "/data/f.txt", ""),
        ("chmod", "/data/f.txt", ""), ("fchmodat", "/data/f.txt", ""), ("fchmodat", "/data/f.txt", ""),
    ]
