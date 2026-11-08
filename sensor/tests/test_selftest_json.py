"""Sensor fixture lines must parse with the unchanged Falco parser into the expected events and syscall groups."""
import pathlib
import subprocess

import pytest

from agents.security_agent.falco import parse_line
from kubeheal.features.security import SYSCALL_GROUPS

BIN = pathlib.Path(__file__).parents[1] / "target/release/kubeheal-sensor"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build first: cd sensor && cargo build --release")


def events():
    out = subprocess.run([BIN, "--selftest-json"], check=True, capture_output=True, text=True).stdout  # noqa: S603
    return [parse_line(line) for line in out.splitlines()]


def test_every_line_parses_with_identity_and_time():
    evs = events()
    assert len(evs) == 17 and all(evs)
    for e in evs:
        assert (e["namespace"], e["pod"], e["pid"]) == ("demo", "web-0", 42)
        assert e["pod_uid"] == "11111111-2222-3333-4444-555555555555" and e["container_id"] == "c" * 64
        assert e["ts_ms"] == 1_700_000_000_000


def test_syscall_groups_and_paths():
    by = [(e["syscall"], e["path"], e["new_path"]) for e in events()]
    f, locked = "/data/f.txt", "/data/f.txt.locked"
    assert by == [
        ("open_r", f, ""), ("open_r", f, ""),                     # open O_RDONLY|O_LARGEFILE, openat O_RDONLY
        ("open_w", f, ""), ("open_w", f, ""), ("open_w", f, ""),  # openat O_WRONLY|O_CREAT, openat2 O_RDWR, creat
        ("open_w", f, ""),                                        # openat O_RDONLY|O_TRUNC
        ("rename", f, locked), ("renameat", f, locked), ("renameat2", f, locked),
        ("unlink", f, ""), ("unlinkat", f, ""), ("truncate", f, ""), ("ftruncate", f, ""),
        ("chmod", f, ""), ("fchmod", f, ""), ("fchmodat", f, ""), ("fchmodat", f, ""),
    ]
    group = {s: g for g, ss in SYSCALL_GROUPS.items() for s in ss}
    assert [group[s] for s, _, _ in by] == ["read"] * 2 + ["write"] * 4 + ["rename"] * 3 + ["unlink"] * 2 + \
        ["truncate"] * 2 + ["chmod"] * 4
