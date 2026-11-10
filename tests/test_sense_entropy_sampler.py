"""P5-S1: entropy of data actually written by the suspect process, via a fake /proc tree on a temp dir.

Symlinks need a privilege on Windows, so the fd targets come from an injected readlink; everything else
(fd dir listing, fdinfo, the container root under <proc>/<pid>/root) is real files."""
import asyncio
import os
import pathlib
import random

import pytest

from agents.security_agent.entropy_sampler import (
    EntropySampler, EntropyResult, ProcFdReader, SamplerConfig, shannon_entropy,
    DEFAULT_SAMPLES, DEFAULT_INTERVAL_S, DEFAULT_MAX_READ_BYTES, DEFAULT_MAX_FILES,
)

PID = 777
RANDOM_BLOCK = random.Random(1234).randbytes(4096)       # stands in for encrypted data
O_WRONLY_LARGEFILE = "0100001"
O_RDONLY_LARGEFILE = "0100000"
O_RDWR = "0100002"


class Proc:
    """Builds <root>/<pid>/{fd,fdinfo,root} and the readlink table."""

    def __init__(self, root):
        self.root = root
        self.links = {}
        (root / str(PID) / "fd").mkdir(parents=True)
        (root / str(PID) / "fdinfo").mkdir()
        (root / str(PID) / "root").mkdir()

    def add_fd(self, fd, target, flags, pos):
        p = self.root / str(PID)
        (p / "fd" / str(fd)).write_text("")
        (p / "fdinfo" / str(fd)).write_text(f"pos:\t{pos}\nflags:\t{flags}\nmnt_id:\t30\n")
        self.links[str(p / "fd" / str(fd))] = target

    def set_pos(self, fd, pos, flags=O_WRONLY_LARGEFILE):
        (self.root / str(PID) / "fdinfo" / str(fd)).write_text(f"pos:\t{pos}\nflags:\t{flags}\n")

    def file(self, container_path, data: bytes):
        f = self.root / str(PID) / "root" / container_path.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
        return f

    def reader(self, config=None, listdir=None):
        return ProcFdReader(
            str(self.root), config or SamplerConfig(),
            readlink=lambda path: self.links[str(pathlib.Path(path))],
            listdir=listdir or os.listdir)


@pytest.fixture
def proc(tmp_path):
    return Proc(tmp_path)


def test_defaults_are_documented_values():
    c = SamplerConfig()
    assert (c.samples, c.interval_s, c.max_read_bytes, c.max_files) == (30, 2.0, 4096, 20)
    assert (DEFAULT_SAMPLES, DEFAULT_INTERVAL_S, DEFAULT_MAX_READ_BYTES, DEFAULT_MAX_FILES) == (30, 2.0, 4096, 20)
    env = SamplerConfig.from_env({"ENTROPY_SAMPLES": "5", "ENTROPY_INTERVAL_S": "0.5",
                                  "ENTROPY_MAX_READ_BYTES": "512", "ENTROPY_MAX_FILES": "3",
                                  "ENTROPY_VOLUME_PREFIXES": "/data, /mnt/vol"})
    assert (env.samples, env.interval_s, env.max_read_bytes, env.max_files) == (5, 0.5, 512, 3)
    assert env.volume_prefixes == ("/data", "/mnt/vol")


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"A" * 100) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert shannon_entropy(RANDOM_BLOCK) > 7.9


def test_only_write_capable_regular_files_on_the_volume_are_listed(proc):
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    proc.add_fd(4, "/data/readonly.txt", O_RDONLY_LARGEFILE, 10)      # read only descriptor
    proc.add_fd(5, "/proc/self/status", O_RDWR, 0)                    # virtual fs
    proc.add_fd(6, "pipe:[1234]", O_WRONLY_LARGEFILE, 0)              # not a path
    proc.add_fd(7, "/data/low.txt", O_RDWR, 100)
    proc.add_fd(8, "/data/gone.tmp (deleted)", O_WRONLY_LARGEFILE, 5)
    proc.add_fd(9, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)         # same target twice
    files = proc.reader().written_files(PID)
    assert [f.target for f in files] == ["/data/enc.bin", "/data/low.txt"]
    # the file is read through the host path of the container root
    assert files[0].host_path == f"{proc.root}/{PID}/root/data/enc.bin"
    assert files[0].pos == 4096

    assert proc.reader(SamplerConfig(volume_prefixes=("/mnt/vol",))).written_files(PID) == []
    in_data = proc.reader(SamplerConfig(volume_prefixes=("/data",)))
    assert [f.target for f in in_data.written_files(PID)] == ["/data/enc.bin", "/data/low.txt"]


def test_reads_the_data_written_up_to_pos_not_the_file_head(proc):
    # head is zeros (low entropy), the block the process just wrote is random
    proc.file("/data/enc.bin", b"\0" * 4096 + RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 8192)
    sampler = EntropySampler(proc.reader())
    assert sampler.sample_once(PID) > 7.9
    proc.set_pos(3, 4096)                       # now the process has only written the zero part
    assert sampler.sample_once(PID) == 0.0


def test_read_size_is_bounded(proc):
    proc.file("/data/big.bin", RANDOM_BLOCK * 8)                 # 32 KiB
    proc.add_fd(3, "/data/big.bin", O_WRONLY_LARGEFILE, 32768)
    r = proc.reader(SamplerConfig(max_read_bytes=1024))
    wf = r.written_files(PID)[0]
    data = r.read_written(wf)
    assert len(data) == 1024
    assert data == (RANDOM_BLOCK * 8)[32768 - 1024:32768]
    # unknown offset: head of the file, still bounded
    wf.pos = None
    assert len(r.read_written(wf)) == 1024
    # nothing written yet through this descriptor
    wf.pos = 0
    assert r.read_written(wf) == b""


def test_non_regular_or_missing_host_path_reads_nothing(proc, tmp_path):
    proc.add_fd(3, "/data/dir", O_WRONLY_LARGEFILE, 10)
    proc.add_fd(4, "/data/missing", O_WRONLY_LARGEFILE, 10)
    (proc.root / str(PID) / "root" / "data" / "dir").mkdir(parents=True)
    r = proc.reader()
    for wf in r.written_files(PID):
        assert r.read_written(wf) == b""


def test_collect_takes_30_samples_2s_apart_with_injected_time(proc):
    proc.file("/data/enc.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    state = {"t": 1000.0, "sleeps": []}

    async def sleep(s):
        state["sleeps"].append(s)
        state["t"] += s

    sampler = EntropySampler(proc.reader(), clock=lambda: state["t"], sleep=sleep)
    res = asyncio.run(sampler.collect(PID))
    assert len(res.series) == 30 and res.valid_samples == 30 and res.available
    assert state["sleeps"] == [2.0] * 29                      # no sleep after the last sample
    assert res.files == ["/data/enc.bin"] and not res.ended_early
    assert all(v > 7.9 for v in res.series)
    assert len(res.model_series()) == 30


def test_series_follows_what_the_process_writes_over_time(proc):
    proc.file("/data/enc.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    n = {"sleeps": 0}

    async def sleep(s):
        n["sleeps"] += 1
        if n["sleeps"] == 10:                    # after sample 10 the process starts writing plain text
            proc.file("/data/enc.bin", b"plain text " * 400)
            proc.set_pos(3, 4096)

    sampler = EntropySampler(proc.reader(), sleep=sleep)
    res = asyncio.run(sampler.collect(PID))
    assert all(v > 7.9 for v in res.series[:10])
    assert all(v < 4.0 for v in res.series[10:])


def test_no_readable_data_is_none_not_zero_and_model_series_is_empty(proc):
    proc.add_fd(3, "/data/readonly.txt", O_RDONLY_LARGEFILE, 10)
    async def sleep(s): pass
    cfg = SamplerConfig(samples=5)
    res = asyncio.run(EntropySampler(proc.reader(cfg), config=cfg, sleep=sleep).collect(PID))
    assert res.series == [None] * 5
    assert res.valid_samples == 0 and not res.available and res.mean is None
    assert res.model_series() == []


def test_process_exit_ends_sampling_early(proc):
    proc.file("/data/enc.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    calls = {"n": 0}

    def listdir(path):
        calls["n"] += 1
        if calls["n"] > 3:
            raise FileNotFoundError(path)
        return os.listdir(path)

    async def sleep(s): pass
    sampler = EntropySampler(proc.reader(listdir=listdir), sleep=sleep)
    res = asyncio.run(sampler.collect(PID))
    assert res.ended_early and len(res.series) == 3 and res.valid_samples == 3


def test_unknown_pid_gives_unavailable_result(tmp_path):
    async def sleep(s): pass
    sampler = EntropySampler(ProcFdReader(str(tmp_path)), sleep=sleep)
    res = asyncio.run(sampler.collect(31337))
    assert res.ended_early and res.series == [] and not res.available


def test_model_series_fills_gaps_with_real_values_only():
    r = EntropyResult(pid=1, series=[None, 5.0, None, 6.0, None])
    assert r.model_series() == [5.0, 5.0, 5.0, 6.0, 6.0]
    assert r.valid_samples == 2 and r.mean == pytest.approx(5.5)


def test_max_files_per_sample_is_respected(proc):
    for fd in range(3, 8):
        proc.file(f"/data/f{fd}.bin", RANDOM_BLOCK)
        proc.add_fd(fd, f"/data/f{fd}.bin", O_WRONLY_LARGEFILE, 4096)
    cfg = SamplerConfig(max_files=2)
    seen = []
    EntropySampler(proc.reader(cfg), config=cfg).sample_once(PID, seen)
    assert seen == ["/data/f3.bin", "/data/f4.bin"]


def _symlink_or_skip(link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("this OS/user cannot create symlinks")


def test_symlink_target_is_not_followed(proc, tmp_path):
    secret = tmp_path / "secret.bin"
    secret.write_bytes(RANDOM_BLOCK)
    root_data = proc.root / str(PID) / "root" / "data"
    root_data.mkdir(parents=True)
    _symlink_or_skip(root_data / "link.bin", secret)
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW not available")
    proc.add_fd(3, "/data/link.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    assert r.read_written(r.written_files(PID)[0]) == b""


def test_fifo_target_is_skipped_without_blocking(proc):
    if not hasattr(os, "mkfifo"):
        pytest.skip("this OS cannot create FIFOs")
    root_data = proc.root / str(PID) / "root" / "data"
    root_data.mkdir(parents=True)
    os.mkfifo(root_data / "pipe")
    proc.add_fd(3, "/data/pipe", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    assert r.read_written(r.written_files(PID)[0]) == b""       # returns, does not hang


def test_only_regular_files_are_read_even_if_open_succeeds(proc, monkeypatch):
    """Platform independent check of the fstat gate: the open descriptor, not a separate stat, decides."""
    import stat as st
    from agents.security_agent import entropy_sampler as es
    proc.file("/data/f.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/f.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    wf = r.written_files(PID)[0]
    assert len(r.read_written(wf)) == 4096

    class FifoStat:
        st_mode = st.S_IFIFO | 0o600
    monkeypatch.setattr(es.os, "fstat", lambda fd: FifoStat)
    try:
        assert r.read_written(wf) == b""
    finally:
        monkeypatch.undo()            # os.fstat is global: restore before pytest cleans up tmp_path


def test_collect_runs_the_blocking_sample_off_the_event_loop(proc):
    import threading
    proc.file("/data/enc.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    threads = []

    async def sleep(s):
        await asyncio.sleep(0)

    sampler = EntropySampler(proc.reader(), config=SamplerConfig(samples=2), sleep=sleep)
    orig = sampler.sample_once

    def spy(pid, seen=None):
        threads.append(threading.get_ident())
        return orig(pid, seen)
    sampler.sample_once = spy

    async def go():
        return threading.get_ident(), await sampler.collect(PID)
    main, res = asyncio.run(go())
    assert res.valid_samples == 2 and threads and all(t != main for t in threads)
