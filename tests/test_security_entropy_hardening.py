"""V5-S2 entropy hardening: every path component opened without following a symlink, regular files only, a bounded
LRU cache keyed by the stat signature. Symlink and FIFO behaviour skips where the OS cannot create them
(Windows)."""
import asyncio
import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_sense_entropy_sampler import O_WRONLY_LARGEFILE, PID, RANDOM_BLOCK, Proc  # noqa: E402

from agents.security_agent import entropy_sampler as es                            # noqa: E402
from agents.security_agent.entropy_sampler import (                                # noqa: E402
    EntropyCache, EntropySampler, SamplerConfig, split_target,
)


@pytest.fixture
def proc(tmp_path):
    return Proc(tmp_path)


def _symlink_or_skip(link, target, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("this OS/user cannot create symlinks")


def test_split_target_uses_posix_rules_and_cannot_climb_out_of_the_root():
    assert split_target("/data/a/b.txt") == ["data", "a", "b.txt"]
    assert split_target("/data/../../etc/passwd") == ["etc", "passwd"]
    assert split_target("data//a/./b") == ["data", "a", "b"]
    assert split_target("/") == []


def test_a_file_in_a_nested_directory_is_read_through_every_component(proc):
    proc.file("/data/a/b/c.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/a/b/c.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    assert r.read_written(r.written_files(PID)[0]) == RANDOM_BLOCK


def test_a_symlink_in_an_intermediate_directory_is_refused(proc, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(RANDOM_BLOCK)
    root_data = proc.root / str(PID) / "root" / "data"
    root_data.mkdir(parents=True)
    _symlink_or_skip(root_data / "linkdir", outside, directory=True)
    proc.add_fd(3, "/data/linkdir/secret.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    wf = r.written_files(PID)[0]
    assert r.read_written(wf) == b""
    assert r.written_entropy(wf) is None


def test_an_absolute_symlink_cannot_resolve_against_the_agents_own_root(proc, tmp_path):
    """A workload plants /data/etc -> /etc: followed, it would read the AGENT's /etc, not the container's."""
    root_data = proc.root / str(PID) / "root" / "data"
    root_data.mkdir(parents=True)
    _symlink_or_skip(root_data / "etc", tmp_path, directory=True)
    proc.add_fd(3, "/data/etc/anything", O_WRONLY_LARGEFILE, 10)
    (tmp_path / "anything").write_bytes(b"x" * 10)
    r = proc.reader()
    assert r.read_written(r.written_files(PID)[0]) == b""


def test_a_fifo_is_skipped_without_blocking(proc):
    if not hasattr(os, "mkfifo"):
        pytest.skip("this OS cannot create FIFOs")
    d = proc.root / str(PID) / "root" / "data"
    d.mkdir(parents=True)
    os.mkfifo(d / "pipe")
    proc.add_fd(3, "/data/pipe", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    wf = r.written_files(PID)[0]
    assert r.read_written(wf) == b"" and r.written_entropy(wf) is None


def test_open_in_root_refuses_a_symlink_at_any_component_with_the_fallback_too(tmp_path, monkeypatch):
    """The lstat fallback (no O_PATH / dir_fd, e.g. Windows) also refuses a link at an intermediate component."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "f").write_bytes(b"abc")
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    _symlink_or_skip(root / "data" / "ln", real, directory=True)
    monkeypatch.setattr(es, "_HAVE_DIR_FD", False)
    with pytest.raises(OSError):
        es.open_in_root(str(root), ["data", "ln", "f"], os.O_RDONLY | getattr(os, "O_BINARY", 0))
    (root / "data" / "ok").write_bytes(b"abc")
    fd = es.open_in_root(str(root), ["data", "ok"], os.O_RDONLY | getattr(os, "O_BINARY", 0))
    os.close(fd)


# ---- the LRU cache ---------------------------------------------------------------------------------------------

def test_an_unchanged_file_region_is_not_read_again(proc, monkeypatch):
    proc.file("/data/enc.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    wf = r.written_files(PID)[0]
    reads = []
    orig = r._read_fd
    monkeypatch.setattr(r, "_read_fd", lambda fd, start, length: (reads.append((start, length)), orig(fd, start, length))[1])
    first = r.written_entropy(wf)
    second = r.written_entropy(wf)
    assert first == second and first > 7.9 and len(reads) == 1
    assert (r.cache.hits, r.cache.misses) == (1, 1)


def test_a_change_of_size_mtime_ctime_inode_or_range_misses_the_cache(proc):
    f = proc.file("/data/enc.bin", b"\0" * 4096)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    wf = r.written_files(PID)[0]
    assert r.written_entropy(wf) == 0.0
    f.write_bytes(RANDOM_BLOCK)                                  # same size, new mtime and ctime
    st = f.stat()
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns - 5_000_000_000))   # mtime put back: ctime still differs
    assert r.written_entropy(wf) > 7.9                           # not the stale 0.0
    f.write_bytes(RANDOM_BLOCK + RANDOM_BLOCK)                   # size changed
    wf.pos = 8192
    assert r.written_entropy(wf) > 7.9
    wf.pos = 4096                                                # another range of the same file
    n = len(r.cache)
    r.written_entropy(wf)
    assert len(r.cache) == n + 1


def test_the_cache_key_is_device_inode_size_mtime_ctime_and_the_range(proc):
    proc.file("/data/enc.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/enc.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    r.written_entropy(r.written_files(PID)[0])
    (key,) = list(r.cache._d)
    st = (proc.root / str(PID) / "root" / "data" / "enc.bin").stat()
    assert key == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, 0, 4096)


def test_the_cache_is_bounded_and_evicts_the_least_recently_used():
    c = EntropyCache(3)
    for i in range(3):
        c.put(("k", i), float(i))
    assert c.get(("k", 0)) == (True, 0.0)                        # refreshed: now the newest
    c.put(("k", 3), 3.0)
    assert len(c) == 3 and c.get(("k", 1)) == (False, None)       # the oldest untouched entry went
    assert c.get(("k", 0))[0] and c.get(("k", 3))[0]
    c.put(("none",), None)                                       # "no data" is cacheable too
    assert c.get(("none",)) == (True, None) and len(c) == 3


def test_the_bound_is_configurable_from_the_environment(monkeypatch):
    monkeypatch.setenv("ENTROPY_CACHE_MAX", "7")
    assert SamplerConfig.from_env().cache_max == 7
    assert EntropyCache(SamplerConfig.from_env().cache_max).max_entries == 7
    assert SamplerConfig().cache_max == 512


def test_sampling_through_the_sampler_uses_the_cache_and_tracks_per_file_entropy(proc):
    proc.file("/data/low.bin", b"\0" * 4096)
    proc.file("/data/high.bin", RANDOM_BLOCK)
    proc.add_fd(3, "/data/low.bin", O_WRONLY_LARGEFILE, 4096)
    proc.add_fd(4, "/data/high.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader()
    sampler = EntropySampler(r, config=SamplerConfig(samples=3), sleep=lambda s: asyncio.sleep(0))

    async def go():
        return await sampler.collect(PID)
    result = asyncio.run(go())
    assert result.valid_samples == 3
    assert result.files == ["/data/low.bin", "/data/high.bin"]
    values = result.file_entropies()
    assert len(values) == 2 and values[0] == 0.0 and values[1] > 7.9      # oldest sampled first
    assert r.cache.misses == 2 and r.cache.hits == 4                      # 2 files read once, then cached


def test_per_file_entropies_keep_only_the_eight_most_recent_files(proc):
    for fd in range(3, 15):
        proc.file(f"/data/f{fd}.bin", random.Random(fd).randbytes(4096))
        proc.add_fd(fd, f"/data/f{fd}.bin", O_WRONLY_LARGEFILE, 4096)
    r = proc.reader(SamplerConfig(max_files=20))
    result = asyncio.run(EntropySampler(r, config=SamplerConfig(samples=1, max_files=20)).collect(PID))
    assert len(result.files) == 12 and len(result.file_entropies()) == 8
    assert list(result.files.entropies) == [f"/data/f{fd}.bin" for fd in range(7, 15)]


def test_a_reader_double_that_overrides_read_written_is_still_used(proc):
    from agents.security_agent.entropy_sampler import ProcFdReader

    class Double(ProcFdReader):
        def read_written(self, wf):
            return RANDOM_BLOCK
    proc.add_fd(3, "/data/x.bin", O_WRONLY_LARGEFILE, 4096)
    d = Double(str(proc.root), SamplerConfig(), readlink=lambda p: proc.links[str(Path(p))])
    assert EntropySampler(d).sample_once(PID) > 7.9
