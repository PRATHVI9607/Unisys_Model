"""Security agent: Falco parsing + tailing, windows, entropy sampling, owner resolution, publishing."""

import asyncio
import json
import os
import time
from types import SimpleNamespace

import fakeredis
import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from agents.security_agent import agent as sa
from agents.security_agent.falco import FalcoTail, parse_line
from kubeheal.contracts import STREAM_SECURITY, Prediction, SecurityEvent, key_event
from kubeheal.features.security import MIN_WINDOW_S


def falco_line(evt="openat", path="/data/a.txt", ns="shop", pod="web-7d9f8b6c5-x2x7q", pid=4242,
               flags="O_WRONLY|O_CREAT", **extra):
    fields = {"evt.type": evt, "fd.name": path, "proc.pid": pid, "k8s.ns.name": ns, "k8s.pod.name": pod,
              "evt.arg.flags": flags, **extra}
    return json.dumps({"output": "x", "priority": "Warning", "rule": "r",
                       "time": "2024-05-01T12:00:00.123456789Z", "output_fields": fields})


# ── parsing ──────────────────────────────────────────────────────────────────
def test_parse_line_fields():
    # real Falco 0.45 rename shape: no fd (fd.name null), paths in fs.path.source / fs.path.target
    rename = {"fs.path.source": "/data/a.txt", "fs.path.target": "/data/a.txt.locked"}
    ev = parse_line(falco_line("renameat2", None, **rename))
    assert ev == {"namespace": "shop", "pod": "web-7d9f8b6c5-x2x7q", "pid": 4242, "container_id": "", "pod_uid": "",
                  "syscall": "renameat2",
                  "path": "/data/a.txt", "new_path": "/data/a.txt.locked", "ts_ms": 1714564800123}
    write = parse_line(falco_line("openat", "/data/a.txt", **{"fs.path.source": None, "fs.path.target": None}))
    assert (write["path"], write["new_path"], write["syscall"]) == ("/data/a.txt", "", "open_w")


@pytest.mark.parametrize("evt,flags,expected", [
    ("openat", "O_RDONLY", "open_r"), ("openat", "O_RDONLY|O_CLOEXEC", "open_r"),
    ("openat", "O_RDWR|O_CREAT", "open_w"), ("open", "O_WRONLY|O_TRUNC", "open_w"), ("openat2", "O_CREAT", "open_w"),
    ("openat", None, "open_r"), ("openat", "<NA>", "open_r"), ("openat", "", "open_r"),
    ("openat", "262", "open_w"), ("openat", "577", "open_r"), ("openat", "0", "open_r"), ("creat", None, "open_w"),
    ("unlink", "O_WRONLY", "unlink"), ("ftruncate", None, "ftruncate")])
def test_parse_line_classifies_opens_by_flags(evt, flags, expected):
    assert parse_line(falco_line(evt, flags=flags))["syscall"] == expected


@pytest.mark.parametrize("line", [
    falco_line(ns="<NA>"), falco_line(pod=None), falco_line(evt=""), "not json", "[]", '{"output": "x"}'])
def test_parse_line_drops_unusable(line):
    assert parse_line(line) is None


# ── tailing ──────────────────────────────────────────────────────────────────
def test_tail_skips_history_handles_partial_truncation_rotation(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text("old-1\nold-2\n")
    t = FalcoTail(str(p))
    assert t.read_lines() == []                          # starts at the end: no replay

    with open(p, "a") as f:
        f.write("a\nb-par")
    assert t.read_lines() == [b"a"]
    with open(p, "a") as f:
        f.write("tial\n")
    assert t.read_lines() == [b"b-partial"]

    p.write_text("c\n")                                  # truncated in place (same inode, smaller)
    assert t.read_lines() == [b"c"]

    with open(p, "a") as f:
        f.write("d\n")                                   # written just before rotation, not yet read
    os.rename(p, tmp_path / "events.jsonl.1")
    p.write_text("e\n")                                  # new inode
    assert t.read_lines() == [b"d", b"e"]
    t.close()


def test_tail_frees_consumed_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr("agents.security_agent.falco.FREE_EVERY", 1 << 16)
    p = tmp_path / "events.jsonl"
    p.write_bytes(b"x" * (1 << 20) + b"\n")              # history the tail never reads, freed too
    t = FalcoTail(str(p))
    assert t.read_lines() == []
    with open(p, "ab") as f:                             # the writer keeps appending at its offset
        f.write(b"y" * 100 + b"\n" + b"z" * (1 << 20) + b"\n")
    lines = t.read_lines() + t.read_lines()
    assert lines[0] == b"y" * 100 and len(lines) == 2
    st = os.stat(p)
    assert st.st_size > 2 << 20 and st.st_blocks * 512 < 1 << 20   # same size, storage released
    with open(p, "ab") as f:
        f.write(b"after\n")
    assert t.read_lines() == [b"after"]
    t.close()


def test_tail_missing_file_then_created(tmp_path):
    p = tmp_path / "events.jsonl"
    t = FalcoTail(str(p))
    assert t.read_lines() == []
    p.write_text("first\n")
    assert t.read_lines() == [b"first"]                  # a file created later is read from the start
    t.close()


# ── windows ──────────────────────────────────────────────────────────────────
@pytest.fixture
async def redis():
    r = fakeredis.FakeAsyncRedis(decode_responses=True)
    yield r
    await r.aclose()


class FakeOwners:
    def __init__(self, name="web"):
        self.name, self.calls = name, 0

    async def resolve(self, ns, pod):
        self.calls += 1
        return self.name


def make_agent(redis, proc_root="/nonexistent"):
    return sa.SecurityAgent(redis, None, FakeOwners(), proc_root=proc_root,
                            protected=frozenset({"kube-system"}), namespaces=[])


def test_window_bounded_and_written_tracking(redis):
    a = make_agent(redis)
    for i in range(sa.MAX_EVENTS + 100):
        a.ingest(parse_line(falco_line(path=f"/data/f{i}")))
    w = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    assert len(w.events) == sa.MAX_EVENTS
    assert len(w.written) == sa.MAX_WRITTEN
    assert next(reversed(w.written)) == f"/data/f{sa.MAX_EVENTS + 99}"
    a.ingest(parse_line(falco_line(ns="kube-system")))
    assert ("kube-system", "web-7d9f8b6c5-x2x7q") not in a.windows
    a.ingest(parse_line(falco_line("openat", "/etc/passwd", flags="O_RDONLY")))  # read-only opens are not "written"
    assert "/etc/passwd" not in w.written


def test_recreated_pod_with_same_name_gets_a_fresh_window(redis):
    a = make_agent(redis)
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": "uid-1"})))
    old = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    old.last_publish = time.monotonic()                     # in cooldown
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": "uid-1"})))
    assert a.windows[("shop", "web-7d9f8b6c5-x2x7q")] is old and len(old.events) == 2
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": "uid-2"})))   # killed + recreated under the same name
    w = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    assert w is not old and len(w.events) == 1 and w.last_publish == float("-inf") and w.pod_uid == "uid-2"


async def test_idle_window_evicted(redis):
    a = make_agent(redis)
    a.ingest(parse_line(falco_line()))
    w = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    w.new, w.last_seen = 0, time.monotonic() - sa.IDLE_EVICT_S - 1
    await a.evaluate_all()
    assert a.windows == {}


# ── entropy ──────────────────────────────────────────────────────────────────
def test_sample_entropy_reads_through_proc_root(tmp_path):
    root = tmp_path / "1234" / "root" / "data"
    root.mkdir(parents=True)
    (root / "enc.bin").write_bytes(os.urandom(70_000))
    (root / "plain.txt").write_bytes(b"a" * 1000)
    (root / "empty").write_bytes(b"")
    os.mkfifo(root / "pipe")                              # must not block
    outside = tmp_path / "outside"                        # stands in for a file of the agent's own root
    outside.mkdir()
    (outside / "secret").write_bytes(os.urandom(4096))
    os.symlink(outside, root / "lnk")                     # planted symlinks must not be followed
    os.symlink(outside / "secret", root / "lnk-file")
    paths = ["/data/enc.bin", "/data/plain.txt", "/data/missing", "/data/pipe", "/data/empty",
             "/../../data/enc.bin", "/data/lnk/secret", "/data/lnk-file", "/"]
    ent = sa.sample_entropy(str(tmp_path), [(p, (1234, "")) for p in paths])
    assert len(ent) == 3
    assert ent[0] > 7.9 and ent[1] == 0.0 and ent[2] > 7.9


def test_entropy_pid_resolved_by_container_id(tmp_path):
    """Falco's root-namespace PID (4242) does not exist in a nested node's /proc: find the container by cgroup."""
    (tmp_path / "77" / "root" / "data").mkdir(parents=True)
    (tmp_path / "77" / "root" / "data" / "x.locked").write_bytes(os.urandom(4096))
    (tmp_path / "77" / "cgroup").write_text("0::/kubepods/besteffort/pod1/abc123def456" + "0" * 52 + "\n")
    (tmp_path / "5" / "root").mkdir(parents=True)
    (tmp_path / "5" / "cgroup").write_text("0::/system.slice/containerd.service\n")
    cache = {}
    assert sa.local_pid(str(tmp_path), 4242, "abc123def456", cache) == 77 and cache == {"abc123def456": 77}
    assert sa.local_pid(str(tmp_path), 5, "", cache) == 5                      # no container id: trust Falco
    assert sa.local_pid(str(tmp_path), 4242, "ffffffffffff", cache) is None    # container gone
    ent = sa.sample_entropy(str(tmp_path), [("/data/x.locked", (4242, "abc123def456"))], cache)
    assert len(ent) == 1 and ent[0] > 7.9



def test_entropy_cache_skips_unchanged_files_and_catches_in_place_rewrites(tmp_path, monkeypatch):
    from collections import OrderedDict
    data = tmp_path / "1" / "root" / "data"
    data.mkdir(parents=True)
    f = data / "a.txt"
    f.write_bytes(b"a" * 8192)
    reads = []
    real_read = os.read
    monkeypatch.setattr(sa.os, "read", lambda fd, n: reads.append(n) or real_read(fd, n))
    cache = OrderedDict()
    files = [("/data/a.txt", (1, ""))]
    assert sa.sample_entropy(str(tmp_path), files, cache=cache) == [0.0]
    assert sa.sample_entropy(str(tmp_path), files, cache=cache) == [0.0] and reads == [sa.ENTROPY_BYTES]
    st = f.stat()
    time.sleep(0.05)                                         # past coarse kernel timestamp granularity
    f.write_bytes(os.urandom(8192))                          # same size, mtime set back: ctime still changes
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert sa.sample_entropy(str(tmp_path), files, cache=cache)[0] > 7.0 and len(reads) == 2
    for i in range(sa.MAX_ENTROPY_CACHE + 5):                # bounded LRU
        (data / f"f{i}").write_bytes(b"x")
        sa.sample_entropy(str(tmp_path), [(f"/data/f{i}", (1, ""))], cache=cache)
    assert len(cache) == sa.MAX_ENTROPY_CACHE and "/data/a.txt" not in cache


def test_entropy_reads_only_the_file_head(tmp_path):
    (tmp_path / "1" / "root").mkdir(parents=True)
    (tmp_path / "1" / "root" / "f").write_bytes(b"\0" * sa.ENTROPY_BYTES + os.urandom(65536))
    assert sa.file_entropy(str(tmp_path), 1, "/f") == 0.0


# ── owner resolution ─────────────────────────────────────────────────────────
def meta(*owners):
    return SimpleNamespace(metadata=SimpleNamespace(
        owner_references=[SimpleNamespace(kind=k, name=n) for k, n in owners] or None))


class FakeCore:
    def __init__(self, pods):
        self.pods, self.calls = pods, 0

    async def read_namespaced_pod(self, name, ns, **_):
        self.calls += 1
        if name not in self.pods:
            raise ApiException(status=404, reason="Not Found")
        return self.pods[name]


class FakeApps:
    def __init__(self, rs):
        self.rs = rs

    async def read_namespaced_replica_set(self, name, ns, **_):
        return self.rs[name]


async def test_owner_resolution():
    core = FakeCore({"web-abc12-x2x7q": meta(("ReplicaSet", "web-abc12")),
                     "solo": meta(),
                     "job-pod": meta(("Job", "nightly")),
                     "orphan-rs-pod": meta(("ReplicaSet", "orphan-rs"))})
    apps = FakeApps({"web-abc12": meta(("Deployment", "web")), "orphan-rs": meta()})
    r = sa.OwnerResolver(core, apps)
    assert await r.resolve("shop", "web-abc12-x2x7q") == "web"
    assert await r.resolve("shop", "web-abc12-x2x7q") == "web"
    assert core.calls == 1                                # cached
    assert await r.resolve("shop", "solo") == "solo"
    assert await r.resolve("shop", "job-pod") == "job-pod"
    assert await r.resolve("shop", "orphan-rs-pod") == "orphan-rs-pod"
    assert await r.resolve("shop", "gone") == "gone"      # API error → pod name


# ── evaluation + publish ─────────────────────────────────────────────────────
def stub_predict(monkeypatch, label, risk, uncertain=False):
    calls = []

    async def fake(session, task, rows):
        calls.extend((task, f) for f in rows)
        return [Prediction(model_version="sec-test", label=label, risk=risk, probabilities={label: 0.9},
                           prediction_set=[label], uncertain=uncertain) for _ in rows]
    monkeypatch.setattr(sa, "predict_batch", fake)
    return calls


async def test_publish_round_trip_and_cooldown(redis, monkeypatch, tmp_path):
    (tmp_path / "4242" / "root" / "data").mkdir(parents=True)
    (tmp_path / "4242" / "root" / "data" / "a.txt.locked").write_bytes(os.urandom(4096))
    a = make_agent(redis, proc_root=str(tmp_path))
    calls = stub_predict(monkeypatch, "ransomware", 0.93)
    a.ingest(parse_line(falco_line("openat", "/data/a.txt")))
    a.ingest(parse_line(falco_line("renameat2", None, **{"fs.path.source": "/data/a.txt",
                                                         "fs.path.target": "/data/a.txt.locked"})))

    await a.evaluate_all()
    entries = await redis.xrange(STREAM_SECURITY)
    assert len(entries) == 1
    ev = SecurityEvent.from_fields(entries[0][1])
    assert (ev.namespace, ev.workload, ev.pod) == ("shop", "web", "web-7d9f8b6c5-x2x7q")
    assert (ev.label, ev.risk, ev.n_events) == ("ransomware", 0.93, 2)
    assert ev.features == calls[0][1] and ev.features["n_entropy_samples"] == 1.0
    assert ev.features["n_events"] == 2.0
    assert ev.window_start_ms <= ev.window_end_ms
    assert await redis.ttl(key_event("security", ev.event_id)) > 0

    await a.evaluate_all()                                # no new events → no evaluation
    assert len(calls) == 1
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()                                # same label inside cooldown → suppressed
    assert len(calls) == 2 and await redis.xlen(STREAM_SECURITY) == 1


async def test_certain_verdict_after_uncertain_skips_cooldown(redis, monkeypatch):
    a = make_agent(redis)
    stub_predict(monkeypatch, "ransomware", 0.8, uncertain=True)
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()
    stub_predict(monkeypatch, "ransomware", 0.9)
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()                                # certain after uncertain: published despite the cooldown
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()                                # certain after certain: cooled down
    assert [SecurityEvent.from_fields(f).uncertain for _, f in await redis.xrange(STREAM_SECURITY)] == [True, False]


async def test_low_risk_and_inference_down_publish_nothing(redis, monkeypatch):
    a = make_agent(redis)
    stub_predict(monkeypatch, "benign", 0.1)
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()

    async def down(*_):
        return None
    monkeypatch.setattr(sa, "predict_batch", down)
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()
    assert await redis.xlen(STREAM_SECURITY) == 0
    calls = stub_predict(monkeypatch, "ransomware", 0.95)     # inference back, no new Falco events
    await a.evaluate_all()
    assert len(calls) == 1 and await redis.xlen(STREAM_SECURITY) == 1


async def test_capture_mode_records_every_scored_window(redis, monkeypatch):
    from kubeheal.contracts import STREAM_CAPTURE
    a = make_agent(redis)
    stub_predict(monkeypatch, "benign", 0.1)
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()
    assert await redis.xlen(STREAM_CAPTURE) == 0               # off by default
    a.capture = True
    a.ingest(parse_line(falco_line()))
    await a.evaluate_all()
    (_, fields), = await redis.xrange(STREAM_CAPTURE)
    ev = SecurityEvent.from_fields(fields)
    assert (ev.namespace, ev.pod, ev.workload, ev.n_events) == ("shop", "web-7d9f8b6c5-x2x7q", "web", 2)
    assert ev.features and ev.window_end_ms >= ev.window_start_ms
    assert await redis.xlen(STREAM_SECURITY) == 0              # below threshold: nothing published


# ── pod byte counters (write_bytes_per_s, net_out_bytes_per_s) ─────────────────
UID = "72a0a512-5844-4eed-9098-44afdfec5286"
NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999 1 0 0 0 0 0 0 {lo} 1 0 0 0 0 0 0
  eth0: 2344074 27971 0 0 0 0 0 0 {eth0} 24665 0 0 0 0 0 0
"""


def fake_node(root, tx=1000, wbytes=(500, 20), lo=7777):
    """A /proc tree with pid 4242 (net/dev) and the node's cgroup2 tree under /proc/1/root (systemd driver)."""
    (root / "4242" / "net").mkdir(parents=True, exist_ok=True)
    (root / "4242" / "net" / "dev").write_text(NET_DEV.format(lo=lo, eth0=tx))
    cg = root / "1/root/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice"
    cg = cg / f"kubepods-burstable-pod{UID.replace('-', '_')}.slice"
    cg.mkdir(parents=True, exist_ok=True)
    (cg / "io.stat").write_text("".join(f"25{i}:0 rbytes=7 wbytes={b} rios=1 wios=1 dbytes=0 dios=0\n"
                                        for i, b in enumerate(wbytes)))


def test_net_tx_bytes_sums_non_loopback(tmp_path):
    fake_node(tmp_path, tx=12211861)
    assert sa.net_tx_bytes(str(tmp_path), 4242) == 12211861.0
    assert sa.net_tx_bytes(str(tmp_path), 999) is None                        # process gone
    (tmp_path / "4242" / "net" / "dev").write_text("h1\nh2\n  eth0: garbage\n")
    assert sa.net_tx_bytes(str(tmp_path), 4242) is None                       # unparsable, never 0


def test_cgroup_write_bytes_sums_devices_and_validates_uid(tmp_path):
    fake_node(tmp_path)
    cg = str(tmp_path / "1/root/sys/fs/cgroup")
    assert sa.cgroup_write_bytes(cg, UID) == 520.0
    assert sa.cgroup_write_bytes(cg, "0" * 8 + UID[8:]) is None               # no such pod
    assert sa.cgroup_write_bytes(cg, "") is None
    assert sa.cgroup_write_bytes(cg, "../../../etc") is None                  # never a path from Falco
    fs = tmp_path / "cgfs" / "kubepods" / "besteffort" / f"pod{UID}"         # cgroupfs driver layout
    fs.mkdir(parents=True)
    (fs / "io.stat").write_text("")                                          # cgroup exists, no I/O yet
    assert sa.cgroup_write_bytes(str(tmp_path / "cgfs"), UID) == 0.0


def test_counter_delta():
    assert sa.counter_delta([(1, 100.0, None), (2, 350.0, 7.0)], 1) == 250.0
    assert sa.counter_delta([(1, 100.0, None), (2, 350.0, 7.0)], 2) is None   # first sample unknown
    assert sa.counter_delta([(1, 100.0, 1.0)], 1) is None                     # one sample: no delta
    assert sa.counter_delta([(1, 100.0, 1.0), (2, 50.0, 1.0)], 1) is None     # counter reset


async def test_window_rates_from_first_and_last_sample(redis, monkeypatch, tmp_path):
    clock = [time.time_ns() // 1_000_000]
    monkeypatch.setattr(sa, "now_ms", lambda: clock[0])      # samples are >= SAMPLE_EVERY_S apart
    fake_node(tmp_path, tx=1000, wbytes=(500,))
    a = make_agent(redis, proc_root=str(tmp_path))
    calls = stub_predict(monkeypatch, "benign", 0.1)
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": UID})))
    await a.evaluate_all()
    clock[0] += 1500
    assert calls[-1][1]["net_out_bytes_per_s"] is None and calls[-1][1]["write_bytes_per_s"] is None
    fake_node(tmp_path, tx=6000, wbytes=(500 + 10_000,))
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": UID})))
    await a.evaluate_all()
    clock[0] += 1500
    f = calls[-1][1]                                         # same event ts → window_s floors at MIN_WINDOW_S
    assert f["net_out_bytes_per_s"] == 5000 / MIN_WINDOW_S
    assert f["write_bytes_per_s"] == 10_000 / MIN_WINDOW_S
    w = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    w.samples[0] = (0, 0.0, 0.0)                             # older than the event window: trimmed, not used
    clock[0] += 1500
    fake_node(tmp_path, tx=9000, wbytes=(500 + 10_000,))
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": UID})))
    await a.evaluate_all()
    assert calls[-1][1]["net_out_bytes_per_s"] == 3000 / MIN_WINDOW_S and len(w.samples) == 2
    assert calls[-1][1]["write_bytes_per_s"] == 0.0                     # measured: nothing written, not None


async def test_burst_triggers_scoring_before_the_timer(redis, monkeypatch):
    a = make_agent(redis)
    calls = stub_predict(monkeypatch, "benign", 0.1)
    a.ingest(parse_line(falco_line(pod="quiet")))
    for i in range(sa.BURST_EVENTS - 1):
        a.ingest(parse_line(falco_line(path=f"/data/f{i}")))
    assert not a.wake.is_set()
    await a.evaluate_all(burst_only=True)
    assert calls == []                                       # below the threshold: waits for the timer
    a.ingest(parse_line(falco_line()))
    assert a.wake.is_set()
    await a.evaluate_all(burst_only=True)                    # only the bursting pod, in one batch
    assert len(calls) == 1 and calls[0][1]["n_events"] == sa.BURST_EVENTS
    await a.evaluate_all()                                   # timer tick: the slow pod
    assert len(calls) == 2 and calls[1][1]["n_events"] == 1.0


async def test_timer_scores_a_quiet_pod_within_the_interval(redis, monkeypatch):
    assert sa.BURST_EVENTS == 32 and sa.EVAL_INTERVAL_S == 1.0           # sub-second kill budget (manifest sets 1 too)
    monkeypatch.setattr(sa, "EVAL_INTERVAL_S", 0.05)
    monkeypatch.setattr(sa, "MIN_TICK_S", 0.01)
    a = make_agent(redis)
    calls = stub_predict(monkeypatch, "benign", 0.1)
    a.ingest(parse_line(falco_line()))                                    # 1 event: far below the burst threshold
    task = asyncio.create_task(a.eval_loop())
    await asyncio.sleep(0.3)
    task.cancel()
    assert len(calls) == 1 and calls[0][1]["n_events"] == 1.0


async def test_one_inference_call_per_tick_and_partial_feature_failure(redis, monkeypatch):
    a = make_agent(redis)
    batches = []

    async def fake(session, task, rows):
        batches.append(len(rows))
        return [Prediction(model_version="t", label="benign", risk=0.1, probabilities={"benign": 1.0},
                           prediction_set=["benign"], uncertain=False) for _ in rows]
    monkeypatch.setattr(sa, "predict_batch", fake)
    for pod in ("a", "b", "c"):
        a.ingest(parse_line(falco_line(pod=pod)))
    a.windows[("shop", "c")].events.clear()                  # its feature extraction raises: skipped, logged
    await a.evaluate_all()
    assert batches == [2]


# ── review fixes ────────────────────────────────────────────────────────────
def test_written_files_leave_with_the_event_window(tmp_path):
    root = tmp_path / "42" / "root" / "data"
    root.mkdir(parents=True)
    for i in range(8):
        (root / f"b{i}.gz").write_bytes(os.urandom(16384))
    a = sa.SecurityAgent(None, None, None, proc_root=str(tmp_path), protected=frozenset(), namespaces=[])
    ev = lambda sc, p, ts: {"namespace": "ns", "pod": "p", "pid": 42, "container_id": "", "pod_uid": "",  # noqa: E731
                            "syscall": sc, "path": p, "new_path": "", "ts_ms": ts}
    for i in range(8):
        a.ingest(ev("open_w", f"/data/b{i}.gz", 1_000))
    a.ingest(ev("open_r", "/data/app.log", 300_000))             # 5 min later: one read
    f, events, *_ = asyncio.run(a._features(a.windows[("ns", "p")]))
    assert len(events) == 1 and f["n_entropy_samples"] == 0.0 and not a.windows[("ns", "p")].written


async def test_sustained_byte_rate_survives_burst_rescoring(redis, monkeypatch, tmp_path):
    clock = [1_714_564_800_000]
    monkeypatch.setattr(sa, "now_ms", lambda: clock[0])
    a = make_agent(redis, proc_root=str(tmp_path))
    calls = stub_predict(monkeypatch, "benign", 0.1)
    for sec in range(61):                                        # 10 MB/s for 60 s, scored 5 x per second
        fake_node(tmp_path, tx=1000, wbytes=(sec * 10_000_000,))
        for _ in range(5):
            a.ingest(parse_line(falco_line(**{"k8s.pod.uid": UID})))
            a.windows[("shop", "web-7d9f8b6c5-x2x7q")].events[-1]["ts_ms"] = clock[0]
            await a.evaluate_all()
            clock[0] += 200
    rate = calls[-1][1]["write_bytes_per_s"]
    assert 0.95e7 < rate < 1.05e7, rate
    assert len(a.windows[("shop", "web-7d9f8b6c5-x2x7q")].samples) <= sa.MAX_SAMPLES


async def test_owner_lookups_run_concurrently_for_the_batch(redis, monkeypatch):
    class Slow:
        active = peak = 0

        async def resolve(self, ns, pod):
            Slow.active += 1
            Slow.peak = max(Slow.peak, Slow.active)
            await asyncio.sleep(0.02)
            Slow.active -= 1
            return "web"
    a = sa.SecurityAgent(redis, None, Slow(), protected=frozenset(), namespaces=[])
    stub_predict(monkeypatch, "ransomware", 0.95)
    for i in range(4):
        a.ingest(parse_line(falco_line(pod=f"web-7d9f8b6c5-p{i}")))
    await a.evaluate_all()
    assert Slow.peak == 4


def test_idle_eviction_drops_container_pid_cache(redis):
    a = make_agent(redis)
    a.ingest(parse_line(falco_line(**{"container.id": "abc123"})))
    a.pids["abc123"] = 77
    w = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    w.last_seen -= sa.IDLE_EVICT_S + 1
    asyncio.run(a.evaluate_all())
    assert not a.windows and "abc123" not in a.pids


async def test_published_event_carries_pod_uid(redis, monkeypatch):
    a = make_agent(redis)
    stub_predict(monkeypatch, "ransomware", 0.95)
    a.ingest(parse_line(falco_line(**{"k8s.pod.uid": UID})))
    await a.evaluate_all()
    (_, fields), = await redis.xrange(STREAM_SECURITY)
    assert SecurityEvent.from_fields(fields).pod_uid == UID


async def test_agent_recent_features_match_the_feature_function(redis, tmp_path):
    from kubeheal.features.security import RECENT_EVENTS, recent_features
    a = make_agent(redis, proc_root=str(tmp_path))
    for i in range(300):
        a.ingest(parse_line(falco_line(path=f"/data/old{i}", flags="O_RDONLY")))
    for i in range(RECENT_EVENTS):
        a.ingest(parse_line(falco_line(path=f"/data/new{i}.txt")))
    w = a.windows[("shop", "web-7d9f8b6c5-x2x7q")]
    features, events, *_ = await a._features(w)
    want = recent_features(events, [])                 # /nonexistent files: no entropy samples
    assert {k: features[k] for k in want} == want
    assert features["recent_frac_write"] == 1.0 and features["frac_write"] < 0.3
    assert features["recent_unique_files"] == RECENT_EVENTS
