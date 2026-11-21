"""KubeHeal security agent (DaemonSet, hostPID): Falco events + file entropy → SecurityEvents.

It never decides (fusion is the single decision point) and never fabricates events: every feature comes
from a real Falco event or a real file read. Its one action is fusion's: a containment command on
STREAM_CONTAIN freezes that pod's cgroup if the pod runs on this node (contain_loop).

Run: python -m agents.security_agent.agent
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import posixpath
import re
import ssl
import stat
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from types import SimpleNamespace

import aiohttp
import orjson
import redis.asyncio as aioredis
from prometheus_client import Counter, Gauge, Histogram

from agents.common import (
    connect_redis,
    contain_verify,
    env_list,
    load_kube_config,
    predict_batch,
    protected_namespaces,
    publish_event,
    run,
    setup_logging,
    start_http,
)
from agents.security_agent.falco import FalcoTail, parse_line, watch_dir
from kubeheal.contracts import (
    SECURITY_PUBLISH_RISK,
    STREAM_CAPTURE,
    STREAM_CONTAIN,
    STREAM_SECURITY,
    SecurityEvent,
    new_event_id,
    now_ms,
)
from kubeheal.features.security import (
    MAX_ENTROPY_SAMPLES,
    MAX_WINDOW_EVENTS,
    SECURITY_FEATURES,
    SYSCALL_GROUPS,
    WINDOW_S,
    security_features,
    shannon_entropy,
    window_seconds,
)
from kubeheal.ml.bundle import ModelBundle

log = logging.getLogger("kubeheal.security")

FALCO_EVENTS_PATH = os.environ.get("FALCO_EVENTS_PATH", "/var/run/falco/events.jsonl")
PROC_ROOT = os.environ.get("PROC_ROOT", "/proc")
# Node cgroup2 root (hostPath /sys/fs/cgroup, read-write: containment freezes pods); unset or absent → the node's
# tree through its init's mount namespace (PROC_ROOT/1/root, hostPID + SYS_PTRACE).
CGROUP_ROOT = os.environ.get("CGROUP_ROOT", "/host/sys/fs/cgroup")
EVAL_INTERVAL_S = float(os.environ.get("EVAL_INTERVAL_S", "1"))   # timer for pods below the burst threshold
CAPTURE = os.environ.get("KUBEHEAL_CAPTURE", "0") == "1"   # lab data collection: also XADD every scored window
# Embedded scoring: the security bundle loaded in-process; unset, absent or unloadable → the inference service.
MODEL_DIR = os.environ.get("SECURITY_MODEL_DIR", "/models/security")
# Containment commands must carry fusion's HMAC (agents.common.contain_sign); unset → unsigned ones are accepted.
CONTAIN_KEY = os.environ.get("CONTAIN_HMAC_KEY", "")

MAX_EVENTS = MAX_WINDOW_EVENTS   # per-pod window; events older than WINDOW_S (vs the newest) leave it
# Capture entries carry the raw window (~70 KB); the lab reader consumes continuously, so a short cap keeps
# Redis (maxmemory 192mb, noeviction) far from full.
CAPTURE_MAXLEN = 500
BURST_EVENTS = 32          # a pod with this many new events is scored at once, not at the next timer tick
MIN_TICK_S = 0.25          # pause between evaluation rounds: bounds burst re-scoring under a flood
MAX_BATCH = 256            # inference service's predict_batch cap
IDLE_EVICT_S = 300.0       # forget pods with no events for this long
MAX_WRITTEN = 64           # recently written files remembered per pod
ENTROPY_BYTES = 16 * 1024  # file head: encrypted/compressed heads score within 0.01 bit/byte of 64 KiB
MAX_ENTROPY_CACHE = 2 * MAX_WRITTEN   # per pod: files whose entropy is reused while their stat is unchanged
COOLDOWN_S = 60.0          # per pod; a label change still publishes
RISK_RISE = 0.05           # a risk this much above the last published one is news: not cooled down
POD_MIN_INTERVAL_S = 0.5   # a pod is re-scored at most this often; a pod not scored that recently goes at once
HOT_INTERVAL_S = 0.05      # ... but a pod that just renamed a file to "<name>.<ext>" (the encryption signature), or
                           # last scored suspicious or worse, is re-scored this often
HOT_TICK_S = 0.02          # pause between evaluation rounds while a hot pod is due (MIN_TICK_S otherwise)
IDLE_POLL_S = 0.2          # tail poll when the file watch (inotify) is unavailable; with it, the fallback wake-up
MAX_BACKOFF_S = 30.0       # failed evaluations retry at once, then after 1, 2, 4 ... s up to this
PID_MISS_TTL_S = 10.0      # a container id not found in /proc is not searched for again this long
MAX_PID_CACHE = 4096
# A pod this agent froze that is still frozen after this long (no kill, no release) is logged and counted, never
# thawed on its own: ransomware must not run again without a decision.
FREEZE_MAX_S = float(os.environ.get("FREEZE_MAX_S", "900"))
# The sensor writes its counters here every ~5 s (shared volume); read on the eval tick, at most every STATS_EVERY_S.
SENSOR_STATS_PATH = os.environ.get("SENSOR_STATS_PATH", "/var/run/kubeheal/sensor-stats.json")
# "sensor" (eBPF, default) or "falco": only labels kubeheal_security_event_source so KubeHealSensorDown skips Falco installs.
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "sensor")
STATS_EVERY_S = 5.0
STATS_FRESH_S = 30.0       # a stats file older than this: the sensor is down
CONTAIN_MAX_AGE_S = 30.0   # older containment commands are stale (the API delete has landed or failed by now)
LAG_WARN_S = 5.0           # event lag (now - event time) worth a WARNING, logged at most once a minute
OWNER_TTL_S = 300.0
KUBE_TIMEOUT_S = 10        # owner lookups run inside an evaluation; never let one stall the eval loop
MAX_CONCURRENT = 8
SAMPLE_EVERY_S = 1.0       # counter samples are >= this far apart: a burst of re-scoring must not flush the window
MAX_SAMPLES = int(WINDOW_S) + 2   # one per SAMPLE_EVERY_S across the whole event window
POD_UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

WRITE_SYSCALLS = SYSCALL_GROUPS["write"] | SYSCALL_GROUPS["truncate"]
RENAME_SYSCALLS = SYSCALL_GROUPS["rename"]

EVENTS = Counter("kubeheal_security_falco_events_total", "Falco events ingested into pod windows")
EVALS = Counter("kubeheal_security_evaluations_total", "Pod window evaluations by outcome", ["outcome"])
EVENT_LAG = Histogram("kubeheal_security_event_lag_seconds", "Now minus event time, newest event of each read",
                      buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300))
CONTAIN = Counter("kubeheal_security_contain_total", "Containment commands by outcome", ["outcome"])
SCORE_SECONDS = Histogram("kubeheal_security_score_seconds", "Embedded scoring (predict + explain) per batch",
                          buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5))
FROZEN_OVERDUE = Gauge("kubeheal_security_frozen_overdue", "Pods frozen by this agent still frozen after FREEZE_MAX_S")
SENSOR_EVENTS = Counter("kubeheal_sensor_events_total", "Events the node sensor saw (from its stats file)")
SENSOR_DROPS = Counter("kubeheal_sensor_drops_total", "Events the sensor dropped (ring buffer full)")
SENSOR_POOL_FULL = Counter("kubeheal_sensor_pool_full_total", "Sensor event-pool exhaustions")
SENSOR_LOST = Counter("kubeheal_sensor_lost_total", "Events the sensor lost before delivery")
SENSOR_UP = Gauge("kubeheal_sensor_up", "1 while the sensor stats file is fresher than 30 s")
SENSOR_COUNTERS = {"events_total": SENSOR_EVENTS, "drops_total": SENSOR_DROPS, "pool_full_total": SENSOR_POOL_FULL,
                   "lost_total": SENSOR_LOST}
EVENT_SOURCE_INFO = Gauge("kubeheal_security_event_source", "1 for the configured event source", ["source"])
MODEL_MODE = Gauge("kubeheal_security_model_mode", "1 for the scoring path in use", ["mode"])
CONTAIN_AGE = Histogram("kubeheal_security_contain_age_seconds", "Containment command age when its pod froze",
                        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))

Key = tuple[str, str]   # (namespace, pod)


@dataclass
class PodWindow:
    events: deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    written: OrderedDict = field(default_factory=OrderedDict)   # container path → (pid, container id, ts_ms), oldest first
    new: int = 0
    last_seen: float = field(default_factory=time.monotonic)
    last_publish: float = float("-inf")
    last_label: str = ""
    last_uncertain: bool = False
    last_risk: float = 0.0
    due_at: float = float("-inf")                              # monotonic; not scored before (interval, backoff)
    scored_at: float = float("-inf")                           # monotonic time this window was last taken for scoring
    hot: bool = False                                          # a rename added a suffix since the last scoring
    suspicious: bool = False                                   # the last scoring was at publish risk or above
    fails: int = 0                                             # consecutive failed evaluations
    pod_uid: str = ""
    proc: tuple[int, str] = (0, "")                            # (Falco pid, container id) of the latest event
    samples: deque = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES))  # (clock() s, net tx, cgroup wbytes)
    entropy_cache: OrderedDict = field(default_factory=OrderedDict)  # path → (stat signature, entropy), LRU


def _suffix_added(path: str, new: str) -> bool:
    """path → path + ".ext" with a non-numeric ext (file.txt → file.txt.locked); a rotation (x.log → x.log.1) is not."""
    n = len(path)
    return 0 < n < len(new) - 1 and new[n] == "." and new.startswith(path) and not new[n + 1:].isdigit()


clock = time.monotonic   # counter-sample clock (wall-clock steps must not freeze sampling); patched in tests


def _open_dir(root: str, parts: list[str]) -> int:
    """O_PATH fd of root/parts refusing a symlink at every component (O_NOFOLLOW + O_DIRECTORY → ENOTDIR)."""
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
    try:
        for part in parts:
            nfd = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_in_root(root: str, parts: list[str]) -> int:
    """Open root/parts refusing a symlink at every component: an absolute symlink planted by the
    workload would otherwise resolve against *our* root and read files outside its container."""
    fd = _open_dir(root, parts[:-1])
    try:
        # O_NONBLOCK + the caller's regular-file check: a planted FIFO or device cannot hang us.
        return os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)


def file_entropy(proc_root: str, pid: int, path: str, cache: OrderedDict | None = None) -> float | None:
    """Entropy of the first ENTROPY_BYTES of `path` as seen inside the process's mount namespace.

    With `cache` (bounded LRU, path → (signature, entropy)) an unchanged file is not read again. The signature
    includes ctime, which no syscall can set back: in-place encryption that restores size and mtime still re-reads.
    """
    parts = [p for p in posixpath.normpath("/" + path).split("/") if p]   # normpath drops '..'
    if not parts:
        return None
    try:
        fd = _open_in_root(os.path.join(proc_root, str(pid), "root"), parts)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        sig = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if cache is not None and (hit := cache.get(path)) and hit[0] == sig:
            cache.move_to_end(path)
            return hit[1]
        data = os.read(fd, ENTROPY_BYTES)
    except OSError:
        return None
    finally:
        os.close(fd)
    e = shannon_entropy(data) if data else None
    if cache is not None:
        cache[path] = (sig, e)
        cache.move_to_end(path)
        while len(cache) > MAX_ENTROPY_CACHE:
            cache.popitem(last=False)
    return e


def _in_container(proc_root: str, pid: int | str, cid: str) -> bool:
    try:
        with open(os.path.join(proc_root, str(pid), "cgroup")) as fh:
            return cid in fh.read()
    except OSError:
        return False


def local_pid(proc_root: str, pid: int, cid: str, cache: dict[str, float]) -> int | None:
    """A PID in *our* /proc of the container that wrote the file.

    Falco reports PIDs of the kernel's root PID namespace. On a node that is itself a container
    (minikube docker driver, kind) the node's /proc numbers processes differently, so Falco's PID
    is checked against the container id and, if it is not ours, any process of that container is
    found by its cgroup (all of them share the container's mount namespace, i.e. /proc/<pid>/root).
    `cache`: container id → its local PID, or → -(monotonic expiry) after a full /proc scan found nothing.
    """
    if not cid:
        return pid
    hit = cache.get(cid)
    if hit is not None and hit < 0:
        if -hit > time.monotonic():
            return pid if _in_container(proc_root, pid, cid) else None   # the scan is what the miss saves
        hit = None
    for p in (pid, hit):
        if p and _in_container(proc_root, p, cid):
            return int(p)
    for name in os.listdir(proc_root):
        if name.isdigit() and _in_container(proc_root, name, cid):
            cache[cid] = int(name)
            return int(name)
    if len(cache) >= MAX_PID_CACHE:
        cache.clear()
    cache[cid] = -(time.monotonic() + PID_MISS_TTL_S)
    return None


def net_tx_bytes(proc_root: str, pid: int) -> float | None:
    """Bytes sent by the pod's network namespace (every interface but loopback) since it was created.

    None for a hostNetwork pod (its netns is the node's: node egress is not the pod's exfiltration)."""
    try:
        if os.stat(os.path.join(proc_root, str(pid), "ns", "net")).st_ino == \
                os.stat(os.path.join(proc_root, "1", "ns", "net")).st_ino:
            return None
        with open(os.path.join(proc_root, str(pid), "net", "dev")) as fh:
            rows = fh.read().splitlines()[2:]                  # two header lines
        return float(sum(int(data.split()[8]) for name, _, data in (r.partition(":") for r in rows)
                         if name.strip() != "lo"))
    except (OSError, ValueError, IndexError):
        return None


def node_cgroup_root(proc_root: str) -> str:
    return CGROUP_ROOT if os.path.isdir(CGROUP_ROOT) else os.path.join(proc_root, "1", "root", "sys", "fs", "cgroup")


def pod_cgroups(pod_uid: str) -> list[str]:
    """Candidate pod cgroup dirs (relative to the cgroup root), systemd then cgroupfs driver; guaranteed QoS has
    no QoS level. [] unless pod_uid is a well-formed UID: it becomes a path, never trust its shape."""
    if not POD_UID.fullmatch(pod_uid):
        return []
    u = pod_uid.replace("-", "_")
    return [f"kubepods.slice/kubepods-pod{u}.slice",
            f"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{u}.slice",
            f"kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{u}.slice",
            f"kubepods/pod{pod_uid}", f"kubepods/burstable/pod{pod_uid}", f"kubepods/besteffort/pod{pod_uid}"]


def cgroup_write_bytes(cgroup_root: str, pod_uid: str) -> float | None:
    """Bytes the pod's cgroup v2 wrote to block devices (io.stat wbytes, all devices); counted at writeback."""
    for rel in pod_cgroups(pod_uid):
        try:
            with open(os.path.join(cgroup_root, rel, "io.stat")) as fh:
                return float(sum(int(kv[7:]) for kv in fh.read().split() if kv.startswith("wbytes=")))
        except (OSError, ValueError):
            continue
    return None


def freeze_pod(cgroup_root: str, pod_uid: str, freeze: bool = True) -> str:
    """Freeze (or thaw) the pod's cgroup v2 → "frozen" | "thawed" | "not_on_node"; OSError if it exists here but
    cannot be written. Only the fixed pod-cgroup paths of a validated UID, no symlink followed."""
    for rel in pod_cgroups(pod_uid):
        try:
            d = _open_dir(cgroup_root, rel.split("/"))
        except FileNotFoundError:
            continue
        try:
            fd = os.open("cgroup.freeze", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=d)
            try:
                os.write(fd, b"1" if freeze else b"0")
            finally:
                os.close(fd)
        finally:
            os.close(d)
        return "frozen" if freeze else "thawed"
    return "not_on_node"


def cgroup_frozen(cgroup_root: str, pod_uid: str) -> bool | None:
    """True if the pod's cgroup is frozen, False if not, None when it is not on this node (pod gone)."""
    for rel in pod_cgroups(pod_uid):
        try:
            d = _open_dir(cgroup_root, rel.split("/"))
        except FileNotFoundError:
            continue
        try:
            fd = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=d)
            try:
                return "frozen 1" in os.read(fd, 4096).decode().splitlines()
            finally:
                os.close(fd)
        except OSError:
            return None
        finally:
            os.close(d)
    return None


def read_pod(proc_root: str, files: list[tuple[str, tuple[int, str]]], proc: tuple[int, str], pod_uid: str,
             pids: dict[str, float], cache: OrderedDict | None, counters: bool) -> tuple[list[float], tuple | None]:
    """Blocking; run in a thread (one hop per evaluation). (entropy samples, (net tx, cgroup wbytes) or None
    when `counters` is False; a counter is None when unreadable)."""
    entropy = sample_entropy(proc_root, files, pids, cache)
    if not counters:
        return entropy, None
    pid = local_pid(proc_root, proc[0], proc[1], pids) if proc[0] else None
    return entropy, (net_tx_bytes(proc_root, pid) if pid else None,
                     cgroup_write_bytes(node_cgroup_root(proc_root), pod_uid))


def counter_delta(samples, i: int) -> float | None:
    """Increase of counter i between the first and last sample; None if unknown or reset."""
    if len(samples) < 2 or samples[0][i] is None or samples[-1][i] is None or samples[-1][i] < samples[0][i]:
        return None
    return samples[-1][i] - samples[0][i]


def counter_total(samples, i: int, window_s: float) -> float | None:
    """counter_delta rescaled so that total / window_s is the rate over the samples' own time span."""
    delta = counter_delta(samples, i)
    span = samples[-1][0] - samples[0][0] if delta is not None else 0.0
    return delta * window_s / span if span > 0 else None


def sample_entropy(proc_root: str, files: list[tuple[str, tuple[int, str]]],
                   pids: dict[str, float] | None = None, cache: OrderedDict | None = None) -> list[float]:
    """Blocking; run in a thread. Unreadable / vanished / empty files are skipped; cache: see file_entropy."""
    pids = {} if pids is None else pids
    out = []
    for path, (pid, cid) in files:
        p = local_pid(proc_root, pid, cid, pids)
        if p is not None and (e := file_entropy(proc_root, p, path, cache)) is not None:
            out.append(e)
    return out


SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class KubeLite:
    """The two read-only GETs the owner lookup needs (pod, ReplicaSet), straight over aiohttp with the pod's
    service-account token: the generated Kubernetes client costs ~34 MB resident per node for nothing else.
    A non-2xx reply raises aiohttp.ClientResponseError (.status). In-cluster only; elsewhere main() uses the client."""

    def __init__(self, session: aiohttp.ClientSession, sa_dir: str = SA_DIR):
        self.session, self.sa_dir = session, sa_dir
        self.base = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"
        self.ssl = ssl.create_default_context(cafile=f"{sa_dir}/ca.crt")

    async def _get(self, path: str, total_s: float) -> SimpleNamespace:
        with open(f"{self.sa_dir}/token") as fh:   # noqa: ASYNC230  rotated by the kubelet: read per call (lookups are cached)
            headers = {"Authorization": f"Bearer {fh.read().strip()}"}
        async with self.session.get(self.base + path, headers=headers, ssl=self.ssl,
                                    timeout=aiohttp.ClientTimeout(total=total_s)) as resp:
            resp.raise_for_status()
            meta = (await resp.json(loads=orjson.loads)).get("metadata") or {}
        refs = [SimpleNamespace(kind=r.get("kind"), name=r.get("name"), controller=r.get("controller"))
                for r in meta.get("ownerReferences") or []]
        return SimpleNamespace(metadata=SimpleNamespace(owner_references=refs))

    async def read_namespaced_pod(self, name: str, ns: str, _request_timeout: float = 10):
        return await self._get(f"/api/v1/namespaces/{ns}/pods/{name}", _request_timeout)

    async def read_namespaced_replica_set(self, name: str, ns: str, _request_timeout: float = 10):
        return await self._get(f"/apis/apps/v1/namespaces/{ns}/replicasets/{name}", _request_timeout)


class OwnerResolver:
    """pod → workload name, cached. The pod's controller (ownerReference with controller=true): a ReplicaSet
    owned by a Deployment → the Deployment's name; any other controller (StatefulSet, DaemonSet, Job, a bare
    ReplicaSet, ...) → its own name; no controller (bare pod) or a failed lookup → the pod name."""

    def __init__(self, core, apps, ttl_s: float = OWNER_TTL_S):
        self.core, self.apps, self.ttl_s = core, apps, ttl_s
        self.cache: dict[Key, tuple[float, str]] = {}

    async def resolve(self, ns: str, pod: str) -> str:
        now = time.monotonic()
        if (hit := self.cache.get((ns, pod))) and hit[0] > now:
            return hit[1]
        name, ttl = pod, self.ttl_s
        try:
            p = await self.core.read_namespaced_pod(pod, ns, _request_timeout=KUBE_TIMEOUT_S)
            ref = next((r for r in p.metadata.owner_references or [] if r.controller), None)
            if ref is not None and ref.kind == "ReplicaSet":
                rs = await self.apps.read_namespaced_replica_set(ref.name, ns, _request_timeout=KUBE_TIMEOUT_S)
                ref = next((r for r in rs.metadata.owner_references or []
                            if r.controller and r.kind == "Deployment"), ref)
            name = ref.name if ref is not None else pod
        except Exception as e:   # any failed lookup (API error, timeout, odd reply): the pod name, retried soon
            log.warning("owner lookup for %s/%s failed (%s); using pod name", ns, pod, getattr(e, "status", e))
            ttl = 30.0                         # retry the lookup soon
        if len(self.cache) > 4096:
            self.cache = {k: v for k, v in self.cache.items() if v[0] > now}
        self.cache[(ns, pod)] = (now + ttl, name)
        return name


class SecurityAgent:
    def __init__(self, redis: aioredis.Redis, session: aiohttp.ClientSession, owners: OwnerResolver,
                 proc_root: str = PROC_ROOT, protected: frozenset[str] | None = None,
                 namespaces: list[str] | None = None, capture: bool = CAPTURE,
                 bundle: ModelBundle | None = None, contain_key: str = CONTAIN_KEY):
        self.redis, self.session, self.owners, self.proc_root = redis, session, owners, proc_root
        self.bundle, self.contain_key = bundle, contain_key
        self.capture = capture
        self.protected = protected_namespaces() if protected is None else protected
        self.namespaces = set(env_list("WATCH_NAMESPACES") if namespaces is None else namespaces)
        self.windows: dict[Key, PodWindow] = {}
        self.pids: dict[str, float] = {}   # container id → a local PID of it, or a cached miss (see local_pid)
        self.sem = asyncio.Semaphore(MAX_CONCURRENT)
        self.ticks = {"tail": time.monotonic(), "eval": time.monotonic(), "contain": time.monotonic()}
        self.wake = asyncio.Event()        # set when a pod crosses BURST_EVENTS or turns hot
        self.fast = False                  # a hot or suspicious pod was taken in this round: short pause after it
        self.hot_seen = asyncio.Event()    # set when a pod turns hot: ends the pause between rounds early
        self.lag_logged = float("-inf")
        self.frozen: dict[str, list] = {}  # pod uid → [namespace, pod, monotonic freeze time, overdue logged]
        self.stats_at = float("-inf")      # monotonic time of the last sensor-stats read
        self.sensor_seen: dict[str, float] = {}   # last cumulative value per sensor counter (deltas feed Counters)

    def ingest(self, ev: dict) -> bool:
        """Add a parsed Falco event to its pod's window (kept as is: no per-event copy); False if ignored."""
        ns, pod = ev["namespace"], ev["pod"]
        if ns in self.protected or (self.namespaces and ns not in self.namespaces):
            return False
        w = self.windows.get((ns, pod))
        uid = ev["pod_uid"]
        if w is None or (uid and w.pod_uid and uid != w.pod_uid):
            # new pod, or a new pod instance reusing the name (bare pod, StatefulSet): fresh window + cooldown
            w = self.windows[(ns, pod)] = PodWindow(pod_uid=uid)
        elif not w.pod_uid:
            w.pod_uid = uid
        sc, pid = ev["syscall"], ev["pid"]
        ts = ev["ts_ms"] or now_ms()
        ev["ts_ms"] = ts
        w.events.append(ev)
        if pid:
            w.proc = (pid, ev["container_id"])
            target = ev["path"] if sc in WRITE_SYSCALLS else ev["new_path"] if sc in RENAME_SYSCALLS else ""
            if target.startswith("/"):
                written = w.written
                written.pop(target, None)
                written[target] = (pid, ev["container_id"], ts)
                if len(written) > MAX_WRITTEN:
                    written.popitem(last=False)
        w.new += 1
        if sc in RENAME_SYSCALLS and _suffix_added(ev["path"], ev["new_path"]):
            w.hot = True
            self.hot_seen.set()
            if not w.fails:   # a failed window keeps its backoff
                w.due_at = min(w.due_at, w.scored_at + min(HOT_INTERVAL_S, POD_MIN_INTERVAL_S))
            self.wake.set()
        elif w.new == BURST_EVENTS:
            self.wake.set()
        w.last_seen = time.monotonic()
        return True

    async def evaluate_all(self, burst_only: bool = False) -> float | None:
        """Score every pod with new events (timer tick) or only those past BURST_EVENTS (burst wake-up).

        A pod scored less than POD_MIN_INTERVAL_S ago (or backing off after a failure) waits; returns the
        monotonic time the first such pod becomes due, None if there is none."""
        now = time.monotonic()
        due, wake_at = [], None
        for key, w in list(self.windows.items()):
            if now - w.last_seen > IDLE_EVICT_S:
                del self.windows[key]
                for cid in {w.proc[1], *(v[1] for v in w.written.values())}:
                    self.pids.pop(cid, None)
            elif w.hot or w.new >= (BURST_EVENTS if burst_only else 1):
                if w.due_at > now:
                    wake_at = w.due_at if wake_at is None else min(wake_at, w.due_at)
                    self.fast = self.fast or w.hot or w.suspicious   # waiting for a 50 ms slot: do not sleep a full tick
                    continue
                w.new = 0
                w.scored_at = now
                w.due_at = now + (min(HOT_INTERVAL_S, POD_MIN_INTERVAL_S) if w.hot or w.suspicious else POD_MIN_INTERVAL_S)
                self.fast = self.fast or w.hot or w.suspicious
                due.append((key, w))
        for i in range(0, len(due), MAX_BATCH):
            await self.evaluate_batch(due[i:i + MAX_BATCH])
        return wake_at

    @staticmethod
    def _retry(w: PodWindow) -> None:
        """Re-score a failed window even if the pod goes quiet (the attack may be over): at once, then backing off."""
        w.new = max(w.new, 1)
        w.fails += 1
        w.due_at = time.monotonic() + (0.0 if w.fails == 1 else min(MAX_BACKOFF_S, 2.0 ** (w.fails - 2)))

    async def evaluate_batch(self, due: list[tuple[Key, PodWindow]]) -> None:
        """Features per pod (concurrent, file/proc reads in threads), one inference call, then publish per pod."""
        # a pod that may be killed soon gets its owner resolved while its features and score are computed
        early = [asyncio.ensure_future(self.owners.resolve(*key)) for key, w in due if w.hot or w.suspicious]
        for _, w in due:
            w.hot = False
        windows = []
        for (key, w), f in zip(due, await asyncio.gather(*(self.features(key, w) for key, w in due)), strict=True):
            if f is None:
                self._retry(w)
            else:
                windows.append((key, w, f))
        if not windows:
            await asyncio.gather(*early, return_exceptions=True)
            return
        preds = await self.score([f[0] for _, _, f in windows])
        await asyncio.gather(*early, return_exceptions=True)
        if preds or self.capture:   # owner lookups for the whole batch at once, not one by one in the publish loop
            # a failed lookup surfaces again (and is handled) in that pod's _publish
            await asyncio.gather(*(self.owners.resolve(*key) for (key, _, _), p in zip(
                windows, preds or [None] * len(windows), strict=True)
                if self.capture or (p and p.risk >= SECURITY_PUBLISH_RISK)), return_exceptions=True)
        for i, (key, w, f) in enumerate(windows):
            pred = preds[i] if preds else None
            if pred is not None:
                w.suspicious = pred.risk >= SECURITY_PUBLISH_RISK
                if w.suspicious:   # looks bad: re-scored soon, not after the normal interval
                    w.due_at = min(w.due_at, w.scored_at + min(HOT_INTERVAL_S, POD_MIN_INTERVAL_S))
            if pred is None:
                self._retry(w)
                EVALS.labels("inference_error").inc()
                continue
            try:
                EVALS.labels(await self._publish(key, w, pred, *f)).inc()
                w.fails = 0
            except aioredis.RedisError as e:
                log.warning("redis publish failed for %s/%s: %s", *key, e)
                self._retry(w)
                EVALS.labels("redis_error").inc()
            except Exception:
                log.exception("publishing %s/%s failed", *key)
                self._retry(w)
                EVALS.labels("error").inc()

    async def score(self, rows: list[dict]) -> list | None:
        """Predictions in row order: in-process when a bundle is loaded, else the inference service; None on failure."""
        if self.bundle is None:
            return await predict_batch(self.session, "security", rows)
        known = set(self.bundle.features)   # the inference service's rule: ignore unlisted names, missing → None
        try:
            with SCORE_SECONDS.time():
                return await asyncio.to_thread(self.bundle.predict_batch,
                                               [{k: v for k, v in r.items() if k in known} for r in rows],
                                               SECURITY_PUBLISH_RISK)
        except Exception:
            log.exception("embedded security model failed; falling back to the inference service")
            return await predict_batch(self.session, "security", rows)

    async def features(self, key: Key, w: PodWindow) -> tuple[dict, list[dict], int, int, list[float]] | None:
        """(features, events, start_ms, newest_ms, entropy samples) of the pod's window; None (logged) on error."""
        async with self.sem:
            try:
                return await self._features(w)
            except Exception:
                log.exception("evaluation of %s/%s failed", *key)
                EVALS.labels("error").inc()
                return None

    async def _features(self, w: PodWindow) -> tuple[dict, list[dict], int, int, list[float]]:
        newest = w.events[-1]["ts_ms"]
        cutoff = newest - WINDOW_S * 1000
        while w.events and w.events[0]["ts_ms"] < cutoff:
            w.events.popleft()
        events = list(w.events)
        start_ms = min(e["ts_ms"] for e in events)
        window_s = window_seconds(start_ms, newest)
        for path in [p for p, v in w.written.items() if v[2] < cutoff]:   # same window as the events
            del w.written[path]
        files = [(p, v[:2]) for p, v in w.written.items()][-MAX_ENTROPY_SAMPLES:]
        # counters are read only when a sample is due: a burst of re-scoring reuses the samples it has
        sample = not w.samples or clock() - w.samples[-1][0] >= SAMPLE_EVERY_S
        entropy, counters = await asyncio.to_thread(read_pod, self.proc_root, files, w.proc, w.pod_uid, self.pids,
                                                    w.entropy_cache, sample)
        if counters is not None:
            w.samples.append((clock(), *counters))
        # rates come from the samples' own clock and span (a dense burst's event window can be < 1 s long)
        while len(w.samples) > 2 and w.samples[0][0] < w.samples[-1][0] - WINDOW_S:
            w.samples.popleft()
        features = security_features(events, entropy, window_s, counter_total(w.samples, 2, window_s),
                                     counter_total(w.samples, 1, window_s))
        return features, events, start_ms, newest, entropy

    def _cooled_down(self, w: PodWindow, pred) -> bool:
        """Same label as the last publish, inside the cooldown, and nothing new for fusion: a certain verdict
        after an uncertain one (fusion never auto-acts on uncertain) or a clear risk rise is news."""
        return (time.monotonic() - w.last_publish < COOLDOWN_S and pred.label == w.last_label
                and not (w.last_uncertain and not pred.uncertain) and pred.risk < w.last_risk + RISK_RISE)

    async def _publish(self, key: Key, w: PodWindow, pred, features: dict, events: list[dict], start_ms: int,
                       newest: int, entropy: list[float]) -> str:
        ns, pod = key
        outcome = ("below_threshold" if pred.risk < SECURITY_PUBLISH_RISK
                   else "cooldown" if self._cooled_down(w, pred) else "published")
        if outcome != "published" and not self.capture:
            return outcome
        event = SecurityEvent(   # built once: the capture row and the published event share one event id
            event_id=new_event_id("security"), namespace=ns, workload=await self.owners.resolve(ns, pod),
            pod=pod, model_version=pred.model_version, label=pred.label, risk=pred.risk,
            uncertain=pred.uncertain, probabilities=pred.probabilities, top_factors=pred.top_factors,
            features=features, pod_uid=w.pod_uid, window_start_ms=start_ms, window_end_ms=newest, n_events=len(events),
        )
        if self.capture:   # lab data only; a failed capture never costs the real publish
            fields = event.to_fields()
            fields["events_json"] = orjson.dumps([{k: e[k] for k in ("syscall", "path", "new_path", "ts_ms")}
                                                  for e in events]).decode()
            fields["entropy_json"] = orjson.dumps(entropy).decode()
            try:
                await self.redis.xadd(STREAM_CAPTURE, fields, maxlen=CAPTURE_MAXLEN, approximate=True)
            except aioredis.RedisError as e:
                log.warning("capture xadd failed for %s/%s: %s", ns, pod, e)
        if outcome != "published":
            return outcome
        await publish_event(self.redis, STREAM_SECURITY, "security", event)
        w.last_publish, w.last_label, w.last_uncertain, w.last_risk = (time.monotonic(), pred.label,
                                                                       pred.uncertain, pred.risk)
        log.info("published %s for %s/%s (%s): risk=%.2f events=%d entropy_samples=%d", pred.label, ns,
                 pod, event.workload, pred.risk, len(events), len(entropy))
        return "published"

    def observe_lag(self, ts_ms: int | None) -> None:
        """Event lag of the newest event of a read (one sample per read: cheap at any event rate)."""
        if not ts_ms:
            return
        lag = (now_ms() - ts_ms) / 1000
        EVENT_LAG.observe(max(lag, 0.0))
        if lag > LAG_WARN_S and time.monotonic() - self.lag_logged > 60:
            self.lag_logged = time.monotonic()
            log.warning("security events lag %.1fs behind (the event source or this agent cannot keep up)", lag)

    async def tail_loop(self, tail: FalcoTail) -> None:
        """Read the events file as it grows; with a file watch (inotify) an idle tail wakes on the write itself,
        else it polls every IDLE_POLL_S."""
        written, fd = asyncio.Event(), watch_dir(tail.path)
        loop = asyncio.get_running_loop()

        def on_write() -> None:
            try:
                os.read(fd, 65536)   # drain: one wake-up per batch of writes
            except OSError:
                pass
            written.set()
        if fd is not None:
            loop.add_reader(fd, on_write)
        try:
            while True:
                self.ticks["tail"] = time.monotonic()
                written.clear()   # before the read: a write landing during it wakes the next wait
                lines = await asyncio.to_thread(tail.read_lines)
                n, ev = 0, None
                for line in lines:
                    if (ev := parse_line(line)) and self.ingest(ev):
                        n += 1
                EVENTS.inc(n)
                if ev:
                    self.observe_lag(ev["ts_ms"])
                if not lines:
                    try:
                        await asyncio.wait_for(written.wait(), IDLE_POLL_S)
                    except TimeoutError:
                        pass
        finally:
            if fd is not None:
                loop.remove_reader(fd)
                os.close(fd)
            tail.close()

    async def eval_loop(self) -> None:
        next_tick = time.monotonic() + EVAL_INTERVAL_S
        wake_at = None
        while True:
            self.ticks["eval"] = time.monotonic()
            try:
                until = next_tick if wake_at is None else min(next_tick, wake_at)
                try:
                    await asyncio.wait_for(self.wake.wait(), max(0.0, until - time.monotonic()))
                except TimeoutError:
                    pass
                self.wake.clear()
                self.hot_seen.clear()
                timer = time.monotonic() >= next_tick
                if timer:
                    next_tick = time.monotonic() + EVAL_INTERVAL_S
                wake_at = await self.evaluate_all(burst_only=not timer)
                self.housekeep()
            except Exception:   # one bad round must not end the agent (and lose every window); CancelledError passes
                log.exception("evaluation round failed")
                wake_at = None
            if self.fast:   # a hot/suspicious pod was taken or is waiting for its slot: soon. Other waiting pods batch at MIN_TICK_S
                await asyncio.sleep(HOT_TICK_S)
            else:
                try:
                    await asyncio.wait_for(self.hot_seen.wait(), MIN_TICK_S)   # a pod turning hot ends the pause
                except TimeoutError:
                    pass
            self.fast = False

    async def contain(self, fields: dict) -> str:
        """Freeze the commanded pod's cgroup if the pod runs on this node (fusion deletes it via the API next)."""
        uid, ns = fields.get("pod_uid", ""), fields.get("namespace", "")
        action = fields.get("action", "freeze")   # entries from before thaw existed carry none
        try:
            age = (now_ms() - int(fields.get("ts_ms", ""))) / 1000
        except ValueError:
            age = float("inf")
        if self.contain_key and not contain_verify(self.contain_key, fields):
            outcome = "bad_sig"
            log.warning("refusing containment of %s/%s: missing or invalid signature", ns, fields.get("pod"))
        elif age > CONTAIN_MAX_AGE_S:
            outcome = "stale"
        elif action not in ("freeze", "thaw") or ns in self.protected or not POD_UID.fullmatch(uid):   # fusion checks too; never freeze these
            outcome = "error"
            log.warning("refusing containment of %s/%s uid %r", ns, fields.get("pod"), uid)
        else:
            try:
                outcome = freeze_pod(node_cgroup_root(self.proc_root), uid, action == "freeze")
            except OSError as e:
                outcome = "error"
                log.warning("%s of %s/%s (%s) failed: %s", action, ns, fields.get("pod"), uid, e)
            if outcome == "thawed":
                self.frozen.pop(uid, None)
                log.warning("thawed pod %s/%s (%s) for event %s", ns, fields.get("pod"), uid, fields.get("event_id"))
            elif outcome == "frozen":
                self.frozen[uid] = [ns, fields.get("pod", ""), time.monotonic(), False]
                CONTAIN_AGE.observe(max(age, 0.0))
                log.warning("froze pod %s/%s (%s) for event %s, %.0f ms after the decision", ns, fields.get("pod"),
                            uid, fields.get("event_id"), age * 1000)
        CONTAIN.labels(outcome).inc()
        return outcome

    def watch_frozen(self) -> None:
        """Surface pods this agent froze that are still frozen past FREEZE_MAX_S; never thaws them itself."""
        now, overdue = time.monotonic(), 0
        for uid, rec in list(self.frozen.items()):
            if now - rec[2] < FREEZE_MAX_S:
                continue
            if not cgroup_frozen(node_cgroup_root(self.proc_root), uid):   # thawed elsewhere, or the pod is gone
                del self.frozen[uid]
                continue
            overdue += 1
            if not rec[3]:
                rec[3] = True
                log.error("pod %s/%s (%s) still frozen %.0f s after the freeze with no decision: kill or release it",
                          rec[0], rec[1], uid, now - rec[2])
        FROZEN_OVERDUE.set(overdue)

    def read_sensor_stats(self) -> None:
        """Export the sensor's stats file: counter deltas (a sensor restart resets its counters) and liveness."""
        try:
            fresh = time.time() - os.stat(SENSOR_STATS_PATH).st_mtime < STATS_FRESH_S
            with open(SENSOR_STATS_PATH, "rb") as fh:
                stats = orjson.loads(fh.read())
        except (OSError, ValueError):
            SENSOR_UP.set(0)
            return
        SENSOR_UP.set(fresh)
        for name, counter in SENSOR_COUNTERS.items():
            v = stats.get(name)
            if isinstance(v, int | float) and v >= 0:
                prev = self.sensor_seen.get(name)
                counter.inc(v if prev is None or v < prev else v - prev)
                self.sensor_seen[name] = v

    def housekeep(self) -> None:
        """Eval-tick extras, at most every STATS_EVERY_S: sensor stats and the freeze watchdog."""
        if time.monotonic() - self.stats_at < STATS_EVERY_S:
            return
        self.stats_at = time.monotonic()
        self.read_sensor_stats()
        self.watch_frozen()

    async def contain_loop(self) -> None:
        """Follow STREAM_CONTAIN (every node reads every command; no consumer group) from its end at startup."""
        last = None
        while True:
            self.ticks["contain"] = time.monotonic()
            try:
                if last is None:
                    newest = await self.redis.xrevrange(STREAM_CONTAIN, count=1)
                    last = newest[0][0] if newest else "0-0"
                for _, entries in await self.redis.xread({STREAM_CONTAIN: last}, count=100, block=1000) or []:
                    for entry_id, fields in entries:
                        last = entry_id
                        await self.contain(fields)
            except aioredis.RedisError as e:
                log.warning("reading %s failed: %s", STREAM_CONTAIN, e)
                await asyncio.sleep(1.0)

    def healthy(self) -> bool:
        now = time.monotonic()
        return all(now - t < max(60.0, 6 * EVAL_INTERVAL_S) for t in self.ticks.values())


async def main() -> None:
    setup_logging()
    redis = await connect_redis()
    async with contextlib.AsyncExitStack() as stack:
        session = await stack.enter_async_context(aiohttp.ClientSession())
        in_cluster = "KUBERNETES_SERVICE_HOST" in os.environ and os.path.exists(f"{SA_DIR}/token")  # noqa: ASYNC240
        if in_cluster:
            owners = OwnerResolver(*(KubeLite(session),) * 2)
        else:   # outside a cluster: the full client reads kubeconfig (imported only here: it is heavy)
            from kubernetes_asyncio import client
            await load_kube_config()
            api = await stack.enter_async_context(client.ApiClient())
            owners = OwnerResolver(client.CoreV1Api(api), client.AppsV1Api(api))
        try:
            bundle = await asyncio.to_thread(ModelBundle.load, MODEL_DIR)
        except Exception as e:   # absent dir (no model baked into the image) is the normal remote setup
            log.warning("no embedded security model (%s: %r); using the inference service", MODEL_DIR, e)
            bundle = None
        if bundle:   # build the TreeSHAP explainer now: its first use would cost ~1 s inside the first attack
            await asyncio.to_thread(bundle.predict_batch, [{}], 0.0)
        if bundle and not set(bundle.features) <= set(SECURITY_FEATURES):
            log.error("embedded security model uses features the agent does not send: %s; using the inference service",
                      sorted(set(bundle.features) - set(SECURITY_FEATURES)))
            bundle = None
        mode = "embedded" if bundle else "remote"
        MODEL_MODE.labels(mode).set(1)
        EVENT_SOURCE_INFO.labels(EVENT_SOURCE).set(1)
        log.info("security scoring: %s (%s)", mode, MODEL_DIR if bundle else "inference service")
        if not CONTAIN_KEY:
            log.warning("CONTAIN_HMAC_KEY unset: unsigned containment commands are accepted")
        agent = SecurityAgent(redis, session, owners, bundle=bundle)
        runner = await start_http(agent.healthy)
        log.info("security agent tailing %s (proc root %s, cgroup root %s, eval every %.0fs)",
                 FALCO_EVENTS_PATH, PROC_ROOT, node_cgroup_root(PROC_ROOT), EVAL_INTERVAL_S)
        try:
            await asyncio.gather(agent.tail_loop(FalcoTail(FALCO_EVENTS_PATH)), agent.eval_loop(),
                                 agent.contain_loop())
        finally:
            await runner.cleanup()
            await redis.aclose()


if __name__ == "__main__":
    run(main)
