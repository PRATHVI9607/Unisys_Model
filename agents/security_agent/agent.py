"""KubeHeal security agent (DaemonSet, hostPID): Falco events + file entropy → SecurityEvents.

Observes only. It never kills or modifies anything (fusion is the single decision point) and never
fabricates events: every feature comes from a real Falco event or a real file read.

Run: python -m agents.security_agent.agent
"""

from __future__ import annotations

import asyncio
import logging
import os
import posixpath
import re
import stat
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

import aiohttp
import redis.asyncio as aioredis
from kubernetes_asyncio import client
from kubernetes_asyncio.client.exceptions import ApiException
from prometheus_client import Counter

from agents.common import (
    connect_redis,
    env_list,
    load_kube_config,
    predict_batch,
    protected_namespaces,
    publish_event,
    run,
    setup_logging,
    start_http,
)
from agents.security_agent.falco import FalcoTail, parse_line
from kubeheal.contracts import (
    SECURITY_PUBLISH_RISK,
    STREAM_CAPTURE,
    STREAM_MAXLEN,
    STREAM_SECURITY,
    SecurityEvent,
    new_event_id,
    now_ms,
)
from kubeheal.features.security import (
    MAX_ENTROPY_SAMPLES,
    MAX_WINDOW_EVENTS,
    SYSCALL_GROUPS,
    WINDOW_S,
    security_features,
    shannon_entropy,
    window_seconds,
)

log = logging.getLogger("kubeheal.security")

FALCO_EVENTS_PATH = os.environ.get("FALCO_EVENTS_PATH", "/var/run/falco/events.jsonl")
PROC_ROOT = os.environ.get("PROC_ROOT", "/proc")
EVAL_INTERVAL_S = float(os.environ.get("EVAL_INTERVAL_S", "2"))   # timer for pods below the burst threshold
CAPTURE = os.environ.get("KUBEHEAL_CAPTURE", "0") == "1"   # lab data collection: also XADD every scored window

MAX_EVENTS = MAX_WINDOW_EVENTS   # per-pod window; events older than WINDOW_S (vs the newest) leave it
BURST_EVENTS = 64          # a pod with this many new events is scored at once, not at the next timer tick
MIN_TICK_S = 0.25          # pause between evaluation rounds: bounds burst re-scoring under a flood
MAX_BATCH = 256            # inference service's predict_batch cap
IDLE_EVICT_S = 300.0       # forget pods with no events for this long
MAX_WRITTEN = 64           # recently written files remembered per pod
ENTROPY_BYTES = 16 * 1024  # file head: encrypted/compressed heads score within 0.01 bit/byte of 64 KiB
MAX_ENTROPY_CACHE = 2 * MAX_WRITTEN   # per pod: files whose entropy is reused while their stat is unchanged
COOLDOWN_S = 60.0          # per pod; a label change still publishes
OWNER_TTL_S = 300.0
KUBE_TIMEOUT_S = 10        # owner lookups run inside an evaluation; never let one stall the eval loop
MAX_CONCURRENT = 8
MAX_SAMPLES = 32           # per-pod counter samples (one per evaluation, trimmed to the event window)
POD_UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

WRITE_SYSCALLS = SYSCALL_GROUPS["write"] | SYSCALL_GROUPS["truncate"]
RENAME_SYSCALLS = SYSCALL_GROUPS["rename"]

EVENTS = Counter("kubeheal_security_falco_events_total", "Falco events ingested into pod windows")
EVALS = Counter("kubeheal_security_evaluations_total", "Pod window evaluations by outcome", ["outcome"])

Key = tuple[str, str]   # (namespace, pod)


@dataclass
class PodWindow:
    events: deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    written: OrderedDict = field(default_factory=OrderedDict)   # container path → (pid, container id), oldest first
    new: int = 0
    last_seen: float = field(default_factory=time.monotonic)
    last_publish: float = float("-inf")
    last_label: str = ""
    pod_uid: str = ""
    proc: tuple[int, str] = (0, "")                            # (Falco pid, container id) of the latest event
    samples: deque = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES))  # (ts_ms, net tx, cgroup wbytes)
    entropy_cache: OrderedDict = field(default_factory=OrderedDict)  # path → (stat signature, entropy), LRU


def _open_in_root(root: str, parts: list[str]) -> int:
    """Open root/parts refusing a symlink at every component: an absolute symlink planted by the
    workload would otherwise resolve against *our* root and read files outside its container."""
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nfd = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
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


def local_pid(proc_root: str, pid: int, cid: str, cache: dict[str, int]) -> int | None:
    """A PID in *our* /proc of the container that wrote the file.

    Falco reports PIDs of the kernel's root PID namespace. On a node that is itself a container
    (minikube docker driver, kind) the node's /proc numbers processes differently, so Falco's PID
    is checked against the container id and, if it is not ours, any process of that container is
    found by its cgroup (all of them share the container's mount namespace, i.e. /proc/<pid>/root).
    """
    if not cid:
        return pid
    for p in (pid, cache.get(cid)):
        if p and _in_container(proc_root, p, cid):
            return p
    for name in os.listdir(proc_root):
        if name.isdigit() and _in_container(proc_root, name, cid):
            cache[cid] = int(name)
            return int(name)
    return None


def net_tx_bytes(proc_root: str, pid: int) -> float | None:
    """Bytes sent by the pod's network namespace (every interface but loopback) since it was created."""
    try:
        with open(os.path.join(proc_root, str(pid), "net", "dev")) as fh:
            rows = fh.read().splitlines()[2:]                  # two header lines
        return float(sum(int(data.split()[8]) for name, _, data in (r.partition(":") for r in rows)
                         if name.strip() != "lo"))
    except (OSError, ValueError, IndexError):
        return None


def cgroup_write_bytes(cgroup_root: str, pod_uid: str) -> float | None:
    """Bytes the pod's cgroup v2 wrote to block devices (io.stat wbytes, all devices); counted at writeback."""
    if not POD_UID.fullmatch(pod_uid):                      # it becomes a path: never trust its shape
        return None
    u = pod_uid.replace("-", "_")
    for rel in (f"kubepods.slice/kubepods-pod{u}.slice",                                   # systemd driver
                f"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{u}.slice",
                f"kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{u}.slice",
                f"kubepods/pod{pod_uid}", f"kubepods/burstable/pod{pod_uid}", f"kubepods/besteffort/pod{pod_uid}"):
        try:
            with open(os.path.join(cgroup_root, rel, "io.stat")) as fh:
                return float(sum(int(kv[7:]) for kv in fh.read().split() if kv.startswith("wbytes=")))
        except (OSError, ValueError):
            continue
    return None


def pod_counters(proc_root: str, proc: tuple[int, str], pod_uid: str,
                 pids: dict[str, int]) -> tuple[float | None, float | None]:
    """Blocking; run in a thread. (net tx bytes, cgroup write bytes) of the pod now; None = unreadable.

    The node's cgroup2 tree is read through its init's mount namespace (/proc/1/root, hostPID + SYS_PTRACE),
    so no extra hostPath mount is needed; checked on minikube (docker driver, cgroup v2, systemd driver).
    """
    pid = local_pid(proc_root, proc[0], proc[1], pids) if proc[0] else None
    return (net_tx_bytes(proc_root, pid) if pid else None,
            cgroup_write_bytes(os.path.join(proc_root, "1", "root", "sys", "fs", "cgroup"), pod_uid))


def counter_delta(samples, i: int) -> float | None:
    """Increase of counter i between the window's first and last sample; None if unknown or reset."""
    if len(samples) < 2 or samples[0][i] is None or samples[-1][i] is None or samples[-1][i] < samples[0][i]:
        return None
    return samples[-1][i] - samples[0][i]


def sample_entropy(proc_root: str, files: list[tuple[str, tuple[int, str]]],
                   pids: dict[str, int] | None = None, cache: OrderedDict | None = None) -> list[float]:
    """Blocking; run in a thread. Unreadable / vanished / empty files are skipped; cache: see file_entropy."""
    pids = {} if pids is None else pids
    out = []
    for path, (pid, cid) in files:
        p = local_pid(proc_root, pid, cid, pids)
        if p is not None and (e := file_entropy(proc_root, p, path, cache)) is not None:
            out.append(e)
    return out


class OwnerResolver:
    """pod → owning Deployment name (pod → ReplicaSet → Deployment), cached; falls back to the pod name."""

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
            for ref in p.metadata.owner_references or []:
                if ref.kind == "ReplicaSet":
                    rs = await self.apps.read_namespaced_replica_set(ref.name, ns, _request_timeout=KUBE_TIMEOUT_S)
                    name = next((r.name for r in rs.metadata.owner_references or []
                                 if r.kind == "Deployment"), pod)
        except (ApiException, aiohttp.ClientError, TimeoutError) as e:
            log.warning("owner lookup for %s/%s failed (%s); using pod name", ns, pod, getattr(e, "status", e))
            ttl = 30.0                         # retry the lookup soon
        if len(self.cache) > 4096:
            self.cache = {k: v for k, v in self.cache.items() if v[0] > now}
        self.cache[(ns, pod)] = (now + ttl, name)
        return name


class SecurityAgent:
    def __init__(self, redis: aioredis.Redis, session: aiohttp.ClientSession, owners: OwnerResolver,
                 proc_root: str = PROC_ROOT, protected: frozenset[str] | None = None,
                 namespaces: list[str] | None = None, capture: bool = CAPTURE):
        self.redis, self.session, self.owners, self.proc_root = redis, session, owners, proc_root
        self.capture = capture
        self.protected = protected_namespaces() if protected is None else protected
        self.namespaces = set(env_list("WATCH_NAMESPACES") if namespaces is None else namespaces)
        self.windows: dict[Key, PodWindow] = {}
        self.pids: dict[str, int] = {}     # container id → a local PID of it (see local_pid)
        self.sem = asyncio.Semaphore(MAX_CONCURRENT)
        self.ticks = {"tail": time.monotonic(), "eval": time.monotonic()}
        self.wake = asyncio.Event()        # set when a pod crosses BURST_EVENTS

    def ingest(self, ev: dict) -> bool:
        """Add a parsed Falco event to its pod's window (kept as is: no per-event copy); False if ignored."""
        ns, pod = ev["namespace"], ev["pod"]
        if ns in self.protected or (self.namespaces and ns not in self.namespaces):
            return False
        w = self.windows.get((ns, pod))
        uid = ev.get("pod_uid") or ""
        if w is None or (uid and w.pod_uid and uid != w.pod_uid):
            # new pod, or a new pod instance reusing the name (bare pod, StatefulSet): fresh window + cooldown
            w = self.windows[(ns, pod)] = PodWindow(pod_uid=uid)
        w.pod_uid = w.pod_uid or uid
        sc, path, new_path, pid, cid = ev["syscall"], ev["path"], ev["new_path"], ev["pid"], ev["container_id"]
        ev["ts_ms"] = ev["ts_ms"] or now_ms()
        w.events.append(ev)
        if pid:
            w.proc = (pid, cid)
        target = path if sc in WRITE_SYSCALLS else new_path if sc in RENAME_SYSCALLS else ""
        if pid and target.startswith("/"):
            w.written.pop(target, None)
            w.written[target] = (pid, cid)
            if len(w.written) > MAX_WRITTEN:
                w.written.popitem(last=False)
        w.new += 1
        if w.new == BURST_EVENTS:
            self.wake.set()
        w.last_seen = time.monotonic()
        return True

    async def evaluate_all(self, burst_only: bool = False) -> None:
        """Score every pod with new events (timer tick) or only those past BURST_EVENTS (burst wake-up)."""
        now = time.monotonic()
        due = []
        for key, w in list(self.windows.items()):
            if now - w.last_seen > IDLE_EVICT_S:
                del self.windows[key]
            elif w.new >= (BURST_EVENTS if burst_only else 1):
                w.new = 0
                due.append((key, w))
        for i in range(0, len(due), MAX_BATCH):
            await self.evaluate_batch(due[i:i + MAX_BATCH])

    async def evaluate_batch(self, due: list[tuple[Key, PodWindow]]) -> None:
        """Features per pod (concurrent, file/proc reads in threads), one inference call, then publish per pod."""
        windows = [(key, w, f) for (key, w), f in zip(due, await asyncio.gather(
            *(self.features(key, w) for key, w in due)), strict=True) if f is not None]
        if not windows:
            return
        preds = await predict_batch(self.session, "security", [f[0] for _, _, f in windows])
        for i, (key, w, f) in enumerate(windows):
            pred = preds[i] if preds else None
            if pred is None:
                w.new = max(w.new, 1)   # re-score next tick even if the pod goes quiet (attack may be over)
                EVALS.labels("inference_error").inc()
                continue
            try:
                EVALS.labels(await self._publish(key, w, pred, *f)).inc()
            except aioredis.RedisError as e:
                log.warning("redis publish failed for %s/%s: %s", *key, e)
                EVALS.labels("redis_error").inc()
            except Exception:
                log.exception("publishing %s/%s failed", *key)
                EVALS.labels("error").inc()

    async def features(self, key: Key, w: PodWindow) -> tuple[dict, list[dict], int, int, int] | None:
        """(features, events, start_ms, newest_ms, n_entropy) of the pod's window; None (logged) on error."""
        async with self.sem:
            try:
                return await self._features(w)
            except Exception:
                log.exception("evaluation of %s/%s failed", *key)
                EVALS.labels("error").inc()
                return None

    async def _features(self, w: PodWindow) -> tuple[dict, list[dict], int, int, int]:
        newest = w.events[-1]["ts_ms"]
        while w.events and w.events[0]["ts_ms"] < newest - WINDOW_S * 1000:
            w.events.popleft()
        events = list(w.events)
        start_ms = min(e["ts_ms"] for e in events)
        window_s = window_seconds(start_ms, newest)
        files = list(w.written.items())[-MAX_ENTROPY_SAMPLES:]
        entropy = await asyncio.to_thread(sample_entropy, self.proc_root, files, self.pids, w.entropy_cache)
        w.samples.append((now_ms(), *await asyncio.to_thread(pod_counters, self.proc_root, w.proc, w.pod_uid,
                                                            self.pids)))
        while w.samples and w.samples[0][0] < start_ms:
            w.samples.popleft()
        features = security_features(events, entropy, window_s, counter_delta(w.samples, 2),
                                     counter_delta(w.samples, 1))
        return features, events, start_ms, newest, len(entropy)

    async def _publish(self, key: Key, w: PodWindow, pred, features: dict, events: list[dict], start_ms: int,
                       newest: int, n_entropy: int) -> str:
        ns, pod = key

        async def build() -> SecurityEvent:
            return SecurityEvent(
                event_id=new_event_id("security"), namespace=ns, workload=await self.owners.resolve(ns, pod),
                pod=pod, model_version=pred.model_version, label=pred.label, risk=pred.risk,
                uncertain=pred.uncertain, probabilities=pred.probabilities, top_factors=pred.top_factors,
                features=features, window_start_ms=start_ms, window_end_ms=newest, n_events=len(events),
            )

        if self.capture:
            await self.redis.xadd(STREAM_CAPTURE, (await build()).to_fields(), maxlen=STREAM_MAXLEN,
                                  approximate=True)
        if pred.risk < SECURITY_PUBLISH_RISK:
            return "below_threshold"
        if time.monotonic() - w.last_publish < COOLDOWN_S and pred.label == w.last_label:
            return "cooldown"
        event = await build()
        await publish_event(self.redis, STREAM_SECURITY, "security", event)
        w.last_publish, w.last_label = time.monotonic(), pred.label
        log.info("published %s for %s/%s (%s): risk=%.2f events=%d entropy_samples=%d", pred.label, ns,
                 pod, event.workload, pred.risk, len(events), n_entropy)
        return "published"

    async def tail_loop(self, tail: FalcoTail) -> None:
        try:
            while True:
                self.ticks["tail"] = time.monotonic()
                lines = await asyncio.to_thread(tail.read_lines)
                EVENTS.inc(sum(self.ingest(ev) for line in lines if (ev := parse_line(line))))
                if not lines:
                    await asyncio.sleep(0.2)
        finally:
            tail.close()

    async def eval_loop(self) -> None:
        next_tick = time.monotonic() + EVAL_INTERVAL_S
        while True:
            self.ticks["eval"] = time.monotonic()
            try:
                await asyncio.wait_for(self.wake.wait(), max(0.0, next_tick - time.monotonic()))
            except TimeoutError:
                pass
            self.wake.clear()
            timer = time.monotonic() >= next_tick
            if timer:
                next_tick = time.monotonic() + EVAL_INTERVAL_S
            await self.evaluate_all(burst_only=not timer)
            await asyncio.sleep(MIN_TICK_S)

    def healthy(self) -> bool:
        now = time.monotonic()
        return all(now - t < max(60.0, 6 * EVAL_INTERVAL_S) for t in self.ticks.values())


async def main() -> None:
    setup_logging()
    await load_kube_config()
    redis = await connect_redis()
    async with aiohttp.ClientSession() as session, client.ApiClient() as api:
        owners = OwnerResolver(client.CoreV1Api(api), client.AppsV1Api(api))
        agent = SecurityAgent(redis, session, owners)
        runner = await start_http(agent.healthy)
        log.info("security agent tailing %s (proc root %s, eval every %.0fs)",
                 FALCO_EVENTS_PATH, PROC_ROOT, EVAL_INTERVAL_S)
        try:
            await asyncio.gather(agent.tail_loop(FalcoTail(FALCO_EVENTS_PATH)), agent.eval_loop())
        finally:
            await runner.cleanup()
            await redis.aclose()


if __name__ == "__main__":
    run(main)
