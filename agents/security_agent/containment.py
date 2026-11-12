"""
Containment (V5-S5a, owner decisions D5 and Q2): the Security Agent half of cgroup-freeze containment.
=========================================================================================================
The Executor, behind the kill switch and after a ledger entry, publishes a REQUEST on the node's stream
`kubeheal.contain.req:<node>` and waits a bounded time for the RESULT hash `kubeheal:contain:result:<id>`.
This node-local consumer validates the request, re-checks the kill-switch mode, freezes the pod's cgroup
(cgroup v2 `cgroup.freeze`), reads the state back from `cgroup.events` and writes the result.

Rules this module keeps (pinned by tests/test_containment_agent.py and tests/test_cgroup_writes_static.py):
  * It never writes to Kubernetes. The only write it makes anywhere is `write_cgroup_freeze` below, the ONE
    function that touches a cgroup control file. Nothing else in the repository may name that file.
  * It reads only its own node's stream (env NODE_NAME, from the downward API spec.nodeName). Without
    NODE_NAME the consumer does not start.
  * Every request is validated before anything is touched; each failure is a `refused` result with a reason,
    never an exception. A freeze is only ever done for the labels `ransomware` and `exfiltration` (Q2):
    `suspicious` never freezes.
  * The mode comes from `agents.common.killswitch.ModeWatcher` (the global mode is absolute, a namespace label
    can only be stricter). It is read at validation and AGAIN immediately before the write. Not `enforce`, or
    unreadable, is a `dry_run` result and nothing is written.
  * The cgroup path comes from /proc (`0::/path` lines, cgroup v2 only) and is checked hard: under the cgroup
    root, no `..`, below a `kubepods` component, and it must carry the pod UID. No guessing of systemd versus
    cgroupfs layouts.
  * A freeze that cannot be confirmed is `failed` (`freeze_not_confirmed`). The cgroup is left as it is: there
    is NO automatic thaw (a half frozen pod must be looked at by a human or by an explicit thaw request).
  * A request id that already has a result is acknowledged and ignored. A message is acknowledged only after its
    result is written. A Redis error never ends the loop.

Result reasons are a short code, optionally followed by `: detail`. The Executor must treat anything except
status `frozen` with `frozen` equal to `1` as NOT frozen.
"""

import asyncio
import logging
import os
import posixpath
import re
import socket
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from agents.common.killswitch import ENFORCE, TEST, ModeWatcher, normalize
from agents.executor.guard import check_target
from agents.security_agent.proc_scanner import PodIndex, scan_pids

logger = logging.getLogger(__name__)

REQUEST_STREAM_PREFIX = "kubeheal.contain.req:"
RESULT_KEY_PREFIX = "kubeheal:contain:result:"
GROUP = "security-agent"

ACTIONS = frozenset({"freeze", "thaw"})
FREEZE_LABELS = frozenset({"ransomware", "exfiltration"})     # Q2: the only labels that may freeze
REQUESTERS = frozenset({"executor", "operator"})

STATUS_FROZEN, STATUS_THAWED, STATUS_DRY_RUN = "frozen", "thawed", "dry_run"
STATUS_REFUSED, STATUS_FAILED = "refused", "failed"

# chosen defaults (owner brief, V5-S5a); each can be overridden by the environment variable named
DEFAULT_REQUEST_TTL_S = 60.0       # CONTAIN_REQUEST_TTL_S: an older request is never executed
DEFAULT_VERIFY_S = 5.0             # CONTAIN_FREEZE_VERIFY_S: how long cgroup.events is polled
DEFAULT_RESULT_TTL_S = 300         # EX of the result hash
DEFAULT_POLL_S = 0.1               # chosen: interval between cgroup.events reads
DEFAULT_BLOCK_MS = 2000            # chosen: XREADGROUP block time
DEFAULT_RECLAIM_S = 30.0           # chosen: how often stale pending messages of dead consumers are reclaimed
BACKOFF_INITIAL_S, BACKOFF_MAX_S = 1.0, 30.0   # chosen: back off after a Redis error

_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")            # an id we may use as part of a Redis key
_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_DNS_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
_POD_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _positive(raw, default: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 and value == value and value != float("inf") else default


@dataclass
class ContainmentConfig:
    node: str
    request_ttl_s: float = DEFAULT_REQUEST_TTL_S
    verify_s: float = DEFAULT_VERIFY_S
    poll_s: float = DEFAULT_POLL_S
    result_ttl_s: int = DEFAULT_RESULT_TTL_S
    block_ms: int = DEFAULT_BLOCK_MS
    reclaim_s: float = DEFAULT_RECLAIM_S
    proc_root: str = "/proc"
    cgroup_root: str = "/sys/fs/cgroup"
    group: str = GROUP
    consumer: str = ""

    @property
    def stream(self) -> str:
        return REQUEST_STREAM_PREFIX + self.node

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> Optional["ContainmentConfig"]:
        """None (and a log line) when NODE_NAME is unset or not a node name: the consumer does not start."""
        env = os.environ if env is None else env
        node = (env.get("NODE_NAME") or "").strip()
        if not node:
            logger.warning("containment consumer not started: NODE_NAME is not set "
                           "(set it from the downward API, spec.nodeName)")
            return None
        if len(node) > 253 or not _DNS_SUBDOMAIN.match(node):
            logger.warning("containment consumer not started: NODE_NAME is not a valid node name")
            return None
        return cls(
            node=node,
            request_ttl_s=_positive(env.get("CONTAIN_REQUEST_TTL_S"), DEFAULT_REQUEST_TTL_S),
            verify_s=_positive(env.get("CONTAIN_FREEZE_VERIFY_S"), DEFAULT_VERIFY_S),
            proc_root=env.get("PROC_ROOT") or "/proc",
            cgroup_root=env.get("CGROUP_ROOT") or "/sys/fs/cgroup",
            consumer=env.get("HOSTNAME") or socket.gethostname(),
        )


# ---------------------------------------------------------------------------------------------------------
# The only cgroup write
# ---------------------------------------------------------------------------------------------------------
def write_cgroup_freeze(directory: str, value: str, cgroup_root: str) -> None:
    """Write `0` or `1` to the freeze control file of `directory`. THE ONLY cgroup write in the repository.

    Defence in depth on top of `resolve_pod_cgroup`: the real path of the directory must be inside the real
    path of `cgroup_root`, must not be the root itself, and the control file must already exist (it is opened
    write-only WITHOUT create, so a wrong path can never make a new file). Raises ValueError for a bad value or
    path and OSError for a failed write."""
    if value not in ("0", "1"):
        raise ValueError(f"freeze value must be '0' or '1', got {value!r}")
    real_root = os.path.realpath(cgroup_root)
    real_dir = os.path.realpath(directory)
    if real_dir == real_root or os.path.commonpath([real_root, real_dir]) != real_root:
        raise ValueError("cgroup directory is not below the cgroup root")
    fd = os.open(os.path.join(real_dir, "cgroup.freeze"), os.O_WRONLY)
    try:
        os.write(fd, value.encode("ascii"))
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------------------------------------
# Read-only helpers (these never write)
# ---------------------------------------------------------------------------------------------------------
def read_cgroup_frozen(directory: str) -> Optional[bool]:
    """The `frozen` flag of cgroup.events, or None when it cannot be read."""
    try:
        with open(os.path.join(directory, "cgroup.events"), "r", encoding="utf-8", errors="replace") as f:
            for line in f.read().splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0] == "frozen":
                    return parts[1] == "1"
    except OSError:
        return None
    return None


class _Refuse(Exception):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _read_cgroup_lines(proc_root: str, pid: int) -> List[str]:
    try:
        with open(f"{proc_root}/{pid}/cgroup", "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return []


def pod_cgroup_components(path: str, pod_uid: str) -> List[str]:
    """The pod-level cgroup directory (as path components below the cgroup root) for a v2 path taken from
    /proc/<pid>/cgroup, or raises _Refuse(cgroup_path_mismatch).

    The pod directory is the parent of the container scope directory: the path component that carries the pod
    UID (dash form or underscore form). It must come after a `kubepods` component (`kubepods` for the cgroupfs
    driver, `kubepods.slice` for systemd). A `.` or `..` component anywhere is refused: /proc already gives an
    absolute path, so a `..` is never legitimate here."""
    comps = path.split("/")
    if any(c in ("..", ".") for c in comps):
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: path has a dot component")
    comps = [c for c in comps if c]
    normalised = posixpath.normpath("/" + "/".join(comps)) if comps else "/"
    if ".." in normalised.split("/"):
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: path escapes the cgroup root")
    forms = (pod_uid, pod_uid.replace("-", "_"))
    uid_at = next((i for i, c in enumerate(comps) if any(f in c for f in forms)), None)
    kube_at = next((i for i, c in enumerate(comps) if c in ("kubepods", "kubepods.slice")), None)
    if uid_at is None:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: path does not contain the pod uid")
    if kube_at is None or kube_at >= uid_at:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: path is not below a kubepods component")
    return comps[: uid_at + 1]


def resolve_pod_cgroup(pod_index: PodIndex, namespace: str, pod: str, pod_uid: str,
                       proc_root: str, cgroup_root: str) -> Tuple[str, str]:
    """(absolute directory, path relative to the cgroup root) of the pod's cgroup, from /proc.
    Raises _Refuse with status refused or failed."""
    pids = [pid for pid, rec in scan_pids(pod_index, proc_root).items()
            if rec.get("uid") == pod_uid and rec.get("namespace") == namespace and rec.get("pod") == pod]
    if not pids:
        raise _Refuse(STATUS_FAILED, "pod_pids_not_found: no process of the pod is visible on this node")
    pod_dirs, saw_v1, v2_seen = set(), False, False
    for pid in sorted(pids):
        for line in _read_cgroup_lines(proc_root, pid):
            hierarchy, _, rest = line.partition(":")
            controllers, _, path = rest.partition(":")
            if hierarchy == "0" and controllers == "":
                v2_seen = True
                try:
                    pod_dirs.add(tuple(pod_cgroup_components(path, pod_uid)))
                except _Refuse as e:
                    if e.reason.startswith("cgroup_path_mismatch: path does not contain"):
                        continue              # a process outside the pod's directory tree (pid reuse): ignore
                    raise
            elif hierarchy.isdigit() and hierarchy != "0":
                saw_v1 = True
    if not pod_dirs:
        if saw_v1 and not v2_seen:
            raise _Refuse(STATUS_FAILED, "cgroup_v1_not_supported")
        if saw_v1:
            raise _Refuse(STATUS_FAILED, "cgroup_v1_not_supported: hybrid hierarchy, the pod is not on cgroup v2")
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: no cgroup v2 path of the pod carries its uid")
    if len(pod_dirs) > 1:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: the pod's processes report different pod cgroups")
    comps = list(next(iter(pod_dirs)))
    real_root = os.path.realpath(cgroup_root)
    directory = os.path.realpath(os.path.join(real_root, *comps))
    if directory == real_root or os.path.commonpath([real_root, directory]) != real_root:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: directory is outside the cgroup root")
    if not os.path.isdir(directory):
        raise _Refuse(STATUS_FAILED, "cgroup_dir_missing: the pod cgroup directory does not exist under the root")
    return directory, "/".join(comps)


# ---------------------------------------------------------------------------------------------------------
# Request handling (no Redis in here; everything injectable)
# ---------------------------------------------------------------------------------------------------------
def _s(value, limit: int = 253) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return ("" if value is None else str(value))[:limit]


class ContainmentHandler:
    def __init__(self, cfg: ContainmentConfig, pod_index: PodIndex, mode_for: Callable[[str], str], *,
                 writer: Callable[[str, str, str], None] = write_cgroup_freeze,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], "asyncio.Future"] = asyncio.sleep):
        self.cfg, self.pod_index, self._mode_for = cfg, pod_index, mode_for
        self._writer, self._clock, self._monotonic, self._sleep = writer, clock, monotonic, sleep

    def _mode(self, namespace: str) -> str:
        """`test` or `enforce`; anything that goes wrong is `test` (fail safe)."""
        try:
            return ENFORCE if normalize(self._mode_for(namespace)) == ENFORCE else TEST
        except Exception as e:
            logger.warning(f"mode could not be read ({e}); treating as test")
            return TEST

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def _result(self, f: Dict[str, str], status: str, reason: str = "", frozen: str = "0",
                mode_seen: str = "", cgroup: str = "") -> Dict[str, str]:
        namespace = _s(f.get("namespace"))
        return {
            "status": status, "reason": reason, "request_id": _s(f.get("request_id")),
            "incident_id": _s(f.get("incident_id")), "namespace": namespace, "pod": _s(f.get("pod")),
            "pod_uid": _s(f.get("pod_uid")), "node": self.cfg.node, "action": _s(f.get("action")),
            "frozen": frozen, "mode_seen": mode_seen or self._mode(namespace), "cgroup": cgroup,
            "ts_ms": str(self._now_ms()),
        }

    def _expired(self, f: Dict[str, str]) -> Optional[str]:
        try:
            ts = int(_s(f.get("timestamp_ms")))
        except ValueError:
            return "bad_timestamp"
        now = self._now_ms()
        ttl_ms = int(self.cfg.request_ttl_s * 1000)
        if now - ts > ttl_ms:
            return "expired"
        if ts - now > ttl_ms:
            return "bad_timestamp: the request is dated in the future"
        return None

    def validate(self, f: Dict[str, str]) -> Optional[Tuple[str, str]]:
        """None when the request is acceptable, else (status, reason). Pure apart from the pod index and mode."""
        if not _REQUEST_ID.match(_s(f.get("request_id"))):
            return STATUS_REFUSED, "bad_request_id"
        action, label = _s(f.get("action")), _s(f.get("label")).strip()
        if action not in ACTIONS:
            return STATUS_REFUSED, f"bad_action: {_s(f.get('action'), 32)!r}"
        if action == "freeze" and label not in FREEZE_LABELS:
            return STATUS_REFUSED, f"label_not_allowed: a freeze needs ransomware or exfiltration, got {label[:32]!r}"
        if action == "thaw" and label:
            return STATUS_REFUSED, "label_not_allowed: a thaw carries no label"
        if _s(f.get("requested_by")) not in REQUESTERS:
            return STATUS_REFUSED, "bad_requested_by"
        incident_id = _s(f.get("incident_id"))
        if len(incident_id) > 63 or not _DNS_LABEL.match(incident_id):
            return STATUS_REFUSED, "bad_incident_id"
        namespace, pod, pod_uid, node = (_s(f.get(k)) for k in ("namespace", "pod", "pod_uid", "node"))
        if len(namespace) > 63 or not _DNS_LABEL.match(namespace):
            return STATUS_REFUSED, "bad_namespace"
        if len(pod) > 253 or not _DNS_SUBDOMAIN.match(pod):
            return STATUS_REFUSED, "bad_pod"
        if not _POD_UID.match(pod_uid):
            return STATUS_REFUSED, "bad_pod_uid"
        if node != self.cfg.node:
            return STATUS_REFUSED, "wrong_node: the request is for another node"
        problem = self._expired(f)
        if problem:
            return STATUS_REFUSED, problem
        ok, why = check_target(namespace)          # the Executor's own guard: never-act and allowed namespaces
        if not ok:
            return STATUS_REFUSED, f"namespace_not_allowed: {why}"
        info = self.pod_index.lookup_pod(namespace, pod)
        if info is None:
            return STATUS_REFUSED, "pod_unknown: this node's pod index does not know the pod"
        if info.uid != pod_uid:
            return STATUS_REFUSED, "pod_uid_mismatch"
        if not info.node:
            return STATUS_REFUSED, "pod_node_unknown"
        if info.node != self.cfg.node:
            return STATUS_REFUSED, "wrong_node: the pod runs on another node"
        return None

    async def handle(self, f: Dict[str, str]) -> Dict[str, str]:
        """Validate, check the mode, find the cgroup, write, verify. Always returns a result, never raises
        for a bad request."""
        bad = self.validate(f)
        if bad:
            return self._result(f, bad[0], bad[1])
        namespace, action = _s(f.get("namespace")), _s(f.get("action"))
        mode = self._mode(namespace)
        if mode != ENFORCE:
            return self._result(f, STATUS_DRY_RUN, f"mode_{mode}: nothing was written", mode_seen=mode)
        try:
            directory, rel = resolve_pod_cgroup(self.pod_index, namespace, _s(f.get("pod")),
                                                _s(f.get("pod_uid")), self.cfg.proc_root, self.cfg.cgroup_root)
        except _Refuse as e:
            return self._result(f, e.status, e.reason, mode_seen=mode)
        # The decisive checks, immediately before the write: the mode may have flipped to test, or the request
        # may have aged out while the pod was being looked up.
        mode = self._mode(namespace)
        if mode != ENFORCE:
            return self._result(f, STATUS_DRY_RUN, f"mode_{mode}: the mode changed before the write, "
                                "nothing was written", mode_seen=mode, cgroup=rel)
        problem = self._expired(f)
        if problem:
            return self._result(f, STATUS_REFUSED, problem, mode_seen=mode, cgroup=rel)
        want = action == "freeze"
        try:
            self._writer(directory, "1" if want else "0", self.cfg.cgroup_root)
        except (OSError, ValueError) as e:
            now = read_cgroup_frozen(directory)
            return self._result(f, STATUS_FAILED, f"cgroup_write_failed: {type(e).__name__}: {_s(e, 120)}",
                                frozen="1" if now else "0", mode_seen=mode, cgroup=rel)
        state = await self._verify(directory, want)
        frozen = "1" if state else "0"
        if state is want:
            return self._result(f, STATUS_FROZEN if want else STATUS_THAWED, "", frozen=frozen,
                                mode_seen=mode, cgroup=rel)
        if want:
            logger.error(f"freeze of {namespace}/{_s(f.get('pod'))} not confirmed in {self.cfg.verify_s}s; "
                         f"the cgroup {rel} is left as it is (no automatic thaw)")
            reason = "freeze_not_confirmed: cgroup left as it is, not thawed"
        else:
            reason = "thaw_not_confirmed: cgroup left as it is"
        return self._result(f, STATUS_FAILED, reason, frozen=frozen, mode_seen=mode, cgroup=rel)

    async def _verify(self, directory: str, want: bool) -> Optional[bool]:
        """Poll cgroup.events (bounded) until `frozen` equals `want`; return the last value read."""
        deadline = self._monotonic() + self.cfg.verify_s
        while True:
            state = read_cgroup_frozen(directory)
            if state is want or self._monotonic() >= deadline:
                return state
            await self._sleep(self.cfg.poll_s)


# ---------------------------------------------------------------------------------------------------------
# Redis consumer
# ---------------------------------------------------------------------------------------------------------
def _fields(raw) -> Dict[str, str]:
    return {_s(k): _s(v, 4096) for k, v in (raw or {}).items()}


class ContainmentConsumer:
    def __init__(self, redis, handler: ContainmentHandler, cfg: ContainmentConfig, metrics=None,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], "asyncio.Future"] = asyncio.sleep):
        self.redis, self.handler, self.cfg, self.metrics = redis, handler, cfg, metrics
        self._monotonic, self._sleep = monotonic, sleep
        self.running = False

    async def ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(self.cfg.stream, self.cfg.group, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def _write_result(self, result: Dict[str, str]) -> None:
        key = RESULT_KEY_PREFIX + result["request_id"]
        await self.redis.hset(key, mapping=result)
        await self.redis.expire(key, self.cfg.result_ttl_s)

    def _count(self, result: Dict[str, str]) -> None:
        if self.metrics is None:
            return
        action = result.get("action") if result.get("action") in ACTIONS else "invalid"
        try:
            self.metrics.record_action(f"cgroup_{action}", result["status"])   # kubeheal_actions_total
        except Exception:
            pass

    async def process(self, msg_id: str, raw_fields) -> None:
        """Answer one message and acknowledge it after the result is written. Redis errors propagate (the
        message stays pending and is retried); anything else becomes a `failed` result."""
        f = _fields(raw_fields)
        request_id = f.get("request_id", "")
        if not _SAFE_TOKEN.match(request_id):
            logger.warning(f"containment message {msg_id} dropped: no usable request_id")
            await self.redis.xack(self.cfg.stream, self.cfg.group, msg_id)
            return
        key = RESULT_KEY_PREFIX + request_id
        if await self.redis.hget(key, "status") is not None:
            await self.redis.expire(key, self.cfg.result_ttl_s)    # a half written result keeps no stale TTL
            await self.redis.xack(self.cfg.stream, self.cfg.group, msg_id)
            return
        try:
            result = await self.handler.handle(f)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception("containment handler failed")
            result = self.handler._result(f, STATUS_FAILED, f"internal_error: {type(e).__name__}")
        result["request_id"] = request_id
        await self._write_result(result)
        await self.redis.xack(self.cfg.stream, self.cfg.group, msg_id)
        self._count(result)
        logger.info(f"containment {result['action']} {result['namespace']}/{result['pod']} -> "
                    f"{result['status']} {result['reason']}".rstrip())

    async def _reclaim(self) -> None:
        """Take over messages a dead consumer (an earlier pod of this DaemonSet) left pending. Anything idle
        for longer than the request TTL is expired by definition and is answered `refused: expired`."""
        reply = await self.redis.xautoclaim(self.cfg.stream, self.cfg.group, self.cfg.consumer,
                                            min_idle_time=int(self.cfg.request_ttl_s * 1000),
                                            start_id="0-0", count=10)
        for msg_id, raw in (reply[1] if reply else []):
            await self.process(msg_id, raw)

    async def run(self) -> None:
        self.running = True
        need_group, pending_done = True, False
        last_reclaim = float("-inf")
        backoff = BACKOFF_INITIAL_S
        while self.running:
            try:
                if need_group:
                    await self.ensure_group()
                    need_group = False
                if self._monotonic() - last_reclaim >= self.cfg.reclaim_s:
                    await self._reclaim()
                    last_reclaim = self._monotonic()
                # first our own pending messages (a crash between result and ack), then new ones
                position = ">" if pending_done else "0"
                reply = await self.redis.xreadgroup(self.cfg.group, self.cfg.consumer, {self.cfg.stream: position},
                                                    count=10, block=self.cfg.block_ms if pending_done else None)
                entries = reply[0][1] if reply else []
                if not pending_done and not entries:
                    pending_done = True
                for msg_id, raw in entries:
                    await self.process(msg_id, raw)
                backoff = BACKOFF_INITIAL_S
            except asyncio.CancelledError:
                self.running = False
                raise
            except Exception as e:
                logger.warning(f"containment consumer error ({type(e).__name__}: {_s(e, 120)}); "
                               f"retrying in {backoff}s")
                need_group, pending_done = True, False
                await self._sleep(backoff)
                backoff = min(backoff * 2, BACKOFF_MAX_S)


class ContainmentService:
    """What the Security Agent holds: the mode watcher and the consumer task. `from_env` returns None when
    NODE_NAME is unset (the consumer must not start)."""

    def __init__(self, consumer: ContainmentConsumer, mode: ModeWatcher):
        self.consumer, self.mode = consumer, mode
        self._task: Optional[asyncio.Task] = None

    @classmethod
    def from_env(cls, redis, pod_index: PodIndex, metrics=None,
                 env: Optional[Dict[str, str]] = None) -> Optional["ContainmentService"]:
        cfg = ContainmentConfig.from_env(env)
        if cfg is None:
            return None
        mode = ModeWatcher()
        handler = ContainmentHandler(cfg, pod_index, mode.mode_for)
        return cls(ContainmentConsumer(redis, handler, cfg, metrics), mode)

    async def start(self, core_api) -> None:
        try:
            await self.mode.start(core_api)       # read-only: kubeheal-mode ConfigMap and namespace labels
        except Exception as e:
            logger.warning(f"kill switch watcher not started ({e}); containment stays in dry_run")
        self._task = asyncio.create_task(self.consumer.run())
        logger.info(f"containment consumer started on {self.consumer.cfg.stream}")

    async def stop(self) -> None:
        self.consumer.running = False
        if self._task:
            self._task.cancel()
        await self.mode.stop()
