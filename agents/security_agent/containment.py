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
    unreadable, is a `dry_run` result and nothing is written. A FREEZE also needs a namespace without the
    `kubeheal/protected` label (`namespace_protected`) and never targets the agent's own pod (`self_pod`; env
    POD_UID and POD_NAME come from the downward API. Without a valid POD_UID the consumer still starts but
    refuses every freeze with `self_pod_unknown`: fail closed).
  * A THAW is the safe direction (owner decision): it works in any mode, also `test` and unreadable, so
    flipping the panic button to test can never leave a pod frozen with no way back. It must come from
    `requested_by` operator (an executor thaw is `bad_requested_by`) and passes every other check. `mode_seen`
    is still recorded.
  * The target directory is found from the VALIDATED pod UID, not from the path /proc shows (see "Path logic").
    cgroup v2 only. The result is checked hard: under the cgroup root, no symlinks, below `kubepods` or
    `kubepods.slice`, named exactly like the pod directory, exactly one match, and holding a container
    directory of a container id seen in the pod's own /proc entries.
  * A freeze that cannot be confirmed is `failed` (`freeze_not_confirmed`). The cgroup is left as it is: there
    is NO automatic thaw (a half frozen pod must be looked at by a human or by an explicit thaw request).
  * A request id that already has a result is acknowledged and ignored. A message is acknowledged only after its
    result is written. A Redis error never ends the loop. A poison message (one that raised MAX_DELIVERIES
    times, was delivered more than that, or hit a Redis ResponseError such as WRONGTYPE on its result key) is
    answered best effort with `failed: poison` and acknowledged, so it cannot block the requests behind it.
  * The writer enforces the safety rules itself (defence in depth): the directory must be below the cgroup
    root, below a `kubepods` or `kubepods.slice` component, end in a component that carries a pod UID, and not
    be a QoS slice.
  * The /proc scan runs in a thread (asyncio.to_thread), so the event loop is not blocked.

Path logic (fixed after the first real k3d run, cgroup v2, cgroupfs driver, hostPID, host cgroup root mounted
read-write at /host/cgroup). What was observed from inside the agent pod: its own /proc/self/cgroup is `0::/`
(a PRIVATE cgroup namespace whose root is the agent's own container cgroup); other pods' processes show paths
RELATIVE to that root with leading `..` components, for example `0::/../../pod<uid>/<ctr>` (Guaranteed),
`0::/../../../burstable/pod<uid>/<ctr>` (Burstable, one more `..` for the QoS directory) and node processes
`0::/../../../../init`; there is no `kubepods` word in these paths. The mount shows the node cgroup root with a
`kubepods` directory (no `kubepods.slice`), so pod directories are <root>/kubepods/pod<uid>,
<root>/kubepods/burstable/pod<uid> and <root>/kubepods/besteffort/pod<uid>. The first version refused every real
pod (`..` components, no kubepods word). Now:
  (a) the pod's pids come from the PodIndex scan (proc_scanner also reads the relative forms), and their v2 line
      is read; (b) only a LEADING run of `..` is allowed and stripped; a `.` or `..` after the first normal
      component is refused; the pod-level directory NAME is the one path component that is exactly `pod<uid>`
      (cgroupfs) or `kubepods[-burstable|-besteffort]-pod<uid_with_underscores>.slice` (systemd), never its
      parent and never a container scope below it; (c) that name is looked up in the mounted tree at exactly six
      places (<root>/kubepods/<name>, <root>/kubepods/{burstable,besteffort}/<name> and the same under
      kubepods.slice with kubepods-{burstable,besteffort}.slice), depth at most 3, no recursive walk, lstat only,
      no symlink is followed (a symlink named like the pod directory is refused); exactly one match is needed
      (none: `cgroup_dir_missing`, several: `cgroup_path_ambiguous`); (d) the writer keeps its own guards.
  Own pod: with a private cgroup namespace the agent cannot tell its own pod from its own cgroup path, so the
  primary protection is the env POD_UID. The own-cgroup-path check stays only as an extra when that path is a
  normal absolute path that carries a pod UID.
  NOT verified: the actual cgroup.freeze write on Docker Desktop (no test can do that).

Timing. CONTAIN_REQUEST_TTL_S defaults to 30 s (chosen): the Executor waits CONTAIN_FREEZE_TIMEOUT_S, 10 s, for
the result and then reports `freeze_unconfirmed`; a request that reaches this agent later than the Executor
gave up must not freeze the pod behind its back, so the TTL is deliberately short and the TTL is checked again
right before the write.

Crash windows (known gaps, a human is told through the Executor's gap report): if the agent dies between the
cgroup write and the result, the pod stays frozen and the Executor sees no answer. When that request is read
again after its TTL has run out it is not executed, but the cgroup state is read back (bounded, errors
ignored): a cgroup that is actually frozen is answered `failed` with reason `expired_but_frozen` and frozen 1,
never `refused` with frozen 0.

Result reasons are a short code, optionally followed by `: detail`. The Executor must treat anything except
status `frozen` with `frozen` equal to `1` as NOT frozen.
"""

import asyncio
import logging
import os
import re
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import PurePath
from typing import Callable, Dict, List, Optional, Tuple

from redis.exceptions import ResponseError

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
DEFAULT_REQUEST_TTL_S = 30.0       # CONTAIN_REQUEST_TTL_S (chosen, see Timing): an older request is never executed
DEFAULT_VERIFY_S = 5.0             # CONTAIN_FREEZE_VERIFY_S: how long cgroup.events is polled
DEFAULT_RESULT_TTL_S = 300         # EX of the result hash
DEFAULT_POLL_S = 0.1               # chosen: interval between cgroup.events reads
DEFAULT_BLOCK_MS = 2000            # chosen: XREADGROUP block time
DEFAULT_RECLAIM_S = 30.0           # chosen: how often stale pending messages of dead consumers are reclaimed
BACKOFF_INITIAL_S, BACKOFF_MAX_S = 1.0, 30.0   # chosen: back off after a Redis error
MAX_DELIVERIES = 3                 # chosen: a message that failed or was delivered this often is poison

_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")            # an id we may use as part of a Redis key
_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_DNS_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
_POD_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_UID_IN_NAME = re.compile(r"[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}")
_KUBEPODS = ("kubepods", "kubepods.slice")
_QOS_DIRS = frozenset({"kubepods-burstable.slice", "kubepods-besteffort.slice", "kubepods-guaranteed.slice",
                       "burstable", "besteffort", "guaranteed"})


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
    own_pod_uid: str = ""            # env POD_UID (downward API metadata.uid); empty or malformed: freezes refused
    own_pod_name: str = ""           # env POD_NAME
    own_namespace: str = "kubeheal"  # env NAMESPACE

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
        if len(node) > 253 or not _DNS_SUBDOMAIN.fullmatch(node):
            logger.warning("containment consumer not started: NODE_NAME is not a valid node name")
            return None
        own_uid = (env.get("POD_UID") or "").strip().lower()
        if not _POD_UID.fullmatch(own_uid):
            own_uid = ""
            logger.warning("POD_UID is not set (or not a pod uid): every freeze will be refused with "
                           "self_pod_unknown (set it from the downward API, metadata.uid)")
        return cls(
            node=node,
            own_pod_uid=own_uid,
            own_pod_name=(env.get("POD_NAME") or "").strip(),
            own_namespace=(env.get("NAMESPACE") or "kubeheal").strip(),
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

    Defence in depth on top of `resolve_pod_cgroup`, the writer refuses (ValueError) a directory unless its real
    path is below the real path of `cgroup_root`, some component is `kubepods` or `kubepods.slice` with at least
    one component below it, the final component carries a pod UID (dash or underscore form), and the final
    component is not a QoS directory or slice (that would freeze every pod of a QoS class). The control file
    must already exist: it is opened write-only WITHOUT create, so a wrong path can never make a new file.
    Raises OSError for a failed write."""
    if value not in ("0", "1"):
        raise ValueError(f"freeze value must be '0' or '1', got {value!r}")
    real_root = os.path.realpath(cgroup_root)
    real_dir = os.path.realpath(directory)
    if real_dir == real_root or os.path.commonpath([real_root, real_dir]) != real_root:
        raise ValueError("cgroup directory is not below the cgroup root")
    parts = PurePath(real_dir).relative_to(real_root).parts
    kube_at = next((i for i, c in enumerate(parts) if c in _KUBEPODS), None)
    if kube_at is None or kube_at >= len(parts) - 1:
        raise ValueError("cgroup directory is not below a kubepods component")
    if parts[-1] in _QOS_DIRS or not _UID_IN_NAME.search(parts[-1]):
        raise ValueError("cgroup directory is not a pod directory (no pod uid, or a QoS directory)")
    fd = os.open(os.path.join(real_dir, "cgroup.freeze"), os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
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


def pod_dir_name(path: str, pod_uid: str) -> str:
    """The NAME of the pod-level cgroup directory for a v2 path taken from /proc/<pid>/cgroup, or raises
    _Refuse(cgroup_path_mismatch).

    The path may start with a run of `..` (a private cgroup namespace shows other pods relative to its own root);
    only that leading run is allowed and it is dropped. A `.` or `..` after the first normal component is
    refused. The name is the path component that is exactly `pod<uid>` (cgroupfs) or
    `kubepods[-burstable|-besteffort]-pod<uid_with_underscores>.slice` (systemd): never its parent, never a
    container scope below it. A component that carries the uid in any other form is refused."""
    comps = [c for c in path.split("/") if c]
    lead = 0
    while lead < len(comps) and comps[lead] == "..":
        lead += 1
    rest = comps[lead:]
    if any(c in (".", "..") for c in rest):
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: path has a dot component")
    dash, under = pod_uid, pod_uid.replace("-", "_")
    names = (f"pod{dash}", f"kubepods-pod{under}.slice", f"kubepods-burstable-pod{under}.slice",
             f"kubepods-besteffort-pod{under}.slice")
    for c in rest:
        if c in names:
            return c
    if any(dash in c or under in c for c in rest):
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: a path component carries the pod uid in an unknown form")
    raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: path does not contain the pod uid")


# where a pod directory can be, relative to the cgroup root (depth at most 3 including the name)
_PLACES = (("kubepods",), ("kubepods", "burstable"), ("kubepods", "besteffort"), ("kubepods.slice",),
           ("kubepods.slice", "kubepods-burstable.slice"), ("kubepods.slice", "kubepods-besteffort.slice"))


def _kind(path: str) -> Optional[str]:
    """`dir`, `link` or `other` for what lstat finds at `path` (never follows a symlink); None when absent."""
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return None
    if stat.S_ISLNK(mode):
        return "link"
    return "dir" if stat.S_ISDIR(mode) else "other"


def find_pod_dir(real_root: str, name: str) -> str:
    """The one directory called exactly `name` at the six places above, or raises _Refuse. A symlink with that
    name is refused, an intermediate symlink is not walked."""
    matches = []
    for prefix in _PLACES:
        here, walkable = real_root, True
        for part in prefix:
            here = os.path.join(here, part)
            if _kind(here) != "dir":
                walkable = False
                break
        if not walkable:
            continue
        candidate = os.path.join(here, name)
        kind = _kind(candidate)
        if kind == "link":
            raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: the pod directory name is a symlink")
        if kind == "dir":
            matches.append(candidate)
    if not matches:
        raise _Refuse(STATUS_REFUSED, "cgroup_dir_missing: no directory of that name at the known places under the root")
    if len(matches) > 1:
        raise _Refuse(STATUS_REFUSED, f"cgroup_path_ambiguous: {len(matches)} directories carry that name")
    return matches[0]


def require_container_dir(directory: str, container_ids) -> None:
    """The found pod directory must hold a container directory (never a symlink) of a container the pod's own
    processes were seen in: cgroupfs names it `<container id>`, systemd `<runtime>-<container id>.scope`. The pod
    uid picks the directory, this ties it to the container ids read from /proc, so a directory that merely carries
    the right name but has none of the pod's containers in it is refused (`cgroup_container_missing`)."""
    prefixes = {c[:12] for c in container_ids if len(c) >= 12}
    try:
        with os.scandir(directory) as it:
            for entry in it:
                if _kind(os.path.join(directory, entry.name)) != "dir":     # lstat: a symlink or a file never counts
                    continue
                ident = entry.name[:-len(".scope")] if entry.name.endswith(".scope") else entry.name
                ident = ident.rsplit("-", 1)[-1]
                if ident[:12] in prefixes:
                    return
    except OSError:
        pass
    raise _Refuse(STATUS_REFUSED, "cgroup_container_missing: the pod directory holds none of the pod's container ids")


def resolve_pod_cgroup(pod_index: PodIndex, namespace: str, pod: str, pod_uid: str,
                       proc_root: str, cgroup_root: str) -> Tuple[str, str]:
    """(absolute directory, path relative to the cgroup root) of the pod's cgroup. The pod's pids prove which pod
    directory NAME to look for (from their /proc cgroup path); the directory itself is found under the cgroup
    root by `find_pod_dir`. Raises _Refuse with status refused or failed."""
    recs = {pid: rec for pid, rec in scan_pids(pod_index, proc_root).items()
            if rec.get("uid") == pod_uid and rec.get("namespace") == namespace and rec.get("pod") == pod}
    pids = list(recs)
    if not pids:
        raise _Refuse(STATUS_FAILED, "pod_pids_not_found: no process of the pod is visible on this node")
    container_ids = {str(rec.get("container_id") or "") for rec in recs.values()} - {""}
    names, saw_v1, v2_seen = set(), False, False
    for pid in sorted(pids):
        for line in _read_cgroup_lines(proc_root, pid):
            hierarchy, _, rest = line.partition(":")
            controllers, _, path = rest.partition(":")
            if hierarchy == "0" and controllers == "":
                v2_seen = True
                try:
                    names.add(pod_dir_name(path, pod_uid))
                except _Refuse as e:
                    if e.reason.startswith("cgroup_path_mismatch: path does not contain"):
                        continue              # a process outside the pod's directory tree (pid reuse): ignore
                    raise
            elif hierarchy.isdigit() and hierarchy != "0":
                saw_v1 = True
    if not names:
        if saw_v1 and not v2_seen:
            raise _Refuse(STATUS_FAILED, "cgroup_v1_not_supported")
        if saw_v1:
            raise _Refuse(STATUS_FAILED, "cgroup_v1_not_supported: hybrid hierarchy, the pod is not on cgroup v2")
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: no cgroup v2 path of the pod carries its uid")
    if len(names) > 1:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: the pod's processes report different pod cgroups")
    name = next(iter(names))
    real_root = os.path.realpath(cgroup_root)
    candidate = find_pod_dir(real_root, name)
    directory = os.path.realpath(candidate)
    if directory != candidate or os.path.basename(directory) != name:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: the pod directory is not the directory that was found")
    if directory == real_root or os.path.commonpath([real_root, directory]) != real_root:
        raise _Refuse(STATUS_REFUSED, "cgroup_path_mismatch: directory is outside the cgroup root")
    require_container_dir(directory, container_ids)
    return directory, "/".join(PurePath(directory).relative_to(real_root).parts)


def refuse_own_pod(directory: str, pod_uid: str, proc_root: str, cgroup_root: str) -> None:
    """Extra own-pod check from <proc_root>/self/cgroup (`self_pod`). It only applies when that path is a normal
    absolute path that carries a pod UID (no `..`); with a private cgroup namespace the agent sees itself as `/`
    and this check does nothing, the env POD_UID check in `validate` is the primary protection. When it applies
    it refuses a target that carries the agent's uid, equals the agent's directory or is an ancestor of it."""
    real_root = os.path.realpath(cgroup_root)
    for line in _read_cgroup_lines(proc_root, "self"):
        if not line.startswith("0::"):
            continue
        path = line.partition(":")[2].partition(":")[2]
        comps = [c for c in path.split("/") if c and c != "."]
        if ".." in comps or not _UID_IN_NAME.search(path):
            continue
        if pod_uid in path or pod_uid.replace("-", "_") in path:
            raise _Refuse(STATUS_REFUSED, "self_pod: the target is the agent's own pod")
        own_dir = os.path.realpath(os.path.join(real_root, *comps))
        if os.path.commonpath([directory, own_dir]) == directory:     # equal to, or an ancestor of, the agent
            raise _Refuse(STATUS_REFUSED, "self_pod: the target is or contains the agent's own cgroup")


# ---------------------------------------------------------------------------------------------------------
# Request handling (no Redis in here; everything injectable)
# ---------------------------------------------------------------------------------------------------------
def _s(value, limit: int = 253) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return ("" if value is None else str(value))[:limit]


class ContainmentHandler:
    def __init__(self, cfg: ContainmentConfig, pod_index: PodIndex, mode_for: Callable[[str], str], *,
                 protected_for: Optional[Callable[[str], bool]] = None,
                 writer: Callable[[str, str, str], None] = write_cgroup_freeze,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], "asyncio.Future"] = asyncio.sleep):
        self.cfg, self.pod_index, self._mode_for = cfg, pod_index, mode_for
        self._protected_for = protected_for
        self._writer, self._clock, self._monotonic, self._sleep = writer, clock, monotonic, sleep

    def _mode(self, namespace: str) -> str:
        """`test` or `enforce`; anything that goes wrong is `test` (fail safe)."""
        try:
            return ENFORCE if normalize(self._mode_for(namespace)) == ENFORCE else TEST
        except Exception as e:
            logger.warning(f"mode could not be read ({e}); treating as test")
            return TEST

    def _protected(self, namespace: str) -> bool:
        """The kubeheal/protected label of the namespace; an unreadable or unknown state counts as protected."""
        if self._protected_for is None:
            return False
        try:
            return bool(self._protected_for(namespace))
        except Exception as e:
            logger.warning(f"protected label could not be read ({e}); treating the namespace as protected")
            return True

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

    def validate(self, f: Dict[str, str], check_ttl: bool = True) -> Optional[Tuple[str, str]]:
        """None when the request is acceptable, else (status, reason). Pure apart from the pod index, the mode
        watcher's protected label and the clock."""
        if not _REQUEST_ID.fullmatch(_s(f.get("request_id"))):
            return STATUS_REFUSED, "bad_request_id"
        action, label = _s(f.get("action")), _s(f.get("label")).strip()
        if action not in ACTIONS:
            return STATUS_REFUSED, f"bad_action: {_s(f.get('action'), 32)!r}"
        if action == "freeze" and label not in FREEZE_LABELS:
            return STATUS_REFUSED, f"label_not_allowed: a freeze needs ransomware or exfiltration, got {label[:32]!r}"
        if action == "thaw" and label:
            return STATUS_REFUSED, "label_not_allowed: a thaw carries no label"
        requested_by = _s(f.get("requested_by"))
        if requested_by not in REQUESTERS:
            return STATUS_REFUSED, "bad_requested_by"
        if action == "thaw" and requested_by != "operator":
            return STATUS_REFUSED, "bad_requested_by: only an operator may thaw"
        incident_id = _s(f.get("incident_id"))
        if len(incident_id) > 63 or not _DNS_LABEL.fullmatch(incident_id):
            return STATUS_REFUSED, "bad_incident_id"
        namespace, pod, pod_uid, node = (_s(f.get(k)) for k in ("namespace", "pod", "pod_uid", "node"))
        if len(namespace) > 63 or not _DNS_LABEL.fullmatch(namespace):
            return STATUS_REFUSED, "bad_namespace"
        if len(pod) > 253 or not _DNS_SUBDOMAIN.fullmatch(pod):
            return STATUS_REFUSED, "bad_pod"
        if not _POD_UID.fullmatch(pod_uid):
            return STATUS_REFUSED, "bad_pod_uid"
        if node != self.cfg.node:
            return STATUS_REFUSED, "wrong_node: the request is for another node"
        if check_ttl:
            problem = self._expired(f)
            if problem:
                return STATUS_REFUSED, problem
        ok, why = check_target(namespace)          # the Executor's own guard: never-act and allowed namespaces
        if not ok:
            return STATUS_REFUSED, f"namespace_not_allowed: {why}"
        if action == "freeze" and self._protected(namespace):
            return STATUS_REFUSED, "namespace_protected: the namespace carries kubeheal/protected or is unknown"
        info = self.pod_index.lookup_pod(namespace, pod)
        if info is None:
            return STATUS_REFUSED, "pod_unknown: this node's pod index does not know the pod"
        if info.uid != pod_uid:
            return STATUS_REFUSED, "pod_uid_mismatch"
        if not info.node:
            return STATUS_REFUSED, "pod_node_unknown"
        if info.node != self.cfg.node:
            return STATUS_REFUSED, "wrong_node: the pod runs on another node"
        if action == "freeze":
            if not self.cfg.own_pod_uid:
                return STATUS_REFUSED, "self_pod_unknown: POD_UID is not set, so no freeze can be safe"
            if pod_uid == self.cfg.own_pod_uid or (self.cfg.own_pod_name and pod == self.cfg.own_pod_name
                                                  and namespace == self.cfg.own_namespace):
                return STATUS_REFUSED, "self_pod: the target is the Security Agent's own pod"
        return None

    def _resolve(self, f: Dict[str, str], check_self: bool) -> Tuple[str, str]:
        """Blocking part (reads /proc): run it in a thread. Raises _Refuse."""
        uid = _s(f.get("pod_uid"))
        directory, rel = resolve_pod_cgroup(self.pod_index, _s(f.get("namespace")), _s(f.get("pod")), uid,
                                            self.cfg.proc_root, self.cfg.cgroup_root)
        if check_self:
            refuse_own_pod(directory, uid, self.cfg.proc_root, self.cfg.cgroup_root)
        return directory, rel

    async def handle(self, f: Dict[str, str]) -> Dict[str, str]:
        """Validate, check the mode, find the cgroup, write, verify. Always returns a result, never raises
        for a bad request.

        A thaw is the SAFE direction (owner decision): it works in any mode, also `test` and unreadable, so a
        pod frozen before the panic button was pressed can still be released. It must come from an operator and
        passes every other check (namespace guard, pod UID, node, TTL, path safety). It records `mode_seen`."""
        action, namespace = _s(f.get("action")), _s(f.get("namespace"))
        bad = self.validate(f)
        if bad:
            if bad[1] == "expired" and action == "freeze" and self.validate(f, check_ttl=False) is None:
                return await self._expired_readback(f)
            return self._result(f, bad[0], bad[1])
        freezing = action == "freeze"
        mode = self._mode(namespace)
        if freezing and mode != ENFORCE:
            return self._result(f, STATUS_DRY_RUN, f"mode_{mode}: nothing was written", mode_seen=mode)
        try:
            directory, rel = await asyncio.to_thread(self._resolve, f, freezing)
        except _Refuse as e:
            return self._result(f, e.status, e.reason, mode_seen=mode)
        # The decisive checks, immediately before the write: the mode may have flipped to test, or the request
        # may have aged out while the pod was being looked up.
        mode = self._mode(namespace)
        if freezing and mode != ENFORCE:
            return self._result(f, STATUS_DRY_RUN, f"mode_{mode}: the mode changed before the write, "
                                "nothing was written", mode_seen=mode, cgroup=rel)
        problem = self._expired(f)
        if problem:
            return self._result(f, STATUS_REFUSED, problem, mode_seen=mode, cgroup=rel)
        try:
            self._writer(directory, "1" if freezing else "0", self.cfg.cgroup_root)
        except ValueError as e:                  # the writer's own safety rules refused the path
            return self._result(f, STATUS_REFUSED, f"cgroup_path_mismatch: writer refused: {_s(e, 120)}",
                                mode_seen=mode, cgroup=rel)
        except OSError as e:
            now = read_cgroup_frozen(directory)
            return self._result(f, STATUS_FAILED, f"cgroup_write_failed: {type(e).__name__}: {_s(e, 120)}",
                                frozen="1" if now else "0", mode_seen=mode, cgroup=rel)
        state = await self._verify(directory, freezing)
        frozen = "1" if state else "0"
        if state is freezing:
            return self._result(f, STATUS_FROZEN if freezing else STATUS_THAWED, "", frozen=frozen,
                                mode_seen=mode, cgroup=rel)
        if freezing:
            logger.error(f"freeze of {namespace}/{_s(f.get('pod'))} not confirmed in {self.cfg.verify_s}s; "
                         f"the cgroup {rel} is left as it is (no automatic thaw)")
            reason = "freeze_not_confirmed: cgroup left as it is, not thawed"
        else:
            reason = "thaw_not_confirmed: cgroup left as it is"
        return self._result(f, STATUS_FAILED, reason, frozen=frozen, mode_seen=mode, cgroup=rel)

    async def _expired_readback(self, f: Dict[str, str]) -> Dict[str, str]:
        """An expired freeze is never executed. But an earlier attempt of the same request may have written the
        freeze before the agent crashed, so the state is read back (read-only, bounded, errors ignored): a pod
        that IS frozen is reported `failed: expired_but_frozen` with frozen 1, never `refused` with frozen 0."""
        try:
            directory, rel = await asyncio.to_thread(self._resolve, f, False)
            if read_cgroup_frozen(directory):
                return self._result(f, STATUS_FAILED, "expired_but_frozen", frozen="1", cgroup=rel)
        except Exception as e:
            logger.debug(f"expired freeze: read-back skipped ({type(e).__name__})")
        return self._result(f, STATUS_REFUSED, "expired")

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
        self._fails: Dict[str, int] = {}      # message id -> failed attempts in this process (poison tracking)

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
        """Answer one message and acknowledge it after the result is written. Redis errors propagate (see
        `_guarded` for what happens to a message that keeps failing); a handler error becomes a `failed` result."""
        f = _fields(raw_fields)
        request_id = f.get("request_id", "")
        if not _SAFE_TOKEN.fullmatch(request_id):
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

    async def _deliveries(self, msg_id: str) -> int:
        """times_delivered from the pending list (0 when it cannot be read)."""
        try:
            rows = await self.redis.xpending_range(self.cfg.stream, self.cfg.group, min=msg_id, max=msg_id, count=1)
            return int(rows[0].get("times_delivered", 0)) if rows else 0
        except Exception:
            return 0

    async def _poison(self, msg_id: str, raw_fields, why: str) -> None:
        """Best effort, never raises: a `failed` result with reason `poison` (unless a result already exists),
        then the ack, so one bad message cannot block the queue behind it."""
        logger.error(f"containment message {msg_id} is poison ({why}); answering failed and acknowledging")
        self._fails.pop(msg_id, None)
        f = _fields(raw_fields)
        request_id = f.get("request_id", "")
        result = None
        if _SAFE_TOKEN.fullmatch(request_id):
            key = RESULT_KEY_PREFIX + request_id
            try:
                answered = await self.redis.hget(key, "status") is not None
            except Exception:
                answered = False          # the key itself may be what fails (WRONGTYPE): try to write anyway
            if not answered:
                try:
                    result = self.handler._result(f, STATUS_FAILED, "poison")
                    result["request_id"] = request_id
                    await self._write_result(result)
                except Exception as e:
                    logger.error(f"poison result could not be written ({type(e).__name__})")
                    result = None
        try:
            await self.redis.xack(self.cfg.stream, self.cfg.group, msg_id)
        except Exception as e:
            logger.error(f"poison message {msg_id} could not be acknowledged ({type(e).__name__})")
        if result is not None:
            self._count(result)

    async def _guarded(self, msg_id: str, raw_fields) -> None:
        """`process` with poison protection: a message that raised MAX_DELIVERIES times, was delivered
        more than MAX_DELIVERIES times, or hit a Redis ResponseError (for example WRONGTYPE on its result key,
        which no retry can cure) is answered `failed: poison` and acknowledged. Connection errors are transient
        and are retried by the loop."""
        if self._fails.get(msg_id, 0) >= MAX_DELIVERIES or await self._deliveries(msg_id) > MAX_DELIVERIES:
            await self._poison(msg_id, raw_fields, "too many deliveries")
            return
        try:
            await self.process(msg_id, raw_fields)
            self._fails.pop(msg_id, None)
        except asyncio.CancelledError:
            raise
        except ResponseError as e:
            await self._poison(msg_id, raw_fields, f"redis ResponseError: {_s(e, 80)}")
        except Exception:
            self._fails[msg_id] = self._fails.get(msg_id, 0) + 1
            raise

    async def _reclaim(self) -> None:
        """Take over messages a dead consumer (an earlier pod of this DaemonSet) left pending. Anything idle
        for longer than the request TTL is expired by definition (an expired freeze is not executed)."""
        reply = await self.redis.xautoclaim(self.cfg.stream, self.cfg.group, self.cfg.consumer,
                                            min_idle_time=int(self.cfg.request_ttl_s * 1000),
                                            start_id="0-0", count=10)
        for msg_id, raw in (reply[1] if reply else []):
            await self._guarded(msg_id, raw)

    async def run(self) -> None:
        self.running = True
        need_group, pending_done = True, False
        pending_seen = set()
        last_reclaim = float("-inf")
        backoff = BACKOFF_INITIAL_S
        while self.running:
            try:
                if need_group:
                    await self.ensure_group()
                    need_group = False
                if self._monotonic() - last_reclaim >= self.cfg.reclaim_s:
                    last_reclaim = self._monotonic()
                    try:                      # a failing reclaim must never keep us from reading new requests
                        await self._reclaim()
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.warning(f"containment reclaim failed ({type(e).__name__}: {_s(e, 120)})")
                # first our own pending messages (a crash between result and ack), then new ones
                position = ">" if pending_done else "0"
                reply = await self.redis.xreadgroup(self.cfg.group, self.cfg.consumer, {self.cfg.stream: position},
                                                    count=10, block=self.cfg.block_ms if pending_done else None)
                entries = reply[0][1] if reply else []
                if not pending_done:
                    # an entry that stays pending after we handled it (an ack that fails) must not be read again
                    # and again: the second time round the pending pass is over
                    entries_new = [(i, r) for i, r in entries if i not in pending_seen]
                    pending_seen.update(i for i, _ in entries)
                    pending_done = not entries_new
                    entries = entries_new
                for msg_id, raw in entries:
                    await self._guarded(msg_id, raw)
                backoff = BACKOFF_INITIAL_S
            except asyncio.CancelledError:
                self.running = False
                raise
            except Exception as e:
                logger.warning(f"containment consumer error ({type(e).__name__}: {_s(e, 120)}); "
                               f"retrying in {backoff}s")
                need_group, pending_done = True, False
                pending_seen.clear()
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
        handler = ContainmentHandler(cfg, pod_index, mode.mode_for, protected_for=mode.protected_for)
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
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        await self.mode.stop()
