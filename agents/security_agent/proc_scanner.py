"""
proc_scanner - PID -> (namespace, pod, container, workload) mapping (S-SA-1)
============================================================================
Supports cgroups v1 AND v2 (cgroupfs and systemd layouts) and every namespace. The pod uid found in
`/proc/<pid>/cgroup` is resolved through a read-only `PodIndex` that the Security Agent refreshes from
the Kubernetes API (pods + replicasets, list verbs only). Lookups hit a dict, so a ransomware burst of
hundreds of events per second for one pod costs no API calls.

The PROC_ROOT environment variable (default /proc) lets tests point the scanner at a fixture tree.
"""

import os
import re
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Tuple

PROC_ROOT = os.environ.get("PROC_ROOT", "/proc")

# cgroupfs, v1 and v2: .../kubepods[/<qos>]/pod<uid>/<container-id>
_V1 = re.compile(r"/kubepods(?:/[^/]+)?/pod([a-f0-9-]+)/([a-f0-9]+)")
# systemd driver: ...pod<uid>.slice/<runtime-prefix>-<container_hex>.scope (uid uses underscores)
_V2 = re.compile(r"kubepods[^/]*/[^/]*pod([a-f0-9_-]+)\.slice/[^/]*?([a-f0-9]{12,})\.scope")


def parse_cgroup_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse one cgroup line -> (pod_uid, container_id[:12]) or None."""
    line = line.strip()
    m = _V1.search(line)
    if m:
        return m.group(1), m.group(2)[:12]
    m = _V2.search(line)
    if m:
        return m.group(1).replace("_", "-"), m.group(2)[:12]
    return None


def pod_uid_for_pid(pid: int, proc_root: Optional[str] = None) -> Optional[Tuple[str, str]]:
    root = proc_root or PROC_ROOT
    try:
        with open(f"{root}/{pid}/cgroup") as f:
            for line in f:
                parsed = parse_cgroup_line(line)
                if parsed:
                    return parsed
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return None
    return None


@dataclass
class PodInfo:
    namespace: str
    pod: str
    container: str
    workload_kind: str
    workload: str
    uid: str = ""

    def as_dict(self) -> Dict[str, str]:
        return asdict(self)


class PodIndex:
    """pod uid -> PodInfo, filled from the API (read-only)."""

    def __init__(self):
        self.by_uid: Dict[str, PodInfo] = {}
        self.by_pod: Dict[Tuple[str, str], PodInfo] = {}     # (namespace, pod name) -> PodInfo

    async def refresh(self, core_api, apps_api) -> int:
        pods = await core_api.list_pod_for_all_namespaces()
        rsets = await apps_api.list_replica_set_for_all_namespaces()
        rs_owner: Dict[Tuple[str, str], str] = {}
        for rs in rsets.items:
            for o in (rs.metadata.owner_references or []):
                if o.kind == "Deployment":
                    rs_owner[(rs.metadata.namespace, rs.metadata.name)] = o.name
        self.update_from(pods.items, rs_owner)
        return len(self.by_uid)

    def update_from(self, pods, rs_owner: Dict[Tuple[str, str], str]) -> None:
        index: Dict[str, PodInfo] = {}
        for p in pods:
            md = p.metadata
            kind, workload = "Pod", md.name
            for o in (md.owner_references or []):
                if o.kind == "ReplicaSet":
                    owner = rs_owner.get((md.namespace, o.name))
                    kind, workload = ("Deployment", owner) if owner else ("ReplicaSet", o.name)
                else:
                    kind, workload = o.kind, o.name
                break
            container = ""
            if p.spec and p.spec.containers:
                container = p.spec.containers[0].name
            index[md.uid] = PodInfo(md.namespace, md.name, container, kind, workload, md.uid)
        self.by_uid = index
        self.by_pod = {(i.namespace, i.pod): i for i in index.values()}

    def lookup(self, uid: str) -> Optional[PodInfo]:
        return self.by_uid.get(uid)

    def lookup_pod(self, namespace: str, pod: str) -> Optional[PodInfo]:
        """The pod by name (what a Falco event carries); None when the index does not know it (yet)."""
        return self.by_pod.get((namespace, pod))


def scan_pids(index: PodIndex, proc_root: Optional[str] = None) -> Dict[int, Dict[str, str]]:
    """Map every PID whose cgroup belongs to a known pod. Unknown pods are skipped."""
    root = proc_root or PROC_ROOT
    out: Dict[int, Dict[str, str]] = {}
    try:
        entries = os.listdir(root)
    except OSError:
        return out
    for d in entries:
        if not d.isdigit():
            continue
        parsed = pod_uid_for_pid(int(d), root)
        if not parsed:
            continue
        info = index.lookup(parsed[0])
        if info is None:
            continue
        rec = info.as_dict()
        rec["pid"] = int(d)
        rec["container_id"] = parsed[1]
        out[int(d)] = rec
    return out
