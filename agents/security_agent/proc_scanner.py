"""
proc_scanner — PID → (namespace, pod, container) mapping (PRD Section 08.3)
==========================================================================
Supports cgroups v1 AND v2 (Minikube on Ubuntu 22.04 uses v2 — a demo-breaking
gap in v3). kubectl lookup is LRU-cached (ransomware fires hundreds of eBPF
events/sec for the same pod; uncached this would saturate the API server).
"""

import os
import re
import subprocess
from functools import lru_cache
from typing import Optional, Tuple

PROC_ROOT = os.environ.get("PROC_ROOT", "/proc")

_V1 = re.compile(r"/kubepods(?:/[^/]+)?/pod([a-f0-9-]+)/([a-f0-9]+)")
# cgroups v2: ...pod<uid>.slice/<runtime-prefix-><container_hex>.scope
_V2 = re.compile(r"kubepods[^/]*/[^/]*pod([a-f0-9_-]+)\.slice/[^/]*?([a-f0-9]{12,})\.scope")


def get_pod_for_pid(pid: int) -> Optional[Tuple[str, str, str]]:
    """Return (namespace, pod_name, container_name) or None."""
    cgroup_path = f"{PROC_ROOT}/{pid}/cgroup"
    if not os.path.exists(cgroup_path):
        return None
    try:
        with open(cgroup_path) as f:
            lines = f.readlines()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return None

    pod_uid = container_id = None
    for line in lines:
        line = line.strip()
        m = _V1.search(line)
        if m:
            pod_uid, container_id = m.group(1), m.group(2)[:12]
            break
        m = _V2.search(line)
        if m:
            # cgroups v2 encodes pod uid with underscores: pod<uid>.slice
            pod_uid = m.group(1).replace("_", "-")
            container_id = m.group(2)[:12]
            break

    if not pod_uid:
        return None
    return _kubectl_lookup_pod(pod_uid, container_id)


@lru_cache(maxsize=1000)
def _kubectl_lookup_pod(pod_uid: str, container_id: str) -> Optional[Tuple[str, str, str]]:
    """Cached pod_uid → (namespace, pod, container). Runtime-agnostic via kubectl."""
    try:
        jsonpath = (
            "{range .items[*]}{.metadata.namespace},{.metadata.name},"
            "{.spec.containers[0].name},{.metadata.uid}{\"\\n\"}{end}"
        )
        result = subprocess.run(
            ["kubectl", "get", "pod", "--all-namespaces", "-o", f"jsonpath={jsonpath}"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split(",")
            if len(parts) == 4 and parts[3] == pod_uid:
                return (parts[0], parts[1], parts[2])
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return None


def parse_cgroup_line(line: str) -> Optional[Tuple[str, str]]:
    """Exposed for unit tests: parse a single cgroup line → (pod_uid, container_id)."""
    line = line.strip()
    m = _V1.search(line)
    if m:
        return m.group(1), m.group(2)[:12]
    m = _V2.search(line)
    if m:
        return m.group(1).replace("_", "-"), m.group(2)[:12]
    return None
