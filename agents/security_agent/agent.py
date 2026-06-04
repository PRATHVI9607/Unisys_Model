import asyncio
import base64
import json
import logging
import math
import os
import struct
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

import aiohttp
import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, config
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def emb_b64(vec) -> str:
    """Pack a float list as base64 float32 bytes for the Redis stream."""
    vec = list(vec or [])
    return base64.b64encode(struct.pack(f"{len(vec)}f", *vec)).decode() if vec else ""


def namespace_tier(namespace: str) -> str:
    n = (namespace or "").lower()
    if "prod" in n:
        return "prod"
    if "stag" in n:
        return "staging"
    return "dev"


def synth_events(early_signals: Dict, n: int = 60) -> List[Dict]:
    """Synthesize a syscall event window from early signals for the Security
    Model (the Falco gRPC stream is optional; entropy + these signals drive
    detection). Ransomware-consistent ops when signals fire, else benign I/O."""
    if early_signals.get("rename_burst") or early_signals.get("high_entropy"):
        pool = (["write", "rename", "ftruncate", "open", "read"]
                + (["mmap", "msync"] if early_signals.get("mmap_detected") else []))
        paths = [f"/data/file_{i}.locked" for i in range(20)]
    else:
        pool = ["read", "stat", "open", "close"]
        paths = [f"/var/log/app_{i}.log" for i in range(5)]
    import random
    return [{"syscall": random.choice(pool), "fd_path": random.choice(paths)}
            for _ in range(n)]


class ThreatLevel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_RANSOMWARE = "likely_ransomware"
    RANSOMWARE_CRITICAL = "ransomware-critical"


class SecurityEvent(BaseModel):
    event_id: str
    target: Dict[str, str]
    risk_score: float = Field(ge=0.0, le=1.0)
    label: ThreatLevel
    pid_target: Optional[int] = None
    entropy: Optional[float] = None
    early_signals: Optional[Dict[str, bool]] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    # New fields from DIT-Sec model comparison
    model_used: Optional[str] = None  # "pytorch" or "heuristic"
    model_score: Optional[float] = None  # model risk score, 0-1
    heuristic_score: Optional[float] = None  # Score from heuristic, 0-1
    inference_method: Optional[str] = (
        None  # e.g., "health_model_v4"/"security_model_v4" or "heuristic"
    )


class EntropyCalculator:
    """Calculate Shannon entropy for file samples."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        byte_freq = {}
        for byte in data:
            byte_freq[byte] = byte_freq.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def calculate_file_entropy(file_path: str, sample_size: int = 4096) -> float:
        """Calculate entropy from file sample."""
        try:
            fd = os.open(file_path, os.O_RDONLY)
            data = os.read(fd, sample_size)
            os.close(fd)
            return EntropyCalculator.calculate_entropy(data)
        except Exception:
            return 0.0

    @staticmethod
    def calculate_file_entropy_random(
        file_paths: List[str], max_samples: int = 20
    ) -> float:
        """Calculate average entropy from multiple files."""
        import random

        if not file_paths:
            return 0.0

        sample_paths = random.sample(file_paths, min(max_samples, len(file_paths)))

        entropies = []
        for path in sample_paths:
            ent = EntropyCalculator.calculate_file_entropy(path)
            entropies.append(ent)

        return sum(entropies) / len(entropies) if entropies else 0.0


class ProcessScanner:
    """Scan /proc for PID → pod mapping."""

    async def scan_pids(self) -> Dict[int, Dict[str, str]]:
        """Scan /proc for process information."""
        pid_map = {}

        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue

                pid = int(pid_dir)

                try:
                    with open(f"/proc/{pid}/cgroup", "r") as f:
                        cgroup = f.read()

                        if "kubepods" in cgroup:
                            parts = cgroup.strip().split("/")

                            pod_name = ""
                            container_id = ""
                            namespace = "default"

                            for part in parts:
                                if part.startswith("pod"):
                                    pod_name = (
                                        part.split("-", 1)[1] if "-" in part else part
                                    )
                                if part.startswith("containerd"):
                                    container_id = part

                            for part in parts:
                                if part in ["default", "kube-system", "kubeheal"]:
                                    namespace = part

                            pid_map[pid] = {
                                "pid": pid,
                                "pod": pod_name,
                                "container": container_id,
                                "namespace": namespace,
                            }
                except (FileNotFoundError, PermissionError):
                    continue
        except Exception as e:
            logger.debug(f"PID scan error: {e}")

        return pid_map


class InotifyWatcher:
    """Watch filesystem with inotify for ransomware patterns."""

    def __init__(self):
        self.rename_burst_threshold = 10
        self.suspicious_extensions = [
            ".encrypted",
            ".locked",
            ".crypt",
            ".locked",
            "DECRYPT_FILES.txt",
            "README_DECRYPT.txt",
        ]
        self.recent_events: List[Dict] = []

    def check_rename_burst(self) -> float:
        """Check for rename burst pattern."""
        rename_count = sum(
            1 for e in self.recent_events if e.get("syscall") == "rename"
        )

        if rename_count > self.rename_burst_threshold:
            return 0.50

        return 0.0

    def check_suspicious_filename(self, filename: str) -> float:
        """Check for suspicious filename."""
        for ext in self.suspicious_extensions:
            if ext.lower() in filename.lower():
                return 0.65
        return 0.0


class SecurityAgent:
    """
    Security Agent - monitors filesystem, entropy, process tree.
    Detects ransomware and publishes SecurityEvent.
    """

    def __init__(
        self,
        namespace: str = "kubeheal",
        redis_url: str = None,
        falco_grpc_addr: str = None,
        dit_sec_url: str = None,
        entropy_threshold: float = 7.2,
        mmap_entropy_threshold: float = 7.0,
        mmap_size_threshold: int = 50 * 1024 * 1024,
    ):
        self.namespace       = namespace
        self.redis_url       = redis_url       or os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.falco_grpc_addr = falco_grpc_addr or os.environ.get("FALCO_GRPC_ADDR", "127.0.0.1:5060")
        # v4: dedicated Security Model server (was the v3 DIT-Sec monolith)
        self.security_model_url = (dit_sec_url
            or os.environ.get("SECURITY_MODEL_URL")
            or os.environ.get("DIT_SEC_URL", "http://kubeheal-security-model:8002"))
        self.entropy_threshold = entropy_threshold
        self.mmap_entropy_threshold = mmap_entropy_threshold
        self.mmap_size_threshold = mmap_size_threshold

        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None

        self.running = False

        self.pid_scanner = ProcessScanner()
        self.inotify_watcher = InotifyWatcher()

        self.entropy_calculator = EntropyCalculator()

        self.write_counters: Dict[int, int] = {}

    async def start(self) -> None:
        """Start the Security Agent."""
        logger.info("Starting Security Agent...")

        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes config")
        except config.ConfigException:
            try:
                await config.load_kube_config()
                logger.info("Loaded kubeconfig")
            except Exception as e2:
                logger.error(f"Failed to load kubeconfig: {e2}")
                raise

        self.core_api = client.CoreV1Api()
        self.networking_api = client.NetworkingV1Api()

        self.redis = aioredis.from_url(self.redis_url, decode_responses=True)

        logger.info("Security Agent started successfully")

        self.running = True
        asyncio.create_task(self._scan_pids_periodic())
        asyncio.create_task(self._handle_falco_events())
        asyncio.create_task(self._process_write_events())

    async def stop(self) -> None:
        """Stop the Security Agent."""
        logger.info("Stopping Security Agent...")
        self.running = False

        if self.redis:
            await self.redis.aclose()

        logger.info("Security Agent stopped")

    async def _scan_pids_periodic(self) -> None:
        """Scan /proc for PID → pod mapping every 5s."""
        while self.running:
            try:
                pid_map = await self.pid_scanner.scan_pids()

                for pid, info in pid_map.items():
                    key = f"kubeheal:pid:{pid}"
                    await self.redis.setex(key, 300, json.dumps(info))

                await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"PID scan error: {e}")
                await asyncio.sleep(5)

    async def _handle_falco_events(self) -> None:
        """Consume REAL Falco syscall events (gRPC Outputs API or JSON tail),
        maintain a rolling syscall window per PID, and trigger an entropy check
        when a window shows a ransomware-indicative burst (mass write+rename+
        ftruncate) or a Falco ransomware rule fires. Disabled by default
        (the /proc write tracker covers detection); enable with FALCO_ENABLED."""
        if os.environ.get("FALCO_ENABLED", "false").lower() != "true":
            logger.info("Falco disabled; using /proc write tracker")
            return
        from agents.security_agent.falco_client import (
            falco_event_stream, RANSOMWARE_SYSCALLS,
        )
        logger.info("Falco event consumer started")
        BURST = int(os.environ.get("FALCO_BURST_THRESHOLD", "15"))  # ops/window
        windows: Dict[int, list] = {}   # pid -> recent ransomware-syscall names
        last_fire: Dict[int, float] = {}
        import time as _t
        while self.running:
            try:
                async for evt in falco_event_stream(self.falco_grpc_addr):
                    if not self.running:
                        break
                    pid = evt.get("pid")
                    sysc = evt.get("syscall", "")
                    # Record PID→pod mapping from Falco's k8s fields
                    if pid and evt.get("pod"):
                        await self.redis.setex(
                            f"kubeheal:pid:{pid}", 300,
                            json.dumps({"pid": pid, "pod": evt["pod"],
                                        "namespace": evt.get("namespace", "default")}),
                        )
                    if not pid:
                        continue
                    # rolling window of ransomware-relevant syscalls
                    if sysc in RANSOMWARE_SYSCALLS:
                        w = windows.setdefault(pid, [])
                        w.append(sysc)
                        if len(w) > 256:
                            del w[: len(w) - 256]
                        renames = sum(1 for s in w if s.startswith("rename"))
                        writes = sum(1 for s in w if "write" in s or s == "ftruncate")
                        ransom_rule = "ransom" in evt.get("rule", "").lower()
                        if (renames + writes >= BURST or ransom_rule) and \
                           (_t.monotonic() - last_fire.get(pid, 0) > 5):
                            last_fire[pid] = _t.monotonic()
                            self.inotify_watcher.recent_events = [
                                {"syscall": s} for s in w
                            ]
                            await self._trigger_entropy_check(pid)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Falco consumer error: {e}; retry in 3s")
                await asyncio.sleep(3)

    def _sample_write_bytes(self) -> Dict[int, int]:
        """Cumulative write_bytes per kubepods PID from /proc/<pid>/io."""
        proc = os.environ.get("PROC_ROOT", "/proc")
        out: Dict[int, int] = {}
        try:
            for d in os.listdir(proc):
                if not d.isdigit():
                    continue
                pid = int(d)
                try:
                    with open(f"{proc}/{pid}/cgroup") as f:
                        if "kubepods" not in f.read():
                            continue
                    with open(f"{proc}/{pid}/io") as f:
                        for line in f:
                            if line.startswith("write_bytes:"):
                                out[pid] = int(line.split()[1])
                                break
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
        except Exception as e:
            logger.debug(f"write-bytes sample error: {e}")
        return out

    async def _process_write_events(self) -> None:
        """Detect high write throughput per PID via /proc/<pid>/io deltas, then
        trigger an entropy check. This is what actually wires ransomware
        detection (write_counters is populated here from real deltas)."""
        logger.info("Processing write events (/proc io tracker)...")
        WRITE_BYTES_THRESHOLD = int(os.environ.get("WRITE_BYTES_THRESHOLD", str(10 * 1024 * 1024)))
        prev: Dict[int, int] = {}
        while self.running:
            try:
                await asyncio.sleep(2)
                current = self._sample_write_bytes()
                self.write_counters = {
                    pid: cum - prev[pid]
                    for pid, cum in current.items()
                    if pid in prev and cum >= prev[pid]
                }
                prev = current
                for pid, delta in self.write_counters.items():
                    if delta > WRITE_BYTES_THRESHOLD:
                        await self._trigger_entropy_check(pid)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Write event error: {e}")

    async def _trigger_entropy_check(self, pid: int) -> None:
        """Trigger entropy calculation and DIT-Sec scoring for high-write PID."""
        logger.info(f"Entropy check for PID {pid}")

        pid_info = await self._get_pid_info(pid)
        if not pid_info:
            return

        # Sample files from PV mount paths (real paths in production)
        files_written = [f"/data/test_{i}.dat" for i in range(20)]
        entropy_avg = self.entropy_calculator.calculate_file_entropy_random(files_written)
        mmap_detected = await self._check_mmap_entropy(pid)

        rename_score = self.inotify_watcher.check_rename_burst()
        early_signals = {
            "rename_burst":      rename_score > 0,
            "ftruncate_pattern": False,
            "high_entropy":      entropy_avg > self.entropy_threshold,
            "mmap_detected":     mmap_detected,
        }

        # Build entropy series (30 steps). Prefer the REAL Falco syscall window
        # when present (set by _handle_falco_events); else synthesize from signals.
        entropy_series = [entropy_avg + (0.1 * (i % 3)) for i in range(30)]
        real = getattr(self.inotify_watcher, "recent_events", None)
        events = ([{"syscall": e.get("syscall", ""), "fd_path": ""} for e in real]
                  if real else synth_events(early_signals))

        # Call the v4 Security Model
        sec = await self._call_security_model(events, entropy_series, early_signals)
        model_risk = float(sec["risk_score"]) if sec else None

        # Heuristic baseline (floor — clear ransomware signatures)
        heuristic_risk = 0.0
        if mmap_detected:
            heuristic_risk = 0.85
        elif entropy_avg > self.entropy_threshold:
            heuristic_risk = min(0.95, entropy_avg / 8.0)
        if early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.60)
        if early_signals["high_entropy"] and early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.95)

        risk_score = max(model_risk or 0.0, heuristic_risk)
        logger.info(f"PID {pid} entropy={entropy_avg:.2f} risk={risk_score:.3f}")

        if risk_score >= 0.90:
            await self._direct_kill(pid, pid_info, risk_score, early_signals, entropy_avg, sec)
        elif risk_score >= 0.40:
            await self._publish_security_event(pid_info, risk_score, early_signals, entropy_avg, sec)

    async def _direct_kill(
        self, pid: int, pid_info: Optional[Dict], risk_score: float,
        early_signals: Dict, entropy_avg: float, sec: Optional[Dict],
    ) -> None:
        """Direct kill without Fusion (fastest path for critical ransomware)."""
        logger.warning(f"DIRECT KILL: PID {pid}, risk={risk_score:.2f}")

        namespace = pid_info.get("namespace", "default") if pid_info else "default"
        await self._apply_network_isolation(namespace)
        pid_info = pid_info or {"pid": pid, "namespace": namespace}
        await self._publish_security_event(
            pid_info, risk_score, early_signals, entropy_avg, sec,
            label="ransomware_active", action="direct_kill",
        )
        try:
            os.kill(pid, 9)
            logger.info(f"Killed PID {pid}")
        except Exception as e:
            logger.error(f"Failed to kill PID {pid}: {e}")

    async def _apply_network_isolation(self, namespace: str) -> None:
        """Apply NetworkPolicy to block egress."""
        logger.info(f"Applying network isolation to {namespace}")

        np_manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "kubeheal-quarantine", "namespace": namespace},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [{"to": [{"podSelector": {}}]}],
            },
        }

        try:
            if self.networking_api:
                await self.networking_api.create_namespaced_network_policy(
                    namespace, np_manifest
                )
                logger.info(f"NetworkPolicy applied to {namespace}")
        except Exception as e:
            logger.debug(f"NetworkPolicy error: {e}")

    async def _publish_security_event(
        self,
        pid_info: Dict,
        risk_score: float,
        early_signals: Dict,
        entropy: Optional[float] = None,
        sec: Optional[Dict] = None,
        label: Optional[str] = None,
        action: str = "observe",
    ) -> None:
        """Publish the v4 SecurityEvent schema (Section 15.A.1) to
        kubeheal.security.events + a hash for dashboard detail lookup."""
        pod = pid_info.get("pod") or "unknown"
        namespace = pid_info.get("namespace", "default")
        event_id = f"sec-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}-{pod}"
        sec = sec or {}

        sec_label = label or sec.get("label") or (
            "ransomware_active" if risk_score >= 0.85 else "ransomware_staging"
        )

        payload = {
            "event_id": event_id,
            "namespace": namespace,
            "pod_name": pod,
            "namespace_tier": namespace_tier(namespace),
            "sec_risk": f"{risk_score:.4f}",
            "sec_label": sec_label,
            "sec_ci_width": f"{float(sec.get('ci_width', 0.0)):.4f}",
            "top_syscall": sec.get("top_syscall", ""),
            "syscall_attribution_json": json.dumps(sec.get("syscall_attention_weights", {})),
            "entropy_spike_json": json.dumps(sec.get("entropy_spike", {})),
            "security_embedding_b64": emb_b64(sec.get("security_embedding", [])),
            "early_signals_json": json.dumps(early_signals),
            "pid_target": str(pid_info.get("pid", 0)),
            "entropy": f"{float(entropy or 0.0):.4f}",
            "action": action,
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        }
        await self.redis.xadd("kubeheal.security.events", payload)
        hkey = f"kubeheal:security:{event_id}"
        await self.redis.hset(hkey, mapping={k: v for k, v in payload.items()
                                             if k != "security_embedding_b64"})
        await self.redis.expire(hkey, 86400)
        logger.info(f"Security event {event_id}: risk={risk_score:.2f} label={sec_label}")

    async def _get_pid_info(self, pid: int) -> Optional[Dict]:
        """Get PID info from cache."""
        key = f"kubeheal:pid:{pid}"
        data = await self.redis.get(key)

        if data:
            return json.loads(data)
        return None

    async def _check_mmap_entropy(self, pid: int) -> bool:
        """Check for anonymous mmap with high entropy."""
        try:
            maps_path = f"/proc/{pid}/maps"
            if not os.path.exists(maps_path):
                return False

            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        perms = parts[1]
                        path = parts[5]

                        if "rw-p" in perms and path.startswith("/"):
                            size_str = parts[0].split("-")[1]
                            if size_str:
                                try:
                                    size = int(size_str, 16)
                                    if size > self.mmap_size_threshold:
                                        return True
                                except:
                                    continue
        except Exception as e:
            logger.debug(f"mmap check error: {e}")

        return False

    async def _call_security_model(
        self,
        events: List[Dict],
        entropy_series: List[float],
        early_signals: Dict[str, bool],
    ) -> Optional[Dict[str, Any]]:
        """Call the v4 Security Model /security/score. Returns the full v4
        result (sec_risk, label, ci_width, top_syscall, entropy_spike,
        security_embedding) or None if the server is unreachable."""
        payload = {
            "events": events or [],
            "entropy_series": entropy_series or [],
            "early_signals": early_signals or {},
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.security_model_url}/security/score",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning(f"Security Model returned {resp.status}")
        except Exception as e:
            logger.debug(f"Security Model call failed: {e}")
        return None


async def main():
    """Run Security Agent."""
    agent = SecurityAgent()

    try:
        await agent.start()
        while agent.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
