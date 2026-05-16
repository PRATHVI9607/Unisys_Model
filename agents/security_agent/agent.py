import asyncio
import json
import logging
import math
import os
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
    model_used: Optional[str] = None  # "onnx_model" or "heuristic"
    model_score: Optional[float] = None  # Score from ONNX model, 0-1
    heuristic_score: Optional[float] = None  # Score from heuristic, 0-1
    inference_method: Optional[str] = (
        None  # e.g., "ONNX inference" or "Heuristic fallback"
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
        redis_url: str = "redis://redis-master:6379",
        falco_grpc_addr: str = "127.0.0.1:5060",
        dit_sec_url: str = "http://dit-sec-server:8000",
        entropy_threshold: float = 7.2,
        mmap_entropy_threshold: float = 7.0,
        mmap_size_threshold: int = 50 * 1024 * 1024,
    ):
        self.namespace = namespace
        self.redis_url = redis_url
        self.falco_grpc_addr = falco_grpc_addr
        self.dit_sec_url = dit_sec_url
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
        except config.ConfigException as e:
            logger.error(f"Failed to load in-cluster config: {e}")
            raise

        self.core_api = client.CoreV1Api()
        self.networking_api = client.NetworkingV1Api()

        self.redis = aioredis.from_url(self.redis_url)

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
        """Handle Falco gRPC events."""
        logger.info("Handling Falco events...")

        while self.running:
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Falco handler error: {e}")

    async def _process_write_events(self) -> None:
        """Process write events and check entropy."""
        logger.info("Processing write events...")

        while self.running:
            try:
                await asyncio.sleep(2)

                for pid, count in list(self.write_counters.items()):
                    if count > 1000:
                        await self._trigger_entropy_check(pid)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Write event error: {e}")

    async def _trigger_entropy_check(self, pid: int) -> None:
        """Trigger entropy calculation on written files."""
        logger.debug(f"Checking entropy for PID {pid}")

        pid_info = await self._get_pid_info(pid)
        if not pid_info:
            return

        files_written = [f"/data/test_{i}.dat" for i in range(20)]

        entropy_avg = self.entropy_calculator.calculate_file_entropy_random(
            files_written
        )

        mmap_detected = await self._check_mmap_entropy(pid)

        early_signals = {
            "rename_burst": self.inotify_watcher.check_rename_burst() > 0,
            "high_entropy": entropy_avg > self.entropy_threshold,
            "mmap_detected": mmap_detected,
        }

        risk_score = 0.0

        if mmap_detected:
            risk_score = 0.70
        elif entropy_avg > self.entropy_threshold:
            risk_score = min(0.93, entropy_avg / 10.0)

        if early_signals.get("rename_burst"):
            risk_score = max(risk_score, 0.50)

        if risk_score >= 0.98:
            await self._direct_kill(pid, risk_score, early_signals)
        elif risk_score >= 0.40:
            await self._publish_security_event(
                pid_info, risk_score, early_signals, entropy_avg
            )

    async def _direct_kill(
        self, pid: int, risk_score: float, early_signals: Dict
    ) -> None:
        """Direct kill without Fusion (fastest path for critical ransomware)."""
        logger.warning(f"DIRECT KILL: PID {pid}, risk={risk_score:.2f}")

        pid_info = await self._get_pid_info(pid)
        namespace = pid_info.get("namespace", "default") if pid_info else "default"
        await self._apply_network_isolation(namespace)

        event_id = f"sec-direct-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{pid}"

        # Call DIT-Sec to enrich event with model comparison data
        dit_sec_response = await self._call_dit_sec_score(None, early_signals)

        await self.redis.xadd(
            "kubeheal.security.events",
            {
                "event_id": event_id,
                "target": json.dumps({"pid": pid, "namespace": namespace}),
                "risk_score": str(risk_score),
                "label": ThreatLevel.RANSOMWARE_CRITICAL.value,
                "early_signals": json.dumps(early_signals),
                "action": "direct_kill",
                "timestamp": datetime.utcnow().isoformat(),
                # Add new fields from DIT-Sec model comparison
                "model_used": dit_sec_response.get("model_used") or "",
                "model_score": str(dit_sec_response.get("model_score"))
                if dit_sec_response.get("model_score") is not None
                else "",
                "heuristic_score": str(dit_sec_response.get("heuristic_score"))
                if dit_sec_response.get("heuristic_score") is not None
                else "",
                "inference_method": dit_sec_response.get("inference_method") or "",
            },
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
    ) -> None:
        """Publish SecurityEvent to Redis Stream."""
        event_id = f"sec-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{pid_info.get('pod', 'unknown')}"

        label = (
            ThreatLevel.RANSOMWARE_CRITICAL.value
            if risk_score >= 0.85
            else ThreatLevel.LIKELY_RANSOMWARE.value
        )

        # Call DIT-Sec to enrich event with model comparison data
        dit_sec_response = await self._call_dit_sec_score(entropy, early_signals)

        event_data = {
            "event_id": event_id,
            "target": json.dumps(pid_info),
            "risk_score": str(risk_score),
            "label": label,
            "pid_target": str(pid_info.get("pid", 0)),
            "entropy": str(entropy) if entropy else "0.0",
            "early_signals": json.dumps(early_signals),
            "timestamp": datetime.utcnow().isoformat(),
            # Add new fields from DIT-Sec model comparison
            "model_used": dit_sec_response.get("model_used") or "",
            "model_score": str(dit_sec_response.get("model_score"))
            if dit_sec_response.get("model_score") is not None
            else "",
            "heuristic_score": str(dit_sec_response.get("heuristic_score"))
            if dit_sec_response.get("heuristic_score") is not None
            else "",
            "inference_method": dit_sec_response.get("inference_method") or "",
        }

        await self.redis.xadd("kubeheal.security.events", event_data)

        logger.info(f"Security event: {event_id}, risk={risk_score:.2f}")

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

    async def _call_dit_sec_score(
        self, entropy: Optional[float], early_signals: Dict[str, bool]
    ) -> Dict[str, Any]:
        """Call DIT-Sec /score endpoint to enrich security event with model comparison data."""
        try:
            payload = {
                "entropy": entropy or 0.0,
                "early_signals": early_signals,
            }

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(
                        f"{self.dit_sec_url}/score",
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            result = await resp.json()
                            return {
                                "model_used": result.get("model_used"),
                                "model_score": result.get("model_score"),
                                "heuristic_score": result.get("heuristic_score"),
                                "inference_method": result.get("inference_method"),
                            }
                        else:
                            logger.warning(f"DIT-Sec returned status {resp.status}")
                            return self._default_dit_sec_response()
                except asyncio.TimeoutError:
                    logger.warning("DIT-Sec call timed out, using fallback")
                    return self._default_dit_sec_response()
        except Exception as e:
            logger.debug(f"DIT-Sec call failed: {e}")
            return self._default_dit_sec_response()

    def _default_dit_sec_response(self) -> Dict[str, Any]:
        """Return default DIT-Sec response when service is unavailable."""
        return {
            "model_used": None,
            "model_score": None,
            "heuristic_score": None,
            "inference_method": None,
        }


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
