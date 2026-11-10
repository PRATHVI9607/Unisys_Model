import asyncio
import base64
import json
import logging
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
from agents.security_agent.proc_scanner import PodIndex, scan_pids
from agents.security_agent.entropy_sampler import EntropySampler, EntropyResult, shannon_entropy
from agents.security_agent.falco_client import (
    falco_event_stream, replay_stream, resolve_falco_mode,
)
from agents.security_agent.syscall_window import (
    FalcoWindowTracker, build_model_input, DEFAULT_BURST_THRESHOLD, DEFAULT_COOLDOWN_S,
)
from pydantic import BaseModel, ConfigDict, Field

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


class ThreatLevel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_RANSOMWARE = "likely_ransomware"
    RANSOMWARE_CRITICAL = "ransomware-critical"


class SecurityEvent(BaseModel):
    model_config = ConfigDict(protected_namespaces=())  # allow model_* fields
    event_id: str
    target: Dict[str, str]
    risk_score: float = Field(ge=0.0, le=1.0)
    label: ThreatLevel
    pid_target: Optional[int] = None
    entropy: Optional[float] = None
    early_signals: Optional[Dict[str, bool]] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    # Fields from the Security Model server's score response
    model_used: Optional[str] = None  # "pytorch" or "heuristic"
    model_score: Optional[float] = None  # model risk score, 0-1
    heuristic_score: Optional[float] = None  # Score from heuristic, 0-1
    inference_method: Optional[str] = (
        None  # e.g., "health_model_v4"/"security_model_v4" or "heuristic"
    )


class EntropyCalculator:
    """Shannon entropy of a byte string. File sampling lives in entropy_sampler.EntropySampler
    (data actually written by the suspect process); this class no longer reads any fixed paths."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        return shannon_entropy(data)


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

    def check_rename_burst(self, events: Optional[List[Dict]] = None) -> float:
        """Check for rename burst pattern in `events` (default: the last recorded window)."""
        window = self.recent_events if events is None else events
        rename_count = sum(
            1 for e in window if e.get("syscall", "").startswith("rename")
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
        security_model_url: str = None,
        entropy_threshold: float = 7.2,
        mmap_entropy_threshold: float = 7.0,
        mmap_size_threshold: int = 50 * 1024 * 1024,
        sampler: Optional[EntropySampler] = None,
    ):
        self.namespace       = namespace
        self.redis_url       = redis_url       or os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.falco_grpc_addr = falco_grpc_addr or os.environ.get("FALCO_GRPC_ADDR", "127.0.0.1:5060")
        # v4: dedicated Security Model server (was the v3 DIT-Sec monolith)
        self.security_model_url = security_model_url or os.environ.get(
            "SECURITY_MODEL_URL", "http://kubeheal-security-model:8002"
        )
        self.entropy_threshold = entropy_threshold
        self.mmap_entropy_threshold = mmap_entropy_threshold
        self.mmap_size_threshold = mmap_size_threshold

        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None

        self.running = False

        self.pod_index = PodIndex()
        self.apps_api: Optional[client.AppsV1Api] = None
        self.inotify_watcher = InotifyWatcher()

        self.entropy_calculator = EntropyCalculator()
        # Real write-entropy sampler (30 samples, 2 s apart, bounded reads); injectable for tests.
        self.sampler = sampler or EntropySampler()
        self.falco_mode = "off"
        self._checks: Dict[int, "asyncio.Task"] = {}   # pid -> running entropy check

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
        self.apps_api = client.AppsV1Api()

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
        for t in list(self._checks.values()):
            t.cancel()

        if self.redis:
            await self.redis.aclose()

        logger.info("Security Agent stopped")

    async def _scan_pids_periodic(self) -> None:
        """Scan /proc for PID → pod mapping every 5s."""
        while self.running:
            try:
                try:
                    await self.pod_index.refresh(self.core_api, self.apps_api)
                except Exception as e:
                    logger.warning(f"pod index refresh failed, using stale index: {e}")
                pid_map = scan_pids(self.pod_index)

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
        """Consume Falco syscall events and keep a rolling syscall window per PID. The source is chosen
        by falco_client.resolve_falco_mode: live Falco (gRPC Outputs API or JSON tail) when it is
        available, REPLAY of recorded Falco JSON traces (FALCO_REPLAY_PATH) when it is not, or off (the
        /proc write tracker alone). Live and replay events go through the same ingest path."""
        mode, reason = resolve_falco_mode()
        self.falco_mode = mode
        logger.info("Falco input mode: %s (%s)", mode, reason)
        if mode == "off":
            return
        tracker = FalcoWindowTracker(
            burst_threshold=int(os.environ.get("FALCO_BURST_THRESHOLD", str(DEFAULT_BURST_THRESHOLD))),
            cooldown_s=float(os.environ.get("FALCO_TRIGGER_COOLDOWN_S", str(DEFAULT_COOLDOWN_S))),
        )
        if mode == "replay":
            path = os.environ["FALCO_REPLAY_PATH"]
            delay = float(os.environ.get("FALCO_REPLAY_DELAY_S", "0"))
            n = await self._consume_falco(replay_stream(path, delay), tracker, "replay")
            logger.info("Falco replay of %s finished: %d event(s)", path, n)
            return
        logger.info("Falco event consumer started")
        while self.running:
            try:
                await self._consume_falco(falco_event_stream(self.falco_grpc_addr), tracker, "falco")
                await asyncio.sleep(3)          # stream ended normally: do not spin
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Falco consumer error: {e}; retry in 3s")
                await asyncio.sleep(3)

    async def _consume_falco(self, stream, tracker: FalcoWindowTracker, source: str) -> int:
        n = 0
        async for evt in stream:
            if not self.running:
                break
            n += 1
            await self._ingest_falco_event(evt, tracker, source)
        return n

    async def _ingest_falco_event(self, evt: Dict, tracker: FalcoWindowTracker, source: str) -> None:
        """One normalised Falco event (live or replayed): record PID to pod from Falco's k8s fields, update
        the window, and start an entropy check on a burst or a Falco ransomware rule."""
        pid = evt.get("pid")
        if pid and evt.get("pod"):
            await self.redis.setex(
                f"kubeheal:pid:{pid}", 300,
                json.dumps({"pid": pid, "pod": evt["pod"],
                            "namespace": evt.get("namespace", "default")}),
            )
        trigger = tracker.add(evt)
        if trigger:
            self.inotify_watcher.recent_events = trigger.events
            await self._trigger_entropy_check(trigger.pid, trigger.events, source)

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

    async def _trigger_entropy_check(self, pid: int, syscall_events: Optional[List[Dict]] = None,
                                     syscall_source: str = "none") -> None:
        """Start an entropy check for `pid` in the background (one at a time per PID: a full run takes
        samples x interval, 60 s with the defaults, and must not block the detectors that call this).

        `syscall_events` is the real syscall window (from Falco live or replay) when there is one;
        `syscall_source` says where it came from ("falco", "replay") or "none"."""
        running = self._checks.get(pid)
        if running is not None and not running.done():
            return
        task = asyncio.create_task(self._run_entropy_check(pid, list(syscall_events or []), syscall_source))

        def _done(t, pid=pid):
            if self._checks.get(pid) is t:
                self._checks.pop(pid, None)
            if not t.cancelled() and t.exception():
                logger.error(f"Entropy check for PID {pid} failed: {t.exception()}")
        task.add_done_callback(_done)
        self._checks[pid] = task

    async def _run_entropy_check(self, pid: int, events: List[Dict], source: str) -> None:
        """Sample the entropy of what `pid` writes, assess, publish. An initial assessment is published after
        the first sample (so detection does not wait for the whole window), a final one when the series is
        complete. Both carry entropy_phase and entropy_valid_samples."""
        logger.info(f"Entropy check for PID {pid} (syscalls from: {source})")
        pid_info = await self._get_pid_info(pid)
        if not pid_info:
            return
        mmap_detected = await self._check_mmap_entropy(pid)

        async def first_sample(result: EntropyResult, i: int) -> None:
            if i == 0 and self.sampler.config.samples > 1:
                await self._assess_and_publish(pid, pid_info, result, events, source,
                                               mmap_detected, "initial")

        result = await self.sampler.collect(pid, on_sample=first_sample)
        await self._assess_and_publish(pid, pid_info, result, events, source, mmap_detected, "complete")

    async def _assess_and_publish(self, pid: int, pid_info: Dict, result: EntropyResult,
                                  events: List[Dict], source: str, mmap_detected: bool,
                                  phase: str) -> None:
        entropy_avg = result.mean                      # None when no sample had readable data
        entropy_known = entropy_avg is not None
        rename_score = self.inotify_watcher.check_rename_burst(events)
        early_signals = {
            "rename_burst":      rename_score > 0,
            "ftruncate_pattern": False,
            "high_entropy":      entropy_known and entropy_avg > self.entropy_threshold,
            "mmap_detected":     mmap_detected,
        }

        # The Security Model needs a real syscall window. Without one (no Falco, no replay) the model is not
        # called and nothing is fabricated: the event is scored from the entropy and /proc heuristics only
        # and says so (model_scored=false, syscall_source=none).
        sec = None
        if events:
            sec = await self._call_security_model(events, result.model_series(), early_signals)
        model_risk = float(sec["risk_score"]) if sec else None

        # Heuristic baseline (floor, clear ransomware signatures)
        heuristic_risk = 0.0
        if mmap_detected:
            heuristic_risk = 0.85
        elif entropy_known and entropy_avg > self.entropy_threshold:
            heuristic_risk = min(0.95, entropy_avg / 8.0)
        if early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.60)
        if early_signals["high_entropy"] and early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.95)

        risk_score = max(model_risk or 0.0, heuristic_risk)
        logger.info(f"PID {pid} [{phase}] entropy="
                    f"{'n/a' if not entropy_known else format(entropy_avg, '.2f')} "
                    f"valid_samples={result.valid_samples} risk={risk_score:.3f}")

        # The Security Agent only senses and reports (S-SA-5). Containment is decided by the
        # Fusion Agent and executed by the Executor.
        if risk_score >= 0.40:
            await self._publish_security_event(
                pid_info, risk_score, early_signals, entropy_avg, sec,
                extra={
                    "entropy_phase": phase,
                    "entropy_valid_samples": str(result.valid_samples),
                    "entropy_files_json": json.dumps(result.files),
                    "syscall_source": source if events else "none",
                    "model_scored": "true" if sec else "false",
                },
            )

    async def _publish_security_event(
        self,
        pid_info: Dict,
        risk_score: float,
        early_signals: Dict,
        entropy: Optional[float] = None,
        sec: Optional[Dict] = None,
        label: Optional[str] = None,
        action: str = "observe",
        extra: Optional[Dict[str, str]] = None,
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
            "deployment": pid_info.get("workload") or pod,
            "workload_kind": pid_info.get("workload_kind", "Pod"),
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
            # empty (not 0.0) when no sample of written data could be read
            "entropy": f"{float(entropy):.4f}" if entropy is not None else "",
            "action": action,
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
        }
        payload.update(extra or {})
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
        payload = build_model_input(events or [], entropy_series or [], early_signals or {})
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
