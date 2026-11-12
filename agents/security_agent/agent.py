import asyncio
import json
import logging
import math
import os
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Any, Tuple
from enum import Enum

import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, config
from agents.common.metrics import KubeHealMetrics
from agents.common.tiers import namespace_tier as _namespace_tier
from agents.common.sampling import sampling_factor, scaled_interval
from agents.security_agent.containment import ContainmentService
from agents.security_agent.counters import CounterSamples, read_pod_counters
from agents.security_agent.inference import InferenceClient
from agents.security_agent.proc_scanner import PodIndex, process_start_time, scan_pids
from agents.security_agent.v5_window import top_syscall, window_from_normalised
from agents.security_agent.entropy_sampler import EntropySampler, EntropyResult, shannon_entropy
from agents.security_agent.falco_client import (
    falco_event_stream, replay_stream, resolve_falco_mode,
)
from agents.security_agent.syscall_window import (
    FalcoWindowTracker, build_model_input, DEFAULT_BURST_THRESHOLD, DEFAULT_COOLDOWN_S,
)
from kubeheal.contracts import SECURITY_PUBLISH_RISK
from kubeheal.features.security import MAX_WINDOW_EVENTS, WINDOW_S, security_features
from pydantic import BaseModel, ConfigDict, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
METRICS = KubeHealMetrics()


def namespace_tier(namespace: str) -> str:
    """See agents/common/tiers.py: NAMESPACE_TIER_MAP first, then the name rule; otherwise "unknown"."""
    return _namespace_tier(namespace)


SCORE_KEY_PREFIX = "kubeheal:security:score"          # + ":<namespace>:<workload>"; Fusion reads it (SECURITY_SCORE_PREFIX)
DEFAULT_SCORE_TTL_S = 60.0                              # chosen, not measured (env SECURITY_SCORE_TTL_S)
HEURISTIC_LABEL = "suspicious"                          # label of a heuristic-only event: never an auto-contain label
MAX_TRACKED_WORKLOADS = 1024                            # chosen, not measured: bound on the per-workload state maps
MAX_TRACKED_PIDS = 4096                                 # chosen, not measured: bound on PID-scoped state

# ARGV: 1 model_scored ('true'|'false'), 2 risk ('' when false), 3 now ms, 4 ttl s, 5 publish risk.
# The hold time of both rules below is the TTL itself (ttl * 1000 ms).
#  - A 'true' answer keeps the highest risk of the last hold period, but never extends that high value's life:
#    high_ts_ms is set only when a new high is stored, so one false positive cannot keep the risk raised forever.
#  - A 'false' (no model answer, or a heuristic conflict) is kept for one hold period against a lower-evidence
#    'true' (risk below the publish risk): an idle-pod score must not flip an attack's 'false' to 'confirmed low'.
RECORD_SECURITY_SCORE_LUA = """
-- kubeheal:record_security_score
local key = KEYS[1]
local scored, risk = ARGV[1], ARGV[2]
local now, ttl, publish = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5])
local hold = ttl * 1000
local false_ts = tonumber(redis.call('HGET', key, 'false_ts_ms'))
if scored == 'true' then
  local incoming = tonumber(risk)
  if false_ts and now - false_ts < hold and incoming and incoming < publish
     and redis.call('TTL', key) > 0 then
    return ''
  end
  local high = tonumber(redis.call('HGET', key, 'high_risk'))
  local high_ts = tonumber(redis.call('HGET', key, 'high_ts_ms'))
  if high and high_ts and now - high_ts < hold and high > incoming then
    risk = redis.call('HGET', key, 'high_risk')
  else
    redis.call('HSET', key, 'high_risk', risk, 'high_ts_ms', ARGV[3])
  end
else
  redis.call('HSET', key, 'false_ts_ms', ARGV[3])
end
redis.call('HSET', key, 'sec_risk', risk, 'model_scored', scored, 'ts_ms', ARGV[3])
redis.call('EXPIRE', key, ARGV[4])
return risk
"""


def _positive_float(raw, default: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) and value > 0 else default


def falco_t0_ms(events: List[Dict]) -> Optional[int]:
    """Return the earliest timezone-aware Falco event time, or None when the source time is unknown.

    This only reads the normalized `ts` field. It never substitutes the Security Agent's publish time.
    """
    stamps = []
    for event in events or []:
        raw = event.get("ts")
        if not isinstance(raw, str) or not raw:
            continue
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                continue
            stamp_ms = int(parsed.timestamp() * 1000)
            if stamp_ms > 0:
                stamps.append(stamp_ms)
        except (TypeError, ValueError, OverflowError, OSError):
            continue
    return min(stamps) if stamps else None


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
        inference_url: str = None,
        entropy_threshold: float = 7.2,
        mmap_entropy_threshold: float = 7.0,
        mmap_size_threshold: int = 50 * 1024 * 1024,
        sampler: Optional[EntropySampler] = None,
    ):
        self.namespace       = namespace
        self.redis_url       = redis_url       or os.environ.get("REDIS_URL", "redis://redis-master:6379")
        self.falco_grpc_addr = falco_grpc_addr or os.environ.get("FALCO_GRPC_ADDR", "127.0.0.1:5060")
        # V5-S2: the LightGBM security bundle behind the inference service (POST /v1/security/predict)
        self.inference = InferenceClient(inference_url, metrics=METRICS)
        self.score_ttl_s = _positive_float(os.environ.get("SECURITY_SCORE_TTL_S"), DEFAULT_SCORE_TTL_S)
        self.proc_root = os.environ.get("PROC_ROOT", "/proc")
        self.entropy_threshold = entropy_threshold
        self.mmap_entropy_threshold = mmap_entropy_threshold
        self.mmap_size_threshold = mmap_size_threshold

        self.redis: Optional[aioredis.Redis] = None
        self.core_api: Optional[client.CoreV1Api] = None

        self.running = False

        self.pod_index = PodIndex()
        self.containment: Optional[ContainmentService] = None      # V5-S5a, created in start() when NODE_NAME is set
        self.apps_api: Optional[client.AppsV1Api] = None
        self.inotify_watcher = InotifyWatcher()

        self.entropy_calculator = EntropyCalculator()
        # Real write-entropy sampler (30 samples, 2 s apart, bounded reads); injectable for tests.
        self.sampler = sampler or EntropySampler()
        self.falco_mode = "off"
        self._checks: Dict[Tuple[int, Optional[int]], "asyncio.Task"] = {}   # (pid, /proc starttime) -> check

        self.write_counters: Dict[Tuple[int, int], int] = {}
        # earliest Falco timestamp seen per PID (kept outside the capped syscall window) for T0
        self._falco_first_ts: "OrderedDict[int, str]" = OrderedDict()
        self._falco_tracker: Optional[FalcoWindowTracker] = None
        # checks that did not produce an event, by reason (logged as well; no Prometheus counter here)
        self.dropped_checks: Dict[str, int] = {}
        self._pid_map: Dict[int, Dict] = {}                         # last PID scan: pid -> pod record
        self._counters: Dict[Tuple[str, str], CounterSamples] = {}  # (namespace, pod) -> write/net samples
        self.score_write_errors = 0
        self._wall = time.time                                      # tests replace it
        self._mono = time.monotonic

    def _drop(self, reason: str, pid: int, detail: str = "") -> None:
        self.dropped_checks[reason] = self.dropped_checks.get(reason, 0) + 1
        logger.warning(f"entropy check for PID {pid} dropped ({reason}) {detail}; "
                       f"{self.dropped_checks[reason]} dropped for this reason so far")

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
        asyncio.create_task(self._score_quiet_workloads_periodic())
        # V5-S5a: node-local cgroup-freeze consumer (reads only this node's request stream; none without NODE_NAME)
        self.containment = ContainmentService.from_env(self.redis, self.pod_index, METRICS)
        if self.containment:
            await self.containment.start(self.core_api)

    async def stop(self) -> None:
        """Stop the Security Agent."""
        logger.info("Stopping Security Agent...")
        self.running = False
        if self.containment:
            await self.containment.stop()
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
                self._pid_map = pid_map

                for pid, info in pid_map.items():
                    key = f"kubeheal:pid:{pid}"
                    await self.redis.setex(key, 300, json.dumps(info))

                await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"PID scan error: {e}")
                await asyncio.sleep(5)

    async def _score_quiet_workloads_periodic(self) -> None:
        """Refresh a real, possibly eventless model window before the Fusion score TTL expires."""
        interval = max(1.0, self.score_ttl_s / 2.0)  # chosen cadence derived from the configured score TTL
        while self.running:
            try:
                await asyncio.sleep(interval)
                await self._score_quiet_workloads_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("quiet workload scoring failed: %s", e)

    async def _score_quiet_workloads_once(self) -> None:
        """Score one fresh feature window per indexed pod; no heuristic is written as a model answer."""
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for pid, rec in self._pid_map.items():
            info = self._with_workload(rec)
            namespace, pod = info.get("namespace", "default"), info.get("pod") or ""
            if not pod:
                continue
            group = groups.setdefault((namespace, pod), {"info": info, "pids": set()})
            group["pids"].add(pid)
        for (namespace, pod), group in groups.items():
            pids = sorted(group["pids"])
            if any(key[0] in group["pids"] and not task.done() for key, task in self._checks.items()):
                continue
            pid = pids[0]
            info = self._with_workload(group["info"])
            events = []
            if self._falco_tracker is not None:
                for event_pid in pids:
                    events.extend(self._falco_tracker.window(event_pid))
            v5_events, _start, _end, window_s = window_from_normalised(events)
            # An eventless period is still a real 60 s observation window: the rates come from actual /proc counters.
            window_s = window_s or WINDOW_S
            try:
                samples = await self._sample_counters(pid, info)
                features = security_features(v5_events, [], window_s,
                                             samples.total(2, window_s), samples.total(1, window_s))
                pred = await self._predict(features)
            except Exception as e:
                pred = None
                logger.warning("quiet security scoring failed for %s/%s: %s", namespace, pod, e)
            # The hash is fresh only for a validated inference answer. A failure clears a stale true value.
            await self._record_score(namespace, info["workload"], pred)

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
            max_events=MAX_WINDOW_EVENTS,       # the v5 window cut (60 s, 512 events) is applied at scoring time
            burst_threshold=int(os.environ.get("FALCO_BURST_THRESHOLD", str(DEFAULT_BURST_THRESHOLD))),
            cooldown_s=float(os.environ.get("FALCO_TRIGGER_COOLDOWN_S", str(DEFAULT_COOLDOWN_S))),
        )
        self._falco_tracker = tracker
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
        if pid:
            start_time = process_start_time(int(pid), self.proc_root)
            if start_time is not None:
                evt["proc_starttime"] = start_time
        if pid and evt.get("pod"):
            # Carry the workload the PID scan would have stored. The scan writes the same key, and a record
            # without `workload` made the event, and the score hash, be keyed by the POD name (never Fusion's join key).
            await self.redis.setex(
                f"kubeheal:pid:{pid}", 300,
                json.dumps(self._with_workload({"pid": pid, "pod": evt["pod"],
                                                "namespace": evt.get("namespace", "default"),
                                                "pod_uid": evt.get("pod_uid", "")})),
            )
        trigger = tracker.add(evt)
        if trigger:
            if trigger.first_ts:
                self._falco_first_ts[trigger.pid] = trigger.first_ts
                self._falco_first_ts.move_to_end(trigger.pid)
                while len(self._falco_first_ts) > MAX_TRACKED_PIDS:
                    self._falco_first_ts.popitem(last=False)
            self.inotify_watcher.recent_events = trigger.events
            await self._trigger_entropy_check(
                trigger.pid, trigger.events, source,
                window_provider=lambda pid=trigger.pid, tracker=tracker: tracker.window(pid),
            )

    def _sample_write_bytes(self) -> Dict[Tuple[int, int], int]:
        """Cumulative write_bytes per kubepods PID from /proc/<pid>/io."""
        proc = self.proc_root
        out: Dict[Tuple[int, int], int] = {}
        try:
            for d in os.listdir(proc):
                if not d.isdigit():
                    continue
                pid = int(d)
                start_time = process_start_time(pid, proc)
                if start_time is None:
                    continue
                try:
                    with open(f"{proc}/{pid}/cgroup") as f:
                        if "kubepods" not in f.read():
                            continue
                    with open(f"{proc}/{pid}/io") as f:
                        for line in f:
                            if line.startswith("write_bytes:"):
                                out[(pid, start_time)] = int(line.split()[1])
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
        prev: Dict[Tuple[int, int], int] = {}
        while self.running:
            try:
                await asyncio.sleep(2)
                current = self._sample_write_bytes()
                self.write_counters = {
                    identity: cum - prev[identity]
                    for identity, cum in current.items()
                    if identity in prev and cum >= prev[identity]
                }
                prev = current
                for (pid, _start_time), delta in self.write_counters.items():
                    if delta > WRITE_BYTES_THRESHOLD:
                        await self._trigger_entropy_check(pid)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Write event error: {e}")

    async def _trigger_entropy_check(self, pid: int, syscall_events: Optional[List[Dict]] = None,
                                     syscall_source: str = "none",
                                     window_provider=None) -> None:
        """Start an entropy check for `pid` in the background (one at a time per PID: a full run takes
        samples x interval, 60 s with the defaults, and must not block the detectors that call this).

        `syscall_events` is the real syscall window (from Falco live or replay) when there is one;
        `syscall_source` says where it came from ("falco", "replay") or "none"."""
        start_time = process_start_time(pid, self.proc_root)
        check_key = (pid, start_time)
        for old_key, old_task in list(self._checks.items()):
            if old_key[0] == pid and old_key != check_key and not old_task.done():
                old_task.cancel()
        running = self._checks.get(check_key)
        if running is not None and not running.done():
            return
        task = asyncio.create_task(self._run_entropy_check(
            pid, list(syscall_events or []), syscall_source,
            window_provider=window_provider, expected_start_time=start_time,
        ))

        def _done(t, check_key=check_key, pid=pid):
            if self._checks.get(check_key) is t:
                self._checks.pop(check_key, None)
            if not any(key[0] == pid for key in self._checks):
                self._falco_first_ts.pop(pid, None)
            if not t.cancelled() and t.exception():
                self._drop("check_failed", pid, str(t.exception()))
        task.add_done_callback(_done)
        if len(self._checks) >= MAX_TRACKED_PIDS:
            oldest = next(iter(self._checks))
            self._checks[oldest].cancel()
            self._checks.pop(oldest, None)
        self._checks[check_key] = task

    async def _run_entropy_check(self, pid: int, events: List[Dict], source: str,
                                  window_provider=None, expected_start_time: Optional[int] = None) -> None:
        """Sample the entropy of what `pid` writes, assess, publish. An initial assessment is published after
        the first sample (so detection does not wait for the whole window), a final one when the series is
        complete. Both carry entropy_phase and entropy_valid_samples."""
        logger.info(f"Entropy check for PID {pid} (syscalls from: {source})")
        if expected_start_time is not None and process_start_time(pid, self.proc_root) != expected_start_time:
            self._drop("pid_reused", pid, "starttime changed before sampling")
            return
        pid_info = await self._get_pid_info(pid)
        if not pid_info:
            # the PID cache entry (300 s) expired or never existed: no pod to report against
            self._drop("pid_cache_expired", pid, "no kubeheal:pid entry; no event published")
            return
        pid_info = self._with_workload(pid_info)
        await self._sample_counters(pid, pid_info)           # baseline for the write and network rates
        mmap_detected = await self._check_mmap_entropy(pid)

        async def first_sample(result: EntropyResult, i: int) -> None:
            if i == 0 and self.sampler.config.samples > 1:
                current_events = window_provider() if window_provider else events
                await self._assess_and_publish(pid, pid_info, result, current_events, source,
                                               mmap_detected, "initial")

        async def next_sample_interval() -> float:
            factor = await sampling_factor(self.redis, pid_info.get("namespace", ""),
                                           pod=pid_info.get("pod"))
            return scaled_interval(self.sampler.config.interval_s, factor)

        collect_kwargs = {"on_sample": first_sample, "interval_provider": next_sample_interval}
        if expected_start_time is not None:
            collect_kwargs["expected_start_time"] = expected_start_time
        result = await self.sampler.collect(pid, **collect_kwargs)
        current_events = window_provider() if window_provider else events
        await self._assess_and_publish(pid, pid_info, result, current_events, source, mmap_detected, "complete")

    # ---- workload, counters, score hash ------------------------------------------------------------------
    def _with_workload(self, pid_info: Dict) -> Dict:
        """pid_info with `workload` (the Deployment name for a Deployment-owned pod, else the controller, else the
        pod: what the Health Agent and Fusion call `deployment`), `workload_kind`, `container` and `pod_uid` filled
        from the pod index when the record lacks them."""
        info = dict(pid_info)
        namespace, pod = info.get("namespace", "default"), info.get("pod")
        known = self.pod_index.lookup_pod(namespace, pod) if pod else None
        if known is not None:
            # the index is authoritative: a record written before the index knew the pod holds the pod-name fallback
            info["workload"] = known.workload
            info["workload_kind"] = known.workload_kind
            info["container"] = info.get("container") or known.container
        info["pod_uid"] = info.get("pod_uid") or info.get("uid") or (known.uid if known is not None else "")
        info["workload"] = info.get("workload") or pod or "unknown"
        return info

    def _pod_pids(self, pid: int, pid_info: Dict) -> List[int]:
        namespace, pod = pid_info.get("namespace", "default"), pid_info.get("pod")
        pids = {pid}
        pids.update(p for p, rec in self._pid_map.items()
                    if rec.get("pod") == pod and rec.get("namespace") == namespace)
        return sorted(p for p in pids if p)

    async def _sample_counters(self, pid: int, pid_info: Dict) -> CounterSamples:
        """Add one write-bytes and net-tx sample for the pod (blocking /proc reads run in a thread)."""
        key = (pid_info.get("namespace", "default"), pid_info.get("pod") or "unknown")
        samples = self._counters.get(key)
        if samples is None:
            if len(self._counters) >= MAX_TRACKED_WORKLOADS:
                self._counters.pop(next(iter(self._counters)))
            samples = self._counters[key] = CounterSamples()
        net, wbytes = await asyncio.to_thread(read_pod_counters, self.proc_root, self._pod_pids(pid, pid_info))
        samples.add(self._mono(), net, wbytes)
        return samples

    async def _record_score(self, namespace: str, workload: str, pred: Optional[Dict]) -> None:
        """Write `kubeheal:security:score:<namespace>:<workload>` (sec_risk, ts_ms, model_scored) with an expiry:
        what the Fusion Agent reads to know a FRESH Security Model response exists and what its raw risk is.

        model_scored is "true" only when the service answered with a valid prediction. A failed window writes
        "false" with an empty sec_risk, so a "true" from a moment earlier is overwritten (fail closed). When the
        service answered, sec_risk is the highest model risk of this workload within the TTL: another process
        of the same workload that scored low a second later must not hide a high one."""
        now = self._wall()
        model_scored = "true" if pred is not None else "false"
        risk = f"{pred['risk']:.4f}" if pred is not None else ""
        hkey = f"{SCORE_KEY_PREFIX}:{namespace}:{workload}"
        try:
            await self.redis.eval(RECORD_SECURITY_SCORE_LUA, 1, hkey,
                                  model_scored, risk, str(int(now * 1000)),
                                  str(max(1, int(math.ceil(self.score_ttl_s)))),
                                  str(SECURITY_PUBLISH_RISK))
        except Exception as e:           # a Redis error must not end the check; Fusion treats a missing hash as stale
            self.score_write_errors += 1
            logger.warning("score hash %s not written (%s); %d write error(s) so far", hkey, e,
                           self.score_write_errors)

    async def _predict(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """The inference service's prediction for one feature window, or None (fail closed: unreachable, timeout,
        non-200, unusable body). The single injectable point of the model call."""
        return await self.inference.predict(features)

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
        pid_info = self._with_workload(pid_info)
        namespace, workload = pid_info.get("namespace", "default"), pid_info["workload"]

        # The Security Model needs a real syscall window. For eventless assessments, the periodic quiet path
        # supplies a near-empty window with live /proc counters. A window this path cannot score is written false.
        pred: Optional[Dict[str, Any]] = None
        issue = ""
        window: Tuple[List[Dict], int, int, float] = ([], 0, 0, 0.0)
        if events:
            window = window_from_normalised(events)
            v5_events, _start, _end, window_s = window
            if v5_events:
                try:
                    samples = await self._sample_counters(pid, pid_info)
                    features = security_features(v5_events, result.file_entropies(), window_s,
                                                 samples.total(2, window_s), samples.total(1, window_s))
                    pred = await self._predict(features)
                    issue = "" if pred else f"inference_{self.inference.last_issue or 'unreachable'}"
                except Exception as e:
                    issue = f"feature_or_inference_error:{type(e).__name__}"
                    logger.warning("security feature/model assessment failed for %s/%s: %s", namespace, workload, e)
            else:
                issue = "no_scorable_events"
        else:
            issue = "no_scorable_events"

        # The heuristic is an independent detector. It never turns a model answer into a certain model verdict:
        # if it catches high entropy that the model calls low risk, publish a human-only heuristic event and clear
        # model_scored in the score hash so Fusion cannot treat the low model result as Q1 confirmation.
        heuristic_risk = 0.0
        if mmap_detected:
            heuristic_risk = 0.85
        elif entropy_known and entropy_avg > self.entropy_threshold:
            heuristic_risk = min(0.95, entropy_avg / 8.0)
        if early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.60)
        if early_signals["high_entropy"] and early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.95)

        heuristic_conflict = pred is not None and heuristic_risk >= SECURITY_PUBLISH_RISK \
            and pred["risk"] < SECURITY_PUBLISH_RISK
        model_for_event = None if heuristic_conflict else pred
        await self._record_score(namespace, workload, None if heuristic_conflict else pred)
        risk_score = heuristic_risk if heuristic_conflict or pred is None else pred["risk"]
        logger.info(f"PID {pid} [{phase}] entropy="
                    f"{'n/a' if not entropy_known else format(entropy_avg, '.2f')} "
                    f"valid_samples={result.valid_samples} risk={risk_score:.3f} "
                    f"model_scored={'true' if pred else 'false'}")

        # The Security Agent only senses and reports (S-SA-5). Containment is decided by the
        # Fusion Agent and executed by the Executor.
        if risk_score >= SECURITY_PUBLISH_RISK:
            # T0 is the earliest Falco time seen for this PID: the capped window can start later
            # than the real onset in a long attack, so the first-seen timestamp is added to it.
            first_ts = self._falco_first_ts.get(pid, "")
            t0_ms = falco_t0_ms(list(events) + ([{"ts": first_ts}] if first_ts else []))
            extra = {
                "entropy_phase": phase,
                "entropy_valid_samples": str(result.valid_samples),
                "entropy_files_json": json.dumps(result.files),
                "syscall_source": source if events else "none",
                "model_scored": "true" if model_for_event else "false",
                "top_syscall": top_syscall(events),
            }
            if window[0]:
                extra["window_start_ms"], extra["window_end_ms"] = str(window[1]), str(window[2])
                extra["n_events"] = str(len(window[0]))
            if t0_ms is not None:
                extra["t0_ms"] = str(t0_ms)
            if heuristic_conflict:
                extra["model_risk"] = f"{pred['risk']:.4f}"
                extra["model_issue"] = "heuristic_model_conflict"
            elif issue:
                extra["model_issue"] = issue
            await self._publish_security_event(
                pid_info, risk_score, early_signals, entropy_avg, model_for_event,
                label=HEURISTIC_LABEL if heuristic_conflict else None, extra=extra,
            )

    async def _publish_security_event(
        self,
        pid_info: Dict,
        risk_score: float,
        early_signals: Dict,
        entropy: Optional[float] = None,
        pred: Optional[Dict] = None,
        label: Optional[str] = None,
        action: str = "observe",
        extra: Optional[Dict[str, str]] = None,
    ) -> None:
        """Publish the SecurityEvent to kubeheal.security.events + a hash for dashboard detail lookup. The field
        names and formats are the ones the Fusion Agent reads (agents/fusion_agent/event_mapping.to_security_event).

        `pred` is the validated inference answer (None: not model scored). An event without it carries a heuristic
        risk, an EMPTY prediction set and uncertain=true, so it can never look certain: Fusion needs a model
        score (models_ok) and exactly one label in the set before it acts automatically."""
        pod = pid_info.get("pod") or "unknown"
        namespace = pid_info.get("namespace", "default")
        event_id = f"sec-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}-{pod}"
        model_scored = pred is not None
        pred = pred or {}

        sec_label = label or pred.get("label") or HEURISTIC_LABEL

        payload = {
            "event_id": event_id,
            "namespace": namespace,
            "pod_name": pod,
            "deployment": pid_info.get("workload") or pod,
            "workload_kind": pid_info.get("workload_kind", "Pod"),
            "namespace_tier": namespace_tier(namespace),
            "pod_uid": pid_info.get("pod_uid", "") or "",
            "sec_risk": f"{risk_score:.4f}",
            "sec_label": sec_label,
            "sec_prediction_set": json.dumps(pred.get("prediction_set", [])),
            "sec_uncertain": "true" if (not model_scored or pred.get("uncertain", True)) else "false",
            "top_factors_json": json.dumps(pred.get("top_factors", [])),
            "model_version": pred.get("model_version", ""),
            # Observed, not model output: kept because Fusion and the dashboard read them. The LightGBM model has
            # no attention weights or entropy spike, so these stay empty ({}); the model's explanation is
            # top_factors_json.
            "syscall_attribution_json": "{}",
            "entropy_spike_json": "{}",
            "early_signals_json": json.dumps(early_signals),
            "pid_target": str(pid_info.get("pid", 0)),
            # empty (not 0.0) when no sample of written data could be read
            "entropy": f"{float(entropy):.4f}" if entropy is not None else "",
            "action": action,
            # epoch ms; datetime.utcnow().timestamp() reads the naive UTC time as local time (wrong off UTC)
            "timestamp_ms": str(int(self._wall() * 1000)),
        }
        payload.update(extra or {})
        await self.redis.xadd("kubeheal.security.events", payload)
        hkey = f"kubeheal:security:{event_id}"
        await self.redis.hset(hkey, mapping=dict(payload))
        await self.redis.expire(hkey, 86400)
        logger.info(f"Security event {event_id}: risk={risk_score:.2f} label={sec_label} "
                    f"model_scored={model_scored}")

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
            maps_path = os.path.join(self.proc_root, str(pid), "maps")
            if not os.path.exists(maps_path):
                return False

            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        perms = parts[1]
                        path = parts[5]

                        if "rw-p" in perms and path.startswith("/"):
                            try:
                                start_hex, end_hex = parts[0].split("-")
                                size = int(end_hex, 16) - int(start_hex, 16)   # the mapping length, not its end address
                            except ValueError:
                                continue
                            if size > self.mmap_size_threshold:
                                return True
        except Exception as e:
            logger.debug(f"mmap check error: {e}")

        return False


async def main():
    """Run Security Agent."""
    METRICS.start_server(int(os.environ.get("METRICS_PORT", "9100")))
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
