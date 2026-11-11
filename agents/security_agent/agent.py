import asyncio
import json
import logging
import math
import os
import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Any, Tuple
from enum import Enum

import redis.asyncio as aioredis
import kubernetes_asyncio
from kubernetes_asyncio import client, config
from agents.common.metrics import KubeHealMetrics
from agents.common.sampling import sampling_factor, scaled_interval
from agents.security_agent.counters import CounterSamples, read_pod_counters
from agents.security_agent.inference import InferenceClient
from agents.security_agent.proc_scanner import PodIndex, scan_pids
from agents.security_agent.v5_window import top_syscall, window_from_normalised
from agents.security_agent.entropy_sampler import EntropySampler, EntropyResult, shannon_entropy
from agents.security_agent.falco_client import (
    falco_event_stream, replay_stream, resolve_falco_mode,
)
from agents.security_agent.syscall_window import (
    FalcoWindowTracker, build_model_input, DEFAULT_BURST_THRESHOLD, DEFAULT_COOLDOWN_S,
)
from kubeheal.contracts import SECURITY_PUBLISH_RISK
from kubeheal.features.security import MAX_WINDOW_EVENTS, security_features
from pydantic import BaseModel, ConfigDict, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
METRICS = KubeHealMetrics()


def namespace_tier(namespace: str) -> str:
    n = (namespace or "").lower()
    if "prod" in n:
        return "prod"
    if "stag" in n:
        return "staging"
    if "dev" in n:
        return "dev"
    # A namespace that matches none of the known names is "unknown", not "dev": the decision policy scores an
    # unknown tier with the highest multiplier and never acts automatically on it. (The `kubeheal/tier`
    # namespace label is set by the manifests but is not read by any agent yet; the name rule is all there is.)
    return "unknown"


SCORE_KEY_PREFIX = "kubeheal:security:score"          # + ":<namespace>:<workload>"; Fusion reads it (SECURITY_SCORE_PREFIX)
DEFAULT_SCORE_TTL_S = 60.0                              # chosen, not measured (env SECURITY_SCORE_TTL_S)
HEURISTIC_LABEL = "suspicious"                          # label of a heuristic-only event: never an auto-contain label
MAX_TRACKED_WORKLOADS = 1024                            # chosen, not measured: bound on the per-workload state maps


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
        self.apps_api: Optional[client.AppsV1Api] = None
        self.inotify_watcher = InotifyWatcher()

        self.entropy_calculator = EntropyCalculator()
        # Real write-entropy sampler (30 samples, 2 s apart, bounded reads); injectable for tests.
        self.sampler = sampler or EntropySampler()
        self.falco_mode = "off"
        self._checks: Dict[int, "asyncio.Task"] = {}   # pid -> running entropy check

        self.write_counters: Dict[int, int] = {}
        # earliest Falco timestamp seen per PID (kept outside the capped syscall window) for T0
        self._falco_first_ts: Dict[int, str] = {}
        # checks that did not produce an event, by reason (logged as well; no Prometheus counter here)
        self.dropped_checks: Dict[str, int] = {}
        self._pid_map: Dict[int, Dict] = {}                         # last PID scan: pid -> pod record
        self._counters: Dict[Tuple[str, str], CounterSamples] = {}  # (namespace, pod) -> write/net samples
        self._recent_risk: Dict[Tuple[str, str], Deque] = {}        # (namespace, workload) -> (wall s, risk)
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
                self._drop("check_failed", pid, str(t.exception()))
        task.add_done_callback(_done)
        self._checks[pid] = task

    async def _run_entropy_check(self, pid: int, events: List[Dict], source: str) -> None:
        """Sample the entropy of what `pid` writes, assess, publish. An initial assessment is published after
        the first sample (so detection does not wait for the whole window), a final one when the series is
        complete. Both carry entropy_phase and entropy_valid_samples."""
        logger.info(f"Entropy check for PID {pid} (syscalls from: {source})")
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
                await self._assess_and_publish(pid, pid_info, result, events, source,
                                               mmap_detected, "initial")

        async def next_sample_interval() -> float:
            factor = await sampling_factor(self.redis, pid_info.get("namespace", ""),
                                           pod=pid_info.get("pod"))
            return scaled_interval(self.sampler.config.interval_s, factor)

        result = await self.sampler.collect(pid, on_sample=first_sample,
                                            interval_provider=next_sample_interval)
        await self._assess_and_publish(pid, pid_info, result, events, source, mmap_detected, "complete")

    # ---- workload, counters, score hash ------------------------------------------------------------------
    def _with_workload(self, pid_info: Dict) -> Dict:
        """pid_info with `workload` (the Deployment name for a Deployment-owned pod, else the controller, else the
        pod: what the Health Agent and Fusion call `deployment`), `workload_kind`, `container` and `pod_uid` filled
        from the pod index when the record lacks them."""
        info = dict(pid_info)
        namespace, pod = info.get("namespace", "default"), info.get("pod")
        known = self.pod_index.lookup_pod(namespace, pod) if pod else None
        if known is not None:
            info["workload"] = info.get("workload") or known.workload
            info["workload_kind"] = info.get("workload_kind") or known.workload_kind
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
        key = (namespace, workload)
        hist = self._recent_risk.get(key)
        if hist is None:
            if len(self._recent_risk) >= MAX_TRACKED_WORKLOADS:
                self._recent_risk.pop(next(iter(self._recent_risk)))
            hist = self._recent_risk[key] = deque()
        while hist and now - hist[0][0] > self.score_ttl_s:
            hist.popleft()
        if pred is not None:
            hist.append((now, pred["risk"]))
            fields = {"sec_risk": f"{max(r for _, r in hist):.4f}", "model_scored": "true"}
        else:
            fields = {"sec_risk": "", "model_scored": "false"}
        fields["ts_ms"] = str(int(now * 1000))
        hkey = f"{SCORE_KEY_PREFIX}:{namespace}:{workload}"
        try:
            await self.redis.hset(hkey, mapping=fields)
            await self.redis.expire(hkey, max(1, int(math.ceil(self.score_ttl_s))))
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

        # The Security Model needs a real syscall window. Without one (no Falco, no replay, or only events v5 does
        # not count) the service is not called and nothing is fabricated: the event is scored from the entropy and
        # /proc heuristics only and says so (model_scored=false).
        pred: Optional[Dict[str, Any]] = None
        issue = ""
        window: Tuple[List[Dict], int, int, float] = ([], 0, 0, 0.0)
        if events:
            window = window_from_normalised(events)
            v5_events, _start, _end, window_s = window
            if v5_events:
                samples = await self._sample_counters(pid, pid_info)
                features = security_features(v5_events, result.file_entropies(), window_s,
                                             samples.total(2, window_s), samples.total(1, window_s))
                pred = await self._predict(features)
                issue = "" if pred else f"inference_{self.inference.last_issue or 'unreachable'}"
                await self._record_score(namespace, workload, pred)
            else:
                issue = "no_scorable_events"

        # Heuristic baseline: used ONLY when the service gave no score. A scored event carries the model's own
        # risk, label and prediction set; mixing a heuristic into them would break that contract.
        heuristic_risk = 0.0
        if mmap_detected:
            heuristic_risk = 0.85
        elif entropy_known and entropy_avg > self.entropy_threshold:
            heuristic_risk = min(0.95, entropy_avg / 8.0)
        if early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.60)
        if early_signals["high_entropy"] and early_signals["rename_burst"]:
            heuristic_risk = max(heuristic_risk, 0.95)

        risk_score = pred["risk"] if pred else heuristic_risk
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
                "model_scored": "true" if pred else "false",
                "top_syscall": top_syscall(events),
            }
            if window[0]:
                extra["window_start_ms"], extra["window_end_ms"] = str(window[1]), str(window[2])
                extra["n_events"] = str(len(window[0]))
            if t0_ms is not None:
                extra["t0_ms"] = str(t0_ms)
            if issue:
                extra["model_issue"] = issue
            await self._publish_security_event(
                pid_info, risk_score, early_signals, entropy_avg, pred, extra=extra,
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
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000)),
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
