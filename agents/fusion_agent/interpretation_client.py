"""
Interpretation client for the Fusion Agent (S-INT-1 .. S-INT-4, S-FA-2, P6-D6).
==============================================================================
What is where, so nothing here pretends to be more than it is:

  * Field-name mapper (S-INT-1): runs in the Health Model server (it holds the graph and its field paths) and
    arrives in the health event as `field_attribution_json` = {YAML field path: score}. This module reads and
    ranks it (`normalise_attributions`); it does not recompute it.
  * Attributions (S-INT-2): the servers publish GAT node importance (fields), per-channel metric deviation
    and transformer salience (syscalls). These are ATTENTION or deviation measures, not SHAP values, and the
    result says so in `methods`. A real `shap.KernelExplainer` over the metric channels
    (`kernel_metric_attribution`) needs the model and a background set, neither of which the Fusion image
    has (it ships neither torch nor shap), so it is an injectable explainer: pass `explainer=` to
    `InterpretationClient`; its result replaces the metric attribution and is labelled `kernel_shap`. If it
    fails or runs past its deadline the incident goes to a human (models_ok false), it never silently falls
    back inside a decision.
  * Causal chain with attack onset T0 (S-INT-3): the DCM server returns the chain lines (their `T+x s`
    offsets are fixed template values in models/dcm/causal_chain_builder.py, not measurements). T0 comes only
    from an event field `t0_ms` (the Security Agent's earliest Falco syscall time for the process, published
    when that time is known; an event without a usable Falco time carries no `t0_ms`). The event
    `timestamp_ms` is the PUBLISH time, after the onset, and is never used
    as T0: restoring "before T0" from it could pick a snapshot that already holds encrypted data.
    Absent means absent: no field, no T0, no invented value. When several events of one incident carry
    `t0_ms`, the earliest is used (the safer end for a pre-T0 snapshot).

The one network call to the DCM server is `correlate`; the explainer step has its own deadline.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import aiohttp
import numpy as np

logger = logging.getLogger(__name__)


# ---- T0 ----------------------------------------------------------------------------------------------
def parse_t0(event: Optional[Dict]) -> Optional[int]:
    """Attack onset (epoch ms) from the event's `t0_ms`, or None. Anything not a positive integer is None."""
    raw = (event or {}).get("t0_ms")
    if raw in (None, ""):
        return None
    try:
        value = int(str(raw))
    except ValueError:
        return None
    return value if value > 0 else None


def earliest_t0(*events: Optional[Dict], known: Optional[int] = None) -> Optional[int]:
    values = [v for v in [parse_t0(e) for e in events] + [known] if v]
    return min(values) if values else None


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ts(event: Optional[Dict]) -> Optional[int]:
    try:
        v = int(str((event or {}).get("timestamp_ms", "")))
        return v if v > 0 else None
    except ValueError:
        return None


# ---- causal chain ------------------------------------------------------------------------------------
def build_causal_chain(health: Optional[Dict], sec: Optional[Dict], dcm_chain: Sequence[str],
                       t0_ms: Optional[int]) -> List[str]:
    """Without T0: the DCM lines as they are. With T0: a T0 line, the events Fusion really saw with offsets
    computed from their real publish times, then the DCM lines marked as the DCM layer's."""
    dcm_lines = [str(x) for x in (dcm_chain or [])]
    if not t0_ms:
        return dcm_lines
    chain = [f"T0: attack onset {_iso(t0_ms)} (t0_ms={t0_ms}), from the security event"]
    seen = []
    for label, ev in (("security", sec), ("health", health)):
        ts = _ts(ev)
        if ev and ts:
            if label == "security":
                what = (f"security event {ev.get('event_id', '')} published "
                        f"(phase {ev.get('entropy_phase') or 'n/a'}, sec_risk={ev.get('sec_risk', 'n/a')})")
            else:
                what = f"health event {ev.get('event_id', '')} published (health_risk={ev.get('health_risk', 'n/a')})"
            seen.append((ts, what))
    for ts, what in sorted(seen):
        chain.append(f"T{(ts - t0_ms) / 1000.0:+.1f}s: {what}")
    chain.extend(f"DCM: {line}" for line in dcm_lines)
    return chain


# ---- attributions ------------------------------------------------------------------------------------
def _json(event: Optional[Dict], key: str):
    raw = (event or {}).get(key)
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None


def _ranked(weights, limit: int = 10) -> List[Dict]:
    if not isinstance(weights, dict):
        return []
    rows = []
    for k, v in weights.items():
        try:
            rows.append({"name": str(k), "weight": float(v)})
        except (TypeError, ValueError):
            continue
    rows.sort(key=lambda r: abs(r["weight"]), reverse=True)
    return rows[:limit]


def normalise_attributions(health: Optional[Dict], sec: Optional[Dict]) -> Dict:
    """Ranked attributions from what the model servers published, each with the method that produced it."""
    out: Dict = {"methods": {}}
    if health:
        fields = _ranked(_json(health, "field_attribution_json"))
        if fields:
            out["health_fields"] = fields
            out["methods"]["health_fields"] = "gat_node_importance (attention, not SHAP)"
        if health.get("top_metric"):
            out["health_top_metric"] = health["top_metric"]
            out["methods"]["health_top_metric"] = "metric_channel_deviation (fallback, not SHAP)"
    if sec:
        syscalls = _ranked(_json(sec, "syscall_attribution_json"))
        if syscalls:
            out["syscalls"] = syscalls
            out["methods"]["syscalls"] = "transformer_salience (attention, not SHAP)"
        spike = _json(sec, "entropy_spike_json")
        if isinstance(spike, dict) and spike:
            out["entropy_spike"] = spike
    return out


def deviation_attribution(window, names: Sequence[str]) -> Dict[str, float]:
    """Fallback metric attribution: each channel's mean absolute deviation from its own mean, normalised.
    A heuristic, labelled as such."""
    arr = np.asarray(window, dtype=np.float64)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    per = np.abs(arr - arr.mean(axis=0, keepdims=True)).mean(axis=0)
    total = float(per.sum()) + 1e-12
    return {names[i]: float(per[i] / total) for i in range(min(len(names), per.shape[0]))}


def kernel_metric_attribution(predict: Callable, window, background, names: Sequence[str],
                              shap_module=None) -> Tuple[Dict[str, float], str]:
    """SHAP KernelExplainer over the metric channels (window averaged over time, like the model's summary
    features). `predict(X)` maps an [n, channels] array to [n] risks. Returns (attribution, method). If shap
    is not importable or fails, the deviation fallback is returned and the method says so."""
    arr = np.asarray(window, dtype=np.float64)
    x = arr.reshape(-1, arr.shape[-1]).mean(axis=0, keepdims=True)
    try:
        shap = shap_module
        if shap is None:
            import shap  # type: ignore
        explainer = shap.KernelExplainer(predict, np.asarray(background, dtype=np.float64))
        values = np.asarray(explainer.shap_values(x)).reshape(-1)
        mags = np.abs(values)
        total = float(mags.sum()) + 1e-12
        return {names[i]: float(mags[i] / total) for i in range(min(len(names), len(mags)))}, "kernel_shap"
    except Exception as e:
        logger.warning(f"KernelExplainer unavailable ({e}); using the deviation fallback")
        return deviation_attribution(window, names), "metric_channel_deviation (fallback, not SHAP)"


# ---- the client --------------------------------------------------------------------------------------
@dataclass
class CorrelateResult:
    ok: bool
    data: Dict = field(default_factory=dict)
    error: str = ""


@dataclass
class Explanation:
    ok: bool
    t0_ms: Optional[int]
    causal_chain: List[str]
    attributions: Dict
    error: str = ""


class InterpretationClient:
    def __init__(self, dcm_url: str, redis=None, explainer: Optional[Callable] = None):
        """`explainer(health, sec) -> dict` is optional and async-capable; its keys are merged into the
        attributions (for example the result of `kernel_metric_attribution`)."""
        self.dcm_url = dcm_url
        self.redis = redis
        self.explainer = explainer

    async def correlate(self, health: Dict, sec: Dict, h_emb, s_emb, deadline_s: float) -> CorrelateResult:
        """The DCM call (correlation, compound flag, causal chain, summary). `ok` is False for any failure
        or a response later than `deadline_s`: the caller must not read a zero score as a real answer."""
        async def call():
            async with aiohttp.ClientSession() as s:
                async with s.post(f"{self.dcm_url}/dcm/correlate", json={
                    "health_embedding": h_emb, "security_embedding": s_emb,
                    "health_assessment": health, "security_event": sec,
                    "field_attribution": _json(health, "field_attribution_json") or {},
                    "want_nl_summary": True,
                }, timeout=aiohttp.ClientTimeout(total=deadline_s)) as r:
                    if r.status != 200:
                        return CorrelateResult(False, error=f"DCM answered {r.status}")
                    data = await r.json()
                    if not isinstance(data, dict) or "correlation_score" not in data \
                            or "compound_flag" not in data:
                        return CorrelateResult(False, error="DCM answer lacks correlation_score or compound_flag")
                    return CorrelateResult(True, data)
        try:
            return await asyncio.wait_for(call(), timeout=deadline_s)
        except asyncio.TimeoutError:
            return CorrelateResult(False, error=f"DCM call exceeded its deadline of {deadline_s}s")
        except Exception as e:
            return CorrelateResult(False, error=f"DCM call failed: {e}")

    async def explain(self, health: Optional[Dict], sec: Optional[Dict], dcm_chain: Sequence[str],
                      t0_ms: Optional[int], deadline_s: float) -> Explanation:
        """Attributions and causal chain with T0. The local steps cannot fail; only the optional explainer
        can, and it has `deadline_s`. On its failure `ok` is False (Fusion then sends the incident to a human)."""
        chain = build_causal_chain(health, sec, dcm_chain, t0_ms)
        attributions = normalise_attributions(health, sec)
        if self.explainer is None:
            return Explanation(True, t0_ms, chain, attributions)

        async def run():
            res = self.explainer(health or {}, sec or {})
            if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
                res = await res
            return res
        try:
            extra = await asyncio.wait_for(run(), timeout=deadline_s)
        except asyncio.TimeoutError:
            return Explanation(False, t0_ms, chain, attributions,
                               f"explainer exceeded its deadline of {deadline_s}s")
        except Exception as e:
            return Explanation(False, t0_ms, chain, attributions, f"explainer failed: {e}")
        if isinstance(extra, dict):
            methods = dict(attributions.get("methods", {}), **(extra.pop("methods", None) or {}))
            attributions.update(extra)
            attributions["methods"] = methods
        return Explanation(True, t0_ms, chain, attributions)

    # ---- kept from the first version: best-effort NL summary, never blocks the decision ----------------
    async def summary(self, health: Dict, sec: Dict, h_emb, s_emb, timeout: float = 4.0) -> Optional[str]:
        res = await self.correlate(health, sec, h_emb, s_emb, timeout)
        return res.data.get("nl_summary") if res.ok else None

    def fire_and_forget(self, incident_id: str, health: Dict, sec: Dict, h_emb, s_emb):
        async def _run():
            nl = await self.summary(health, sec, h_emb, s_emb)
            if nl and self.redis and incident_id:
                try:
                    await self.redis.hset(f"kubeheal:incident:{incident_id}", mapping={"nl_summary": nl})
                except Exception:
                    pass
        asyncio.create_task(_run())
