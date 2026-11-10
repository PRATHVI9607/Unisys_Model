"""
Drift path: canary patch (S-RD-1 .. S-RD-4, P7-RR-1, P7-RR-2).
================================================================
1. Read the live Deployment, diff its drift view against the golden baseline and keep ONLY the
   differences at or under the request's `patch_field` (never the whole pod template).
2. Save the live spec and both patches as a rollback point (Redis, survives an Executor restart).
3. Patch as RFC 6902 JSON Patch (every replace/remove is guarded by a `test` op on the live value)
   with `strategy.rollingUpdate.maxUnavailable` forced to 0 for this rollout.
4. Wait for the rollout, then watch CANARY_WINDOWS (3, from the spec) windows of p99 latency and CPU
   throttling through the injected `metric_source`.
5. Keep (and put the pre-canary strategy back, because the strategy is part of the drift view) or roll
   back and escalate.

"Improved" has no absolute thresholds. It is relative to a reading of the same two metrics taken
before the patch: in every window no metric present before may be worse, and at least one must be
strictly lower. A missing metric after the patch counts as not improved. If no pre-patch reading
exists the Executor escalates before it writes anything.

Every Kubernetes write below is `_write(gate, ...)`: tests/test_killswitch.py and
tests/test_remediation_static.py enforce that.
"""

import asyncio
import copy
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from agents.executor.actions import ModeBlocked, _blocked_outcome, _write
from agents.executor.config import ConfigMissing, ExecConfig
from agents.executor.support import Recorder, gate_open, poll_until, to_dict
from agents.executor.validation import Request
from agents.health_agent.baseline import drift_view

logger = logging.getLogger(__name__)

CANARY_WINDOWS = 3                      # S-RD-4
METRIC_KEYS = ("http_p99_latency_ms", "cpu_throttle_percent")   # names used by the Health Agent
ROLLBACK_PREFIX = "kubeheal:rollback"

Op = Dict[str, Any]   # {"tokens": [...], "op": "replace|add|remove", "value": ..., "old": ...}


# ---- pure diff and patch building ---------------------------------------------------------------
def key_path(tokens: List[Any]) -> str:
    """Dotted path with [i] list indexes: the same format as the health model's field_paths."""
    out = ""
    for t in tokens:
        if isinstance(t, int):
            out += f"[{t}]"
        else:
            out += f".{t}" if out else str(t)
    return out


def pointer(tokens: List[Any], base: str = "/spec") -> str:
    parts = [str(t).replace("~", "~0").replace("/", "~1") for t in tokens]
    return base + "".join("/" + p for p in parts)


def diff_ops(desired: Any, current: Any, tokens: Optional[List[Any]] = None) -> List[Op]:
    """Minimal ops that turn `current` into `desired`. Lists of different length are replaced whole."""
    tokens = tokens or []
    ops: List[Op] = []
    if isinstance(desired, dict) and isinstance(current, dict):
        for k in sorted(set(desired) | set(current), key=str):
            if k not in current:
                ops.append({"tokens": tokens + [k], "op": "add", "value": desired[k], "old": None})
            elif k not in desired:
                ops.append({"tokens": tokens + [k], "op": "remove", "value": None, "old": current[k]})
            else:
                ops += diff_ops(desired[k], current[k], tokens + [k])
    elif isinstance(desired, list) and isinstance(current, list) and len(desired) == len(current):
        for i, (d, c) in enumerate(zip(desired, current)):
            ops += diff_ops(d, c, tokens + [i])
    elif desired != current:
        ops.append({"tokens": tokens, "op": "replace", "value": desired, "old": current})
    return ops


def apply_ops(doc: Dict, ops: List[Op]) -> Dict:
    out = copy.deepcopy(doc)
    for o in ops:
        parent = out
        for t in o["tokens"][:-1]:
            parent = parent[t]
        last = o["tokens"][-1]
        if o["op"] == "remove":
            del parent[last]
        else:
            parent[last] = copy.deepcopy(o["value"])
    return out


def to_json_patch(ops: List[Op], guard: bool = True) -> List[Dict]:
    """RFC 6902 document. With guard=True each replace/remove is preceded by a `test` of the live value."""
    patch: List[Dict] = []
    for o in ops:
        p = pointer(o["tokens"])
        if guard and o["op"] in ("replace", "remove"):
            patch.append({"op": "test", "path": p, "value": o["old"]})
        if o["op"] == "remove":
            patch.append({"op": "remove", "path": p})
        else:
            patch.append({"op": o["op"], "path": p, "value": o["value"]})
    return patch


def _under(path: str, field: str) -> bool:
    """True if `path` is `field`, below it, or an ancestor of it (an op may replace a whole list)."""
    def below(a: str, b: str) -> bool:
        return a == b or a.startswith(b + ".") or a.startswith(b + "[")
    return below(path, field) or below(field, path)


def _is_zero(v: Any) -> bool:
    return v in (0, "0", "0%")


class PlanError(Exception):
    """The patch cannot be built safely; `reason` becomes `escalated:<reason>`."""


class PatchPlan:
    def __init__(self, forward: List[Dict], rollback: List[Dict], restore_strategy: List[Dict],
                 drifted: List[str], target: Dict):
        self.forward, self.rollback, self.restore_strategy = forward, rollback, restore_strategy
        self.drifted, self.target = drifted, target


def build_patch(golden_spec: Dict, live_spec: Dict, field: str) -> PatchPlan:
    field = (field or "").strip()
    if field.startswith("spec.") and "spec" not in golden_spec:
        field = field[len("spec."):]
    if not field or field.lower() == "unknown":
        raise PlanError("no_patch_field")
    all_ops = diff_ops(golden_spec, live_spec)
    drift_ops = [o for o in all_ops if _under(key_path(o["tokens"]), field)]
    if not drift_ops:
        raise PlanError(f"no_drift_at_field:{field}")
    target = apply_ops(live_spec, drift_ops)

    strategy = target.get("strategy") or {}
    ru = dict(strategy.get("rollingUpdate") or {})
    if _is_zero(ru.get("maxSurge")):
        raise PlanError("max_surge_zero: maxUnavailable 0 needs maxSurge above 0")
    ru["maxUnavailable"] = 0
    desired = dict(target)
    desired["strategy"] = {**{k: v for k, v in strategy.items() if k != "rollingUpdate"},
                           "type": "RollingUpdate", "rollingUpdate": ru}
    strat_ops = [o for o in diff_ops(desired, target)]
    final = apply_ops(target, strat_ops)

    forward = to_json_patch(drift_ops + strat_ops, guard=True)
    rollback = to_json_patch(diff_ops(live_spec, final), guard=False)
    restore = to_json_patch([o for o in diff_ops(target, final) if o["tokens"][0] == "strategy"],
                            guard=False)
    return PatchPlan(forward, rollback, restore, [key_path(o["tokens"]) for o in drift_ops], target)


def improved(before: Dict, after: Dict) -> Tuple[bool, str]:
    """Relative rule, see the module docstring. Lower is better for both metrics."""
    keys = [k for k in METRIC_KEYS if before.get(k) is not None]
    if not keys:
        return False, "no pre-patch reading"
    strictly = False
    for k in keys:
        a = after.get(k)
        if a is None:
            return False, f"{k} missing after patch"
        if a > before[k]:
            return False, f"{k} worse: {a} > {before[k]}"
        if a < before[k]:
            strictly = True
    return (True, "") if strictly else (False, "no metric improved")


# ---- rollback point store -------------------------------------------------------------------------
class RollbackStore:
    """Rollback points in Redis (not a Kubernetes write). One live point per workload."""

    def __init__(self, redis):
        self.redis = redis

    @staticmethod
    def key(namespace: str, deployment: str) -> str:
        return f"{ROLLBACK_PREFIX}:{namespace}:{deployment}"

    async def save(self, namespace: str, deployment: str, record: Dict) -> None:
        if self.redis is None:
            raise RuntimeError("no redis for the rollback point")
        await self.redis.set(self.key(namespace, deployment), json.dumps(record, sort_keys=True))

    async def load(self, namespace: str, deployment: str) -> Optional[Dict]:
        raw = await self.redis.get(self.key(namespace, deployment)) if self.redis else None
        return json.loads(raw) if raw else None


# ---- the path ---------------------------------------------------------------------------------------
async def _rollout_done(apps_api, namespace: str, name: str) -> bool:
    d = to_dict(await apps_api.read_namespaced_deployment(name, namespace))
    spec, st, md = d.get("spec") or {}, d.get("status") or {}, d.get("metadata") or {}
    want = spec.get("replicas", 1)
    return ((st.get("observedGeneration") or 0) >= (md.get("generation") or 0)
            and (st.get("updatedReplicas") or 0) == want
            and (st.get("availableReplicas") or 0) == want
            and (st.get("replicas") or 0) == want)


async def canary_patch(gate, apps_api, req: Request, golden: Optional[Dict], record: Recorder,
                       metric_source: Optional[Callable], store: RollbackStore,
                       cfg: Optional[ExecConfig] = None, sleep: Callable = asyncio.sleep,
                       clock: Callable[[], float] = time.monotonic) -> str:
    ns, name = req.namespace, req.deployment
    cfg = cfg or ExecConfig()
    if not apps_api:
        return "no_kube_client"
    if not golden:
        await record("no_baseline", {})
        return "no_baseline_escalated"
    if metric_source is None:
        await record("preflight_failed", {"reason": "no metric source"})
        return "escalated:no_metric_source: cannot verify a canary without p99 and throttling data"
    try:
        window_s, timeout_s, poll_s = cfg.canary_window_s, cfg.rollout_timeout_s, cfg.rollout_poll_s
    except ConfigMissing as e:
        await record("preflight_failed", {"reason": f"config {e.name}"})
        return f"escalated:config_missing:{e.name}"

    done: List[str] = []
    planned = ["patch_deployment"]
    try:
        live = drift_view(to_dict(await apps_api.read_namespaced_deployment(name, ns)).get("spec") or {})
        try:
            plan = build_patch(golden.get("spec") or {}, live, req.patch_field)
        except PlanError as e:
            await record("plan_refused", {"reason": str(e)})
            return f"escalated:{e}"
        await record("plan", {"field": req.patch_field, "drifted": plan.drifted, "patch": plan.forward})

        before = await metric_source(ns, name, window_s)
        await record("metrics_before", {"metrics": before})
        if not any((before or {}).get(k) is not None for k in METRIC_KEYS):
            return "escalated:no_pre_patch_metrics: nothing to compare the canary against"

        try:
            await store.save(ns, name, {"incident_id": req.incident_id, "live_spec": live,
                                        "rollback": plan.rollback, "restore_strategy": plan.restore_strategy,
                                        "saved_at": time.time()})
        except Exception as e:
            await record("rollback_point_failed", {"error": str(e)})
            return f"escalated:rollback_point_not_saved:{e}"
        await record("rollback_point_saved", {"rollback": plan.rollback})

        await _write(gate, ns, planned[0], apps_api.patch_namespaced_deployment, name, ns, plan.forward)
        done.append("patch_deployment")
        await record("patched", {"drifted": plan.drifted})

        ok = await poll_until(lambda: _rollout_done(apps_api, ns, name), timeout_s, poll_s, sleep, clock)
        if not ok:
            await record("rollout_timeout", {})
            return await _roll_back(gate, apps_api, req, plan, record, done, "rollout did not settle in time")

        for i in range(1, CANARY_WINDOWS + 1):
            if not gate_open(gate, ns):
                await record("canary_stopped", {"window": i, "reason": "mode switched to test"})
                return (f"stopped_mode_test: mode switched to test before canary window {i}; "
                        f"completed {done}; patched but unverified, escalated to HUMAN")
            await sleep(window_s)
            try:
                after = await metric_source(ns, name, window_s)
            except Exception as e:      # a failing metric source is "not improved": roll back
                after = None
                await record("canary_metric_error", {"window": i, "error": str(e)})
            good, why = improved(before, after or {})
            await record("canary_window", {"window": i, "metrics": after, "improved": good, "why": why})
            if not good:
                return await _roll_back(gate, apps_api, req, plan, record, done,
                                        f"window {i}: {why}")

        if plan.restore_strategy:
            await _write(gate, ns, "restore_strategy", apps_api.patch_namespaced_deployment,
                         name, ns, plan.restore_strategy)
            done.append("restore_strategy")
            await record("strategy_restored", {})
        await record("kept", {"windows": CANARY_WINDOWS})
        return "patched_kept"
    except ModeBlocked as b:
        await record("blocked", {"step": b.step})
        return _blocked_outcome(f"PATCH {ns}/{name}", planned, done, b)
    except Exception as e:
        logger.error(f"drift path failed for {ns}/{name}: {e}")
        await record("failed", {"error": str(e)})
        if done:
            return f"patch_failed:{e}; completed {done}; the rollback point is in Redis"
        return f"patch_failed:{e}"


async def _roll_back(gate, apps_api, req: Request, plan: PatchPlan, record: Recorder,
                     done: List[str], reason: str) -> str:
    ns, name = req.namespace, req.deployment
    try:
        await _write(gate, ns, "rollback_deployment", apps_api.patch_namespaced_deployment,
                     name, ns, plan.rollback)
    except ModeBlocked as b:
        await record("blocked", {"step": b.step})
        return (f"stopped_mode_test: mode switched to test before '{b.step}'; completed {done}; "
                f"canary failed ({reason}) but the rollback was not applied; escalated to HUMAN")
    except Exception as e:
        await record("rollback_failed", {"error": str(e)})
        return f"patch_failed:rollback error {e} after canary failure ({reason}); escalated to HUMAN"
    done.append("rollback_deployment")
    await record("rolled_back", {"reason": reason})
    return f"rolled_back:{reason}"
