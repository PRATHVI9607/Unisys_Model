"""
Drift path: canary patch (S-RD-1 .. S-RD-4, P7-RR-1, P7-RR-2).
================================================================
1. Read the live Deployment, diff its drift view against the golden baseline and keep ONLY the
   differences at or under the request's candidate fields `patch_fields` (the spec diff Fusion saw; never the
   whole pod template). The Executor verifies the real diff itself: a candidate that does not differ is
   skipped, and it escalates only when none of them differs. Before any write the patched template must keep
   the Deployment selector matching (a matchExpressions selector always escalates) and must not weaken the
   security posture of the live template (`kubeheal.posture.weakens_posture`; an unreadable spec escalates).
2. Once the kill-switch gate allows the write, save the live spec and both patches as a rollback point
   (Redis, survives an Executor restart). State "pending" only exists while a patch may be in flight: it
   is closed ("failed") when nothing was patched.
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
from agents.executor.ledger_guard import LedgerUnavailable
from agents.executor.config import ConfigMissing, ExecConfig
from agents.executor.support import Recorder, gate_open, poll_until, to_dict
from agents.executor.validation import Request
from agents.health_agent.baseline import drift_view
from kubeheal.posture import PostureError, weakens_posture

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


def _normalise_fields(fields, strip_spec: bool = True) -> List[str]:
    """Candidate field paths from one string or a list; `spec.` prefix dropped, blanks and "unknown" removed."""
    if isinstance(fields, str):
        fields = [fields]
    out: List[str] = []
    for f in fields or []:
        f = (f or "").strip()
        if strip_spec and f.startswith("spec."):
            f = f[len("spec."):]
        if f and f.lower() != "unknown" and f not in out:
            out.append(f)
    return out


def validate_patch_target(raw_live_spec: Dict, live_view: Dict, target: Dict) -> None:
    """V5-D6. Raises PlanError (the request escalates, nothing is written) unless the patched template still
    matches the Deployment selector and does not weaken the live security posture."""
    selector = (raw_live_spec or {}).get("selector") or {}
    if selector.get("matchExpressions"):
        raise PlanError("selector_match_expressions: the Deployment selector uses matchExpressions, "
                        "the Executor cannot prove the template still matches it")
    match_labels = selector.get("matchLabels") or {}
    if not match_labels:
        raise PlanError("selector_missing: the Deployment has no matchLabels selector")
    template_labels = (((target.get("template") or {}).get("metadata") or {}).get("labels")) or {}
    missing = sorted(k for k, v in match_labels.items() if template_labels.get(k) != v)
    if missing:
        raise PlanError(f"selector_mismatch: the patched template would not carry the selector labels {missing}")
    try:
        weakened = weakens_posture(target, live_view)
    except PostureError as e:
        raise PlanError(f"posture_unreadable: {e}")
    if weakened:
        raise PlanError(f"patch_weakens_posture: {', '.join(weakened)}")


def build_patch(golden_spec: Dict, live_spec: Dict, fields) -> PatchPlan:
    fields = _normalise_fields(fields, strip_spec="spec" not in golden_spec)
    if not fields:
        raise PlanError("no_patch_field")
    all_ops = diff_ops(golden_spec, live_spec)
    drift_ops = [o for o in all_ops if any(_under(key_path(o["tokens"]), f) for f in fields)]
    if not drift_ops:
        raise PlanError(f"no_drift_at_fields:{','.join(fields)}")
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

    async def set_state(self, namespace: str, deployment: str, incident_id: str, state: str) -> None:
        saved = await self.load(namespace, deployment)
        if saved and saved.get("incident_id") == incident_id:
            saved["state"] = state
            saved["state_updated_at"] = time.time()
            await self.save(namespace, deployment, saved)


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
    saved = False            # a pending rollback point of this request is in the store
    patch_started = False    # the patch call was issued and has not returned yet
    try:
        try:
            previous = await store.load(ns, name)
        except Exception as e:
            await record("rollback_point_read_failed", {"error": str(e)})
            return f"escalated:rollback_point_unreadable:{e}"
        # Only an explicit "pending" blocks. A record without a state is a legacy or foreign record and
        # is treated as terminal, so it can never trigger a recovery rollback by accident.
        if previous and previous.get("state") == "pending":
            previous_incident = previous.get("incident_id")
            if previous_incident != req.incident_id:
                await record("rollback_recovery_blocked", {"pending_incident_id": previous_incident})
                return (f"escalated:rollback_recovery_required: pending canary from incident "
                        f"{previous_incident}; human review required")
            rollback_patch = previous.get("rollback")
            if not isinstance(rollback_patch, list) or not rollback_patch:
                await record("rollback_recovery_blocked", {"reason": "saved rollback patch missing"})
                return "escalated:rollback_recovery_required: saved rollback patch is missing"
            try:
                await _write(gate, ns, "recover_rollback_after_restart",
                             apps_api.patch_namespaced_deployment, name, ns, rollback_patch)
            except ModeBlocked as b:
                await record("rollback_recovery_blocked", {"reason": "kill switch", "step": b.step})
                return (f"stopped_mode_test: recovery rollback blocked at {b.step}; "
                        "workload requires human review")
            ok = await poll_until(lambda: _rollout_done(apps_api, ns, name), timeout_s, poll_s, sleep, clock)
            if not ok:
                await record("rollback_recovery_timeout", {})
                return "patch_failed: restart recovery rollback did not settle; escalated to HUMAN"
            await store.set_state(ns, name, req.incident_id, "recovered")
            await record("rollback_recovered_after_restart", {"incident_id": req.incident_id})
            return "rolled_back:executor_restart_recovery"

        raw_live = to_dict(await apps_api.read_namespaced_deployment(name, ns)).get("spec") or {}
        live = drift_view(raw_live)
        candidates = req.patch_fields or ([req.patch_field] if req.patch_field else [])
        try:
            plan = build_patch(golden.get("spec") or {}, live, candidates)
            validate_patch_target(raw_live, live, plan.target)
        except PlanError as e:
            await record("plan_refused", {"reason": str(e), "candidates": candidates})
            return f"escalated:{e}"
        await record("plan", {"field": req.patch_field, "candidates": candidates, "rule_path": req.rule_path,
                              "drifted": plan.drifted, "patch": plan.forward})

        before = await metric_source(ns, name, window_s)
        await record("metrics_before", {"metrics": before})
        if not any((before or {}).get(k) is not None for k in METRIC_KEYS):
            return "escalated:no_pre_patch_metrics: nothing to compare the canary against"

        # A "pending" rollback point must exist only while a patch may really be in flight. Check the gate
        # first, so a dry run (or test mode) never leaves a pending record behind.
        if not gate_open(gate, ns):
            if gate is not None and hasattr(gate, "record_step"):
                await gate.record_step(ns, planned[0], "blocked_by_kill_switch")
            raise ModeBlocked(planned[0])
        try:
            await store.save(ns, name, {"incident_id": req.incident_id, "live_spec": live,
                                        "rollback": plan.rollback, "restore_strategy": plan.restore_strategy,
                                        "saved_at": time.time(), "state": "pending"})
        except Exception as e:
            await record("rollback_point_failed", {"error": str(e)})
            return f"escalated:rollback_point_not_saved:{e}"
        saved = True
        await record("rollback_point_saved", {"rollback": plan.rollback})

        patch_started = True
        await _write(gate, ns, planned[0], apps_api.patch_namespaced_deployment, name, ns, plan.forward)
        patch_started = False
        done.append("patch_deployment")
        await record("patched", {"drifted": plan.drifted})

        ok = await poll_until(lambda: _rollout_done(apps_api, ns, name), timeout_s, poll_s, sleep, clock)
        if not ok:
            await record("rollout_timeout", {})
            return await _roll_back(gate, apps_api, req, plan, record, done, "rollout did not settle in time",
                                    timeout_s, poll_s, sleep, clock, store)

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
                                        f"window {i}: {why}", timeout_s, poll_s, sleep, clock, store)

        if plan.restore_strategy:
            await _write(gate, ns, "restore_strategy", apps_api.patch_namespaced_deployment,
                         name, ns, plan.restore_strategy)
            done.append("restore_strategy")
            await record("strategy_restored", {})
        await record("kept", {"windows": CANARY_WINDOWS})
        await store.set_state(ns, name, req.incident_id, "kept")
        return "patched_kept"
    except ModeBlocked as b:
        await record("blocked", {"step": b.step})
        if saved and not done:        # the gate closed between the save and the patch: nothing was patched
            await _discard_pending(store, req, record, "blocked before the patch")
        return _blocked_outcome(f"PATCH {ns}/{name}", planned, done, b)
    except Exception as e:
        logger.error(f"drift path failed for {ns}/{name}: {e}")
        await record("failed", {"error": str(e)})
        # Nothing was patched when the failure came before the patch call, or when the API refused the
        # patch with a client error. An ambiguous failure of the patch call (timeout, connection loss)
        # may have been applied, so that pending rollback point stays for recovery or a human.
        if saved and not done and (not patch_started or _not_applied(e)):
            await _discard_pending(store, req, record, f"failed before anything was patched: {e}")
        if done:
            return f"patch_failed:{e}; completed {done}; the rollback point is in Redis"
        if isinstance(e, LedgerUnavailable):
            # Refused before anything was written (the "about to do" entry failed). `patch_failed` would write
            # a 7-day done marker and a re-approval of this incident after MinIO recovers would be skipped;
            # `escalated:` is not final, so the retry really runs. A human is still told.
            return f"escalated:{e}"
        return f"patch_failed:{e}"


def _not_applied(exc: Exception) -> bool:
    """True when the patch cannot have been applied: the API server rejected it outright (4xx), or the
    "about to do" ledger write failed inside `_write` before the call was made (LedgerUnavailable)."""
    if isinstance(exc, LedgerUnavailable):
        return True
    status = getattr(exc, "status", None)
    return isinstance(status, int) and 400 <= status < 500 and status not in (408, 429)


async def _discard_pending(store: RollbackStore, req: Request, record: Recorder, why: str) -> None:
    """Make this request's pending rollback point terminal. Never raises: the outcome stays the same."""
    try:
        await store.set_state(req.namespace, req.deployment, req.incident_id, "failed")
        await record("rollback_point_discarded", {"reason": why})
    except Exception as e:
        logger.error(f"could not close the pending rollback point of {req.namespace}/{req.deployment}: {e}")
        await record("rollback_point_discard_failed", {"error": str(e)})


async def _roll_back(gate, apps_api, req: Request, plan: PatchPlan, record: Recorder,
                     done: List[str], reason: str, timeout_s: float, poll_s: float,
                     sleep: Callable, clock: Callable, store: RollbackStore) -> str:
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
    if not await poll_until(lambda: _rollout_done(apps_api, ns, name), timeout_s, poll_s, sleep, clock):
        await record("rollback_rollout_timeout", {"reason": reason})
        return f"patch_failed:rollback rollout did not settle after canary failure ({reason}); escalated to HUMAN"
    await store.set_state(ns, name, req.incident_id, "rolled_back")
    await record("rolled_back", {"reason": reason})
    return f"rolled_back:{reason}"
