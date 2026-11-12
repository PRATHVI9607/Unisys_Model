"""
Golden baseline store (S-HA-2 / S-HA-3) and baseline promotion (V5-D5, owner decision D3).
=========================================================================================
The golden baseline of a workload lives under `kubeheal:baseline:<namespace>:<deployment>`.

The FIRST baseline is written on first sight with SET NX (`get_or_set_baseline`): persistent drift never
replaces it. After that the golden baseline is overwritten ONLY by

  1. a PROMOTION (`promote_baseline`): the Health Agent judged the current spec benign AND certain (the
     conformal prediction set is exactly {benign}), the rollout is complete, there are no failure reasons and no
     posture violation, and the spec differs from the golden baseline. Policy by tier:
       dev, staging   automatic (needs a configured ledger; HEALTH_BASELINE_PROMOTION=off disables it);
       prod, unknown  the agent only stores a promotion CANDIDATE (`store_candidate`); a human approves it
                      (`approve_promotion`) or rejects it (`reject_promotion`), the dashboard calls those.
  2. the operator tool `scripts/baseline_tool.py` (`reset`, `restore`).

Ledger first: every promotion, automatic or approved, appends a ledger entry (step `baseline_promoted`) that
KEEPS the previous golden record in full (plus its digest and a pointer to the promotion that created it) BEFORE
the key is overwritten. If the ledger write fails nothing is promoted (fail closed). A rejected or superseded
candidate is a ledger entry too. The overwrite itself is a compare-and-set against the exact golden text the
decision was based on, so two promoters (or the tool) can never both win.

The drift diff is always live spec versus golden baseline. The Executor (P2 onwards) reads the same key to
restore a drifted Deployment.

Candidate key (JSON string), written by the Health Agent, read and removed by the dashboard side:
  `kubeheal:baseline-candidate:<namespace>:<deployment>`
    schema 1, candidate_id, namespace, deployment, tier, spec_hash (hash of the candidate drift view),
    golden_sha256 (digest of the golden text the candidate was assessed against), spec, template,
    changed_fields, assessment {label, risk, prediction_set, model_version, event_id}, created_at, status "pending"
  `kubeheal:baseline-candidate-rejected:<namespace>:<deployment>` holds the spec_hash of a rejected candidate so
  the agent does not propose the same spec again; it is removed when the live spec changes.
A candidate is dropped (ledger entry `baseline_candidate_superseded`) when the live spec changes again, when the
golden baseline changes under it, or when the workload is deleted.
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

BASELINE_PREFIX = "kubeheal:baseline"
CANDIDATE_PREFIX = "kubeheal:baseline-candidate"
REJECTED_PREFIX = "kubeheal:baseline-candidate-rejected"
CANDIDATE_SCHEMA = 1

AUTO_TIERS = ("dev", "staging")          # promoted automatically; every other tier (prod, unknown) needs approval
AUTO_ACTOR = "health-agent"

STEP_PROMOTED = "baseline_promoted"
STEP_ABORTED = "baseline_promotion_aborted"
STEP_CANDIDATE = "baseline_candidate_created"
STEP_REJECTED = "baseline_candidate_rejected"
STEP_SUPERSEDED = "baseline_candidate_superseded"

# Compare-and-set overwrite: only replace the golden text the decision was based on.
PROMOTE_BASELINE_LUA = """
-- kubeheal:promote_baseline
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2])
  return 1
end
return 0
"""

_OFF_VALUES = {"off", "false", "0", "no", "disabled", "disable"}


def baseline_key(namespace: str, deployment: str) -> str:
    return f"{BASELINE_PREFIX}:{namespace}:{deployment}"


def candidate_key(namespace: str, deployment: str) -> str:
    return f"{CANDIDATE_PREFIX}:{namespace}:{deployment}"


def rejected_key(namespace: str, deployment: str) -> str:
    return f"{REJECTED_PREFIX}:{namespace}:{deployment}"


def ledger_incident_id(namespace: str, deployment: str) -> str:
    """One ledger incident per workload. Namespaces are DNS labels (no dots), so the id is unambiguous."""
    return f"baseline.{namespace}.{deployment}"


def drift_view(spec: Dict) -> Dict:
    """The part of a Deployment spec that counts as configuration drift.
    `replicas` is excluded: scaling (HPA, kubectl scale) is not drift."""
    return {k: v for k, v in (spec or {}).items() if k != "replicas"}


def make_record(spec: Dict) -> Dict:
    view = drift_view(spec)
    return {
        "spec": view,
        "template": view.get("template", {}),
        "stored_at": datetime.now(timezone.utc).isoformat(),
    }


def _text(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    return raw.decode() if isinstance(raw, (bytes, bytearray)) else raw


def raw_digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def record_digest(record: Dict) -> str:
    """Digest of the golden spec (the drift view), stable across the extra bookkeeping fields."""
    return hashlib.sha256(json.dumps((record or {}).get("spec") or {}, sort_keys=True).encode()).hexdigest()


# ── first baseline and reads ─────────────────────────────────────────────────
async def get_or_set_baseline(redis, namespace: str, deployment: str,
                              live_spec: Dict) -> Tuple[Dict, bool]:
    """Return (golden_record, created). `created` is True only for the call that wrote it (SET NX)."""
    key = baseline_key(namespace, deployment)
    record = make_record(live_spec)
    created = await redis.set(key, json.dumps(record, sort_keys=True), nx=True)
    if created:
        return record, True
    raw = await redis.get(key)
    return json.loads(raw), False


async def load_baseline(redis, namespace: str, deployment: str) -> Optional[Dict]:
    raw = await redis.get(baseline_key(namespace, deployment))
    return json.loads(raw) if raw else None


async def load_baseline_raw(redis, namespace: str, deployment: str) -> Optional[Tuple[str, Dict]]:
    """(exact stored text, parsed record): the text is what a promotion compares and sets against."""
    raw = _text(await redis.get(baseline_key(namespace, deployment)))
    return (raw, json.loads(raw)) if raw else None


def is_drifted(golden: Dict, live_spec: Dict) -> bool:
    return golden.get("spec") != drift_view(live_spec)


# ── promotion policy (pure) ──────────────────────────────────────────────────
def promotion_enabled_from_env(env: Optional[Dict[str, str]] = None) -> bool:
    """HEALTH_BASELINE_PROMOTION: on (default) or off. `off` (also false, 0, no, disabled) disables AUTOMATIC
    promotion in dev and staging; prod candidates are still stored."""
    import os
    env = os.environ if env is None else env
    return (env.get("HEALTH_BASELINE_PROMOTION") or "on").strip().lower() not in _OFF_VALUES


def verdict_blocker(label: str, prediction_set: List[str], uncertain: bool, failure_reasons: List[str],
                    rollout_done: bool) -> Optional[str]:
    """None when the assessment allows a promotion, otherwise the first reason it does not."""
    if label != "benign":
        return f"label is {label}, not benign"
    if list(prediction_set) != ["benign"] or uncertain:
        return "prediction set is not exactly {benign}"
    if failure_reasons:
        return f"failure reasons present: {sorted(failure_reasons)}"
    if not rollout_done:
        return "rollout is not complete"
    return None


def promotion_route(tier: str, auto_enabled: bool, ledger_available: bool) -> Tuple[str, str]:
    """("auto" | "candidate" | "none", reason). prod and an unknown tier get a candidate, never an automatic one."""
    if tier not in AUTO_TIERS:
        return "candidate", f"tier {tier or 'unknown'} needs approval"
    if not auto_enabled:
        return "none", "automatic promotion is switched off (HEALTH_BASELINE_PROMOTION)"
    if not ledger_available:
        return "none", "no ledger configured (a promotion must be ledgered first)"
    return "auto", f"tier {tier} promotes automatically"


# ── ledger helpers ───────────────────────────────────────────────────────────
async def _ledger(ledger, namespace: str, deployment: str, step: str, payload: Dict):
    """Append one entry (blocking store call off the event loop). Raises on failure."""
    return await asyncio.to_thread(ledger.append, ledger_incident_id(namespace, deployment), step, payload)


async def _ledger_best_effort(ledger, namespace: str, deployment: str, step: str, payload: Dict) -> Optional[str]:
    if ledger is None:
        return None
    try:
        return (await _ledger(ledger, namespace, deployment, step, payload)).key
    except Exception as e:
        logger.error(f"ledger entry {step} for {namespace}/{deployment} failed: {e!r}")
        return None


# ── promotion ────────────────────────────────────────────────────────────────
async def promote_baseline(redis, ledger, namespace: str, deployment: str, *, new_spec: Dict, spec_hash: str,
                           golden_raw: str, kind: str, actor: str, tier: str = "", evidence: Optional[Dict] = None,
                           changed_fields: Optional[List[str]] = None, candidate_id: Optional[str] = None,
                           reason: str = "", proceed: Optional[Callable[[], bool]] = None) -> Dict:
    """Replace the golden baseline by `new_spec` (its drift view). `golden_raw` is the exact stored text of the
    golden record the decision was based on. Returns {"status": ...}:
      promoted     ledger entry written, key overwritten; also "ledger_key", "record"
      no_ledger    no ledger given: nothing happens
      no_baseline  there is no golden record to replace
      ledger_failed  the ledger write failed: baseline untouched (fail closed)
      aborted      `proceed()` said no after the ledger write (the spec was superseded); an abort entry is
                   appended and the baseline is untouched
      conflict     the golden text changed since `golden_raw` was read (another promotion or the tool): untouched
    """
    if ledger is None:
        return {"status": "no_ledger"}
    previous = json.loads(golden_raw) if golden_raw else None
    if previous is None:
        return {"status": "no_baseline"}
    record = make_record(new_spec)
    payload = {
        "namespace": namespace, "deployment": deployment, "tier": tier, "kind": kind, "approver": actor,
        "reason": reason, "candidate_id": candidate_id,
        "previous": previous, "previous_spec_digest": record_digest(previous),
        "previous_text_sha256": raw_digest(golden_raw), "previous_promotion": previous.get("promotion"),
        "new": record, "new_spec_hash": spec_hash, "new_spec_digest": record_digest(record),
        "changed_fields": list(changed_fields or []), "evidence": evidence or {},
    }
    try:
        entry = await _ledger(ledger, namespace, deployment, STEP_PROMOTED, payload)
    except Exception as e:
        logger.error(f"baseline promotion of {namespace}/{deployment} refused: ledger write failed ({e!r}); "
                     "the golden baseline is unchanged")
        return {"status": "ledger_failed", "error": repr(e)}
    record["promotion"] = {"kind": kind, "approver": actor, "ledger_key": entry.key,
                           "incident_id": ledger_incident_id(namespace, deployment),
                           "previous_text_sha256": payload["previous_text_sha256"],
                           "promoted_at": datetime.now(timezone.utc).isoformat()}
    abort_reason = None
    if proceed is not None:
        try:
            if not proceed():
                abort_reason = "the spec was superseded while the ledger entry was written"
        except Exception as e:
            abort_reason = f"final check failed: {e!r}"
    if abort_reason is None:
        won = await redis.eval(PROMOTE_BASELINE_LUA, 1, baseline_key(namespace, deployment), golden_raw,
                               json.dumps(record, sort_keys=True))
        if not won:
            abort_reason = "the golden baseline changed since the decision (compare-and-set lost)"
            status = "conflict"
        else:
            logger.info(f"golden baseline of {namespace}/{deployment} promoted ({kind}, ledger {entry.key})")
            return {"status": "promoted", "ledger_key": entry.key, "record": record}
    else:
        status = "aborted"
    logger.warning(f"baseline promotion of {namespace}/{deployment} not applied: {abort_reason}")
    await _ledger_best_effort(ledger, namespace, deployment, STEP_ABORTED,
                              {"namespace": namespace, "deployment": deployment, "promotion_ledger_key": entry.key,
                               "reason": abort_reason})
    return {"status": status, "reason": abort_reason, "ledger_key": entry.key}


# ── candidates (prod and unknown tier) ───────────────────────────────────────
def candidate_id_for(namespace: str, deployment: str, spec_hash: str, golden_raw: str) -> str:
    material = f"{namespace}\0{deployment}\0{spec_hash}\0{raw_digest(golden_raw)}".encode()
    return hashlib.sha256(material).hexdigest()[:24]


async def get_candidate(redis, namespace: str, deployment: str) -> Optional[Dict]:
    raw = await redis.get(candidate_key(namespace, deployment))
    return json.loads(raw) if raw else None


async def list_candidates(redis) -> List[Dict]:
    """All pending candidates (uses SCAN: the dashboard side lists them)."""
    out = []
    async for key in redis.scan_iter(match=f"{CANDIDATE_PREFIX}:*"):
        raw = await redis.get(key)
        if raw:
            out.append(json.loads(raw))
    return sorted(out, key=lambda c: (c.get("namespace", ""), c.get("deployment", "")))


async def store_candidate(redis, ledger, namespace: str, deployment: str, *, new_spec: Dict, spec_hash: str,
                          golden_raw: str, tier: str, changed_fields: List[str], assessment: Dict) -> Dict:
    """Write the promotion candidate for prod and an unknown tier. No ledger is needed to store it (the ledger
    entry `baseline_candidate_created` is best effort). Idempotent per candidate id. A different older candidate
    is superseded (ledger entry first, best effort). Returns {"status": "stored" | "unchanged" | "rejected_before"}."""
    if _text(await redis.get(rejected_key(namespace, deployment))) == spec_hash:
        return {"status": "rejected_before"}
    cid = candidate_id_for(namespace, deployment, spec_hash, golden_raw)
    existing = await get_candidate(redis, namespace, deployment)
    if existing and existing.get("candidate_id") == cid:
        return {"status": "unchanged", "candidate_id": cid}
    if existing:
        await drop_candidate(redis, ledger, namespace, deployment, "a newer candidate replaced it")
    view = drift_view(new_spec)
    candidate = {
        "schema": CANDIDATE_SCHEMA, "candidate_id": cid, "namespace": namespace, "deployment": deployment,
        "tier": tier, "spec_hash": spec_hash, "golden_sha256": raw_digest(golden_raw),
        "spec": view, "template": view.get("template", {}), "changed_fields": list(changed_fields),
        "assessment": assessment, "created_at": datetime.now(timezone.utc).isoformat(), "status": "pending",
    }
    await redis.set(candidate_key(namespace, deployment), json.dumps(candidate, sort_keys=True))
    await _ledger_best_effort(ledger, namespace, deployment, STEP_CANDIDATE,
                              {"namespace": namespace, "deployment": deployment, "candidate_id": cid,
                               "tier": tier, "spec_hash": spec_hash, "changed_fields": list(changed_fields),
                               "assessment": assessment})
    return {"status": "stored", "candidate_id": cid}


async def drop_candidate(redis, ledger, namespace: str, deployment: str, reason: str) -> bool:
    """Remove a candidate that no longer applies (the live spec changed, a newer candidate, the golden baseline
    moved, the workload is gone). The ledger entry is best effort here: leaving a stale candidate in place would
    be the unsafe outcome, so a ledger failure is logged and the candidate is removed anyway."""
    candidate = await get_candidate(redis, namespace, deployment)
    if candidate is None:
        return False
    await _ledger_best_effort(ledger, namespace, deployment, STEP_SUPERSEDED,
                              {"namespace": namespace, "deployment": deployment,
                               "candidate_id": candidate.get("candidate_id"), "reason": reason,
                               "spec_hash": candidate.get("spec_hash")})
    await redis.delete(candidate_key(namespace, deployment))
    logger.info(f"baseline candidate of {namespace}/{deployment} dropped: {reason}")
    return True


def _check_approver(approver: str) -> None:
    if not isinstance(approver, str) or not approver.strip():
        raise ValueError("approver must be a non-empty string")


async def approve_promotion(redis, namespace: str, deployment: str, approver: str, ledger,
                            candidate_id: Optional[str] = None, reason: str = "") -> Dict:
    """Approve the pending candidate (called by the dashboard). `candidate_id`, when given, must match the
    candidate the approver looked at. Statuses: promoted, not_found, id_mismatch, no_ledger, no_baseline,
    stale (the golden baseline moved since the candidate was assessed: the candidate is superseded),
    ledger_failed, aborted, conflict (see `promote_baseline`)."""
    _check_approver(approver)
    candidate = await get_candidate(redis, namespace, deployment)
    if candidate is None:
        return {"status": "not_found"}
    if candidate_id is not None and candidate.get("candidate_id") != candidate_id:
        return {"status": "id_mismatch", "candidate_id": candidate.get("candidate_id")}
    if ledger is None:
        return {"status": "no_ledger"}        # approval needs the ledger; the candidate stays pending
    held = await load_baseline_raw(redis, namespace, deployment)
    if held is None:
        return {"status": "no_baseline"}
    golden_raw, _ = held
    if raw_digest(golden_raw) != candidate.get("golden_sha256"):
        await drop_candidate(redis, ledger, namespace, deployment,
                             "the golden baseline changed since the candidate was assessed")
        return {"status": "stale"}
    result = await promote_baseline(
        redis, ledger, namespace, deployment, new_spec=candidate["spec"], spec_hash=candidate["spec_hash"],
        golden_raw=golden_raw, kind="approved", actor=approver.strip(), tier=candidate.get("tier", ""),
        evidence=candidate.get("assessment") or {}, changed_fields=candidate.get("changed_fields") or [],
        candidate_id=candidate.get("candidate_id"), reason=reason)
    if result["status"] == "promoted":
        current = await get_candidate(redis, namespace, deployment)
        if current and current.get("candidate_id") == candidate.get("candidate_id"):
            await redis.delete(candidate_key(namespace, deployment))
    return result


async def reject_promotion(redis, namespace: str, deployment: str, approver: str, ledger,
                           candidate_id: Optional[str] = None, reason: str = "") -> Dict:
    """Reject the pending candidate. Ledger entry first; if it fails the candidate stays pending. The spec hash
    is remembered so the agent does not propose the same spec again (cleared when the live spec changes).
    Statuses: rejected, not_found, id_mismatch, no_ledger, ledger_failed."""
    _check_approver(approver)
    candidate = await get_candidate(redis, namespace, deployment)
    if candidate is None:
        return {"status": "not_found"}
    if candidate_id is not None and candidate.get("candidate_id") != candidate_id:
        return {"status": "id_mismatch", "candidate_id": candidate.get("candidate_id")}
    if ledger is None:
        return {"status": "no_ledger"}
    try:
        entry = await _ledger(ledger, namespace, deployment, STEP_REJECTED,
                              {"namespace": namespace, "deployment": deployment,
                               "candidate_id": candidate.get("candidate_id"), "approver": approver.strip(),
                               "reason": reason, "spec_hash": candidate.get("spec_hash"),
                               "changed_fields": candidate.get("changed_fields") or []})
    except Exception as e:
        logger.error(f"rejection of the baseline candidate of {namespace}/{deployment} not applied: "
                     f"ledger write failed ({e!r})")
        return {"status": "ledger_failed", "error": repr(e)}
    await redis.set(rejected_key(namespace, deployment), candidate.get("spec_hash", ""))
    await redis.delete(candidate_key(namespace, deployment))
    return {"status": "rejected", "ledger_key": entry.key}


async def clear_rejected_if_changed(redis, namespace: str, deployment: str, current_hash: str) -> None:
    """The live spec changed: a remembered rejection of an older spec no longer applies."""
    marker = _text(await redis.get(rejected_key(namespace, deployment)))
    if marker is not None and marker != current_hash:
        await redis.delete(rejected_key(namespace, deployment))
