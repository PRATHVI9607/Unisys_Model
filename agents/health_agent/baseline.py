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

Ledger payloads of `baseline_promoted` and `baseline_promotion_aborted` carry `applied: false`: the entry is written
BEFORE the overwrite and never updated. To know whether a promotion was applied, read the golden record: its
`promotion.ledger_key` names the `baseline_promoted` entry that produced it. An entry that no golden record points
to (and that is followed by a `baseline_promotion_aborted` entry naming it) was not applied.

Kill switch: the golden record is a Redis write the kill switch does not gate by itself, so a promotion honours the
mode like every other writer. In mode `test`, or when the mode is unknown or unreadable (fail safe to test), an
AUTOMATIC promotion does not overwrite the record: it appends one ledger entry `baseline_promotion_dry_run` (what it
would have promoted: previous and candidate digests, changed fields, evidence, the mode) and nothing else.
`approve_promotion` takes the caller's mode view and is a dry run in the same cases (ledger entry, candidate stays
pending, status `dry_run`). A prod candidate is only a proposal, so it is stored in any mode.

Coordination (V5-D5 review): before an automatic promotion, a candidate, and an approval the code refuses while
the workload has a pending Executor rollback record (`kubeheal:rollback:<ns>:<name>` with state "pending"), a held
incident lock (`kubeheal:incident-lock:<ns>:<name>`), a Fusion incident whose `action_state` is queued or
human_pending (hash `kubeheal:fusion:incident:<id>` with namespace and deployment; Fusion never clears that
state, so it blocks until the hash expires, INCIDENT_CONTEXT_TTL_S, a conservative choice), a cool-off marker
(`kubeheal:baseline-cooloff:<ns>:<name>`, set by the Health Agent after any event that was not benign and certain)
or a veto of the spec (`kubeheal:baseline-veto:<ns>:<name>` holds the spec hash of a non-benign or uncertain
verdict). A Redis error while reading any of them also refuses (fail closed).

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
import math
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from agents.common import killswitch

logger = logging.getLogger(__name__)

BASELINE_PREFIX = "kubeheal:baseline"
CANDIDATE_PREFIX = "kubeheal:baseline-candidate"
REJECTED_PREFIX = "kubeheal:baseline-candidate-rejected"
CANDIDATE_SCHEMA = 1

AUTO_TIERS = ("dev", "staging")          # promoted automatically; every other tier (prod, unknown) needs approval
AUTO_ACTOR = "health-agent"

ROLLBACK_PREFIX = "kubeheal:rollback"            # agents/executor/drift.py ROLLBACK_PREFIX (copied: no Executor import)
LOCK_PREFIX = "kubeheal:incident-lock"           # agents/fusion_agent/incident_lock.py LOCK_PREFIX
FUSION_INCIDENT_PREFIX = "kubeheal:fusion:incident"   # agents/fusion_agent/agent.py INCIDENT_PREFIX
OPEN_INCIDENT_STATES = ("queued", "human_pending")    # Fusion's action_state values
COOLOFF_PREFIX = "kubeheal:baseline-cooloff"
VETO_PREFIX = "kubeheal:baseline-veto"
VETO_TTL_S = 86400                                # chosen, not measured
SECURITY_SCORE_PREFIX = "kubeheal:security:score"      # written by the Security Agent (sec_risk, ts_ms, model_scored)
# agents/fusion_agent/decision_policy.py RAW_SEC_RISK_PATCH_CEILING (copied so the Health image needs no policy module)
RAW_SEC_RISK_CEILING = 0.4
MAX_APPROVER_LEN = 128                            # chosen
MAX_REASON_LEN = 512                              # chosen

STEP_PROMOTED = "baseline_promoted"
STEP_ABORTED = "baseline_promotion_aborted"
STEP_DRY_RUN = "baseline_promotion_dry_run"
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


_DNS_LABEL = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
_NAMESPACE_RE = re.compile(rf"^{_DNS_LABEL}$")
_NAME_RE = re.compile(rf"^{_DNS_LABEL}(\.{_DNS_LABEL})*$")


def validate_workload(namespace: str, deployment: str) -> None:
    """DNS-1123 names only: a colon in a namespace could alias another workload's `ns:name` key."""
    if not isinstance(namespace, str) or len(namespace) > 63 or not _NAMESPACE_RE.match(namespace):
        raise ValueError("namespace must be a DNS-1123 label")
    if not isinstance(deployment, str) or len(deployment) > 253 or not _NAME_RE.match(deployment):
        raise ValueError("deployment must be a DNS-1123 subdomain name")


def baseline_key(namespace: str, deployment: str) -> str:
    return f"{BASELINE_PREFIX}:{namespace}:{deployment}"


def candidate_key(namespace: str, deployment: str) -> str:
    return f"{CANDIDATE_PREFIX}:{namespace}:{deployment}"


def rejected_key(namespace: str, deployment: str) -> str:
    return f"{REJECTED_PREFIX}:{namespace}:{deployment}"


def cooloff_key(namespace: str, deployment: str) -> str:
    return f"{COOLOFF_PREFIX}:{namespace}:{deployment}"


def veto_key(namespace: str, deployment: str) -> str:
    return f"{VETO_PREFIX}:{namespace}:{deployment}"


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


def _norm_map(h: Any) -> Dict[str, Optional[str]]:
    """A Redis hash with keys and values as str, whether the client decodes responses or returns bytes (the
    dashboard's client may not decode)."""
    return {_text(k): _text(v) for k, v in (h or {}).items()}


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
    raw = _text(await redis.get(key))
    return json.loads(raw), False


async def load_baseline(redis, namespace: str, deployment: str) -> Optional[Dict]:
    raw = _text(await redis.get(baseline_key(namespace, deployment)))
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


MAX_VETOED_HASHES = 32     # chosen: the newest vetoed spec hashes of one workload that are kept


async def vetoed_hashes(redis, namespace: str, deployment: str) -> set:
    """Spec hashes vetoed for the workload. The value is a JSON list; the old form (one plain hash string) is
    still read. An unreadable value is returned as a hash nothing can match, so it is simply ignored here, but a
    Redis error propagates (the caller fails closed)."""
    raw = _text(await redis.get(veto_key(namespace, deployment)))
    if not raw:
        return set()
    if raw.lstrip().startswith("["):
        try:
            return {str(x) for x in json.loads(raw)}
        except ValueError:
            return set()
    return {raw}


async def add_veto(redis, namespace: str, deployment: str, spec_hash: str) -> None:
    """Add a spec hash to the workload's veto set (JSON list, newest last, at most MAX_VETOED_HASHES) and refresh
    the 24 h expiry."""
    try:
        old = _text(await redis.get(veto_key(namespace, deployment)))
    except Exception:
        old = None
    if old and old.lstrip().startswith("["):
        try:
            hashes = [str(x) for x in json.loads(old)]
        except ValueError:
            hashes = []
    else:
        hashes = [old] if old else []
    if spec_hash in hashes:
        hashes.remove(spec_hash)
    hashes.append(spec_hash)
    await redis.set(veto_key(namespace, deployment), json.dumps(hashes[-MAX_VETOED_HASHES:]), ex=VETO_TTL_S)


# ── coordination and security gates ──────────────────────────────────────────
async def coordination_blocker(redis, namespace: str, deployment: str, spec_hash: Optional[str] = None
                               ) -> Optional[str]:
    """None when nothing else is acting on the workload, otherwise why a promotion (or candidate, or approval)
    must wait. A Redis error is a blocker (fail closed)."""
    try:
        raw = _text(await redis.get(f"{ROLLBACK_PREFIX}:{namespace}:{deployment}"))
        if raw:
            try:
                state = (json.loads(raw) or {}).get("state")
            except (ValueError, AttributeError):
                return "the Executor rollback record is unreadable"
            if state == "pending":
                return "an Executor rollback is pending"
        if await redis.get(f"{LOCK_PREFIX}:{namespace}:{deployment}"):
            return "the incident lock is held"
        if await redis.get(cooloff_key(namespace, deployment)):
            return "cool-off after a non-benign or uncertain event"
        if spec_hash and spec_hash in await vetoed_hashes(redis, namespace, deployment):
            return "this spec was vetoed by an earlier non-benign or uncertain verdict"
        async for key in redis.scan_iter(match=f"{FUSION_INCIDENT_PREFIX}:*"):
            fields = _norm_map(await redis.hgetall(key))
            if (fields.get("namespace") == namespace and fields.get("deployment") == deployment
                    and fields.get("action_state") in OPEN_INCIDENT_STATES):
                return f"a Fusion incident is open ({fields.get('action_state')})"
    except Exception as e:
        return f"coordination state is unreadable ({e!r})"
    return None


async def security_blocker(redis, namespace: str, deployment: str, *, now_ms: float, fresh_s: float,
                           require: bool, ceiling: float = RAW_SEC_RISK_CEILING) -> Optional[str]:
    """Refuse while a fresh Security Agent score says the workload is under attack (sec_risk at or above the
    ceiling, or not model scored). A missing or stale hash blocks only when `require` is set (default off)."""
    try:
        h = _norm_map(await redis.hgetall(f"{SECURITY_SCORE_PREFIX}:{namespace}:{deployment}"))
    except Exception as e:
        return f"the security score is unreadable ({e!r})"
    fresh = False
    if h:
        try:
            ts_ms = float(h["ts_ms"])
            fresh = math.isfinite(ts_ms) and abs(now_ms - ts_ms) <= fresh_s * 1000.0
        except (KeyError, TypeError, ValueError):
            return "the security score hash is malformed"
    if h and fresh:
        if str(h.get("model_scored", "")).strip().lower() != "true":
            return "the fresh security score was not model scored"
        try:
            risk = float(h["sec_risk"])
        except (KeyError, TypeError, ValueError):
            return "the security score hash is malformed"
        if not math.isfinite(risk) or risk >= ceiling:
            return f"raw security risk {risk} is at or above {ceiling}"
        return None
    return "no fresh security score (HEALTH_PROMOTION_REQUIRE_SECURITY is on)" if require else None


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
    validate_workload(namespace, deployment)
    if ledger is None:
        return {"status": "no_ledger"}
    previous = json.loads(golden_raw) if golden_raw else None
    if previous is None:
        return {"status": "no_baseline"}
    record = make_record(new_spec)
    payload = {
        "namespace": namespace, "deployment": deployment, "tier": tier, "kind": kind, "approver": actor,
        "reason": reason, "candidate_id": candidate_id,
        "applied": False,       # always false: written before the overwrite; see the module docstring
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
                abort_reason = ("superseded or no longer allowed (spec, mode, cool-off or veto) while the ledger "
                                "entry was written")
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
    if await _ledger_best_effort(ledger, namespace, deployment, STEP_ABORTED,
                                 {"namespace": namespace, "deployment": deployment,
                                  "promotion_ledger_key": entry.key, "reason": abort_reason,
                                  "applied": False}) is None:
        logger.error(f"the abort entry for the promotion ledgered at {entry.key} could not be written: that entry "
                     "was NOT applied (the golden record does not point to it)")
    return {"status": status, "reason": abort_reason, "ledger_key": entry.key}


async def record_dry_run(ledger, namespace: str, deployment: str, *, new_spec: Dict, spec_hash: str,
                         golden_raw: str, kind: str, actor: str, tier: str = "", evidence: Optional[Dict] = None,
                         changed_fields: Optional[List[str]] = None, mode: str = "test",
                         candidate_id: Optional[str] = None) -> Dict:
    """Mode test (or unknown): write ONLY the ledger entry for what a promotion would have done. Returns
    {"status": "dry_run", "ledger_key": ...}, {"status": "no_ledger"} or {"status": "ledger_failed"}."""
    validate_workload(namespace, deployment)
    if ledger is None:
        return {"status": "no_ledger"}
    previous = json.loads(golden_raw) if golden_raw else None
    record = make_record(new_spec)
    payload = {
        "namespace": namespace, "deployment": deployment, "tier": tier, "kind": kind, "approver": actor,
        "candidate_id": candidate_id, "mode": mode, "applied": False,
        "dry_run": f"DRY RUN: would have promoted the golden baseline of {namespace}/{deployment}",
        "previous_text_sha256": raw_digest(golden_raw) if golden_raw else None,
        "previous_spec_digest": record_digest(previous) if previous else None,
        "candidate_spec_digest": record_digest(record), "new_spec_hash": spec_hash,
        "changed_fields": list(changed_fields or []), "evidence": evidence or {},
    }
    try:
        entry = await _ledger(ledger, namespace, deployment, STEP_DRY_RUN, payload)
    except Exception as e:
        logger.error(f"dry-run entry for the baseline promotion of {namespace}/{deployment} not written ({e!r})")
        return {"status": "ledger_failed", "error": repr(e)}
    logger.warning(f"DRY RUN: baseline promotion of {namespace}/{deployment} ({kind}) not applied, mode {mode}")
    return {"status": "dry_run", "ledger_key": entry.key}


# ── candidates (prod and unknown tier) ───────────────────────────────────────
def candidate_id_for(namespace: str, deployment: str, spec_hash: str, golden_raw: str) -> str:
    material = f"{namespace}\0{deployment}\0{spec_hash}\0{raw_digest(golden_raw)}".encode()
    return hashlib.sha256(material).hexdigest()[:24]


async def get_candidate(redis, namespace: str, deployment: str) -> Optional[Dict]:
    raw = _text(await redis.get(candidate_key(namespace, deployment)))
    return json.loads(raw) if raw else None


async def list_candidates(redis) -> List[Dict]:
    """All pending candidates (uses SCAN: the dashboard side lists them)."""
    out = []
    async for key in redis.scan_iter(match=f"{CANDIDATE_PREFIX}:*"):
        raw = _text(await redis.get(key))
        if raw:
            out.append(json.loads(raw))
    return sorted(out, key=lambda c: (c.get("namespace", ""), c.get("deployment", "")))


async def store_candidate(redis, ledger, namespace: str, deployment: str, *, new_spec: Dict, spec_hash: str,
                          golden_raw: str, tier: str, changed_fields: List[str], assessment: Dict) -> Dict:
    """Write the promotion candidate for prod and an unknown tier. No ledger is needed to store it (the ledger
    entry `baseline_candidate_created` is best effort). Idempotent per candidate id. A different older candidate
    is superseded (ledger entry first, best effort). Returns {"status": "stored" | "unchanged" | "rejected_before"}."""
    validate_workload(namespace, deployment)
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


def _check_actor(approver: str, reason: str) -> None:
    if not isinstance(approver, str) or not approver.strip():
        raise ValueError("approver must be a non-empty string")
    if len(approver.strip()) > MAX_APPROVER_LEN:
        raise ValueError(f"approver is longer than {MAX_APPROVER_LEN} characters")
    if approver.strip().lower() == AUTO_ACTOR:
        raise ValueError(f"{AUTO_ACTOR!r} is reserved for automatic promotions")
    if not isinstance(reason, str) or len(reason) > MAX_REASON_LEN:
        raise ValueError(f"reason must be a string of at most {MAX_REASON_LEN} characters")


async def approve_promotion(redis, namespace: str, deployment: str, approver: str, ledger,
                            candidate_id: str, reason: str = "", *, mode: Optional[str] = None) -> Dict:
    """Approve the pending candidate (called by the dashboard). `candidate_id` is REQUIRED and must match the
    candidate the approver looked at. ValueError for an invalid workload name, approver (empty, over 128
    characters, or the reserved automatic actor) or reason (over 512 characters). Statuses: promoted, not_found,
    id_mismatch, no_ledger, no_baseline, blocked (another actor is on the workload, see `coordination_blocker`;
    the candidate stays pending), stale (the golden baseline moved since the candidate was assessed: the
    candidate is superseded), dry_run (`mode` is not exactly "enforce", or unknown: a ledger entry
    `baseline_promotion_dry_run` is written, nothing is overwritten, the candidate stays pending), ledger_failed,
    aborted, conflict (see `promote_baseline`). `mode` is the caller's effective kill-switch mode for the
    namespace ("enforce" or "test"); the default None means unknown and is a dry run (fail safe). Pass a callable
    returning the mode to have it asked again right before the overwrite (after the ledger write); a plain string
    is a snapshot taken by the caller."""
    validate_workload(namespace, deployment)
    _check_actor(approver, reason)
    if not candidate_id or not isinstance(candidate_id, str):
        raise ValueError("candidate_id is required")
    candidate = await get_candidate(redis, namespace, deployment)
    if candidate is None:
        return {"status": "not_found"}
    if candidate.get("candidate_id") != candidate_id:
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
    blocker = await coordination_blocker(redis, namespace, deployment, candidate.get("spec_hash"))
    if blocker:
        logger.warning(f"approval of the baseline candidate of {namespace}/{deployment} refused: {blocker}")
        return {"status": "blocked", "reason": blocker}
    current_mode = mode() if callable(mode) else mode
    if killswitch.is_dry_run(current_mode):
        return await record_dry_run(
            ledger, namespace, deployment, new_spec=candidate["spec"], spec_hash=candidate["spec_hash"],
            golden_raw=golden_raw, kind="approved", actor=approver.strip(), tier=candidate.get("tier", ""),
            evidence=candidate.get("assessment") or {}, changed_fields=candidate.get("changed_fields") or [],
            mode=killswitch.normalize(current_mode), candidate_id=candidate.get("candidate_id"))
    result = await promote_baseline(
        redis, ledger, namespace, deployment, new_spec=candidate["spec"], spec_hash=candidate["spec_hash"],
        golden_raw=golden_raw, kind="approved", actor=approver.strip(), tier=candidate.get("tier", ""),
        evidence=candidate.get("assessment") or {}, changed_fields=candidate.get("changed_fields") or [],
        candidate_id=candidate.get("candidate_id"), reason=reason,
        proceed=(lambda: not killswitch.is_dry_run(mode())) if callable(mode) else None)
    if result["status"] == "promoted":
        current = await get_candidate(redis, namespace, deployment)
        if current and current.get("candidate_id") == candidate.get("candidate_id"):
            await redis.delete(candidate_key(namespace, deployment))
    return result


async def reject_promotion(redis, namespace: str, deployment: str, approver: str, ledger,
                           candidate_id: str, reason: str = "") -> Dict:
    """Reject the pending candidate (`candidate_id` is REQUIRED; same validation as `approve_promotion`). Ledger entry first; if it fails the candidate stays pending. The spec hash
    is remembered so the agent does not propose the same spec again (cleared when the live spec changes).
    Statuses: rejected, not_found, id_mismatch, no_ledger, ledger_failed."""
    validate_workload(namespace, deployment)
    _check_actor(approver, reason)
    if not candidate_id or not isinstance(candidate_id, str):
        raise ValueError("candidate_id is required")
    candidate = await get_candidate(redis, namespace, deployment)
    if candidate is None:
        return {"status": "not_found"}
    if candidate.get("candidate_id") != candidate_id:
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
