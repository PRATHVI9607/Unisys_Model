"""Kubernetes evidence that a new Deployment spec cannot run ("failure_reasons").

Pure functions on plain dicts: API-shaped JSON (camelCase), as returned by
`ApiClient.sanitize_for_serialization`. No I/O, no Kubernetes client import, no clock except the optional
`now` default. The Health Agent calls these once it is wired in (a later task).

Ported from the teammate's "v5" Health Agent. The thresholds below are v5's values; we did not measure them.
"""
from __future__ import annotations

import time
from datetime import datetime

# Container waiting reasons that mean the new pods cannot run (v5's list).
WAITING_FAILURES = frozenset({"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CrashLoopBackOff",
                              "CreateContainerConfigError", "CreateContainerError", "RunContainerError"})

# creationTimestamp has whole-second resolution and the change is seen after the API write, so a pod created
# up to this many seconds before the change still counts as new (v5's value, not measured by us).
CREATED_SLACK_S = 5

# Running but never Ready: probe budget (initialDelay + period x failureThreshold, plus the same for a
# startupProbe) plus a margin for slow pods and probe timeouts, never below the floor (v5's values, not
# measured by us). Containers without a readiness probe are Ready as soon as they run and are ignored.
READY_MARGIN_S = 30
READY_FLOOR_S = 60
# Kubernetes probe defaults: initialDelaySeconds 0, periodSeconds 10, failureThreshold 3.
PROBE_DEFAULT_INITIAL_DELAY_S = 0
PROBE_DEFAULT_PERIOD_S = 10
PROBE_DEFAULT_FAILURE_THRESHOLD = 3

PROGRESS_DEADLINE_REASON = "ProgressDeadlineExceeded"
READINESS_REASON = "ReadinessNeverPassed"
OOM_REASON = "OOMKilled"


def _ts(value: object) -> float | None:
    """Epoch seconds of an RFC 3339 string, or None when missing or unparseable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def rollout_complete(dep: dict) -> bool:
    """The controller has rolled the current spec out and every desired replica is available
    (`kubectl rollout status` semantics: no old-ReplicaSet pod is left to count as available).

    Zero desired replicas is never "complete": nothing serving is no evidence the spec is good.
    """
    meta, spec, st = dep.get("metadata") or {}, dep.get("spec") or {}, dep.get("status") or {}
    want, updated = spec.get("replicas", 1), st.get("updatedReplicas") or 0
    return (want > 0 and st.get("observedGeneration", 0) >= meta.get("generation", 1) and updated == want
            and (st.get("replicas") or 0) == updated and (st.get("availableReplicas") or 0) >= updated)


def progress_deadline_exceeded(dep: dict) -> bool:
    """The controller gave up on the current generation's rollout (Progressing=False/ProgressDeadlineExceeded)."""
    meta, st = dep.get("metadata") or {}, dep.get("status") or {}
    return st.get("observedGeneration", 0) >= meta.get("generation", 1) and any(
        c.get("type") == "Progressing" and c.get("status") == "False" and c.get("reason") == PROGRESS_DEADLINE_REASON
        for c in st.get("conditions") or [])


def _probe_budget_s(p: dict | None) -> float:
    if p is None:
        return 0
    return ((p.get("initialDelaySeconds") or PROBE_DEFAULT_INITIAL_DELAY_S)
            + (p.get("periodSeconds") or PROBE_DEFAULT_PERIOD_S)
            * (p.get("failureThreshold") or PROBE_DEFAULT_FAILURE_THRESHOLD))


def readiness_never_passed(pod: dict, now: float) -> bool:
    """Every app container runs, a probed one is not ready, and that has lasted past its readiness budget."""
    st, spec = pod.get("status") or {}, pod.get("spec") or {}
    if any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions") or []):
        return False
    statuses = st.get("containerStatuses") or []
    if not statuses or any("running" not in (cs.get("state") or {}) for cs in statuses):
        return False                            # still starting, or a waiting / terminated state with its own reason
    containers = {c.get("name"): c for c in spec.get("containers") or []}
    for cs in statuses:
        c = containers.get(cs.get("name")) or {}
        started = _ts(((cs.get("state") or {}).get("running") or {}).get("startedAt"))
        if cs.get("ready") or c.get("readinessProbe") is None or started is None:
            continue
        budget = max(READY_FLOOR_S, _probe_budget_s(c["readinessProbe"]) + _probe_budget_s(c.get("startupProbe"))
                     + READY_MARGIN_S)
        if now - started > budget:
            return True
    return False


def owned_by(pod: dict, deployment: dict | str) -> bool:
    """The pod belongs to one of this Deployment's ReplicaSets (named <deployment>-<pod-template-hash>), not to
    another Deployment whose selector overlaps (a canary {app: web, track: canary} matches app=web too).

    `deployment` is the Deployment dict or just its name."""
    name = deployment if isinstance(deployment, str) else (deployment.get("metadata") or {}).get("name")
    meta = pod.get("metadata") or {}
    h = (meta.get("labels") or {}).get("pod-template-hash")
    return bool(name) and bool(h) and any(
        r.get("kind") == "ReplicaSet" and r.get("name") == f"{name}-{h}" for r in meta.get("ownerReferences") or [])


def pod_failure_reasons(pods: list[dict], since_s: float, now: float | None = None) -> set[str]:
    """Failure reasons of pods created at or after `since_s` (epoch s, minus the slack): a bad waiting state
    (init or app container), an OOM kill as last termination, or readiness that never passed.

    Older (previous ReplicaSet) and terminating pods are ignored. Ownership is NOT checked here; use `owned_by`
    first (or `failure_reasons`, which does)."""
    out: set[str] = set()
    now = time.time() if now is None else now
    for p in pods:
        meta = p.get("metadata") or {}
        created = _ts(meta.get("creationTimestamp"))
        if created is None or meta.get("deletionTimestamp") or created < since_s - CREATED_SLACK_S:
            continue
        if readiness_never_passed(p, now):
            out.add(READINESS_REASON)
        st = p.get("status") or {}
        for cs in (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or []):
            if (r := ((cs.get("state") or {}).get("waiting") or {}).get("reason")) in WAITING_FAILURES:
                out.add(r)
            if ((cs.get("lastState") or {}).get("terminated") or {}).get("reason") == OOM_REASON:
                out.add(OOM_REASON)
    return out


def failure_reasons(dep: dict, pods: list[dict], since_s: float, now: float | None = None) -> list[str]:
    """Sorted failure reasons for the Deployment's new spec: pod evidence from its own ReplicaSets' pods created
    at or after `since_s`, plus ProgressDeadlineExceeded when the status says so for the current generation."""
    out = pod_failure_reasons([p for p in pods if owned_by(p, dep)], since_s, now)
    if progress_deadline_exceeded(dep):
        out.add(PROGRESS_DEADLINE_REASON)
    return sorted(out)
