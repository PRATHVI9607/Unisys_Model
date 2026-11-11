"""Security-posture weakenings and resource unit-typo cuts of a Deployment spec versus a baseline.

Pure (no I/O, no Kubernetes client). Shared by the Health Agent (failure_reasons) and the Executor's
validation. Specs may be in any form `kubeheal.features.health.canonical_spec` accepts (API JSON, canonical,
a Deployment), or a bare pod template / pod spec.
"""

from __future__ import annotations

from typing import Any

from kubeheal.contracts import POLICY_REASON_PREFIX
from kubeheal.features.health import canonical_spec, spec_diff_features
from kubeheal.features.quantity import parse_cpu, parse_memory

# Spec-diff features that mean the change weakens security posture. Order is the order of the result.
POSTURE_FEATURES = ("privileged_added", "root_user_added", "capabilities_added",
                    "host_namespace_added", "host_path_added")

# Resource unit typos (500m -> 5m). The cut factor and the floors are v5's values with the owner's inclusive
# comparison (decision D1: a cut of 10x or more to a value AT OR BELOW the floor, so 500m -> 50m fires); they
# were not measured by us. A 2-4x rightsizing, or a 10x cut that leaves a value above the floor (1 CPU -> 100m),
# never fires. Floors are in cores and bytes.
CUT_FACTOR = 10
CUT_FLOORS = {"cpu": (0.05, parse_cpu), "memory": (32 * 2**20, parse_memory)}
_EPS = 1e-9   # relative slack: parse("30m") * 10 != parse("300m") in binary floating point


def _spec(obj: Any) -> dict:
    """canonical_spec that also accepts a bare pod template ({metadata, spec: {containers}}) or pod spec."""
    if isinstance(obj, dict) and "template" not in obj:
        inner = obj.get("spec")
        if isinstance(inner, dict) and "containers" in inner:
            obj = {"template": obj}
        elif "containers" in obj:
            obj = {"template": {"spec": obj}}
    return canonical_spec(obj)


def _resource_cut(base: dict, spec: dict, resource: str) -> bool:
    """Some container's limit or request of `resource` fell by CUT_FACTOR or more, to at or below the floor.

    Containers are matched by name; missing baseline or new values never fire (a removal is not a cut)."""
    floor, parse = CUT_FLOORS[resource]
    old = {c.get("name"): c.get("resources") or {}
           for c in (base.get("template") or {}).get("spec", {}).get("containers", [])}
    for c in (spec.get("template") or {}).get("spec", {}).get("containers", []):
        for kind in ("limits", "requests"):
            was = parse((old.get(c.get("name"), {}).get(kind) or {}).get(resource))
            now = parse(((c.get("resources") or {}).get(kind) or {}).get(resource))
            if (was and now is not None and now <= floor * (1 + _EPS)
                    and was >= CUT_FACTOR * now * (1 - _EPS)):
                return True
    return False


def policy_violations(base: Any, spec: Any) -> list[str]:
    """Posture weakenings `spec` introduces relative to `base` (the restore target), as `policy:<name>`.

    A weakening already present in `base` is not reported. The order is fixed: POSTURE_FEATURES, then
    cpu_cut_10x, then memory_cut_10x."""
    base, spec = _spec(base), _spec(spec)
    f = spec_diff_features(base, spec)
    return [POLICY_REASON_PREFIX + k for k in POSTURE_FEATURES if f[k]] + [
        f"{POLICY_REASON_PREFIX}{r}_cut_{CUT_FACTOR}x" for r in CUT_FLOORS if _resource_cut(base, spec, r)]


def posture_violations_present(base: Any, spec: Any) -> bool:
    """True when `spec` introduces any weakening relative to `base`."""
    return bool(policy_violations(base, spec))


def weakens_posture(candidate: Any, reference: Any) -> list[str]:
    """The weakenings `candidate` introduces relative to `reference` (argument order: new first, baseline second).

    Same semantics as `policy_violations(reference, candidate)`; for Executor validation, where `candidate` is
    the spec a patch would produce and `reference` the live (or baseline) template or spec."""
    return policy_violations(reference, candidate)
