"""Deployment-spec diff and Prometheus-window features for the health model.

Pure functions shared by training (`training/datasets/health.py`) and serving
(health agent). Missing data is None, never 0.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

import numpy as np

from kubeheal.features.quantity import parse_cpu, parse_memory

RAW_METRICS: list[str] = [
    "cpu_usage_cores", "cpu_limit_cores", "cpu_throttled_ratio",
    "memory_working_set_bytes", "memory_limit_bytes",
    "request_rate_rps", "error_rate_rps", "latency_p99_s",
    "restarts_total", "replicas_desired", "replicas_ready",
]

SPEC_FEATURES: list[str] = [
    "cpu_limit_ratio", "cpu_request_ratio", "mem_limit_ratio", "mem_request_ratio",
    "cpu_limit_removed", "mem_limit_removed", "replicas_ratio", "replicas_to_zero",
    "image_changed", "image_unpinned", "privileged_added", "root_user_added",
    "capabilities_added", "host_namespace_added", "host_path_added",
    "probe_changed", "probe_removed", "env_count_delta", "env_values_changed",
    "volume_mounts_removed", "containers_delta", "command_changed",
    "n_changed_fields", "spec_changed",
]

METRIC_FEATURES: list[str] = [
    "cpu_util_mean", "cpu_util_max", "cpu_throttle_mean", "mem_util_mean", "mem_util_max",
    "latency_p99_mean_s", "latency_p99_max_s", "latency_trend", "error_ratio",
    "request_rate_log", "restarts_delta", "ready_ratio",
]

HEALTH_FEATURES: list[str] = SPEC_FEATURES + METRIC_FEATURES

# Prometheus query_range step for every health window, live (health agent) and training (drift_lab).
METRIC_STEP_S = 15
_PROBES = ("livenessProbe", "readinessProbe", "startupProbe")
# Free-form maps whose keys are user data (label names, resource names), not field names.
_USER_KEYED = {"labels", "annotations", "matchLabels", "nodeSelector", "limits", "requests"}   # compared after _camel


# ── Canonical spec ───────────────────────────────────────────────────────────
def _camel(key: str) -> str:
    head, *rest = key.lstrip("_").split("_")   # to_dict() names reserved words "_exec", "_from"
    return head + "".join(w[:1].upper() + w[1:] for w in rest)


def _clean(value: Any, camel_keys: bool = True) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = _camel(k) if camel_keys else k
            v = _clean(v, key not in _USER_KEYED)
            if v is not None and v != {} and v != []:
                out[key] = v
        return out
    if isinstance(value, list):
        return [c for c in (_clean(v) for v in value) if c is not None and c != {} and c != []]
    return value


def canonical_spec(obj: Any) -> dict:
    """DeploymentSpec as a camelCase dict with None/empty values removed."""
    if not isinstance(obj, dict):
        # kubernetes_asyncio model: serialize=True gives API (camelCase) names, the same output
        # as ApiClient().sanitize_for_serialization without needing a client or event loop.
        obj = obj.to_dict(serialize=True)
    if "template" not in obj and isinstance(obj.get("spec"), dict):
        obj = obj["spec"]
    return _clean(obj)


def spec_hash(spec: dict) -> str:
    return hashlib.sha256(json.dumps(canonical_spec(spec), sort_keys=True).encode()).hexdigest()


def _leaf_diffs(a: Any, b: Any, path: str, out: list[str], limit: int) -> None:
    if len(out) >= limit or a == b:
        return
    if isinstance(a, dict) or isinstance(b, dict):
        a = a if isinstance(a, dict) else {}
        b = b if isinstance(b, dict) else {}
        for k in sorted(set(a) | set(b)):
            _leaf_diffs(a.get(k), b.get(k), f"{path}.{k}" if path else k, out, limit)
    elif isinstance(a, list) or isinstance(b, list):
        a = a if isinstance(a, list) else []
        b = b if isinstance(b, list) else []
        for i in range(max(len(a), len(b))):
            _leaf_diffs(a[i] if i < len(a) else None, b[i] if i < len(b) else None, f"{path}[{i}]", out, limit)
    else:
        out.append(path)


def changed_paths(old: dict, new: dict, limit: int = 50) -> list[str]:
    """Dotted leaf paths that differ between two canonical specs."""
    out: list[str] = []
    _leaf_diffs(old, new, "", out, limit)
    return out


# ── Spec-diff features ───────────────────────────────────────────────────────
def _pod(spec: dict) -> dict:
    return spec.get("template", {}).get("spec", {})


def _containers(spec: dict) -> dict[str, dict]:
    return {c.get("name", str(i)): c for i, c in enumerate(_pod(spec).get("containers", []))}


def _posture_containers(spec: dict) -> dict[str, dict]:
    """Containers + initContainers: an init container can be privileged or root too."""
    pod = _pod(spec)
    return {c.get("name", f"#{i}"): c for i, c in enumerate(pod.get("containers", []) + pod.get("initContainers", []))}


def _resource_sum(containers: dict[str, dict], kind: str, name: str, parse) -> float | None:
    vals = [parse(c.get("resources", {}).get(kind, {}).get(name)) for c in containers.values()]
    vals = [v for v in vals if v is not None]
    return sum(vals) if vals else None


def _ratio(new: float | None, old: float | None) -> float | None:
    return new / old if new is not None and old else None


def _image_unpinned(image: str) -> bool:
    if "@" in image:
        return False
    name = image.rsplit("/", 1)[-1]
    return ":" not in name or name.rsplit(":", 1)[1] == "latest"


def _runs_as_root(pod_sc: dict, c_sc: dict) -> bool:
    uid = c_sc.get("runAsUser", pod_sc.get("runAsUser"))   # container securityContext overrides the pod's
    return uid == 0 or c_sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot")) is False


def _env(c: dict) -> dict[str, Any]:
    return {e.get("name"): (e.get("value"), e.get("valueFrom")) for e in c.get("env", [])}


def spec_diff_features(old: dict, new: dict) -> dict[str, float | None]:
    """Features of the change old → new (both canonical DeploymentSpecs)."""
    oc, nc = _containers(old), _containers(new)
    opod, npod = _pod(old), _pod(new)
    both = [(oc[n], nc[n]) for n in nc if n in oc]
    f: dict[str, float | None] = {}

    for feat, kind, res, parse in (
        ("cpu_limit_ratio", "limits", "cpu", parse_cpu), ("cpu_request_ratio", "requests", "cpu", parse_cpu),
        ("mem_limit_ratio", "limits", "memory", parse_memory), ("mem_request_ratio", "requests", "memory", parse_memory),
    ):
        f[feat] = _ratio(_resource_sum(nc, kind, res, parse), _resource_sum(oc, kind, res, parse))
    for feat, res in (("cpu_limit_removed", "cpu"), ("mem_limit_removed", "memory")):
        f[feat] = float(sum(1 for o, n in both
                            if res in o.get("resources", {}).get("limits", {})
                            and res not in n.get("resources", {}).get("limits", {})))

    old_rep, new_rep = old.get("replicas", 1), new.get("replicas", 1)   # API default when unset
    f["replicas_ratio"] = _ratio(float(new_rep), float(old_rep))
    f["replicas_to_zero"] = float(new_rep == 0 and old_rep > 0)

    changed_images = [n.get("image", "") for o, n in both if o.get("image") != n.get("image")]
    changed_images += [c.get("image", "") for name, c in nc.items() if name not in oc]
    f["image_changed"] = float(bool(changed_images))
    f["image_unpinned"] = float(any(_image_unpinned(i) for i in changed_images))

    opc, npc = _posture_containers(old), _posture_containers(new)

    def added(pred) -> float:
        return float(sum(1 for name, c in npc.items() if pred(npod, c) and not (name in opc and pred(opod, opc[name]))))

    f["privileged_added"] = added(lambda p, c: c.get("securityContext", {}).get("privileged") is True)
    f["root_user_added"] = added(lambda p, c: _runs_as_root(p.get("securityContext", {}), c.get("securityContext", {})))
    f["capabilities_added"] = float(sum(
        len(set(c.get("securityContext", {}).get("capabilities", {}).get("add", []))
            - set(opc.get(name, {}).get("securityContext", {}).get("capabilities", {}).get("add", [])))
        for name, c in npc.items()))
    f["host_namespace_added"] = float(sum(1 for k in ("hostNetwork", "hostPID", "hostIPC")
                                          if npod.get(k) is True and opod.get(k) is not True))
    old_host = {v.get("name") for v in opod.get("volumes", []) if "hostPath" in v}
    f["host_path_added"] = float(sum(1 for v in npod.get("volumes", [])
                                     if "hostPath" in v and v.get("name") not in old_host))

    f["probe_changed"] = float(sum(1 for o, n in both for p in _PROBES if o.get(p) != n.get(p)))
    f["probe_removed"] = float(sum(1 for o, n in both for p in _PROBES if p in o and p not in n))
    f["env_count_delta"] = float(sum(len(c.get("env", [])) for c in nc.values())
                                 - sum(len(c.get("env", [])) for c in oc.values()))
    f["env_values_changed"] = float(sum(1 for o, n in both
                                        for k, v in _env(n).items() if _env(o).get(k, v) != v))
    f["volume_mounts_removed"] = float(sum(
        len({m.get("mountPath") for m in o.get("volumeMounts", [])}
            - {m.get("mountPath") for m in nc.get(name, {}).get("volumeMounts", [])})
        for name, o in oc.items()))
    f["containers_delta"] = float(len(nc) - len(oc))
    f["command_changed"] = float(any(o.get(k) != n.get(k) for o, n in both for k in ("command", "args")))
    f["n_changed_fields"] = float(len(changed_paths(old, new, limit=10_000)))
    f["spec_changed"] = float(old != new)
    return {k: f[k] for k in SPEC_FEATURES}


# ── Metric-window features ───────────────────────────────────────────────────
def _series(window: dict[str, list[float]], name: str) -> np.ndarray:
    a = np.asarray([v for v in window.get(name) or [] if v is not None], dtype=float)
    return a[np.isfinite(a)]


def _util(usage: np.ndarray, limit: np.ndarray) -> np.ndarray:
    if not usage.size or not limit.size:
        return np.empty(0)
    # Limits can change mid-window (that is the drift); align sample-wise when possible.
    den = limit if limit.size == usage.size else limit[-1]
    with np.errstate(divide="ignore", invalid="ignore"):
        u = usage / den
    return u[np.isfinite(u)]


def _stat(a: np.ndarray, fn) -> float | None:
    return float(fn(a)) if a.size else None


def metric_features(window: dict[str, list[float]]) -> dict[str, float | None]:
    """Features of a Prometheus window in raw SI units (samples METRIC_STEP_S apart)."""
    s = {name: _series(window, name) for name in RAW_METRICS}
    cpu = _util(s["cpu_usage_cores"], s["cpu_limit_cores"])
    mem = _util(s["memory_working_set_bytes"], s["memory_limit_bytes"])
    lat = s["latency_p99_s"]
    req, err = s["request_rate_rps"], s["error_rate_rps"]
    restarts, desired, ready = s["restarts_total"], s["replicas_desired"], s["replicas_ready"]

    trend = None
    if lat.size >= 2:
        trend = float(np.polyfit(np.arange(lat.size) * METRIC_STEP_S / 60.0, lat, 1)[0])
    return {
        "cpu_util_mean": _stat(cpu, np.mean), "cpu_util_max": _stat(cpu, np.max),
        "cpu_throttle_mean": _stat(s["cpu_throttled_ratio"], np.mean),
        "mem_util_mean": _stat(mem, np.mean), "mem_util_max": _stat(mem, np.max),
        "latency_p99_mean_s": _stat(lat, np.mean), "latency_p99_max_s": _stat(lat, np.max),
        "latency_trend": trend,
        "error_ratio": float(err.sum() / req.sum()) if err.size and req.size and req.sum() > 0 else None,
        "request_rate_log": float(math.log1p(max(req.mean(), 0.0))) if req.size else None,
        "restarts_delta": float(np.clip(np.diff(restarts), 0, None).sum()) if restarts.size else None,
        "ready_ratio": float(ready[-1] / desired[-1]) if ready.size and desired.size and desired[-1] > 0 else None,
    }


def health_features(old: Any, new: Any, window: dict[str, list[float]]) -> dict[str, float | None]:
    """Spec-diff ∪ metric features, ordered by HEALTH_FEATURES."""
    f = spec_diff_features(canonical_spec(old), canonical_spec(new)) | metric_features(window)
    return {k: f[k] for k in HEALTH_FEATURES}
