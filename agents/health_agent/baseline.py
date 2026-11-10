"""
Golden baseline store (S-HA-2 / S-HA-3).
========================================
The golden baseline of a workload is written ONCE, on first sight, with SET NX under
`kubeheal:baseline:<namespace>:<deployment>`. It is never overwritten by later (possibly drifted)
specs; only the documented reset tool (`scripts/baseline_tool.py`) replaces it. The drift diff is
always live spec versus golden baseline.

The Executor (P2 onwards) reads the same key to restore a drifted Deployment.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

BASELINE_PREFIX = "kubeheal:baseline"


def baseline_key(namespace: str, deployment: str) -> str:
    return f"{BASELINE_PREFIX}:{namespace}:{deployment}"


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


async def get_or_set_baseline(redis, namespace: str, deployment: str,
                              live_spec: Dict) -> Tuple[Dict, bool]:
    """Return (golden_record, created). `created` is True only for the call that wrote it."""
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


def is_drifted(golden: Dict, live_spec: Dict) -> bool:
    return golden.get("spec") != drift_view(live_spec)
