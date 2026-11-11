"""Kubernetes resource.Quantity parsing ("500m", "256Mi", "129e6", ...)."""

from __future__ import annotations

import re

_SUFFIX = {
    "": 1.0, "n": 1e-9, "u": 1e-6, "m": 1e-3,
    "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
    "Ki": 2.0**10, "Mi": 2.0**20, "Gi": 2.0**30, "Ti": 2.0**40, "Pi": 2.0**50, "Ei": 2.0**60,
}
# The exponent needs digits after it, so a bare trailing "E" is the exa suffix, not an exponent.
_QUANTITY = re.compile(r"^([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)\s*([a-zA-Z]{0,2})$")


def _parse(q: object) -> float | None:
    if q is None or isinstance(q, bool):
        return None
    if isinstance(q, (int, float)):
        return float(q)
    m = _QUANTITY.match(str(q).strip())
    if not m or m.group(2) not in _SUFFIX:
        return None
    return float(m.group(1)) * _SUFFIX[m.group(2)]


def parse_cpu(q: object) -> float | None:
    """CPU quantity in cores; None when missing or unparsable."""
    return _parse(q)


def parse_memory(q: object) -> float | None:
    """Memory quantity in bytes; None when missing or unparsable."""
    return _parse(q)
