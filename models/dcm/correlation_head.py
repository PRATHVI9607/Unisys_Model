"""
Correlation head re-export (Section 05.x).
==========================================
The correlation head is integrated into CrossModalAttention. This module
exposes the compound-flag threshold and a thin helper so callers can import
a stable name.
"""

COMPOUND_THRESHOLD = 0.60


def is_compound(correlation_score: float) -> bool:
    """A correlation above the threshold marks a compound (causally-linked)
    incident — health and security signals are the same root cause."""
    return correlation_score > COMPOUND_THRESHOLD
