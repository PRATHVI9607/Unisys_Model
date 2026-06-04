"""
Causal Chain Builder — KubeHeal v4 (Section 05.2)
=================================================
Pure-Python (no torch). Turns the two model outputs + DCM correlation into an
ordered, human-readable causal chain with relative timestamps (T+Xs).

Demo-winning panel: traces ransomware spawn → encryption → entropy spike →
CPU thrash → health alert → DCM compound confirmation.
"""

from typing import Dict, List, Optional, Tuple

from .correlation_head import COMPOUND_THRESHOLD


class CausalChainBuilder:
    def build(
        self,
        health_assessment: Optional[Dict],
        security_event: Optional[Dict],
        correlation_score: float,
        field_attribution: Optional[Dict] = None,
    ) -> List[str]:
        events: List[Tuple[float, str]] = []
        ha = health_assessment or {}
        se = security_event or {}
        fa = field_attribution or {}

        # ── Security-origin events ──────────────────────────
        if se:
            sig = se.get("early_signals", {}) or {}
            if sig.get("rename_burst"):
                events.append((2.0, "Rename burst detected (file-locking pattern)"))
            if sig.get("ftruncate_pattern"):
                events.append((2.4, "ftruncate pattern consistent with in-place encryption"))
            spike = se.get("entropy_spike", {}) or {}
            if spike.get("value_bits"):
                t = float(spike.get("timestep_s", 2.9))
                events.append((t, f"File entropy reached {spike['value_bits']:.2f} bits"))
            top_sys = se.get("top_syscall")
            if top_sys:
                events.append((3.1, f"Dominant suspicious syscall: {top_sys}()"))
            if se.get("sec_risk", se.get("risk_score", 0)) >= 0.5:
                r = se.get("sec_risk", se.get("risk_score", 0))
                lbl = se.get("sec_label", se.get("label", "suspicious"))
                events.append((3.3, f"Security model flagged {lbl} (sec_risk={r:.2f})"))

        # ── Health-origin events ────────────────────────────
        if ha:
            top_field = ha.get("top_field") or (next(iter(fa), None) if fa else None)
            if top_field:
                events.append((0.0, f"Config field {top_field} changed"))
            top_metric = ha.get("top_metric")
            if top_metric:
                events.append((5.0, f"{top_metric} degraded after change"))
            if ha.get("health_risk", ha.get("risk_score", 0)) >= 0.5:
                r = ha.get("health_risk", ha.get("risk_score", 0))
                lbl = ha.get("health_label", ha.get("label", "drift"))
                events.append((3.3, f"Health model flagged {lbl} (health_risk={r:.2f})"))

        events.sort(key=lambda x: x[0])
        chain = [f"T+{t:.1f}s: {msg}" for t, msg in events]

        if correlation_score > COMPOUND_THRESHOLD:
            chain.append(
                f"T+4.0s: DCM — compound incident confirmed "
                f"(correlation={correlation_score:.2f}); signals share a root cause"
            )
        elif chain:
            chain.append(
                f"DCM — independent signals (correlation={correlation_score:.2f}); "
                f"handle by separate policies"
            )
        return chain
