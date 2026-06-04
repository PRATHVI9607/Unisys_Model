"""
Natural Language Summary Generator — KubeHeal v4 (Section 06.4)
===============================================================
Deterministic, dependency-free incident summarizer. Turns the structured
incident (health_risk, sec_risk, correlation_score, top_field, action, mttr)
into a 1–3 sentence SRE-readable summary.

No external LLM call — fully local, instant, reproducible, and air-gap safe.
"""

from typing import Dict


def generate_incident_summary(incident_data: Dict) -> str:
    """Single entry point. Always returns a concise plain-English summary."""
    h = incident_data.get("health_risk", 0) or 0
    s = incident_data.get("sec_risk", 0) or 0
    corr = incident_data.get("correlation_score", 0) or 0
    action = incident_data.get("action_taken", "unknown")
    mttr = incident_data.get("mttr_ms", 0)
    top_field = incident_data.get("top_field")
    top_syscall = incident_data.get("top_syscall")

    if s > 0.8 and h > 0.7 and corr > 0.6:
        return (f"Compound incident: ransomware (sec_risk={s:.2f}, syscall={top_syscall}) "
                f"drove performance degradation (health_risk={h:.2f}). "
                f"DCM correlation={corr:.2f} confirms a shared root cause. "
                f"Action: {action}. Resolved in {mttr}ms.")
    if s > 0.8:
        sc = f" Dominant syscall: {top_syscall}." if top_syscall else ""
        return f"Security incident: sec_risk={s:.2f}.{sc} Action: {action}. Resolved in {mttr}ms."
    if h > 0.5:
        fld = f" Top field: {top_field}." if top_field else ""
        return f"Health incident: health_risk={h:.2f}.{fld} Action: {action}. Resolved in {mttr}ms."
    return f"Low-risk event (health={h:.2f}, sec={s:.2f}, corr={corr:.2f}). Action: {action}."
