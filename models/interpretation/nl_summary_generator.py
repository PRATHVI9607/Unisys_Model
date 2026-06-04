"""
Natural Language Summary Generator — KubeHeal v4 (Section 06.4)
===============================================================
Turns structured incident data into a 1-3 sentence plain-English summary via
the Anthropic API (claude-haiku-4-5). Always falls back to a template if the
API key is missing or the call fails — the interpretation layer must never
block the Fusion Agent.
"""

import json
import os
from typing import Dict

SUMMARY_SYSTEM_PROMPT = """You are an expert Kubernetes SRE assistant embedded in
the KubeHeal autonomous healing system. You receive structured incident data and
produce a 1-3 sentence plain English summary of what happened.

Rules:
- Be specific about field paths, metric values, and timestamps
- Clearly state whether it is a health-only, security-only, or compound incident
- State the action taken and its outcome
- Do not use jargon that a non-Kubernetes engineer wouldn't understand
- Keep it under 150 tokens total
- Use past tense (this is a post-incident summary)"""

_MODEL = os.environ.get("NL_SUMMARY_MODEL", "claude-haiku-4-5-20251001")


def generate_incident_summary(incident_data: Dict) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _template_summary(incident_data)
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        prompt = (
            "Here is the structured incident data:\n"
            f"{json.dumps(incident_data, indent=2, default=str)}\n\n"
            "Generate a 1-3 sentence plain English summary of this incident. "
            "Include: what happened, which signal was highest, what action was "
            "taken, and what the outcome was."
        )
        resp = client.messages.create(
            model=_MODEL,
            max_tokens=150,
            system=SUMMARY_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()
    except Exception:
        return _template_summary(incident_data)


def _template_summary(d: Dict) -> str:
    h = d.get("health_risk", 0) or 0
    s = d.get("sec_risk", 0) or 0
    corr = d.get("correlation_score", 0) or 0
    action = d.get("action_taken", "unknown")
    mttr = d.get("mttr_ms", 0)
    top_field = d.get("top_field")
    if s > 0.8 and h > 0.7 and corr > 0.6:
        return (f"Compound incident: ransomware (sec_risk={s:.2f}) caused performance "
                f"degradation (health_risk={h:.2f}). DCM correlation={corr:.2f}. "
                f"Action: {action}. Resolved in {mttr}ms.")
    if s > 0.8:
        return f"Security incident: sec_risk={s:.2f}. Action: {action}. Resolved in {mttr}ms."
    if h > 0.5:
        fld = f" Top field: {top_field}." if top_field else ""
        return f"Health incident: health_risk={h:.2f}.{fld} Action: {action}. Resolved in {mttr}ms."
    return f"Low-risk event (health={h:.2f}, sec={s:.2f}). Action: {action}."
