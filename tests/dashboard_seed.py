"""Realistic console data for the dashboard tests: events, an approval queue and a ledger, written to (fake) Redis."""

import json

from kubeheal.contracts import (
    KEY_APPROVALS_PENDING,
    KEY_MODE_EFFECTIVE,
    STREAM_ACTIONS,
    STREAM_HEALTH,
    STREAM_LEDGER,
    STREAM_SECURITY,
    ActionEvent,
    Decision,
    Factor,
    HealthEvent,
    SecurityEvent,
    key_approval,
    now_ms,
)

HUMAN_PENDING = "act-human-1"
HUMAN_SECOND = "act-human-2"
HUMAN_DONE = "act-human-3"


def seed(r, base_ms: int | None = None) -> None:
    t = base_ms or now_ms() - 600_000
    h_crit = HealthEvent(
        event_id="h-cart-1", namespace="shop-prod", workload="cart", label="critical", risk=0.93, uncertain=False,
        changed_fields=["spec.template.spec.containers[0].image", "spec.template.spec.containers[0].resources.limits.memory"],
        failure_reasons=["ImagePullBackOff"], has_baseline=True, model_version="health-5.0.0-a374e498",
        probabilities={"benign": 0.02, "degradation": 0.05, "critical": 0.93}, timestamp_ms=t,
        top_factors=[Factor(feature="mem_limit_ratio", value=0.25, contribution=0.41),
                     Factor(feature="image_changed", value=1, contribution=0.33),
                     Factor(feature="replicas_delta", value=0, contribution=-0.08)])
    h_deg = HealthEvent(event_id="h-search-1", namespace="shop-prod", workload="search", label="degradation", risk=0.58,
                        uncertain=True, changed_fields=["spec.template.spec.containers[0].resources.limits.cpu"],
                        probabilities={"benign": 0.31, "degradation": 0.58, "critical": 0.11}, timestamp_ms=t + 20_000)
    s_ransom = SecurityEvent(
        event_id="s-cart-1", namespace="shop-prod", workload="billing", pod="billing-7d9f6-x2k4q", pod_uid="u-1", label="ransomware",
        risk=0.98, n_events=2412, window_start_ms=t + 60_000, window_end_ms=t + 90_000, model_version="security-5.0.0-c6fa12d8",
        probabilities={"benign": 0.004, "suspicious": 0.006, "ransomware": 0.98, "exfiltration": 0.01}, timestamp_ms=t + 90_000,
        top_factors=[Factor(feature="frac_rename", value=0.41, contribution=2.1), Factor(feature="entropy_mean", value=7.8, contribution=1.7),
                     Factor(feature="frac_read", value=0.02, contribution=-0.3)])
    s_susp = SecurityEvent(event_id="s-batch-1", namespace="shop-prod", workload="reports", pod="reports-5c-lm2ps", label="suspicious",
                           risk=0.46, uncertain=True, n_events=380, window_start_ms=t + 100_000, window_end_ms=t + 130_000,
                           timestamp_ms=t + 130_000)
    acts = [
        ActionEvent(event_id="a-patch-1", namespace="shop-prod", workload="cart", decision=Decision.AUTO_PATCH, mode="enforce",
                    outcome="patched", score=0.93, compound_score=0.93, health_event_id="h-cart-1", timestamp_ms=t + 5_000,
                    rationale="Rollout failed with ImagePullBackOff; restored the baseline template.",
                    summary="cart: image tag does not exist, baseline restored."),
        ActionEvent(event_id="a-kill-1", namespace="shop-prod", workload="billing", pod="billing-7d9f6-x2k4q", decision=Decision.AUTO_KILL,
                    mode="enforce", outcome="pod_killed", score=0.97, compound_score=0.97, security_event_id="s-cart-1",
                    containment="requested", timestamp_ms=t + 90_840, rationale="Ransomware certain at 98% risk.",
                    summary="Quarantined and deleted billing-7d9f6-x2k4q."),
        ActionEvent(event_id=HUMAN_PENDING, namespace="shop-prod", workload="search", decision=Decision.HUMAN, mode="enforce",
                    outcome="escalated_no_baseline", score=0.58, health_event_id="h-search-1", timestamp_ms=t + 30_000,
                    rationale="CPU limit cut by half but no baseline exists to restore; needs an operator."),
        ActionEvent(event_id=HUMAN_SECOND, namespace="shop-prod", workload="reports", pod="reports-5c-lm2ps", decision=Decision.HUMAN,
                    mode="enforce", outcome="escalated_no_pod", score=0.61, security_event_id="s-batch-1", timestamp_ms=t + 131_000,
                    rationale="Suspicious write burst, uncertain prediction set."),
        ActionEvent(event_id=HUMAN_DONE, namespace="staging", workload="web", decision=Decision.HUMAN, mode="enforce",
                    outcome="escalated_no_baseline", score=0.64, timestamp_ms=t + 140_000, rationale="Replica count dropped to 0."),
        ActionEvent(event_id="a-skip-1", namespace="kube-system", workload="coredns", pod="coredns-1", decision=Decision.AUTO_KILL,
                    mode="enforce", outcome="skipped_protected", score=0.9, timestamp_ms=t + 150_000, rationale="Protected namespace."),
        ActionEvent(event_id="a-dry-1", namespace="demo", workload="victim-app", pod="victim-app-1", decision=Decision.AUTO_KILL,
                    mode="observe", outcome="would_kill", score=0.95, security_event_id="s-batch-1", timestamp_ms=t + 160_000,
                    rationale="Dry run."),
    ]
    for ev in (h_crit, h_deg):
        r.xadd(STREAM_HEALTH, ev.to_fields())
    for ev in (s_ransom, s_susp):
        r.xadd(STREAM_SECURITY, ev.to_fields())
    for ev in acts:
        r.xadd(STREAM_ACTIONS, ev.to_fields())

    def approval(action_id, state, cand, ns, wl, pod="", score=0.6, **extra):
        r.set(key_approval(action_id), json.dumps({"state": state, "candidate": cand, "namespace": ns, "workload": wl, "pod": pod,
                                                   "pod_uid": "", "health_event_id": "", "security_event_id": "",
                                                   "rationale": "needs an operator", "score": score, "created_ms": t + 30_000, **extra}),
              ex=86_400)

    approval(HUMAN_PENDING, "pending", "AUTO_PATCH", "shop-prod", "search", score=0.58)
    approval(HUMAN_SECOND, "pending", "AUTO_KILL", "shop-prod", "reports", "reports-5c-lm2ps", 0.61)
    approval(HUMAN_DONE, "executed", "AUTO_PATCH", "staging", "web", score=0.64, outcome="patched",
             requested={"decision": "approve", "actor": "admin:maria", "approval_id": "x", "ts_ms": t + 200_000})
    r.zadd(KEY_APPROVALS_PENDING, {HUMAN_PENDING: t + 30_000, HUMAN_SECOND: t + 131_000, HUMAN_DONE: t + 140_000})
    r.set(KEY_MODE_EFFECTIVE, "observe", ex=3600)   # fusion rewrites it every few seconds; the tests have no fusion
    for i, (kind, actor, ns, dec, out) in enumerate([
            ("action", "fusion", "shop-prod", "AUTO_PATCH", "patched"), ("action", "fusion", "shop-prod", "AUTO_KILL", "pod_killed"),
            ("approval_pending", "fusion", "shop-prod", "HUMAN", "pending"), ("mode", "admin:maria", "", "enforce", "set"),
            ("approval", "admin:maria", "staging", "AUTO_PATCH", "approve_requested")]):
        r.xadd(STREAM_LEDGER, {"ts_ms": str(t + i * 1000), "kind": kind, "actor": actor, "namespace": ns, "workload": "",
                               "pod": "", "decision": dec, "outcome": out, "mode": "enforce", "action_event_id": "", "detail": ""})
