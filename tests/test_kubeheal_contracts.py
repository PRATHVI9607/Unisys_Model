"""Trimmed inference-side contract: model output types, label tables and the event models."""

import warnings

import pytest

from kubeheal.contracts import (
    HEALTH_CLASS_RISK,
    HEALTH_LABELS,
    POLICY_REASON_PREFIX,
    SECURITY_CLASS_RISK,
    SECURITY_LABELS,
    SECURITY_PUBLISH_RISK,
    Factor,
    HealthEvent,
    Prediction,
    SecurityEvent,
)


def test_label_and_risk_tables_line_up():
    assert len(HEALTH_LABELS) == len(HEALTH_CLASS_RISK) == 3
    assert len(SECURITY_LABELS) == len(SECURITY_CLASS_RISK) == 4
    assert HEALTH_LABELS[0] == SECURITY_LABELS[0] == "benign"
    assert SECURITY_PUBLISH_RISK == 0.4 and POLICY_REASON_PREFIX == "policy:"


def test_model_version_fields_do_not_warn():
    """`model_version` is in pydantic's protected namespace; the models opt out with protected_namespaces=()."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        p = Prediction(model_version="v1", label="benign", risk=0.1, probabilities={"benign": 1.0},
                       prediction_set=["benign"], uncertain=False)
        h = HealthEvent(event_id="h", namespace="n", workload="w", label="benign", risk=0.1, model_version="v1")
        s = SecurityEvent(event_id="s", namespace="n", workload="w", label="benign", risk=0.1, model_version="v1")
    assert p.model_version == h.model_version == s.model_version == "v1"


def test_prediction_risk_is_bounded():
    with pytest.raises(ValueError):
        Prediction(model_version="v", label="benign", risk=1.5, probabilities={}, prediction_set=[], uncertain=True)


def test_event_defaults_and_json_roundtrip():
    h = HealthEvent(event_id="h-1", namespace="shop", workload="web", label="degradation", risk=0.6,
                    top_factors=[Factor(feature="cpu_limit_ratio", value=0.1, contribution=1.2)],
                    changed_fields=["spec.template.spec.containers[0].resources.limits.cpu"],
                    failure_reasons=[POLICY_REASON_PREFIX + "privileged_added"])
    assert h.spec_changed is True and h.has_baseline is False and h.pod == ""
    assert HealthEvent.model_validate_json(h.model_dump_json()) == h
    s = SecurityEvent(event_id="s-1", namespace="shop", workload="web", pod="web-1", label="ransomware", risk=0.97)
    assert s.window_start_ms == 0 and s.n_events == 0 and s.pod_uid == ""
    assert SecurityEvent.model_validate_json(s.model_dump_json()) == s
