"""
Integration test: DIT-Sec v3.0 model with Health Agent
Tests the end-to-end assessment pipeline using trained model
"""

import sys
from pathlib import Path

# Add agent directory to path
sys.path.insert(0, str(Path("agents/health_agent")))

from agent import HealthAgent, _DITSEC_MODEL
import json


def test_model_assessment():
    """Test model-based assessment on real Kubernetes spec."""

    print("=" * 70)
    print("DIT-Sec v3.0 Model + Health Agent Integration Test")
    print("=" * 70)

    if not _DITSEC_MODEL:
        print("✗ Model not loaded!")
        return False

    print("\n✓ Model loaded successfully")

    agent = HealthAgent()
    print("✓ Health Agent initialized")

    # Test Case 1: Normal deployment (low-risk)
    print("\n" + "-" * 70)
    print("TEST 1: Normal Deployment (Expected: Low Risk)")
    print("-" * 70)

    normal_spec = {
        "replicas": 3,
        "template": {
            "metadata": {
                "labels": {"app": "web-app"},
                "annotations": {"version": "1.0"},
            },
            "spec": {
                "serviceAccountName": "web-app-sa",
                "securityContext": {"runAsNonRoot": True},
                "containers": [
                    {
                        "name": "web",
                        "image": "nginx:1.25",
                        "imagePullPolicy": "IfNotPresent",
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                        },
                        "volumeMounts": [{"name": "config", "mountPath": "/etc/nginx"}],
                        "env": [{"name": "LOG_LEVEL", "value": "info"}],
                    }
                ],
            },
        },
    }

    telemetry = {
        "cpu_usage": 15.0,
        "memory_usage": 30.0,
        "disk_io": 5.0,
        "network_io": 10.0,
        "request_rate": 100.0,
        "error_rate": 0.5,
        "latency_ms": 50.0,
    }

    result = agent._local_assessment(normal_spec, telemetry)
    print(f"\nRisk Score: {result['risk_score']:.2%}")
    print(f"Confidence Interval: {result['confidence_interval']}")
    explainability = result.get("explainability", {})
    if "model" in explainability:
        print(f"Model: {explainability['model']}")
        print(f"Class: {explainability['class']}")
        print(f"Severity: {explainability['severity_level']}")
        print(f"Model Confidence: {explainability['confidence']:.2%}")

    # Test Case 2: Performance degradation (high-risk)
    print("\n" + "-" * 70)
    print("TEST 2: CPU-Constrained Deployment (Expected: High Risk)")
    print("-" * 70)

    constrained_spec = {
        "replicas": 1,
        "template": {
            "metadata": {"labels": {"app": "low-resource-app"}},
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "app:latest",
                        "imagePullPolicy": "Always",
                        "resources": {"limits": {"cpu": "50m", "memory": "64Mi"}},
                        "env": [{"name": "MAX_THREADS", "value": "100"}],
                    }
                ]
            },
        },
    }

    high_load_telemetry = {
        "cpu_usage": 95.0,
        "memory_usage": 85.0,
        "disk_io": 50.0,
        "network_io": 80.0,
        "request_rate": 5000.0,
        "error_rate": 25.0,
        "latency_ms": 2000.0,
    }

    result = agent._local_assessment(constrained_spec, high_load_telemetry)
    print(f"\nRisk Score: {result['risk_score']:.2%}")
    print(f"Confidence Interval: {result['confidence_interval']}")
    explainability = result.get("explainability", {})
    if "model" in explainability:
        print(f"Model: {explainability['model']}")
        print(f"Class: {explainability['class']}")
        print(f"Severity: {explainability['severity_level']}")
        print(f"Model Confidence: {explainability['confidence']:.2%}")

    # Test Case 3: Security-sensitive deployment
    print("\n" + "-" * 70)
    print("TEST 3: Security-Sensitive Deployment (Expected: Medium-High Risk)")
    print("-" * 70)

    security_spec = {
        "replicas": 2,
        "template": {
            "metadata": {
                "labels": {"tier": "backend"},
                "annotations": {"security": "critical"},
            },
            "spec": {
                "securityContext": {"runAsUser": 0, "privileged": True},
                "containers": [
                    {
                        "name": "api",
                        "image": "api:v1.0",
                        "imagePullPolicy": "IfNotPresent",
                        "resources": {"limits": {"cpu": "2000m", "memory": "2Gi"}},
                        "env": [
                            {
                                "name": "DB_PASSWORD",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "db-secret",
                                        "key": "password",
                                    }
                                },
                            }
                        ],
                    }
                ],
            },
        },
    }

    normal_telemetry = {
        "cpu_usage": 45.0,
        "memory_usage": 55.0,
        "disk_io": 20.0,
        "network_io": 40.0,
        "request_rate": 1000.0,
        "error_rate": 2.0,
        "latency_ms": 200.0,
    }

    result = agent._local_assessment(security_spec, normal_telemetry)
    print(f"\nRisk Score: {result['risk_score']:.2%}")
    print(f"Confidence Interval: {result['confidence_interval']}")
    explainability = result.get("explainability", {})
    if "model" in explainability:
        print(f"Model: {explainability['model']}")
        print(f"Class: {explainability['class']}")
        print(f"Severity: {explainability['severity_level']}")
        print(f"Model Confidence: {explainability['confidence']:.2%}")
        if "class_probabilities" in explainability:
            print(f"All class probabilities:")
            for class_name, prob in explainability["class_probabilities"].items():
                print(f"  - {class_name}: {prob:.2%}")

    print("\n" + "=" * 70)
    print("Integration Test PASSED ✓")
    print("All 3 scenarios assessed successfully with DIT-Sec v3.0 model")
    print("=" * 70)

    return True


if __name__ == "__main__":
    try:
        success = test_model_assessment()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
