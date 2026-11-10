from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from app import create_app


def exposition_samples(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    return {
        sample.name: sample
        for family in text_string_to_metric_families(response.text)
        for sample in family.samples
    }, response.text


def test_http_counter_exports_the_health_agent_contract():
    client = TestClient(create_app())
    assert client.get("/health").status_code == 200

    samples, exposition = exposition_samples(client)
    request = samples['http_requests_total']
    assert request.labels == {"method": "GET", "path": "/health", "status": "200"}
    assert request.value == 1
    assert '# TYPE http_requests_total counter' in exposition


def test_http_histogram_exports_seconds_with_method_path_and_status():
    client = TestClient(create_app())
    response = client.get("/items/first")
    assert response.status_code == 200

    samples, exposition = exposition_samples(client)
    count = samples['http_request_duration_seconds_count']
    total = samples['http_request_duration_seconds_sum']
    assert count.labels == {"method": "GET", "path": "/items/{item_id}", "status": "200"}
    assert count.value == 1
    assert total.labels == count.labels
    assert total.value >= 0
    assert '# TYPE http_request_duration_seconds histogram' in exposition


def test_route_templates_keep_identifier_values_out_of_metric_labels():
    client = TestClient(create_app())
    assert client.get("/items/first").status_code == 200
    assert client.get("/items/second").status_code == 200

    samples, _ = exposition_samples(client)
    request = samples['http_requests_total']
    assert request.labels == {"method": "GET", "path": "/items/{item_id}", "status": "200"}
    assert request.value == 2
