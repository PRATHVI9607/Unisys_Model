"""disk_io_bytes: the demo victim counter takes precedence, the cAdvisor expression is the fallback."""

from agents.health_agent.metric_queries import SPEC_BY_COLUMN, build_queries


def test_disk_io_query_has_victim_counter_then_cadvisor_fallback():
    q = build_queries("prod", "victim-app")["disk_io_bytes"]
    first, _, fallback = q.partition(" or ")
    assert "kubeheal_victim_disk_io_bytes_total" in first
    assert "container_fs_reads_bytes_total" in fallback
    assert "container_fs_writes_bytes_total" in fallback
    assert "kubeheal_victim_disk_io_bytes_total" not in fallback


def test_disk_io_query_uses_the_workload_selector_everywhere():
    q = build_queries("prod", "victim-app")["disk_io_bytes"]
    assert q.count('namespace="prod",pod=~"victim-app.*"') == 3
    assert "{sel}" not in q


def test_disk_io_is_a_standard_metric_again():
    assert SPEC_BY_COLUMN["disk_io_bytes"].basis == "standard"
