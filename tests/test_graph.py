"""Tests for infrastructure graph module."""
import pytest
from adversary_intel.graph.infra_graph import InfraGraph
from adversary_intel.models import EdgeType, NodeType


@pytest.fixture
def graph():
    return InfraGraph()


def test_add_ip(graph):
    node_id = graph.add_ip("1.2.3.4")
    assert node_id == "ip:1.2.3.4"
    assert "ip:1.2.3.4" in graph._g.nodes


def test_add_domain(graph):
    node_id = graph.add_domain("evil.example.com")
    assert node_id == "domain:evil.example.com"


def test_add_cert(graph):
    node_id = graph.add_cert("AABBCC112233", subject_cn="localhost")
    assert "cert:AABBCC112233" in graph._g.nodes


def test_link_nodes(graph):
    ip_id = graph.add_ip("1.2.3.4")
    domain_id = graph.add_domain("evil.com")
    graph.link(domain_id, ip_id, EdgeType.RESOLVES_TO)
    assert graph._g.has_edge(domain_id, ip_id)


def test_unreported_nodes(graph):
    graph.add_ip("1.2.3.4", reported=False)
    graph.add_ip("5.6.7.8", reported=True)
    unreported = graph.unreported_nodes()
    assert "ip:1.2.3.4" in unreported
    assert "ip:5.6.7.8" not in unreported


def test_get_cluster(graph):
    graph.add_ip("1.2.3.4")
    graph.add_domain("evil.com")
    graph.link("domain:evil.com", "ip:1.2.3.4", EdgeType.RESOLVES_TO)
    cluster = graph.get_cluster("domain:evil.com", depth=1)
    assert "ip:1.2.3.4" in cluster
    assert "domain:evil.com" in cluster


def test_find_jarm_clusters(graph):
    ip1 = graph.add_ip("1.2.3.4")
    ip2 = graph.add_ip("5.6.7.8")
    jarm = "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"
    graph._g.nodes[ip1]["meta"] = {"jarm": jarm}
    graph._g.nodes[ip2]["meta"] = {"jarm": jarm}
    clusters = graph.find_jarm_clusters()
    assert jarm in clusters
    assert len(clusters[jarm]) == 2


def test_stats(graph):
    graph.add_ip("1.2.3.4")
    graph.add_domain("evil.com")
    graph.link("domain:evil.com", "ip:1.2.3.4", EdgeType.RESOLVES_TO)
    stats = graph.stats()
    assert stats["total_nodes"] == 2
    assert stats["total_edges"] == 1


def test_serialization_roundtrip(graph, tmp_path):
    graph.add_ip("1.2.3.4", confidence=90)
    graph.add_domain("evil.com")
    graph.link("domain:evil.com", "ip:1.2.3.4", EdgeType.RESOLVES_TO)
    path = tmp_path / "graph.json"
    graph.save_json(path)
    loaded = InfraGraph.load_json(path)
    assert loaded._g.number_of_nodes() == 2
    assert loaded._g.number_of_edges() == 1


def test_get_ips_and_domains(graph):
    graph.add_ip("10.0.0.1")
    graph.add_ip("10.0.0.2")
    graph.add_domain("phish.example.com")
    ips = graph.get_ips()
    domains = graph.get_domains()
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips
    assert "phish.example.com" in domains
