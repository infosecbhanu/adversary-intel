"""
Infrastructure graph for adversary tracking.

Builds a NetworkX directed graph where nodes are IPs, domains, certificates,
ASNs, and hashes — and edges represent relationships discovered through pivoting.
The graph persists across IP rotations and reveals the full operator cluster.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from adversary_intel.models import EdgeType, InfraEdge, InfraNode, NodeType


class InfraGraph:
    def __init__(self):
        self._g = nx.DiGraph()

    # ── Node management ──────────────────────────────────────────────────────

    def add_node(self, node: InfraNode) -> None:
        self._g.add_node(
            node.id,
            value=node.value,
            node_type=node.node_type.value,
            reported=node.reported,
            confidence=node.confidence,
            tags=node.tags,
            meta=node.meta,
            first_seen=node.first_seen.isoformat() if node.first_seen else None,
            last_seen=node.last_seen.isoformat() if node.last_seen else None,
        )

    def add_ip(self, ip: str, reported: bool = False, confidence: int = 50, **meta) -> str:
        node_id = f"ip:{ip}"
        node = InfraNode(
            id=node_id,
            node_type=NodeType.IP,
            value=ip,
            reported=reported,
            confidence=confidence,
            meta=meta,
        )
        self.add_node(node)
        return node_id

    def add_domain(self, domain: str, reported: bool = False, confidence: int = 50, **meta) -> str:
        node_id = f"domain:{domain}"
        node = InfraNode(
            id=node_id,
            node_type=NodeType.DOMAIN,
            value=domain,
            reported=reported,
            confidence=confidence,
            meta=meta,
        )
        self.add_node(node)
        return node_id

    def add_cert(self, fingerprint: str, subject_cn: str = "", reported: bool = False) -> str:
        node_id = f"cert:{fingerprint}"
        node = InfraNode(
            id=node_id,
            node_type=NodeType.CERTIFICATE,
            value=fingerprint,
            reported=reported,
            confidence=75,
            meta={"subject_cn": subject_cn},
        )
        self.add_node(node)
        return node_id

    def add_asn(self, asn: str, name: str = "", is_bulletproof: bool = False) -> str:
        node_id = f"asn:{asn}"
        node = InfraNode(
            id=node_id,
            node_type=NodeType.ASN,
            value=asn,
            confidence=60,
            meta={"name": name, "is_bulletproof": is_bulletproof},
        )
        self.add_node(node)
        return node_id

    def add_hash(self, hash_val: str, hash_type: str = "sha256") -> str:
        node_id = f"hash:{hash_val}"
        node = InfraNode(
            id=node_id,
            node_type=NodeType.HASH,
            value=hash_val,
            confidence=90,
            meta={"hash_type": hash_type},
        )
        self.add_node(node)
        return node_id

    # ── Edge management ──────────────────────────────────────────────────────

    def add_edge(self, edge: InfraEdge) -> None:
        self._g.add_edge(
            edge.source,
            edge.target,
            edge_type=edge.edge_type.value,
            confidence=edge.confidence,
            meta=edge.meta,
            first_seen=edge.first_seen.isoformat() if edge.first_seen else None,
        )

    def link(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        confidence: int = 70,
        **meta,
    ) -> None:
        edge = InfraEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            confidence=confidence,
            meta=meta,
        )
        self.add_edge(edge)

    # ── Analysis ─────────────────────────────────────────────────────────────

    def get_cluster(self, seed_id: str, depth: int = 2) -> set[str]:
        """Return all node IDs reachable within `depth` hops from seed."""
        if seed_id not in self._g:
            return set()
        return set(nx.single_source_shortest_path(self._g, seed_id, cutoff=depth).keys())

    def unreported_nodes(self) -> list[str]:
        """Nodes not present in any public threat feed — high-value finds."""
        return [
            n for n, data in self._g.nodes(data=True)
            if not data.get("reported", True)
        ]

    def high_confidence_nodes(self, threshold: int = 70) -> list[str]:
        return [
            n for n, data in self._g.nodes(data=True)
            if data.get("confidence", 0) >= threshold
        ]

    def get_ips(self) -> list[str]:
        return [
            data["value"]
            for _, data in self._g.nodes(data=True)
            if data.get("node_type") == NodeType.IP.value
        ]

    def get_domains(self) -> list[str]:
        return [
            data["value"]
            for _, data in self._g.nodes(data=True)
            if data.get("node_type") == NodeType.DOMAIN.value
        ]

    def find_jarm_clusters(self) -> dict[str, list[str]]:
        """
        Group IPs by shared JARM fingerprint.
        Returns {jarm: [ip1, ip2, ...]}
        """
        clusters: dict[str, list[str]] = {}
        for _, data in self._g.nodes(data=True):
            if data.get("node_type") == NodeType.IP.value:
                jarm = data.get("meta", {}).get("jarm")
                if jarm:
                    clusters.setdefault(jarm, []).append(data["value"])
        return {k: v for k, v in clusters.items() if len(v) > 1}

    def find_cert_clusters(self) -> dict[str, list[str]]:
        """
        Find IPs sharing the same TLS certificate template (serial or CN).
        Returns {cert_fingerprint: [ip1, ip2, ...]}
        """
        clusters: dict[str, list[str]] = {}
        for n, edge_data in self._g.edges(data=True):
            if edge_data.get("edge_type") == EdgeType.SHARES_CERT.value:
                target = edge_data.get("meta", {}).get("cert_fingerprint", "unknown")
                clusters.setdefault(target, []).append(n)
        return {k: v for k, v in clusters.items() if len(v) > 1}

    def stats(self) -> dict[str, Any]:
        node_types: dict[str, int] = {}
        for _, data in self._g.nodes(data=True):
            t = data.get("node_type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1
        return {
            "total_nodes": self._g.number_of_nodes(),
            "total_edges": self._g.number_of_edges(),
            "unreported": len(self.unreported_nodes()),
            "node_types": node_types,
        }

    # ── Export ───────────────────────────────────────────────────────────────

    def to_json(self) -> dict:
        return nx.node_link_data(self._g)

    def save_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_json(), f, indent=2, default=str)

    def save_gexf(self, path: Path) -> None:
        """GEXF format for import into Gephi or Maltego."""
        path.parent.mkdir(parents=True, exist_ok=True)
        nx.write_gexf(self._g, str(path))

    def save_graphml(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(self._g, str(path))

    @classmethod
    def from_json(cls, data: dict) -> "InfraGraph":
        g = cls()
        g._g = nx.node_link_graph(data)
        return g

    @classmethod
    def load_json(cls, path: Path) -> "InfraGraph":
        with open(path) as f:
            return cls.from_json(json.load(f))

    def try_interactive_html(self, path: Path) -> bool:
        """Export interactive HTML graph using pyvis (optional dependency)."""
        try:
            from pyvis.network import Network
            net = Network(height="750px", width="100%", directed=True)
            node_colors = {
                "ip": "#e74c3c",
                "domain": "#3498db",
                "certificate": "#2ecc71",
                "asn": "#f39c12",
                "hash": "#9b59b6",
            }
            for node_id, data in self._g.nodes(data=True):
                color = node_colors.get(data.get("node_type", ""), "#95a5a6")
                label = data.get("value", node_id)[:30]
                title = f"Type: {data.get('node_type')}\nConfidence: {data.get('confidence')}%"
                if not data.get("reported"):
                    title += "\n⚠ Not in public feeds"
                net.add_node(node_id, label=label, color=color, title=title)
            for src, tgt, data in self._g.edges(data=True):
                net.add_edge(src, tgt, title=data.get("edge_type", ""))
            path.parent.mkdir(parents=True, exist_ok=True)
            net.save_graph(str(path))
            return True
        except ImportError:
            return False
