"""
Network topology: wraps a NetworkX graph and produces D3-compatible data.

Usage::

    topo = NetworkTopology()
    topo.add_host("192.168.1.1", hostname="gateway", hop=1, node_type="gateway")
    topo.add_host("192.168.1.100", hostname="my-laptop", hop=0, node_type="local")
    topo.add_link("192.168.1.100", "192.168.1.1")
    data = topo.get_graph_data(focal_ip="192.168.1.100")
"""

import math
from typing import Dict, List, Optional, Tuple

import networkx as nx


class NetworkTopology:
    """Manages host nodes and their connections as a NetworkX undirected graph."""

    def __init__(self) -> None:
        self._graph: nx.Graph = nx.Graph()

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_host(
        self,
        ip: str,
        *,
        hostname: str = "",
        mac: str = "",
        hop: int = 0,
        node_type: str = "remote",
        **extra,
    ) -> None:
        """Add (or update) a host node."""
        self._graph.add_node(
            ip,
            hostname=hostname or ip,
            mac=mac,
            hop=hop,
            node_type=node_type,
            **extra,
        )

    def add_link(self, ip_a: str, ip_b: str) -> None:
        """Add an undirected link between two host nodes."""
        if ip_a not in self._graph:
            self.add_host(ip_a)
        if ip_b not in self._graph:
            self.add_host(ip_b)
        self._graph.add_edge(ip_a, ip_b)

    def load(self, scan_result: Dict) -> None:
        """Populate topology from a scanner result dict."""
        for ip, info in scan_result.get("hosts", {}).items():
            # Strip 'ip' from info to avoid duplicate keyword argument
            host_attrs = {k: v for k, v in info.items() if k != "ip"}
            self.add_host(ip, **host_attrs)
        for a, b in scan_result.get("links", []):
            self.add_link(a, b)

    def clear(self) -> None:
        self._graph.clear()

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def link_count(self) -> int:
        return self._graph.number_of_edges()

    def has_node(self, ip: str) -> bool:
        return ip in self._graph

    def neighbors(self, ip: str) -> List[str]:
        return list(self._graph.neighbors(ip))

    def shortest_path_length(self, source: str, target: str) -> Optional[int]:
        try:
            return nx.shortest_path_length(self._graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    # ------------------------------------------------------------------
    # Hop distances from a focal node
    # ------------------------------------------------------------------

    def hop_distances(self, focal_ip: str) -> Dict[str, int]:
        """
        Return a mapping of {ip: hop_distance} measured as shortest-path
        hops from *focal_ip* in the graph.  Unreachable nodes get distance
        equal to the diameter + 1.
        """
        if focal_ip not in self._graph:
            return {}
        try:
            lengths = nx.single_source_shortest_path_length(self._graph, focal_ip)
        except Exception:
            lengths = {}
        max_dist = max(lengths.values(), default=0) + 1
        result = {}
        for node in self._graph.nodes:
            result[node] = lengths.get(node, max_dist)
        return result

    # ------------------------------------------------------------------
    # Radial layout
    # ------------------------------------------------------------------

    def radial_positions(
        self,
        focal_ip: str,
        ring_radius: float = 120.0,
    ) -> Dict[str, Tuple[float, float]]:
        """
        Compute (x, y) canvas positions arranged in concentric rings.

        * Focal node → center (0, 0)
        * Hop-1 nodes → first ring
        * Hop-2 nodes → second ring … etc.
        """
        distances = self.hop_distances(focal_ip)
        if not distances:
            return {}

        # Group nodes by hop distance
        rings: Dict[int, List[str]] = {}
        for ip, d in distances.items():
            rings.setdefault(d, []).append(ip)

        positions: Dict[str, Tuple[float, float]] = {}

        for hop, nodes in rings.items():
            if hop == 0:
                positions[nodes[0]] = (0.0, 0.0)
                continue
            radius = hop * ring_radius
            count = len(nodes)
            for i, ip in enumerate(nodes):
                angle = 2 * math.pi * i / count
                positions[ip] = (radius * math.cos(angle), radius * math.sin(angle))

        return positions

    # ------------------------------------------------------------------
    # D3-compatible output
    # ------------------------------------------------------------------

    def get_graph_data(self, focal_ip: Optional[str] = None) -> Dict:
        """
        Return a dict with ``nodes`` and ``links`` ready for D3.js.

        Each node has:
            id, hostname, mac, hop, node_type, distance_from_focal

        Each link has:
            source, target
        """
        if focal_ip is None:
            # Default to the local node if present, else first node
            local_candidates = [
                n
                for n, d in self._graph.nodes(data=True)
                if d.get("node_type") == "local"
            ]
            focal_ip = local_candidates[0] if local_candidates else (
                next(iter(self._graph.nodes), None)
            )

        distances = self.hop_distances(focal_ip) if focal_ip else {}

        nodes = []
        for ip, data in self._graph.nodes(data=True):
            nodes.append(
                {
                    "id": ip,
                    "hostname": data.get("hostname", ip),
                    "mac": data.get("mac", ""),
                    "hop": data.get("hop", 0),
                    "node_type": data.get("node_type", "remote"),
                    "distance_from_focal": distances.get(ip, 99),
                    "is_focal": ip == focal_ip,
                }
            )

        links = [{"source": u, "target": v} for u, v in self._graph.edges()]

        return {
            "nodes": nodes,
            "links": links,
            "focal": focal_ip,
            "node_count": len(nodes),
            "link_count": len(links),
        }
