"""Tests for nmap_plusplus.topology."""

import pytest

from nmap_plusplus.topology import NetworkTopology


# ---------------------------------------------------------------------------
# add_host / add_link
# ---------------------------------------------------------------------------

class TestMutation:
    def test_add_host_increments_count(self):
        t = NetworkTopology()
        t.add_host("10.0.0.1")
        assert t.node_count == 1

    def test_add_host_stores_attributes(self):
        t = NetworkTopology()
        t.add_host("10.0.0.1", hostname="srv1", hop=2, node_type="remote")
        data = t.get_graph_data()
        node = next(n for n in data["nodes"] if n["id"] == "10.0.0.1")
        assert node["hostname"] == "srv1"
        assert node["hop"] == 2
        assert node["node_type"] == "remote"

    def test_add_link_creates_edge(self):
        t = NetworkTopology()
        t.add_host("10.0.0.1")
        t.add_host("10.0.0.2")
        t.add_link("10.0.0.1", "10.0.0.2")
        assert t.link_count == 1

    def test_add_link_auto_creates_missing_nodes(self):
        t = NetworkTopology()
        t.add_link("10.0.0.1", "10.0.0.2")
        assert t.node_count == 2
        assert t.link_count == 1

    def test_add_link_idempotent(self):
        t = NetworkTopology()
        t.add_link("10.0.0.1", "10.0.0.2")
        t.add_link("10.0.0.1", "10.0.0.2")
        assert t.link_count == 1

    def test_clear_removes_everything(self):
        t = NetworkTopology()
        t.add_host("10.0.0.1")
        t.add_link("10.0.0.1", "10.0.0.2")
        t.clear()
        assert t.node_count == 0
        assert t.link_count == 0

    def test_load_from_scan_result(self):
        t = NetworkTopology()
        t.load({
            "hosts": {
                "1.1.1.1": {"ip": "1.1.1.1", "hostname": "a", "hop": 0},
                "1.1.1.2": {"ip": "1.1.1.2", "hostname": "b", "hop": 1},
            },
            "links": [("1.1.1.1", "1.1.1.2")],
        })
        assert t.node_count == 2
        assert t.link_count == 1


# ---------------------------------------------------------------------------
# has_node / neighbors / shortest_path_length
# ---------------------------------------------------------------------------

class TestQuery:
    def setup_method(self):
        self.t = NetworkTopology()
        self.t.add_host("A", hop=0, node_type="local")
        self.t.add_host("B", hop=1, node_type="remote")
        self.t.add_host("C", hop=2, node_type="remote")
        self.t.add_link("A", "B")
        self.t.add_link("B", "C")

    def test_has_node_existing(self):
        assert self.t.has_node("A")

    def test_has_node_missing(self):
        assert not self.t.has_node("Z")

    def test_neighbors(self):
        assert set(self.t.neighbors("B")) == {"A", "C"}

    def test_shortest_path_length(self):
        assert self.t.shortest_path_length("A", "C") == 2

    def test_shortest_path_length_no_path(self):
        self.t.add_host("D")  # disconnected node
        assert self.t.shortest_path_length("A", "D") is None

    def test_shortest_path_length_unknown_node(self):
        assert self.t.shortest_path_length("A", "Z") is None


# ---------------------------------------------------------------------------
# hop_distances
# ---------------------------------------------------------------------------

class TestHopDistances:
    def test_focal_is_zero(self):
        t = NetworkTopology()
        t.add_host("A"); t.add_host("B"); t.add_host("C")
        t.add_link("A", "B"); t.add_link("B", "C")
        d = t.hop_distances("A")
        assert d["A"] == 0

    def test_distances_in_chain(self):
        t = NetworkTopology()
        for ip in ("A", "B", "C", "D"):
            t.add_host(ip)
        t.add_link("A", "B"); t.add_link("B", "C"); t.add_link("C", "D")
        d = t.hop_distances("A")
        assert d == {"A": 0, "B": 1, "C": 2, "D": 3}

    def test_unknown_focal_returns_empty(self):
        t = NetworkTopology()
        t.add_host("A")
        assert t.hop_distances("Z") == {}

    def test_unreachable_node_gets_large_distance(self):
        t = NetworkTopology()
        t.add_host("A"); t.add_host("X")   # disconnected
        t.add_host("B"); t.add_link("A", "B")
        d = t.hop_distances("A")
        assert d["X"] > d["B"]


# ---------------------------------------------------------------------------
# radial_positions
# ---------------------------------------------------------------------------

class TestRadialPositions:
    def test_focal_at_origin(self):
        t = NetworkTopology()
        t.add_host("A"); t.add_host("B")
        t.add_link("A", "B")
        pos = t.radial_positions("A")
        assert pos["A"] == (0.0, 0.0)

    def test_hop1_node_is_on_ring(self):
        import math
        t = NetworkTopology()
        t.add_host("A"); t.add_host("B")
        t.add_link("A", "B")
        ring_r = 100.0
        pos = t.radial_positions("A", ring_radius=ring_r)
        bx, by = pos["B"]
        dist = math.sqrt(bx ** 2 + by ** 2)
        assert abs(dist - ring_r) < 1e-6

    def test_all_nodes_get_positions(self):
        t = NetworkTopology()
        for ip in ("A", "B", "C"):
            t.add_host(ip)
        t.add_link("A", "B"); t.add_link("B", "C")
        pos = t.radial_positions("A")
        assert set(pos.keys()) == {"A", "B", "C"}


# ---------------------------------------------------------------------------
# get_graph_data
# ---------------------------------------------------------------------------

class TestGetGraphData:
    def _build(self):
        t = NetworkTopology()
        t.add_host("local", node_type="local", hop=0)
        t.add_host("remote1", node_type="remote", hop=1)
        t.add_host("remote2", node_type="remote", hop=2)
        t.add_link("local", "remote1")
        t.add_link("remote1", "remote2")
        return t

    def test_structure(self):
        data = self._build().get_graph_data(focal_ip="local")
        assert "nodes" in data
        assert "links" in data
        assert "focal" in data
        assert data["focal"] == "local"

    def test_focal_node_is_flagged(self):
        data = self._build().get_graph_data(focal_ip="local")
        focal_nodes = [n for n in data["nodes"] if n["is_focal"]]
        assert len(focal_nodes) == 1
        assert focal_nodes[0]["id"] == "local"

    def test_distance_from_focal(self):
        data = self._build().get_graph_data(focal_ip="local")
        by_id = {n["id"]: n for n in data["nodes"]}
        assert by_id["local"]["distance_from_focal"] == 0
        assert by_id["remote1"]["distance_from_focal"] == 1
        assert by_id["remote2"]["distance_from_focal"] == 2

    def test_defaults_to_local_node_as_focal(self):
        data = self._build().get_graph_data()
        assert data["focal"] == "local"

    def test_pov_change_recalculates_distances(self):
        t = self._build()
        data = t.get_graph_data(focal_ip="remote2")
        by_id = {n["id"]: n for n in data["nodes"]}
        # From remote2's POV: remote1 is 1 hop, local is 2 hops
        assert by_id["remote2"]["distance_from_focal"] == 0
        assert by_id["remote1"]["distance_from_focal"] == 1
        assert by_id["local"]["distance_from_focal"] == 2

    def test_node_and_link_counts(self):
        data = self._build().get_graph_data(focal_ip="local")
        assert data["node_count"] == 3
        assert data["link_count"] == 2

    def test_empty_topology_returns_empty(self):
        t = NetworkTopology()
        data = t.get_graph_data()
        assert data["nodes"] == []
        assert data["links"] == []
