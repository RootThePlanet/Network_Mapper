"""Tests for Flask API (nmap_plusplus.app)."""

import json
import pytest

from nmap_plusplus.app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Health / frontend
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["status"] == "ok"

    def test_index_serves_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"nmap++" in r.data


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

class TestDemo:
    def test_demo_returns_nodes(self, client):
        r = client.get("/api/demo")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["node_count"] > 0
        assert len(data["nodes"]) > 0

    def test_demo_contains_local_node(self, client):
        r = client.get("/api/demo")
        data = json.loads(r.data)
        local_nodes = [n for n in data["nodes"] if n["node_type"] == "local"]
        assert len(local_nodes) == 1

    def test_demo_sets_focal(self, client):
        r = client.get("/api/demo")
        data = json.loads(r.data)
        assert data["focal"] is not None


# ---------------------------------------------------------------------------
# Topology endpoints
# ---------------------------------------------------------------------------

class TestTopology:
    def _load_demo(self, client):
        client.get("/api/demo")

    def test_get_topology_empty(self, client):
        r = client.get("/api/topology")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["node_count"] == 0

    def test_get_topology_after_demo(self, client):
        self._load_demo(client)
        r = client.get("/api/topology")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["node_count"] > 0

    def test_get_topology_from_valid_ip(self, client):
        self._load_demo(client)
        # Get demo data to find a valid IP
        demo_data = json.loads(client.get("/api/demo").data)
        some_ip = demo_data["nodes"][0]["id"]

        r = client.get(f"/api/topology/{some_ip}")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["focal"] == some_ip

    def test_get_topology_from_unknown_ip_404(self, client):
        self._load_demo(client)
        r = client.get("/api/topology/0.0.0.0")
        assert r.status_code == 404

    def test_topology_pov_focal_is_distance_zero(self, client):
        self._load_demo(client)
        demo_data = json.loads(client.get("/api/demo").data)
        some_ip = demo_data["nodes"][0]["id"]

        r = client.get(f"/api/topology/{some_ip}")
        data = json.loads(r.data)
        focal_node = next(n for n in data["nodes"] if n["id"] == some_ip)
        assert focal_node["is_focal"] is True
        assert focal_node["distance_from_focal"] == 0

    def test_delete_topology_clears(self, client):
        self._load_demo(client)
        client.delete("/api/topology")
        r = client.get("/api/topology")
        data = json.loads(r.data)
        assert data["node_count"] == 0


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

class TestScan:
    def test_scan_status_idle_initially(self, client):
        r = client.get("/api/scan/status")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["status"] == "idle"

    def test_start_scan_returns_202(self, client):
        r = client.post(
            "/api/scan",
            data=json.dumps({"hop_limit": 2}),
            content_type="application/json",
        )
        assert r.status_code == 202
        data = json.loads(r.data)
        assert data["status"] == "scanning"

    def test_double_scan_returns_409(self, client):
        client.post(
            "/api/scan",
            data=json.dumps({"hop_limit": 2}),
            content_type="application/json",
        )
        r = client.post(
            "/api/scan",
            data=json.dumps({"hop_limit": 2}),
            content_type="application/json",
        )
        # Second request while scan is in progress → 409
        assert r.status_code == 409
