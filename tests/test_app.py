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


@pytest.fixture()
def client_with_key():
    app = create_app(api_key="secret-key")
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
        assert r.status_code == 409

    def test_invalid_hop_limit_returns_400(self, client):
        r = client.post(
            "/api/scan",
            data=json.dumps({"hop_limit": 99}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_invalid_cidr_returns_400(self, client):
        r = client.post(
            "/api/scan",
            data=json.dumps({"hop_limit": 2, "network": "not-a-cidr"}),
            content_type="application/json",
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------

class TestExport:
    def _load_demo(self, client):
        client.get("/api/demo")

    def test_export_json_returns_200(self, client):
        self._load_demo(client)
        r = client.get("/api/export/json")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "nodes" in data

    def test_export_csv_returns_200(self, client):
        self._load_demo(client)
        r = client.get("/api/export/csv")
        assert r.status_code == 200
        assert b"ip,hostname" in r.data

    def test_export_html_returns_200(self, client):
        self._load_demo(client)
        r = client.get("/api/export/html")
        assert r.status_code == 200
        assert b"<table>" in r.data


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

class TestPortScan:
    def test_post_ports_returns_202(self, client):
        r = client.post("/api/ports/192.168.1.1")
        assert r.status_code == 202
        data = json.loads(r.data)
        assert data["status"] == "scanning"

    def test_get_ports_after_scan_started(self, client):
        client.post("/api/ports/192.168.1.1")
        r = client.get("/api/ports/192.168.1.1")
        assert r.status_code == 200

    def test_get_ports_before_scan_404(self, client):
        r = client.get("/api/ports/192.168.99.99")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# History endpoints
# ---------------------------------------------------------------------------

class TestHistory:
    def test_history_returns_list(self, client):
        r = client.get("/api/history")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_alerts_recent_returns_list(self, client):
        r = client.get("/api/alerts/recent")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)


# ---------------------------------------------------------------------------
# API key enforcement
# ---------------------------------------------------------------------------

class TestApiKey:
    def test_request_without_key_returns_401(self, client_with_key):
        r = client_with_key.get("/api/health")
        assert r.status_code == 401

    def test_request_with_correct_bearer_token(self, client_with_key):
        r = client_with_key.get(
            "/api/health",
            headers={"Authorization": "Bearer secret-key"},
        )
        assert r.status_code == 200

    def test_request_with_x_api_key_header(self, client_with_key):
        r = client_with_key.get(
            "/api/health",
            headers={"X-API-Key": "secret-key"},
        )
        assert r.status_code == 200

    def test_wrong_key_returns_401(self, client_with_key):
        r = client_with_key.get(
            "/api/health",
            headers={"X-API-Key": "wrong-key"},
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_sixth_request_returns_429(self):
        app = create_app(rate_limit_max=5, rate_limit_window=60)
        app.config["TESTING"] = True
        with app.test_client() as c:
            for i in range(5):
                r = c.post(
                    "/api/scan",
                    data=json.dumps({"hop_limit": 2}),
                    content_type="application/json",
                )
            # 6th request should hit rate limit
            r = c.post(
                "/api/scan",
                data=json.dumps({"hop_limit": 2}),
                content_type="application/json",
            )
            assert r.status_code == 429

