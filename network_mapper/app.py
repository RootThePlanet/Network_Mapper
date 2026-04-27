"""
Flask web application for Network Mapper.

Routes
------
GET  /                          – serve the SPA
POST /api/scan                  – start a background network scan
GET  /api/scan/status           – scan progress / status
GET  /api/topology              – current topology (focal = local node)
GET  /api/topology/<ip>         – topology from a specific node's POV
GET  /api/demo                  – load demo topology data
DELETE /api/topology            – clear current topology
"""

import logging
import socket
import threading
from pathlib import Path
from typing import Any, Dict

from flask import Flask, abort, jsonify, request, send_from_directory
from flask_cors import CORS

from .scanner import NetworkScanner, generate_demo_topology
from .topology import NetworkTopology

logger = logging.getLogger(__name__)

# Path to the static/ directory (sibling of network_mapper/)
STATIC_DIR = Path(__file__).parent.parent / "static"


def create_app(static_folder: str = str(STATIC_DIR)) -> Flask:
    """Application factory."""
    app = Flask(__name__, static_folder=static_folder, static_url_path="/static")
    CORS(app)

    # ------------------------------------------------------------------ #
    # Shared state
    # ------------------------------------------------------------------ #
    topology = NetworkTopology()
    scan_state: Dict[str, Any] = {
        "status": "idle",       # idle | scanning | complete | error
        "progress": 0,          # 0–100
        "found": 0,
        "error": None,
    }
    state_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Frontend
    # ------------------------------------------------------------------ #

    @app.route("/")
    def index():
        return send_from_directory(static_folder, "index.html")

    # ------------------------------------------------------------------ #
    # Scan endpoints
    # ------------------------------------------------------------------ #

    @app.post("/api/scan")
    def start_scan():
        with state_lock:
            if scan_state["status"] == "scanning":
                return jsonify({"error": "Scan already in progress"}), 409

            hop_limit = int(request.json.get("hop_limit", 4) if request.is_json else 4)
            network = (request.json.get("network") if request.is_json else None) or None

            scan_state.update(status="scanning", progress=0, found=0, error=None)

        topology.clear()

        def _run():
            scanner = NetworkScanner(hop_limit=hop_limit)

            def _on_event(event: str, data: Dict):
                if event == "host_found":
                    ip = data.get("ip", "")
                    attrs = {k: v for k, v in data.items() if k != "ip"}
                    topology.add_host(ip, **attrs)
                    with state_lock:
                        scan_state["found"] += 1

            scanner.add_callback(_on_event)

            try:
                result = scanner.scan(network=network)
                # Ensure links are loaded
                for a, b in result.get("links", []):
                    topology.add_link(a, b)

                with state_lock:
                    scan_state.update(status="complete", progress=100)
            except Exception as exc:
                logger.exception("Scan error")
                with state_lock:
                    scan_state.update(status="error", error=str(exc))

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"status": "scanning"}), 202

    @app.get("/api/scan/status")
    def scan_status():
        with state_lock:
            return jsonify(dict(scan_state))

    # ------------------------------------------------------------------ #
    # Topology endpoints
    # ------------------------------------------------------------------ #

    @app.get("/api/topology")
    def get_topology():
        if topology.node_count == 0:
            return jsonify({"nodes": [], "links": [], "focal": None,
                            "node_count": 0, "link_count": 0})
        return jsonify(topology.get_graph_data())

    @app.get("/api/topology/<path:ip>")
    def get_topology_from(ip: str):
        if topology.node_count == 0:
            abort(404, description="No topology loaded")
        if not topology.has_node(ip):
            abort(404, description=f"Node {ip!r} not found")
        return jsonify(topology.get_graph_data(focal_ip=ip))

    @app.delete("/api/topology")
    def clear_topology():
        topology.clear()
        with state_lock:
            scan_state.update(status="idle", progress=0, found=0, error=None)
        return jsonify({"status": "cleared"})

    # ------------------------------------------------------------------ #
    # Demo data
    # ------------------------------------------------------------------ #

    @app.get("/api/demo")
    def demo():
        topology.clear()
        demo_data = generate_demo_topology()
        topology.load(demo_data)
        with state_lock:
            scan_state.update(
                status="complete",
                progress=100,
                found=topology.node_count,
                error=None,
            )
        return jsonify(topology.get_graph_data())

    # ------------------------------------------------------------------ #
    # Utility
    # ------------------------------------------------------------------ #

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "hostname": socket.gethostname()})

    return app
