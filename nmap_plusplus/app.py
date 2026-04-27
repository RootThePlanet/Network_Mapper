"""
Flask web application for nmap++.

Routes
------
GET  /                          – serve the SPA
POST /api/scan                  – start a background network scan
GET  /api/scan/status           – scan progress / status
GET  /api/scan/stream           – SSE stream of scan events
GET  /api/topology              – current topology (focal = local node)
GET  /api/topology/<ip>         – topology from a specific node's POV
GET  /api/demo                  – load demo topology data
DELETE /api/topology            – clear current topology
POST /api/ports/<ip>            – start port scan for IP (async)
GET  /api/ports/<ip>            – retrieve port scan results for IP
GET  /api/history               – list saved scans
GET  /api/history/<scan_id>     – load a saved scan
GET  /api/history/diff/<old>/<new> – diff two saved scans
GET  /api/export/json           – export topology as JSON download
GET  /api/export/csv            – export topology as CSV download
GET  /api/export/html           – export topology as HTML report
GET  /api/alerts/recent         – recent alert events
"""

import csv
import ipaddress
import io
import json
import logging
import queue
import socket
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, abort, jsonify, request, send_from_directory, stream_with_context
from flask_cors import CORS

from .scanner import NetworkScanner, generate_demo_topology
from .topology import NetworkTopology
from .port_scanner import scan_ports
from .history import ScanHistory

logger = logging.getLogger(__name__)

# Path to the static/ directory (sibling of nmap_plusplus/)
STATIC_DIR = Path(__file__).parent.parent / "static"


def create_app(
    static_folder: str = str(STATIC_DIR),
    api_key: Optional[str] = None,
    allowed_networks: Optional[List[str]] = None,
    rate_limit_window: int = 60,
    rate_limit_max: int = 5,
    webhooks: Optional[List[str]] = None,
    history_dir: str = "scan_history",
) -> Flask:
    """Application factory."""
    app = Flask(__name__, static_folder=static_folder, static_url_path="/static")
    CORS(app)

    # ------------------------------------------------------------------ #
    # Shared state
    # ------------------------------------------------------------------ #
    topology = NetworkTopology()
    history = ScanHistory(storage_dir=history_dir)

    scan_state: Dict[str, Any] = {
        "status": "idle",       # idle | scanning | complete | error
        "progress": 0,          # 0–100
        "found": 0,
        "error": None,
        "phase": "idle",
    }
    state_lock = threading.Lock()

    # Per-IP port scan results
    port_results: Dict[str, List] = {}
    port_lock = threading.Lock()

    # SSE event queue
    sse_queue: queue.Queue = queue.Queue()

    # Rate limiting state
    rate_limit_store: Dict[str, deque] = {}
    rate_lock = threading.Lock()

    # Alerts
    alerts_store: deque = deque(maxlen=50)

    # Previous topology snapshot for diffing (webhook notifications)
    _prev_topology_snapshot: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Security: API key check
    # ------------------------------------------------------------------ #

    @app.before_request
    def _check_api_key():
        if not api_key:
            return None
        # Allow health and static
        if not request.path.startswith("/api/"):
            return None
        key = (
            request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            or request.headers.get("X-API-Key", "").strip()
        )
        if key != api_key:
            return jsonify({"error": "Unauthorized"}), 401

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
        client_ip = request.remote_addr or "unknown"

        # Rate limiting
        now = time.time()
        with rate_lock:
            dq = rate_limit_store.setdefault(client_ip, deque())
            # Remove old timestamps
            while dq and now - dq[0] > rate_limit_window:
                dq.popleft()
            if len(dq) >= rate_limit_max:
                return jsonify({"error": "Rate limit exceeded"}), 429
            dq.append(now)

        with state_lock:
            if scan_state["status"] == "scanning":
                return jsonify({"error": "Scan already in progress"}), 409

            raw_hop = request.json.get("hop_limit", 4) if request.is_json else 4
            try:
                hop_limit = int(raw_hop)
            except (TypeError, ValueError):
                return jsonify({"error": "hop_limit must be an integer"}), 400
            if not (1 <= hop_limit <= 10):
                return jsonify({"error": "hop_limit must be between 1 and 10"}), 400

            network = (request.json.get("network") if request.is_json else None) or None
            if network:
                try:
                    ipaddress.ip_network(network, strict=False)
                except ValueError:
                    return jsonify({"error": f"Invalid network CIDR: {network!r}"}), 400
                # Allowed networks check
                if allowed_networks:
                    net_obj = ipaddress.ip_network(network, strict=False)
                    allowed = False
                    for cidr in allowed_networks:
                        try:
                            allowed_net = ipaddress.ip_network(cidr, strict=False)
                            # subnet_of requires both networks to be the same version
                            if (type(net_obj) is type(allowed_net)
                                    and net_obj.subnet_of(allowed_net)):
                                allowed = True
                                break
                        except Exception:
                            pass
                    if not allowed:
                        return jsonify({"error": "Network not in allowed list"}), 403

            scan_state.update(status="scanning", progress=0, found=0, error=None, phase="starting")

        topology.clear()

        def _send_sse(event: str, data: Any) -> None:
            try:
                sse_queue.put_nowait((event, data))
            except queue.Full:
                pass

        def _run():
            nonlocal _prev_topology_snapshot
            scanner = NetworkScanner(hop_limit=hop_limit)

            def _on_event(event: str, data: Dict):
                if event == "host_found":
                    ip = data.get("ip", "")
                    attrs = {k: v for k, v in data.items() if k != "ip"}
                    topology.add_host(ip, **attrs)
                    with state_lock:
                        scan_state["found"] += 1
                    _send_sse("host", data)

            def _phase_cb(phase: str) -> None:
                with state_lock:
                    scan_state["phase"] = phase
                _send_sse("phase", {"phase": phase})

            scanner.add_callback(_on_event)

            try:
                result = scanner.scan(network=network, phase_callback=_phase_cb)
                for a, b in result.get("links", []):
                    topology.add_link(a, b)

                with state_lock:
                    found = scan_state["found"]
                    scan_state.update(status="complete", progress=100, phase="complete")

                _send_sse("complete", {"found": found})

                # Auto-save history
                try:
                    history.save(topology.get_graph_data())
                except Exception as exc:
                    logger.warning("History save failed: %s", exc)

                # Webhook notifications
                if webhooks:
                    new_snapshot = topology.get_graph_data()
                    new_ips = {n["id"] for n in new_snapshot.get("nodes", [])}
                    old_ips = {n["id"] for n in _prev_topology_snapshot.get("nodes", [])}
                    new_hosts = sorted(new_ips - old_ips)
                    removed_hosts = sorted(old_ips - new_ips)

                    if new_hosts or removed_hosts:
                        alert = {
                            "event": "scan_complete",
                            "new_hosts": new_hosts,
                            "removed_hosts": removed_hosts,
                            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                        }
                        alerts_store.append(alert)
                        payload = json.dumps(alert).encode()
                        for url in webhooks:
                            try:
                                req = urllib.request.Request(
                                    url,
                                    data=payload,
                                    headers={"Content-Type": "application/json"},
                                    method="POST",
                                )
                                urllib.request.urlopen(req, timeout=5)
                            except Exception as exc:
                                logger.warning("Webhook %s failed: %s", url, exc)

                    _prev_topology_snapshot = new_snapshot

            except Exception as exc:
                logger.exception("Scan error")
                with state_lock:
                    scan_state.update(status="error", error=str(exc), phase="error")
                _send_sse("error", {"error": str(exc)})

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"status": "scanning"}), 202

    @app.get("/api/scan/status")
    def scan_status():
        with state_lock:
            return jsonify(dict(scan_state))

    @app.get("/api/scan/stream")
    def scan_stream():
        """Server-Sent Events stream for real-time scan progress."""
        def _generate():
            # Drain the queue
            while True:
                try:
                    event, data = sse_queue.get(timeout=30)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                    if event in ("complete", "error"):
                        break
                except queue.Empty:
                    yield ": keep-alive\n\n"

        return Response(
            stream_with_context(_generate()),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

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
            scan_state.update(status="idle", progress=0, found=0, error=None, phase="idle")
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
                phase="complete",
            )
        return jsonify(topology.get_graph_data())

    # ------------------------------------------------------------------ #
    # Port scanning
    # ------------------------------------------------------------------ #

    @app.post("/api/ports/<ip>")
    def start_port_scan(ip: str):
        def _run():
            results = scan_ports(ip)
            with port_lock:
                port_results[ip] = results

        threading.Thread(target=_run, daemon=True).start()
        with port_lock:
            port_results[ip] = []  # mark as scanning
        return jsonify({"ip": ip, "ports": [], "status": "scanning"}), 202

    @app.get("/api/ports/<ip>")
    def get_port_scan(ip: str):
        with port_lock:
            if ip not in port_results:
                abort(404, description=f"No port scan results for {ip!r}")
            return jsonify({"ip": ip, "ports": port_results[ip]})

    # ------------------------------------------------------------------ #
    # History endpoints
    # ------------------------------------------------------------------ #

    @app.get("/api/history")
    def list_history():
        return jsonify(history.list_scans())

    @app.get("/api/history/diff/<old_id>/<new_id>")
    def history_diff(old_id: str, new_id: str):
        try:
            return jsonify(history.diff(old_id, new_id))
        except FileNotFoundError as exc:
            abort(404, description=str(exc))

    @app.get("/api/history/<scan_id>")
    def load_history(scan_id: str):
        try:
            return jsonify(history.load(scan_id))
        except FileNotFoundError as exc:
            abort(404, description=str(exc))

    # ------------------------------------------------------------------ #
    # Export endpoints
    # ------------------------------------------------------------------ #

    @app.get("/api/export/json")
    def export_json():
        data = topology.get_graph_data()
        response = Response(
            json.dumps(data, indent=2),
            mimetype="application/json",
        )
        response.headers["Content-Disposition"] = "attachment; filename=topology.json"
        return response

    @app.get("/api/export/csv")
    def export_csv():
        data = topology.get_graph_data()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ip", "hostname", "mac", "vendor", "device_type", "node_type", "hop", "open_ports"])
        for node in data.get("nodes", []):
            ip = node.get("id", "")
            with port_lock:
                ports = port_results.get(ip, [])
            open_ports = ";".join(str(p["port"]) for p in ports if p.get("state") == "open")
            writer.writerow([
                ip,
                node.get("hostname", ""),
                node.get("mac", ""),
                node.get("vendor", ""),
                node.get("device_type", ""),
                node.get("node_type", ""),
                node.get("hop", ""),
                open_ports,
            ])
        response = Response(buf.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=topology.csv"
        return response

    @app.get("/api/export/html")
    def export_html():
        data = topology.get_graph_data()
        nodes = data.get("nodes", [])
        rows = ""
        for node in nodes:
            ip = node.get("id", "")
            with port_lock:
                ports = port_results.get(ip, [])
            open_ports = ", ".join(
                f"{p['port']}/{p.get('service','')}" for p in ports if p.get("state") == "open"
            ) or "—"
            rows += (
                f"<tr><td>{ip}</td>"
                f"<td>{node.get('hostname','')}</td>"
                f"<td>{node.get('mac','')}</td>"
                f"<td>{node.get('vendor','')}</td>"
                f"<td>{node.get('device_type','')}</td>"
                f"<td>{node.get('node_type','')}</td>"
                f"<td>{node.get('hop','')}</td>"
                f"<td>{open_ports}</td></tr>\n"
            )
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>nmap++ Report</title>
<style>
body {{ font-family: sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
h1 {{ color: #4a9eff; }}
table {{ border-collapse: collapse; width: 100%; }}
th,td {{ border: 1px solid #30363d; padding: 8px; text-align: left; font-size: 13px; }}
th {{ background: #161b22; color: #8b949e; }}
tr:nth-child(even) {{ background: #161b22; }}
.stat {{ color: #8b949e; margin-bottom: 16px; font-size: 13px; }}
</style></head>
<body>
<h1>nmap++ Network Report</h1>
<p class="stat">Generated: {datetime.now(tz=timezone.utc).isoformat()} &nbsp;|&nbsp;
Nodes: {data.get('node_count',0)} &nbsp;|&nbsp; Links: {data.get('link_count',0)}</p>
<table>
<thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Device</th><th>Type</th><th>Hop</th><th>Open Ports</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body></html>"""
        return Response(html, mimetype="text/html")

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #

    @app.get("/api/alerts/recent")
    def alerts_recent():
        return jsonify(list(alerts_store))

    # ------------------------------------------------------------------ #
    # Utility
    # ------------------------------------------------------------------ #

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "hostname": socket.gethostname()})

    return app

