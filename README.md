# Network Mapper

A web-based application that crawls your network, discovers all reachable
computers, and renders an interactive **fisheye force-directed diagram**
showing how they relate to one another.

---

## Features

| Feature | Details |
|---------|---------|
| **Multicast discovery** | Sends SSDP M-SEARCH multicast packets; hosts reply with unicast responses |
| **ICMP ping sweep** | Concurrent ping sweep across the local subnet |
| **ARP table lookup** | Resolves MAC addresses for discovered hosts |
| **Hop-count limiting** | Configurable TTL / hop limit (1–10) restricts how far discovery propagates across routers |
| **Fisheye diagram** | D3 v7 force-directed graph with radial ring layout and a lens-based fisheye distortion on mouse hover |
| **Change POV** | Click any node to re-draw the diagram from that computer's point of view |
| **Demo mode** | Built-in sample topology for instant visualisation without a live scan |
| **REST API** | Clean JSON API for scan control and topology queries |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
python main.py

# 3. Open in browser
#    http://localhost:5000
```

Click **Load Demo** for an instant preview, or **Start Scan** to discover
your live network (may require elevated privileges for raw-socket operations).

---

## Usage

### Web UI

| Control | Action |
|---------|--------|
| **Hop limit** slider | Maximum router hops to traverse |
| **Network** field | Optional CIDR to scan (e.g. `192.168.1.0/24`) |
| **Start Scan** | Begin live network discovery |
| **Load Demo** | Load a built-in sample topology |
| **Clear** | Reset the diagram |
| Hover over a node | Activate fisheye lens distortion |
| Click a node | Change the point-of-view to that computer |

### Command-line options

```
python main.py [--host HOST] [--port PORT] [--debug]
```

---

## REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Serve the web UI |
| `POST` | `/api/scan` | Start a background scan (`{"hop_limit": 4, "network": null}`) |
| `GET`  | `/api/scan/status` | Scan progress / status |
| `GET`  | `/api/topology` | Current topology (focal = local node) |
| `GET`  | `/api/topology/<ip>` | Topology from a specific node's POV |
| `GET`  | `/api/demo` | Load and return demo topology |
| `DELETE` | `/api/topology` | Clear current topology |
| `GET`  | `/api/health` | Health check |

---

## Project Structure

```
Network_Mapper/
├── main.py                  # Entry point
├── requirements.txt
├── setup.py
├── network_mapper/
│   ├── __init__.py
│   ├── scanner.py           # Multicast + ICMP discovery, hop limiting
│   ├── topology.py          # NetworkX graph, radial layout, D3 data
│   └── app.py               # Flask web server & REST API
├── static/
│   ├── index.html           # Single-page application
│   ├── css/styles.css       # Dark-themed styles
│   └── js/diagram.js        # D3 v7 fisheye diagram
└── tests/
    ├── test_scanner.py
    ├── test_topology.py
    └── test_app.py
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Notes

* Raw-socket multicast discovery may require `sudo` / administrator rights.
* ICMP ping sweeps work without root on most modern Linux distributions
  when `/bin/ping` has the `cap_net_raw` capability set.
* The application gracefully falls back to a reduced scan when elevated
  privileges are unavailable.
