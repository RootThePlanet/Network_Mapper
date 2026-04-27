/**
 * Network Mapper – D3 v7 fisheye force-directed diagram.
 *
 * Features:
 *  - Force-directed layout with radial "ring" force by hop distance
 *  - Fisheye (lens) distortion centred on the mouse cursor
 *  - Click a node → re-pivot the diagram to show the network from that
 *    node's point of view (POV change calls /api/topology/<ip>)
 *  - Zoom / pan
 *  - Animated transitions when the focal node changes
 *  - SSE real-time updates, port scanning, history, export, search,
 *    table view, desktop notifications
 */

/* ============================================================
   Colour helpers
   ============================================================ */
const NODE_COLORS = {
  local:   "#f0c040",
  gateway: "#ff7c5a",
  remote:  null,       // determined by hop
};

/* ============================================================
   Device-type icons (emoji)
   ============================================================ */
const DEVICE_ICONS = {
  router:       "📡",
  phone:        "📱",
  laptop:       "💻",
  desktop:      "🖥️",
  tv:           "📺",
  printer:      "🖨️",
  server:       "🗄️",
  raspberry_pi: "🍓",
  vm:           "☁️",
  iot:          "💡",
  unknown:      "",
};

function deviceIcon(d) {
  return DEVICE_ICONS[d.device_type] || "";
}

function deviceLabel(d) {
  const icon = deviceIcon(d);
  const type = (d.device_type || "").replace(/_/g, " ");
  if (!type || type === "unknown") return d.vendor || "";
  return icon ? `${icon} ${type}` : type;
}

function nodeColor(d) {
  if (d.is_focal)             return "#ff5fd8";
  if (d.node_type === "local")   return NODE_COLORS.local;
  if (d.node_type === "gateway") return NODE_COLORS.gateway;
  const h = d.distance_from_focal ?? d.hop ?? 0;
  if (h <= 1)  return "#4a9eff";
  if (h === 2) return "#5ba88b";
  return "#9275c4";
}

// Colors for history diff highlighting
const DIFF_COLORS = { new: "#3fb950", removed: "#f85149", changed: "#d29922" };

function nodeColor2(d) {
  if (d._diffStatus === "new")     return DIFF_COLORS.new;
  if (d._diffStatus === "removed") return DIFF_COLORS.removed;
  if (d._diffStatus === "changed") return DIFF_COLORS.changed;
  return nodeColor(d);
}

function nodeRadius(d) {
  if (d.is_focal)             return 18;
  if (d.node_type === "local")   return 15;
  if (d.node_type === "gateway") return 13;
  const h = d.distance_from_focal ?? d.hop ?? 0;
  if (h <= 1)  return 11;
  if (h === 2) return 9;
  return 7;
}

/* ============================================================
   Label helpers
   ============================================================ */

const LABEL_MAX_LENGTH = 18;
const LABEL_TRUNCATE_LENGTH = 16;

/**
 * Return a concise primary label for a node.
 * - If hostname is meaningful (not just the IP), strip .local. suffix and
 *   truncate long strings.
 * - For IPv6 IDs with no meaningful hostname, abbreviate to last two groups.
 * - IPv4 IDs are short enough to display as-is.
 */
function nodeLabel(d) {
  const h = d.hostname || d.id;
  if (h !== d.id) {
    // Strip mDNS .local. / .local suffix
    let name = h.replace(/\.local\.?$/, "");
    return name.length > LABEL_MAX_LENGTH ? name.slice(0, LABEL_TRUNCATE_LENGTH) + "…" : name;
  }
  // hostname == id (no reverse-DNS result)
  if (d.id.includes(":")) {
    // IPv6 – show last two groups
    const parts = d.id.split(":");
    return "…:" + parts.slice(-2).join(":");
  }
  return d.id;
}

/* ============================================================
   Fisheye distortion (radial, Sarkar & Brown 1992)
   ============================================================ */
function createFisheye({ distortion = 3, radius = 180 } = {}) {
  function fisheye(point, focus) {
    const dx = point.x - focus.x;
    const dy = point.y - focus.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist === 0 || dist >= radius) return { x: point.x, y: point.y };

    const k = (distortion + 1) * radius;
    const scale = k / (distortion * dist + radius);

    return {
      x: focus.x + dx * scale,
      y: focus.y + dy * scale,
    };
  }
  fisheye.distortion = (v) => { distortion = v; return fisheye; };
  fisheye.radius = (v) => {
    if (v === undefined) return radius;
    radius = v;
    return fisheye;
  };
  return fisheye;
}

/* ============================================================
   Network Diagram class
   ============================================================ */
class NetworkDiagram {
  constructor(svgSelector) {
    this.svg = d3.select(svgSelector);
    this.width = 0;
    this.height = 0;
    this.nodes = [];
    this.links = [];
    this.focalId = null;
    this.simulation = null;
    this.fisheye = createFisheye({ distortion: 3, radius: 200 });
    this._mousePos = null;
    this._fisheyeActive = false;
    this._selectedNode = null;

    this._setupZoom();
    this._setupTooltip();
    this._setupResize();
  }

  /* ── Setup ── */

  _setupZoom() {
    this.zoomBehavior = d3.zoom()
      .scaleExtent([0.1, 8])
      .on("zoom", (event) => {
        this.svg.select("#zoom-group").attr("transform", event.transform);
        this._currentTransform = event.transform;
      });
    this.svg.call(this.zoomBehavior);
    this._currentTransform = d3.zoomIdentity;
  }

  _setupTooltip() {
    this.tooltip = d3.select("body")
      .append("div")
      .attr("id", "tooltip");
  }

  _setupResize() {
    const measure = () => {
      const el = this.svg.node().parentElement;
      this.width = el.clientWidth;
      this.height = el.clientHeight;
    };
    measure();
    window.addEventListener("resize", () => { measure(); this._restartSim(); });
  }

  /* ── Load / render ── */

  load(data) {
    this.nodes = data.nodes.map(d => ({ ...d }));
    this.links = data.links.map(d => ({ ...d }));
    this.focalId = data.focal;
    this._render();
    this._updateStats(data);
    document.getElementById("empty-state").classList.add("hidden");
  }

  /**
   * Add or update a single node without full re-render.
   * Adds a link from it to the focal node if new.
   */
  addOrUpdateNode(hostData) {
    const ip = hostData.ip || hostData.id;
    if (!ip) return;

    const existing = this.nodes.find(n => n.id === ip);
    if (existing) {
      Object.assign(existing, hostData, { id: ip });
    } else {
      const newNode = {
        id: ip,
        hostname: hostData.hostname || ip,
        mac: hostData.mac || "",
        vendor: hostData.vendor || "",
        os: hostData.os || "",
        method: hostData.method || "",
        hop: hostData.hop ?? 1,
        node_type: hostData.node_type || "remote",
        device_type: hostData.device_type || "unknown",
        distance_from_focal: hostData.hop ?? 1,
        is_focal: false,
        x: this.width / 2 + (Math.random() - 0.5) * 100,
        y: this.height / 2 + (Math.random() - 0.5) * 100,
      };
      this.nodes.push(newNode);

      // Add link to focal/local node
      const focalId = this.focalId || (this.nodes.find(n => n.node_type === "local") || {}).id;
      if (focalId && focalId !== ip) {
        this.links.push({ source: focalId, target: ip });
      }

      // Append node group to the DOM
      const nodesLayer = this.svg.select("#nodes-layer");
      const ng = nodesLayer.append("g")
        .datum(newNode)
        .attr("class", "node-group")
        .call(
          d3.drag()
            .on("start", (event, d) => this._dragStart(event, d))
            .on("drag",  (event, d) => this._dragged(event, d))
            .on("end",   (event, d) => this._dragEnd(event, d))
        )
        .on("click",      (event, d) => { event.stopPropagation(); this._onNodeClick(d); })
        .on("mouseover",  (event, d) => { this._showTooltip(event, d); this._fisheyeActive = true; })
        .on("mousemove",  (event)    => { this._mousePos = { x: event.clientX, y: event.clientY }; })
        .on("mouseout",   ()         => { this._hideTooltip(); this._fisheyeActive = false; this._tick(); });

      ng.append("circle")
        .attr("class", "node-circle")
        .attr("r", d => nodeRadius(d))
        .attr("fill", d => nodeColor2(d));

      ng.append("text")
        .attr("class", "node-label")
        .attr("y", d => nodeRadius(d) + 12)
        .text(d => nodeLabel(d));

      ng.append("text")
        .attr("class", "node-sublabel")
        .attr("y", d => nodeRadius(d) + 23)
        .text(d => deviceLabel(d));

      // Rebuild nodeSel selection
      this.nodeSel = this.svg.select("#nodes-layer").selectAll("g.node-group").data(this.nodes, d => d.id);
    }

    // Restart sim with new data
    if (this.simulation) {
      this.simulation.nodes(this.nodes);
      this.simulation.alpha(0.3).restart();
    }
  }

  _render() {
    const linksLayer = this.svg.select("#links-layer");
    const nodesLayer = this.svg.select("#nodes-layer");

    linksLayer.selectAll("*").remove();
    nodesLayer.selectAll("*").remove();

    const nodeMap = new Map(this.nodes.map(n => [n.id, n]));
    const simLinks = this.links.map(l => ({
      source: nodeMap.get(typeof l.source === "string" ? l.source : l.source.id),
      target: nodeMap.get(typeof l.target === "string" ? l.target : l.target.id),
    })).filter(l => l.source && l.target);

    this.linkSel = linksLayer
      .selectAll("line.link")
      .data(simLinks)
      .join("line")
      .attr("class", "link");

    const self = this;
    this.nodeSel = nodesLayer
      .selectAll("g.node-group")
      .data(this.nodes, d => d.id)
      .join("g")
      .attr("class", d => `node-group${d.is_focal ? " focal" : ""}`)
      .call(
        d3.drag()
          .on("start", (event, d) => this._dragStart(event, d))
          .on("drag",  (event, d) => this._dragged(event, d))
          .on("end",   (event, d) => this._dragEnd(event, d))
      )
      .on("click",      (event, d) => { event.stopPropagation(); this._onNodeClick(d); })
      .on("mouseover",  (event, d) => { this._showTooltip(event, d); this._fisheyeActive = true; })
      .on("mousemove",  (event)    => { this._mousePos = { x: event.clientX, y: event.clientY }; })
      .on("mouseout",   ()         => { this._hideTooltip(); this._fisheyeActive = false; this._tick(); });

    this.nodeSel.append("circle")
      .attr("class", "node-circle")
      .attr("r", d => nodeRadius(d))
      .attr("fill", d => nodeColor2(d));

    this.nodeSel.append("text")
      .attr("class", "node-label")
      .attr("y", d => nodeRadius(d) + 12)
      .text(d => nodeLabel(d));

    this.nodeSel.append("text")
      .attr("class", "node-sublabel")
      .attr("y", d => nodeRadius(d) + 23)
      .text(d => deviceLabel(d));

    this._buildSimulation(simLinks);

    this.svg.on("mousemove", (event) => {
      this._mousePos = { x: event.clientX, y: event.clientY };
      if (this._fisheyeActive || true) {
        this._applyFisheye();
      }
    }).on("mouseleave", () => {
      this._mousePos = null;
      this._tick();
    });
  }

  _buildSimulation(simLinks) {
    if (this.simulation) this.simulation.stop();

    const ringRadius = 120;

    this.simulation = d3.forceSimulation(this.nodes)
      .force("link", d3.forceLink(simLinks)
        .id(d => d.id)
        .distance(d => {
          const hops = (d.target.distance_from_focal ?? d.target.hop ?? 1);
          return 60 + hops * 30;
        })
        .strength(0.4))
      .force("charge", d3.forceManyBody().strength(-250))
      .force("collide", d3.forceCollide().radius(d => nodeRadius(d) + 8))
      .force("center",  d3.forceCenter(this.width / 2, this.height / 2))
      .force("radial", d3.forceRadial(
        d => (d.distance_from_focal ?? d.hop ?? 0) * ringRadius,
        this.width / 2,
        this.height / 2
      ).strength(0.35))
      .on("tick", () => this._tick());

    this.simulation.alpha(1).restart();
  }

  _restartSim() {
    if (this.simulation) {
      this.simulation
        .force("center", d3.forceCenter(this.width / 2, this.height / 2))
        .force("radial", d3.forceRadial(
          d => (d.distance_from_focal ?? d.hop ?? 0) * 120,
          this.width / 2,
          this.height / 2
        ).strength(0.35))
        .alpha(0.5)
        .restart();
    }
  }

  /* ── Tick / fisheye ── */

  _tick() {
    if (!this.linkSel || !this.nodeSel) return;

    this.linkSel
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);

    this.nodeSel.attr("transform", d => `translate(${d.x},${d.y})`);
  }

  _applyFisheye() {
    if (!this.linkSel || !this.nodeSel || !this._mousePos) {
      this._tick();
      return;
    }

    const svgNode = this.svg.node();
    const svgRect = svgNode.getBoundingClientRect();
    const t = this._currentTransform || d3.zoomIdentity;

    const mx = (this._mousePos.x - svgRect.left - t.x) / t.k;
    const my = (this._mousePos.y - svgRect.top  - t.y) / t.k;
    const focus = { x: mx, y: my };

    const distorted = new Map();
    this.nodes.forEach(d => {
      distorted.set(d.id, this.fisheye({ x: d.x, y: d.y }, focus));
    });

    this.nodeSel.attr("transform", d => {
      const p = distorted.get(d.id);
      return `translate(${p.x},${p.y})`;
    });

    this.nodeSel.select(".node-circle").attr("r", d => {
      const orig = { x: d.x, y: d.y };
      const dist = Math.sqrt((orig.x - focus.x) ** 2 + (orig.y - focus.y) ** 2);
      const fishR = this.fisheye.radius();
      if (dist >= fishR) return nodeRadius(d);
      const scale = 1 + 1.5 * Math.exp(-dist / (fishR * 0.3));
      return nodeRadius(d) * scale;
    });

    this.linkSel
      .attr("x1", d => distorted.get(d.source.id ?? d.source)?.x ?? d.source.x)
      .attr("y1", d => distorted.get(d.source.id ?? d.source)?.y ?? d.source.y)
      .attr("x2", d => distorted.get(d.target.id ?? d.target)?.x ?? d.target.x)
      .attr("y2", d => distorted.get(d.target.id ?? d.target)?.y ?? d.target.y);
  }

  /* ── Node interaction ── */

  _onNodeClick(d) {
    const ip = d.id;
    this._setSelectedNode(d);

    fetch(`/api/topology/${encodeURIComponent(ip)}`)
      .then(r => r.json())
      .then(data => {
        const posMap = new Map(this.nodes.map(n => [n.id, { x: n.x, y: n.y }]));
        data.nodes = data.nodes.map(n => {
          const prev = posMap.get(n.id);
          return prev ? { ...n, x: prev.x, y: prev.y } : n;
        });
        this.load(data);
      })
      .catch(err => console.error("POV change failed:", err));
  }

  _updateNodeStyles() {
    if (!this.nodeSel) return;
    this.nodeSel
      .attr("class", d => `node-group${d.is_focal ? " focal" : ""}`)
      .select(".node-circle")
      .attr("fill", d => nodeColor2(d));
  }

  _setSelectedNode(d) {
    this._selectedNode = d;
    const panel = document.getElementById("node-details");

    // Port scan section
    const portSection = `
      <div id="port-scan-section" style="margin-top:10px;">
        <button id="btn-scan-ports" class="btn btn-secondary" style="width:100%;margin-bottom:6px;">
          🔍 Scan Ports
        </button>
        <div id="port-results"></div>
      </div>`;

    const optRow = (label, value) =>
      value ? `<div class="detail-row"><span class="dk">${label}</span><span class="dv">${value}</span></div>` : "";

    const deviceTypeRow = (() => {
      if (!d.device_type || d.device_type === "unknown") return "";
      const icon = deviceIcon(d);
      const label = d.device_type.replace(/_/g, " ");
      return `<div class="detail-row"><span class="dk">Device</span><span class="dv">${icon ? icon + " " : ""}${label}</span></div>`;
    })();

    panel.innerHTML = `
      <div class="detail-row"><span class="dk">IP</span>
        <span class="dv">${d.id}</span></div>
      <div class="detail-row"><span class="dk">Hostname</span>
        <span class="dv">${d.hostname || "—"}</span></div>
      ${optRow("Vendor", d.vendor)}
      ${deviceTypeRow}
      ${optRow("OS", d.os)}
      <div class="detail-row"><span class="dk">MAC</span>
        <span class="dv">${d.mac || "—"}</span></div>
      <div class="detail-row"><span class="dk">Type</span>
        <span class="dv">${d.node_type}</span></div>
      ${optRow("Discovered via", d.method)}
      <div class="detail-row"><span class="dk">Hops from focal</span>
        <span class="dv">${d.distance_from_focal ?? d.hop ?? "—"}</span></div>
      <button id="btn-set-focal" class="btn btn-primary"
              ${d.is_focal ? "disabled" : ""}>
        ${d.is_focal ? "✓ Current focal" : "🎯 Set as focal (POV)"}
      </button>
      ${portSection}`;

    document.getElementById("btn-set-focal")?.addEventListener("click", () => {
      this._onNodeClick(d);
    });

    // Port scan button
    document.getElementById("btn-scan-ports")?.addEventListener("click", () => {
      this._triggerPortScan(d.id);
    });

    document.getElementById("stat-focal").textContent = d.hostname || d.id;

    // Check if port results already exist
    this._refreshPortResults(d.id);
  }

  _triggerPortScan(ip) {
    const resultDiv = document.getElementById("port-results");
    if (!resultDiv) return;
    resultDiv.textContent = "Scanning ports…";

    fetch(`/api/ports/${encodeURIComponent(ip)}`, { method: "POST" })
      .then(() => this._pollPortResults(ip))
      .catch(err => {
        if (resultDiv) resultDiv.textContent = "Port scan failed.";
        console.error("Port scan error:", err);
      });
  }

  _pollPortResults(ip, attempts = 0) {
    if (attempts > 40) return;
    setTimeout(() => {
      fetch(`/api/ports/${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then(data => {
          // Show results once we have a valid ports array (even if empty means "no open ports found")
          // Use attempts > 0 to ensure we've waited at least one poll cycle after POSTing
          if (data.ports !== undefined && attempts > 0) {
            this._renderPortResults(ip, data.ports);
          } else {
            this._pollPortResults(ip, attempts + 1);
          }
        })
        .catch(() => this._pollPortResults(ip, attempts + 1));
    }, 800);
  }

  _refreshPortResults(ip) {
    fetch(`/api/ports/${encodeURIComponent(ip)}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.ports) this._renderPortResults(ip, data.ports);
      })
      .catch(() => {});
  }

  _renderPortResults(ip, ports) {
    const resultDiv = document.getElementById("port-results");
    if (!resultDiv) return;
    if (ports.length === 0) {
      resultDiv.innerHTML = '<p style="color:var(--muted);font-size:11px;">No open ports found.</p>';
      return;
    }
    const rows = ports.map(p =>
      `<div style="font-size:11px;color:var(--text);margin-bottom:2px;">
        <span style="color:var(--accent)">${p.port}</span>
        <span style="color:var(--muted)"> ${p.service}</span>
      </div>`
    ).join("");
    resultDiv.innerHTML = `<div style="margin-top:4px;">${rows}</div>`;
  }

  /* ── Drag ── */

  _dragStart(event, d) {
    if (!event.active) this.simulation.alphaTarget(0.3).restart();
    d.fx = d.x; d.fy = d.y;
  }

  _dragged(event, d) {
    d.fx = event.x; d.fy = event.y;
  }

  _dragEnd(event, d) {
    if (!event.active) this.simulation.alphaTarget(0);
    d.fx = null; d.fy = null;
  }

  /* ── Tooltip ── */

  _showTooltip(event, d) {
    // Check for port results
    let portsHtml = "";
    if (window._portResultsCache && window._portResultsCache[d.id]) {
      const openPorts = window._portResultsCache[d.id].filter(p => p.state === "open");
      if (openPorts.length) {
        portsHtml = `<div class="tt-meta" style="margin-top:4px;">Ports: ${openPorts.map(p => `${p.port}${p.service ? "/" + p.service : ""}`).join(", ")}</div>`;
      }
    }

    const label = nodeLabel(d);
    const showHostname = d.hostname && d.hostname !== d.id
      ? `<div class="tt-host">${d.hostname}</div>` : "";

    const metaLines = [];
    if (d.mac)    metaLines.push(`MAC: ${d.mac}`);
    if (d.vendor) metaLines.push(`Vendor: <strong style="color:var(--text)">${d.vendor}</strong>`);
    if (d.device_type && d.device_type !== "unknown") {
      const icon = deviceIcon(d);
      const type = d.device_type.replace(/_/g, " ");
      metaLines.push(`Device: <strong style="color:var(--text)">${icon ? icon + " " : ""}${type}</strong>`);
    }
    if (d.os)     metaLines.push(`OS: <strong style="color:var(--text)">${d.os}</strong>`);
    metaLines.push(`Type: ${d.node_type}`);
    if (d.method) metaLines.push(`Discovered via: ${d.method}`);
    if (d.distance_from_focal != null) metaLines.push(`Hops from focal: ${d.distance_from_focal}`);

    this.tooltip
      .style("display", "block")
      .html(`
        <div class="tt-ip">${label}</div>
        ${label !== d.id ? `<div class="tt-id">${d.id}</div>` : ""}
        ${showHostname}
        <div class="tt-meta">${metaLines.join("<br>")}</div>
        ${portsHtml}
        <div class="tt-meta" style="color:#aaa;margin-top:4px">Click to change POV</div>
      `);
    this._moveTooltip(event);
  }

  _moveTooltip(event) {
    const { clientX: x, clientY: y } = event;
    const tt = this.tooltip.node();
    const offX = x + 14 + tt.offsetWidth > window.innerWidth ? -tt.offsetWidth - 14 : 14;
    const offY = y + 14 + tt.offsetHeight > window.innerHeight ? -tt.offsetHeight - 14 : 14;
    this.tooltip
      .style("left", `${x + offX}px`)
      .style("top",  `${y + offY}px`);
  }

  _hideTooltip() {
    this.tooltip.style("display", "none");
  }

  /* ── Stats ── */

  _updateStats(data) {
    document.getElementById("stat-nodes").textContent = data.node_count ?? data.nodes?.length ?? 0;
    document.getElementById("stat-links").textContent = data.link_count ?? data.links?.length ?? 0;
    if (data.focal) {
      const focal = data.nodes?.find(n => n.id === data.focal);
      document.getElementById("stat-focal").textContent =
        focal ? (focal.hostname || focal.id) : data.focal;
    }
  }

  /* ── Search ── */

  search(query) {
    if (!this.nodeSel) return;
    if (!query) {
      this.nodeSel.classed("search-match", false).classed("search-dim", false);
      return;
    }
    const q = query.toLowerCase();
    this.nodeSel.each(function(d) {
      const matches = (d.id || "").toLowerCase().includes(q) ||
                      (d.hostname || "").toLowerCase().includes(q) ||
                      (d.mac || "").toLowerCase().includes(q) ||
                      (d.vendor || "").toLowerCase().includes(q) ||
                      (d.device_type || "").toLowerCase().includes(q);
      d3.select(this).classed("search-match", matches).classed("search-dim", !matches);
    });
  }

  /* ── Table view ── */

  renderTable(sortCol = "id", sortDir = 1) {
    const tbody = document.getElementById("host-table-body");
    if (!tbody) return;
    const sorted = [...this.nodes].sort((a, b) => {
      const av = a[sortCol] ?? "";
      const bv = b[sortCol] ?? "";
      if (typeof av === "number") return (av - bv) * sortDir;
      return String(av).localeCompare(String(bv)) * sortDir;
    });
    tbody.innerHTML = sorted.map(n => {
      const icon = deviceIcon(n);
      const dtype = n.device_type && n.device_type !== "unknown"
        ? `${icon ? icon + " " : ""}${n.device_type.replace(/_/g, " ")}` : "—";
      return `
      <tr>
        <td>${n.id}</td>
        <td>${n.hostname || "—"}</td>
        <td>${n.vendor || "—"}</td>
        <td>${dtype}</td>
        <td>${n.hop ?? "—"}</td>
        <td>${n.mac || "—"}</td>
        <td>${n.node_type || "—"}</td>
        <td>${n.method || "—"}</td>
      </tr>`;
    }).join("");
  }

  /* ── SVG Export ── */

  exportSVG() {
    const svgEl = document.getElementById("graph-svg");
    const serializer = new XMLSerializer();
    let source = serializer.serializeToString(svgEl);
    // Add XML declaration and namespace
    if (!source.match(/^<\?xml/)) {
      source = '<?xml version="1.0" encoding="UTF-8"?>\n' + source;
    }
    const blob = new Blob([source], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "topology.svg";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /* ── Zoom controls ── */

  zoomIn()    { this.svg.transition().call(this.zoomBehavior.scaleBy, 1.4); }
  zoomOut()   { this.svg.transition().call(this.zoomBehavior.scaleBy, 1 / 1.4); }
  resetView() {
    this.svg.transition().duration(500).call(
      this.zoomBehavior.transform,
      d3.zoomIdentity.translate(0, 0).scale(1)
    );
  }
}

/* ============================================================
   App controller
   ============================================================ */
(function () {
  const diagram = new NetworkDiagram("#graph-svg");
  let pollTimer = null;
  let elapsedTimer = null;
  let scanStartTime = null;
  let activeEventSource = null;
  let tableSortCol = "id";
  let tableSortDir = 1;
  let tableVisible = false;

  // Cache for port results (for tooltip display)
  window._portResultsCache = {};

  /* ── UI elements ── */
  const btnScan       = document.getElementById("btn-scan");
  const btnDemo       = document.getElementById("btn-demo");
  const btnClear      = document.getElementById("btn-clear");
  const btnZoomIn     = document.getElementById("btn-zoom-in");
  const btnZoomOut    = document.getElementById("btn-zoom-out");
  const btnReset      = document.getElementById("btn-reset");
  const btnViewToggle = document.getElementById("btn-view-toggle");
  const btnNotify     = document.getElementById("btn-notify");
  const hopSlider     = document.getElementById("hop-limit");
  const hopVal        = document.getElementById("hop-limit-val");
  const netInput      = document.getElementById("network-input");
  const statusBar     = document.getElementById("scan-status");
  const progressEl    = document.getElementById("scan-progress");
  const scanMsg       = document.getElementById("scan-msg");
  const scanElapsed   = document.getElementById("scan-elapsed");
  const emptyState    = document.getElementById("empty-state");
  const searchInput   = document.getElementById("search-input");
  const tableView     = document.getElementById("table-view");
  const graphSvg      = document.getElementById("graph-svg");
  const hostTable     = document.getElementById("host-table");
  const newHostBanner = document.getElementById("new-hosts-banner");

  /* ── Hop slider ── */
  hopSlider.addEventListener("input", () => {
    hopVal.textContent = hopSlider.value;
  });

  /* ── Zoom buttons ── */
  btnZoomIn.addEventListener("click",  () => diagram.zoomIn());
  btnZoomOut.addEventListener("click", () => diagram.zoomOut());
  btnReset.addEventListener("click",   () => diagram.resetView());

  /* ── View toggle ── */
  btnViewToggle.addEventListener("click", () => {
    tableVisible = !tableVisible;
    if (tableVisible) {
      tableView.classList.remove("hidden");
      graphSvg.style.display = "none";
      diagram.renderTable(tableSortCol, tableSortDir);
    } else {
      tableView.classList.add("hidden");
      graphSvg.style.display = "";
    }
  });

  /* ── Table sorting ── */
  if (hostTable) {
    hostTable.querySelectorAll("th[data-col]").forEach(th => {
      th.addEventListener("click", () => {
        const col = th.dataset.col;
        if (col === tableSortCol) {
          tableSortDir *= -1;
        } else {
          tableSortCol = col;
          tableSortDir = 1;
        }
        diagram.renderTable(tableSortCol, tableSortDir);
      });
    });
  }

  /* ── Search ── */
  searchInput?.addEventListener("input", () => {
    diagram.search(searchInput.value.trim());
  });

  /* ── Notification button ── */
  if (btnNotify) {
    if (!("Notification" in window)) {
      btnNotify.style.display = "none";
    } else {
      btnNotify.addEventListener("click", () => {
        Notification.requestPermission().then(perm => {
          if (perm === "granted") btnNotify.style.display = "none";
        });
      });
      if (Notification.permission === "granted") btnNotify.style.display = "none";
    }
  }

  /* ── Export buttons ── */
  document.getElementById("btn-export-json")?.addEventListener("click", () => {
    window.open("/api/export/json");
  });
  document.getElementById("btn-export-csv")?.addEventListener("click", () => {
    window.open("/api/export/csv");
  });
  document.getElementById("btn-export-html")?.addEventListener("click", () => {
    window.open("/api/export/html");
  });
  document.getElementById("btn-export-svg")?.addEventListener("click", () => {
    diagram.exportSVG();
  });

  /* ── Demo ── */
  btnDemo.addEventListener("click", () => {
    fetch("/api/demo")
      .then(r => r.json())
      .then(data => {
        diagram.load(data);
        emptyState.classList.add("hidden");
        if (tableVisible) diagram.renderTable(tableSortCol, tableSortDir);
        loadHistory();
      })
      .catch(err => console.error("Demo load failed:", err));
  });

  /* ── Clear ── */
  btnClear.addEventListener("click", () => {
    fetch("/api/topology", { method: "DELETE" })
      .then(() => {
        diagram.svg.select("#links-layer").selectAll("*").remove();
        diagram.svg.select("#nodes-layer").selectAll("*").remove();
        diagram.nodes = []; diagram.links = [];
        document.getElementById("stat-nodes").textContent = "0";
        document.getElementById("stat-links").textContent = "0";
        document.getElementById("stat-focal").textContent = "—";
        document.getElementById("node-details").innerHTML =
          '<p class="muted">Click a node to inspect it.</p>';
        emptyState.classList.remove("hidden");
        statusBar.classList.add("hidden");
        stopPolling();
        stopElapsed();
        if (activeEventSource) { activeEventSource.close(); activeEventSource = null; }
        newHostBanner.classList.add("hidden");
      });
  });

  /* ── Scan ── */
  btnScan.addEventListener("click", () => {
    const body = {
      hop_limit: parseInt(hopSlider.value, 10),
      network: netInput.value.trim() || null,
    };

    btnScan.disabled = true;
    statusBar.classList.remove("hidden");
    progressEl.style.width = "5%";
    scanMsg.textContent = "Scanning…";
    scanStartTime = Date.now();
    startElapsed();

    // Open SSE stream for real-time updates
    if (activeEventSource) { activeEventSource.close(); }
    const es = new EventSource("/api/scan/stream");
    activeEventSource = es;

    es.addEventListener("phase", e => {
      try {
        const d = JSON.parse(e.data);
        scanMsg.textContent = d.phase + "…";
      } catch {}
    });

    es.addEventListener("host", e => {
      try {
        const hostData = JSON.parse(e.data);
        diagram.addOrUpdateNode(hostData);
        emptyState.classList.add("hidden");
      } catch {}
    });

    es.addEventListener("complete", e => {
      try {
        const d = JSON.parse(e.data);
        const found = d.found ?? 0;
        scanMsg.textContent = `Done – ${found} host${found !== 1 ? "s" : ""} found`;
        progressEl.style.width = "100%";
        btnScan.disabled = false;
        stopElapsed();
        es.close();
        activeEventSource = null;
        stopPolling();

        // Show desktop notification
        if (typeof Notification !== "undefined" && Notification.permission === "granted") {
          new Notification("nmap++ scan complete", {
            body: `${found} host${found !== 1 ? "s" : ""} discovered`,
          });
        }

        // Final topology fetch to reconcile
        fetch("/api/topology")
          .then(r => r.json())
          .then(data => {
            if (data.node_count > 0) {
              diagram.load(data);
              emptyState.classList.add("hidden");
              if (tableVisible) diagram.renderTable(tableSortCol, tableSortDir);
              checkNewHosts(data);
              loadHistory();
            }
          });
      } catch {}
    });

    es.addEventListener("error", e => {
      try {
        const d = JSON.parse(e.data || "{}");
        scanMsg.textContent = `Error: ${d.error || "unknown"}`;
      } catch {}
      btnScan.disabled = false;
      stopElapsed();
      es.close();
      activeEventSource = null;
    });

    es.onerror = () => {
      // SSE closed, fall back to polling
      es.close();
      activeEventSource = null;
    };

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(r => r.json())
      .then(() => startPolling())
      .catch(err => {
        console.error("Scan start failed:", err);
        scanMsg.textContent = "Scan failed – see console.";
        btnScan.disabled = false;
        stopElapsed();
      });
  });

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollStatus, 1500);
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function startElapsed() {
    stopElapsed();
    elapsedTimer = setInterval(() => {
      if (scanStartTime && scanElapsed) {
        const secs = Math.floor((Date.now() - scanStartTime) / 1000);
        scanElapsed.textContent = `${secs}s`;
      }
    }, 1000);
  }

  function stopElapsed() {
    if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
    if (scanElapsed) scanElapsed.textContent = "";
  }

  function pollStatus() {
    fetch("/api/scan/status")
      .then(r => r.json())
      .then(s => {
        const found = s.found ?? 0;
        progressEl.style.width = `${s.progress ?? 50}%`;
        if (s.phase && s.phase !== "complete" && s.phase !== "idle") {
          scanMsg.textContent = `${s.phase}… ${found} host${found !== 1 ? "s" : ""} found`;
        } else {
          scanMsg.textContent = `Scanning… ${found} host${found !== 1 ? "s" : ""} found`;
        }

        if (s.status === "complete") {
          stopPolling();
          progressEl.style.width = "100%";
          scanMsg.textContent = `Done – ${found} host${found !== 1 ? "s" : ""} found`;
          btnScan.disabled = false;
          stopElapsed();
          fetch("/api/topology")
            .then(r => r.json())
            .then(data => {
              if (data.node_count > 0) {
                diagram.load(data);
                emptyState.classList.add("hidden");
                if (tableVisible) diagram.renderTable(tableSortCol, tableSortDir);
                checkNewHosts(data);
                loadHistory();
              }
            });
        } else if (s.status === "error") {
          stopPolling();
          scanMsg.textContent = `Error: ${s.error}`;
          btnScan.disabled = false;
          stopElapsed();
        }
      })
      .catch(err => console.error("Poll error:", err));
  }

  /* ── New host banner ── */
  let _prevNodeIds = new Set();

  function checkNewHosts(data) {
    const currentIds = new Set((data.nodes || []).map(n => n.id));
    const newIds = [...currentIds].filter(id => !_prevNodeIds.has(id));

    if (_prevNodeIds.size > 0 && newIds.length > 0 && newHostBanner) {
      newHostBanner.classList.remove("hidden");
      newHostBanner.innerHTML = `⚠ ${newIds.length} new device${newIds.length !== 1 ? "s" : ""} discovered since last scan
        <span class="banner-dismiss" onclick="document.getElementById('new-hosts-banner').classList.add('hidden')">✕</span>`;
    }
    _prevNodeIds = currentIds;
  }

  /* ── History ── */

  function loadHistory() {
    fetch("/api/history")
      .then(r => r.json())
      .then(scans => {
        const container = document.getElementById("history-list");
        if (!container) return;
        if (!scans || scans.length === 0) {
          container.innerHTML = '<p class="muted">No history yet.</p>';
          return;
        }
        container.innerHTML = scans.map(s => `
          <div class="history-item" data-id="${s.id}">
            <span class="hist-id">${s.timestamp}</span>
            <span class="hist-count">${s.node_count} nodes</span>
          </div>`).join("");

        container.querySelectorAll(".history-item").forEach(el => {
          el.addEventListener("click", () => loadHistoryScan(el.dataset.id));
        });
      })
      .catch(() => {});
  }

  function loadHistoryScan(scanId) {
    // If we have current topology loaded, compute diff first
    const currentNodes = diagram.nodes.map(n => n.id);

    fetch(`/api/history/${scanId}`)
      .then(r => r.json())
      .then(data => {
        if (currentNodes.length > 0) {
          // Compare: find first scan in history to diff against
          fetch("/api/history")
            .then(r => r.json())
            .then(scans => {
              if (scans.length >= 2) {
                const newerScan = scans[0];
                const olderScan = scans[1];
                fetch(`/api/history/diff/${olderScan.id}/${newerScan.id}`)
                  .then(r => r.json())
                  .then(diff => {
                    // Annotate nodes with diff status
                    data.nodes = data.nodes.map(n => ({
                      ...n,
                      _diffStatus: diff.new.includes(n.id) ? "new"
                                 : diff.removed.includes(n.id) ? "removed"
                                 : diff.changed.includes(n.id) ? "changed"
                                 : null,
                    }));
                    // Add ghost nodes for removed IPs
                    diff.removed.forEach(ip => {
                      if (!data.nodes.find(n => n.id === ip)) {
                        data.nodes.push({
                          id: ip, hostname: ip, mac: "", hop: 1,
                          node_type: "remote", distance_from_focal: 1,
                          is_focal: false, _diffStatus: "removed",
                        });
                      }
                    });
                    diagram.load(data);
                    emptyState.classList.add("hidden");
                  });
              } else {
                diagram.load(data);
                emptyState.classList.add("hidden");
              }
            });
        } else {
          diagram.load(data);
          emptyState.classList.add("hidden");
        }
        if (tableVisible) diagram.renderTable(tableSortCol, tableSortDir);
      })
      .catch(err => console.error("Load history scan failed:", err));
  }

  // Load history on page load
  loadHistory();

})();

