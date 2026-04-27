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
 */

/* ============================================================
   Colour helpers
   ============================================================ */
const NODE_COLORS = {
  local:   "#f0c040",
  gateway: "#ff7c5a",
  remote:  null,       // determined by hop
};

function nodeColor(d) {
  if (d.is_focal)             return "#ff5fd8";
  if (d.node_type === "local")   return NODE_COLORS.local;
  if (d.node_type === "gateway") return NODE_COLORS.gateway;
  const h = d.distance_from_focal ?? d.hop ?? 0;
  if (h <= 1)  return "#4a9eff";
  if (h === 2) return "#5ba88b";
  return "#9275c4";
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
   Fisheye distortion (radial, Sarkar & Brown 1992)
   ============================================================ */
function createFisheye({ distortion = 3, radius = 180 } = {}) {
  function fisheye(point, focus) {
    const dx = point.x - focus.x;
    const dy = point.y - focus.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist === 0 || dist >= radius) return { x: point.x, y: point.y };

    // Magnification factor
    const k = (distortion + 1) * radius;
    const scale = k / (distortion * dist + radius);

    return {
      x: focus.x + dx * scale,
      y: focus.y + dy * scale,
    };
  }
  fisheye.distortion = (v) => { distortion = v; return fisheye; };
  fisheye.radius = (v) => {
    if (v === undefined) return radius;   // getter
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

  _render() {
    const linksLayer = this.svg.select("#links-layer");
    const nodesLayer = this.svg.select("#nodes-layer");

    linksLayer.selectAll("*").remove();
    nodesLayer.selectAll("*").remove();

    // Build maps for D3 link resolution
    const nodeMap = new Map(this.nodes.map(n => [n.id, n]));
    const simLinks = this.links.map(l => ({
      source: nodeMap.get(typeof l.source === "string" ? l.source : l.source.id),
      target: nodeMap.get(typeof l.target === "string" ? l.target : l.target.id),
    })).filter(l => l.source && l.target);

    // ── Links ──
    this.linkSel = linksLayer
      .selectAll("line.link")
      .data(simLinks)
      .join("line")
      .attr("class", "link");

    // ── Node groups ──
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
      .attr("fill", d => nodeColor(d));

    this.nodeSel.append("text")
      .attr("class", "node-label")
      .attr("y", d => nodeRadius(d) + 12)
      .text(d => d.hostname || d.id);

    // ── Simulation ──
    this._buildSimulation(simLinks);

    // ── Fisheye on mouse move over SVG ──
    this.svg.on("mousemove", (event) => {
      this._mousePos = { x: event.clientX, y: event.clientY };
      if (this._fisheyeActive || true) {    // always active for smooth UX
        this._applyFisheye();
      }
    }).on("mouseleave", () => {
      this._mousePos = null;
      this._tick();
    });
  }

  _buildSimulation(simLinks) {
    if (this.simulation) this.simulation.stop();

    // Ring-radius by hop distance from focal
    const ringRadius = 120;

    this.simulation = d3.forceSimulation(this.nodes)
      .force("link", d3.forceLink(simLinks)
        .id(d => d.id)
        .distance(d => {
          // Longer edges for cross-subnet links
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

    // Run more ticks up front for stability
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

    // Convert mouse position from screen coords to SVG content coords
    const svgNode = this.svg.node();
    const svgRect = svgNode.getBoundingClientRect();
    const t = this._currentTransform || d3.zoomIdentity;

    const mx = (this._mousePos.x - svgRect.left - t.x) / t.k;
    const my = (this._mousePos.y - svgRect.top  - t.y) / t.k;
    const focus = { x: mx, y: my };

    // Distort node positions
    const distorted = new Map();
    this.nodes.forEach(d => {
      distorted.set(d.id, this.fisheye({ x: d.x, y: d.y }, focus));
    });

    this.nodeSel.attr("transform", d => {
      const p = distorted.get(d.id);
      return `translate(${p.x},${p.y})`;
    });

    // Scale node radius with distortion (gives "magnifying glass" feel)
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

    // Re-load topology from clicked node's POV
    fetch(`/api/topology/${encodeURIComponent(ip)}`)
      .then(r => r.json())
      .then(data => {
        // Preserve simulation positions for a smooth transition
        const posMap = new Map(this.nodes.map(n => [n.id, { x: n.x, y: n.y }]));
        data.nodes = data.nodes.map(n => {
          const prev = posMap.get(n.id);
          return prev ? { ...n, x: prev.x, y: prev.y } : n;
        });
        // Full re-render so D3 bindings reflect the new focal node
        this.load(data);
      })
      .catch(err => console.error("POV change failed:", err));
  }

  _updateNodeStyles() {
    if (!this.nodeSel) return;
    this.nodeSel
      .attr("class", d => `node-group${d.is_focal ? " focal" : ""}`)
      .select(".node-circle")
      .attr("fill", d => nodeColor(d));
  }

  _setSelectedNode(d) {
    this._selectedNode = d;
    const panel = document.getElementById("node-details");
    panel.innerHTML = `
      <div class="detail-row"><span class="dk">IP</span>
        <span class="dv">${d.id}</span></div>
      <div class="detail-row"><span class="dk">Hostname</span>
        <span class="dv">${d.hostname || "—"}</span></div>
      <div class="detail-row"><span class="dk">MAC</span>
        <span class="dv">${d.mac || "—"}</span></div>
      <div class="detail-row"><span class="dk">Type</span>
        <span class="dv">${d.node_type}</span></div>
      <div class="detail-row"><span class="dk">Hops from focal</span>
        <span class="dv">${d.distance_from_focal ?? d.hop ?? "—"}</span></div>
      <button id="btn-set-focal" class="btn btn-primary"
              ${d.is_focal ? "disabled" : ""}>
        ${d.is_focal ? "✓ Current focal" : "🎯 Set as focal (POV)"}
      </button>`;

    document.getElementById("btn-set-focal")?.addEventListener("click", () => {
      this._onNodeClick(d);
    });

    document.getElementById("stat-focal").textContent =
      d.hostname || d.id;
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
    this.tooltip
      .style("display", "block")
      .html(`
        <div class="tt-ip">${d.id}</div>
        <div class="tt-host">${d.hostname || ""}</div>
        <div class="tt-meta">
          ${d.mac ? `MAC: ${d.mac}<br>` : ""}
          Type: ${d.node_type}<br>
          ${d.distance_from_focal != null ? `Hops from focal: ${d.distance_from_focal}` : ""}
        </div>
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

  /* ── UI elements ── */
  const btnScan    = document.getElementById("btn-scan");
  const btnDemo    = document.getElementById("btn-demo");
  const btnClear   = document.getElementById("btn-clear");
  const btnZoomIn  = document.getElementById("btn-zoom-in");
  const btnZoomOut = document.getElementById("btn-zoom-out");
  const btnReset   = document.getElementById("btn-reset");
  const hopSlider  = document.getElementById("hop-limit");
  const hopVal     = document.getElementById("hop-limit-val");
  const netInput   = document.getElementById("network-input");
  const statusBar  = document.getElementById("scan-status");
  const progressEl = document.getElementById("scan-progress");
  const scanMsg    = document.getElementById("scan-msg");
  const emptyState = document.getElementById("empty-state");

  /* ── Hop slider ── */
  hopSlider.addEventListener("input", () => {
    hopVal.textContent = hopSlider.value;
  });

  /* ── Zoom buttons ── */
  btnZoomIn.addEventListener("click",  () => diagram.zoomIn());
  btnZoomOut.addEventListener("click", () => diagram.zoomOut());
  btnReset.addEventListener("click",   () => diagram.resetView());

  /* ── Demo ── */
  btnDemo.addEventListener("click", () => {
    fetch("/api/demo")
      .then(r => r.json())
      .then(data => {
        diagram.load(data);
        emptyState.classList.add("hidden");
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
      });
  });

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollStatus, 1500);
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function pollStatus() {
    fetch("/api/scan/status")
      .then(r => r.json())
      .then(s => {
        const found = s.found ?? 0;
        progressEl.style.width = `${s.progress ?? 50}%`;
        scanMsg.textContent = `Scanning… ${found} host${found !== 1 ? "s" : ""} found`;

        if (s.status === "complete") {
          stopPolling();
          progressEl.style.width = "100%";
          scanMsg.textContent = `Done – ${found} host${found !== 1 ? "s" : ""} found`;
          btnScan.disabled = false;
          fetch("/api/topology")
            .then(r => r.json())
            .then(data => {
              if (data.node_count > 0) {
                diagram.load(data);
                emptyState.classList.add("hidden");
              }
            });
        } else if (s.status === "error") {
          stopPolling();
          scanMsg.textContent = `Error: ${s.error}`;
          btnScan.disabled = false;
        }
      })
      .catch(err => console.error("Poll error:", err));
  }
})();
