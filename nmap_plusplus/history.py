"""
Scan history persistence: save/load/diff topology snapshots as JSON files.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class ScanHistory:
    """Persists topology snapshots to a directory of timestamped JSON files."""

    def __init__(self, storage_dir: str = "scan_history") -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------

    def save(self, topology_data: dict) -> str:
        """Write topology_data to a timestamped JSON file. Returns filename."""
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{ts}.json"
        path = self.storage_dir / filename
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(topology_data, fh, indent=2)
        logger.info("Scan history saved: %s", path)
        return filename

    def list_scans(self) -> List[Dict]:
        """Return scan metadata sorted newest first."""
        entries = []
        for p in sorted(self.storage_dir.glob("*.json"), reverse=True):
            try:
                with open(p, encoding="utf-8") as fh:
                    data = json.load(fh)
                node_count = data.get("node_count", len(data.get("nodes", [])))
                entries.append({
                    "id": p.stem,
                    "timestamp": p.stem,
                    "node_count": node_count,
                })
            except Exception as exc:
                logger.warning("Could not read history file %s: %s", p, exc)
        return entries

    def load(self, scan_id: str) -> dict:
        """Load and return scan data for *scan_id*."""
        path = self.storage_dir / f"{scan_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Scan {scan_id!r} not found")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def diff(self, old_id: str, new_id: str) -> dict:
        """
        Compare two scans and return dicts of new/removed/changed node IPs.
        """
        old_data = self.load(old_id)
        new_data = self.load(new_id)

        def _node_map(data: dict) -> Dict[str, dict]:
            return {n["id"]: n for n in data.get("nodes", [])}

        old_nodes = _node_map(old_data)
        new_nodes = _node_map(new_data)

        old_ips = set(old_nodes)
        new_ips = set(new_nodes)

        added = sorted(new_ips - old_ips)
        removed = sorted(old_ips - new_ips)

        # "changed" = same IP but different hostname or node_type
        changed = []
        for ip in old_ips & new_ips:
            o, n = old_nodes[ip], new_nodes[ip]
            if o.get("hostname") != n.get("hostname") or o.get("node_type") != n.get("node_type"):
                changed.append(ip)

        return {"new": added, "removed": removed, "changed": sorted(changed)}
