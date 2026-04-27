"""Tests for nmap_plusplus.history."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from nmap_plusplus.history import ScanHistory


def _make_topo(node_ids):
    """Build a minimal topology dict with the given node IDs."""
    return {
        "nodes": [{"id": ip, "hostname": ip, "node_type": "remote", "hop": 1} for ip in node_ids],
        "links": [],
        "focal": node_ids[0] if node_ids else None,
        "node_count": len(node_ids),
        "link_count": 0,
    }


@pytest.fixture()
def tmp_history(tmp_path):
    return ScanHistory(storage_dir=str(tmp_path / "hist"))


class TestSave:
    def test_save_creates_json_file(self, tmp_history):
        filename = tmp_history.save(_make_topo(["10.0.0.1"]))
        assert filename.endswith(".json")
        path = Path(tmp_history.storage_dir) / filename
        assert path.exists()

    def test_save_content_round_trips(self, tmp_history):
        data = _make_topo(["10.0.0.1", "10.0.0.2"])
        filename = tmp_history.save(data)
        path = Path(tmp_history.storage_dir) / filename
        loaded = json.loads(path.read_text())
        assert loaded["node_count"] == 2


class TestListScans:
    def test_empty_dir_returns_empty_list(self, tmp_history):
        assert tmp_history.list_scans() == []

    def test_list_returns_all_saved(self, tmp_history):
        tmp_history.save(_make_topo(["1.1.1.1"]))
        tmp_history.save(_make_topo(["2.2.2.2"]))
        scans = tmp_history.list_scans()
        assert len(scans) == 2

    def test_list_sorted_newest_first(self, tmp_history):
        import time
        tmp_history.save(_make_topo(["1.1.1.1"]))
        time.sleep(0.05)  # Ensure different timestamps
        tmp_history.save(_make_topo(["2.2.2.2"]))
        scans = tmp_history.list_scans()
        assert scans[0]["id"] > scans[1]["id"]

    def test_list_includes_node_count(self, tmp_history):
        tmp_history.save(_make_topo(["1.1.1.1", "2.2.2.2", "3.3.3.3"]))
        scans = tmp_history.list_scans()
        assert scans[0]["node_count"] == 3


class TestLoad:
    def test_load_returns_saved_data(self, tmp_history):
        data = _make_topo(["10.0.0.1"])
        filename = tmp_history.save(data)
        scan_id = filename.replace(".json", "")
        loaded = tmp_history.load(scan_id)
        assert loaded["node_count"] == 1

    def test_load_nonexistent_raises(self, tmp_history):
        with pytest.raises(FileNotFoundError):
            tmp_history.load("nonexistent-id")


class TestDiff:
    def test_diff_identifies_new_nodes(self, tmp_history):
        old_fn = tmp_history.save(_make_topo(["10.0.0.1"]))
        new_fn = tmp_history.save(_make_topo(["10.0.0.1", "10.0.0.2"]))
        old_id = old_fn.replace(".json", "")
        new_id = new_fn.replace(".json", "")
        diff = tmp_history.diff(old_id, new_id)
        assert "10.0.0.2" in diff["new"]
        assert diff["removed"] == []

    def test_diff_identifies_removed_nodes(self, tmp_history):
        old_fn = tmp_history.save(_make_topo(["10.0.0.1", "10.0.0.2"]))
        new_fn = tmp_history.save(_make_topo(["10.0.0.1"]))
        old_id = old_fn.replace(".json", "")
        new_id = new_fn.replace(".json", "")
        diff = tmp_history.diff(old_id, new_id)
        assert "10.0.0.2" in diff["removed"]
        assert diff["new"] == []

    def test_diff_no_changes(self, tmp_history):
        old_fn = tmp_history.save(_make_topo(["10.0.0.1"]))
        new_fn = tmp_history.save(_make_topo(["10.0.0.1"]))
        old_id = old_fn.replace(".json", "")
        new_id = new_fn.replace(".json", "")
        diff = tmp_history.diff(old_id, new_id)
        assert diff == {"new": [], "removed": [], "changed": []}

    def test_diff_identifies_changed_nodes(self, tmp_history):
        old_data = _make_topo(["10.0.0.1"])
        old_data["nodes"][0]["hostname"] = "host-a"
        old_fn = tmp_history.save(old_data)

        new_data = _make_topo(["10.0.0.1"])
        new_data["nodes"][0]["hostname"] = "host-b"
        new_fn = tmp_history.save(new_data)

        old_id = old_fn.replace(".json", "")
        new_id = new_fn.replace(".json", "")
        diff = tmp_history.diff(old_id, new_id)
        assert "10.0.0.1" in diff["changed"]
