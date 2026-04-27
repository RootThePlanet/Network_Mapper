"""Tests for nmap_plusplus.config."""

import json
import os
from pathlib import Path

import pytest

from nmap_plusplus.config import DEFAULT_CONFIG, load_config


class TestLoadConfigDefaults:
    def test_no_file_returns_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg["host"] == DEFAULT_CONFIG["host"]
        assert cfg["port"] == DEFAULT_CONFIG["port"]
        assert cfg["debug"] is False
        assert cfg["hop_limit"] == 4

    def test_returns_all_default_keys(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        for key in DEFAULT_CONFIG:
            assert key in cfg


class TestLoadConfigJson:
    def test_json_file_overrides_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text(json.dumps({"port": 9999, "debug": True}))
        cfg = load_config(str(cfg_file))
        assert cfg["port"] == 9999
        assert cfg["debug"] is True
        # Other keys remain as defaults
        assert cfg["host"] == DEFAULT_CONFIG["host"]

    def test_unknown_keys_ignored(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text(json.dumps({"unknown_key": "value", "port": 8080}))
        cfg = load_config(str(cfg_file))
        assert "unknown_key" not in cfg
        assert cfg["port"] == 8080

    def test_nonexistent_path_returns_defaults(self, tmp_path):
        cfg = load_config(str(tmp_path / "nonexistent.json"))
        assert cfg["port"] == DEFAULT_CONFIG["port"]

    def test_empty_json_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text("{}")
        cfg = load_config(str(cfg_file))
        assert cfg["port"] == DEFAULT_CONFIG["port"]


class TestLoadConfigYaml:
    def test_yaml_file_overrides_defaults(self, tmp_path):
        pytest.importorskip("yaml")
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("port: 7777\ndebug: true\n")
        cfg = load_config(str(cfg_file))
        assert cfg["port"] == 7777
        assert cfg["debug"] is True
