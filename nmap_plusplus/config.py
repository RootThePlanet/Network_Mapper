"""
Configuration loading: reads config.yaml / config.json and merges with defaults.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": False,
    "hop_limit": 4,
    "api_key": None,
    "allowed_networks": [],
    "schedule": None,
    "output": None,
    "headless": False,
    "history_dir": "scan_history",
    "webhooks": [],
}


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a YAML or JSON file and merge with defaults.

    If *path* is None, searches the current directory for config.yaml or
    config.json.  Missing keys fall back to DEFAULT_CONFIG values.
    """
    config = dict(DEFAULT_CONFIG)

    candidates = [path] if path else ["config.yaml", "config.yml", "config.json"]

    for candidate in candidates:
        if candidate is None:
            continue
        p = Path(candidate)
        if not p.exists():
            continue
        try:
            if p.suffix in (".yaml", ".yml"):
                try:
                    import yaml  # type: ignore
                    with open(p, encoding="utf-8") as fh:
                        file_cfg = yaml.safe_load(fh) or {}
                except ImportError:
                    logger.warning("PyYAML not installed; cannot read %s", p)
                    file_cfg = {}
            else:
                with open(p, encoding="utf-8") as fh:
                    file_cfg = json.load(fh)

            if isinstance(file_cfg, dict):
                config.update({k: v for k, v in file_cfg.items() if k in DEFAULT_CONFIG})
                logger.info("Loaded config from %s", p)
        except Exception as exc:
            logger.warning("Failed to load config file %s: %s", p, exc)
        break   # use first found

    return config
