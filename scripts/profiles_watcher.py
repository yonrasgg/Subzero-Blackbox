#!/usr/bin/env python3
"""
scripts/profiles_watcher.py

Simple stub that:
- Loads config.yaml and profiles.yaml
- Shows the active profile and enabled modules
Intended to be launched by systemd (blackbox-profiles.service).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def main() -> int:
    cfg = load_yaml(CONFIG_PATH)
    profiles = load_yaml(PROFILES_PATH).get("profiles", {})

    active = cfg.get("profiles", {}).get("active_profile")
    print(f"[profiles_watcher] Active profile: {active}")

    if active and active in profiles:
        data = profiles[active]
        print(f"[profiles_watcher] internet_via: {data.get('internet_via')}")
        print(f"[profiles_watcher] modules_enabled: {data.get('modules_enabled')}")
    else:
        print("[profiles_watcher] No active profile or not found in profiles.yaml")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
