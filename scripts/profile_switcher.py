#!/usr/bin/env python3
"""
scripts/profile_switcher.py

Manages Blackbox audit/tethering profiles:

- Reads config/config.yaml and config/profiles.yaml.
- Lists available profiles.
- Shows the active profile.
- Switches profiles safely:
    * Does not switch if already active.
    * Refuses to switch if there are jobs "running".
    * Applies enable/disable to interfaces.
    * Calls scripts/tethering_switch.sh according to internet_via.
- Logs changes in the profiles_log table of data/blackbox.db.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from sqlalchemy.orm import Session


# ---------------------------------------------------------------------------
# sys.path bootstrap to allow importing 'worker' when running as script:
# python scripts/profile_switcher.py ...
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent  # ~/blackbox-dev
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

IS_ROOT = (os.geteuid() == 0)

# Now this works because BASE_DIR is in sys.path
from worker.db import SessionLocal, ProfileLog, Job  # noqa: E402  # noqa: E402



# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------

CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"
LOG_DIR = BASE_DIR / "data" / "logs"
LOG_FILE = LOG_DIR / "blackbox.log"
TETHERING_SWITCH = BASE_DIR / "scripts" / "tethering_switch.sh"



# ---------------------------------------------------------------------------
# Basic logging
# ---------------------------------------------------------------------------

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [profile_switcher] %(message)s",
)



# ---------------------------------------------------------------------------
# YAML utilities
# ---------------------------------------------------------------------------



def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Loads a YAML file and always returns a dict (empty in case of error).
    """
    if not path.is_file():
        logging.warning("YAML file %s not found; returning empty dict", path)
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logging.error("Error reading YAML %s: %s", path, exc)
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        logging.warning("YAML %s did not produce a dict; got %r", path, type(data))
        return {}
    return data



def _save_yaml(path: Path, data: Dict[str, Any]) -> None:
    """
    Saves a dict as YAML (creates directory if it does not exist).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    yaml.safe_dump(data, path.open("w", encoding="utf-8"), sort_keys=False)


def get_profiles_config() -> Dict[str, Any]:
    data = _load_yaml(PROFILES_PATH)
    return data.get("profiles", {})


def get_config() -> Dict[str, Any]:
    return _load_yaml(CONFIG_PATH)


def get_active_profile_name(cfg: Dict[str, Any]) -> Optional[str]:
    return cfg.get("profiles", {}).get("active_profile")


def set_active_profile_name(cfg: Dict[str, Any], profile_name: str) -> Dict[str, Any]:
    if "profiles" not in cfg or not isinstance(cfg["profiles"], dict):
        cfg["profiles"] = {}
    cfg["profiles"]["active_profile"] = profile_name
    return cfg



# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------



def has_running_jobs(session: Session) -> bool:
    """
    Returns True if there is any job with status 'running'.
    """
    return (
        session.query(Job)
        .filter(Job.status == "running")
        .limit(1)
        .count()
        > 0
    )



def insert_profile_log(
    session: Session,
    old_profile: Optional[str],
    new_profile: str,
    reason: Optional[str] = None,
    triggered_by: Optional[str] = None,
) -> None:
    rec = ProfileLog(
        old_profile=old_profile,
        new_profile=new_profile,
        reason=reason,
        triggered_by=triggered_by,
    )
    session.add(rec)
    session.commit()



# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def run_cmd(cmd: list[str]) -> None:
    """
    Runs a system command without breaking the flow and without printing errors to the screen.

    - Captures stdout/stderr.
    - If return code != 0, logs the error message.
    - Does NOT raise exception: intended for ip/hciconfig/etc.
    """
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:  # noqa: BLE001
        logging.error("Error running command %s: %s", cmd, exc)
        return

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        logging.error(
            "Command %s failed with rc=%s, stderr=%s",
            cmd,
            result.returncode,
            stderr,
        )


def apply_interfaces(disable: list[str], enable: list[str]) -> None:
    """
    Brings network/bt interfaces up or down in a very simple way.

    - If NOT running as root → does nothing, just logs.
    - If the name starts with 'hci' it is assumed to be a Bluetooth interface → hciconfig.
    - Otherwise uses `ip link set ... up/down`.
    """
    if not IS_ROOT:
        logging.info(
            "Not running as root; skipping interface changes. disable=%s enable=%s",
            disable,
            enable,
        )
        return

    for iface in disable:
        if not iface:
            continue
        logging.info("Disabling interface: %s", iface)
        if iface.startswith("hci"):
            run_cmd(["hciconfig", iface, "down"])
        else:
            run_cmd(["ip", "link", "set", iface, "down"])

    for iface in enable:
        if not iface:
            continue
        logging.info("Enabling interface: %s", iface)
        if iface.startswith("hci"):
            run_cmd(["hciconfig", iface, "up"])
        else:
            run_cmd(["ip", "link", "set", iface, "up"])


def call_tethering_switch(mode: str) -> None:
    """
    Calls scripts/tethering_switch.sh with mode 'wifi', 'bluetooth', 'usb', 'off' or 'status'.

    - Only runs if the process is running as root (IS_ROOT).
    - If not root: logs and exits without calling the script.
    - If the script returns rc != 0, logs the error with stderr.
    """
    if mode not in ("wifi", "bluetooth", "usb", "off", "status"):
        logging.warning("call_tethering_switch called with invalid mode: %s", mode)
        return

    if not TETHERING_SWITCH.is_file():
        logging.warning("tethering_switch.sh not found at %s", TETHERING_SWITCH)
        return

    if not IS_ROOT:
        logging.warning(
            "Not running as root; skipping tethering_switch.sh (mode=%s).", mode
        )
        return

    cmd = [str(TETHERING_SWITCH), mode]
    logging.info("Calling tethering_switch (root): %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:  # noqa: BLE001
        logging.error("Error calling tethering_switch (%s): %s", mode, exc)
        return

    if result.returncode != 0:
        logging.error(
            "tethering_switch failed (mode=%s, rc=%s, stderr=%s)",
            mode,
            result.returncode,
            (result.stderr or "").strip(),
        )


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------



def cmd_list() -> None:
    profiles = get_profiles_config()
    if not profiles:
        print("No profiles defined in config/profiles.yaml")
        return

    print("Available profiles:")
    for name, data in profiles.items():
        desc = data.get("description", "")
        print(f"  - {name}: {desc}")



def cmd_show() -> None:
    cfg = get_config()
    active = get_active_profile_name(cfg)
    profiles = get_profiles_config()

    print(f"Active profile: {active or '-'}")
    if active and active in profiles:
        data = profiles[active]
        print("  internet_via:", data.get("internet_via"))
        print("  disable_interfaces:", data.get("disable_interfaces", []))
        print("  enable_interfaces:", data.get("enable_interfaces", []))
        print("  modules_enabled:", data.get("modules_enabled", []))



def cmd_set(profile_name: str) -> None:
    """
    Safely switches profile.

    - Verifies that the profile exists in profiles.yaml.
    - Opens DB, checks that there are no jobs 'running'.
    - If the profile is already active, does nothing (idempotent).
    - Applies enable/disable to interfaces.
    - Calls tethering_switch.sh according to internet_via.
    - Updates config.yaml and writes to profiles_log.
    """
    profiles = get_profiles_config()
    if profile_name not in profiles:
        print(f"[ERROR] Unknown profile: {profile_name}")
        sys.exit(1)

    profile_data = profiles[profile_name]
    internet_via = profile_data.get("internet_via")
    disable = profile_data.get("disable_interfaces", []) or []
    enable = profile_data.get("enable_interfaces", []) or []

    cfg = get_config()
    old = get_active_profile_name(cfg)

    # If already active, exit without doing anything
    if old == profile_name:
        print(f"[INFO] Profile {profile_name} is already active; nothing to do.")
        logging.info("Profile %s already active; nothing to do", profile_name)
        return

    # Open DB to validate that there are no jobs 'running'
    with SessionLocal() as session:
        if has_running_jobs(session):
            msg = "There are jobs in status 'running'; refusing to switch profile."
            print(f"[ERROR] {msg}")
            logging.warning(msg)
            return

        triggered_by = os.environ.get("BLACKBOX_TRIGGERED_BY", "cli")
        reason = os.environ.get("BLACKBOX_PROFILE_REASON")

        print(f"[INFO] Switching profile: {old} -> {profile_name}")
        logging.info("Switching profile: %s -> %s", old, profile_name)

        # Apply interfaces
        apply_interfaces(disable, enable)

        # Switch tethering according to internet_via
        if internet_via in ("wifi", "bluetooth", "usb"):
            call_tethering_switch(internet_via)
        elif internet_via:
            logging.warning("Unknown internet_via '%s' for profile %s", internet_via, profile_name)

        # Update config.yaml
        cfg = set_active_profile_name(cfg, profile_name)
        _save_yaml(CONFIG_PATH, cfg)

        # Log in profiles_log
        insert_profile_log(
            session,
            old_profile=old,
            new_profile=profile_name,
            reason=reason,
            triggered_by=triggered_by,
        )

        print("[INFO] Profile switch completed.")
        logging.info("Profile switch completed: %s -> %s", old, profile_name)



# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------



def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Blackbox profile/tethering switcher",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available profiles from profiles.yaml")
    sub.add_parser("show", help="Show active profile and basic info")

    p_set = sub.add_parser("set", help="Set active profile")
    p_set.add_argument("profile", help="Profile name to activate")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        cmd_list()
        return 0
    if args.command == "show":
        cmd_show()
        return 0
    if args.command == "set":
        cmd_set(args.profile)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
