"""
Bluetooth active module.

Performs active operations on Bluetooth devices:
- Connect to devices.
- Query services.
- Sniffing if possible.
- Optimized for low resources; uses bluez tools.
"""

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, List

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"


def _load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.is_file():
        return {}
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


def _run_command(cmd: List[str], timeout: int = 30) -> str:
    """Run a command and return stdout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error("Command failed: %s, stderr: %s", cmd, e.stderr)
        return ""
    except subprocess.TimeoutExpired:
        logger.error("Command timed out: %s", cmd)
        return ""


def connect_device(mac: str) -> bool:
    """Attempt to connect to a BT device."""
    logger.info("Attempting to connect to BT device %s", mac)
    cmd = ["sudo", "bluetoothctl", "connect", mac]
    output = _run_command(cmd)
    return "Connection successful" in output


def scan_services(mac: str) -> str:
    """Scan services of a connected device."""
    logger.info("Scanning services for %s", mac)
    cmd = ["sudo", "bluetoothctl", "info", mac]
    return _run_command(cmd)


def save_results(services: str, job_id: int) -> None:
    """Save services results to JSON file."""
    data = {
        "job_id": job_id,
        "timestamp": int(time.time()),
        "services_output": services,
    }
    filename = f"bt_active_job_{job_id}.json"
    filepath = DATA_DIR / filename
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Results saved to %s", filepath)
    except Exception as e:
        logger.error("Error saving results: %s", e)


def run(job) -> None:
    """Run Bluetooth active operations for the given job."""
    profile = job.profile or "default"
    logger.info("Starting BT active ops for job %s with profile %s", job.id, profile)

    target_mac = job.params.get("target_mac") if job.params else None

    if not target_mac:
        logger.error("No target_mac provided for job %s", job.id)
        return

    try:
        if connect_device(target_mac):
            services = scan_services(target_mac)
            logger.info("BT services for job %s: %s", job.id, services)
            # Save results
            save_results(services, job.id)
            # Disconnect
            cmd = ["sudo", "bluetoothctl", "disconnect", target_mac]
            _run_command(cmd)
        else:
            logger.error("Failed to connect to %s for job %s", target_mac, job.id)
        logger.info("BT active ops completed for job %s", job.id)
    except Exception as e:
        logger.error("Error in BT active ops for job %s: %s", job.id, e)
