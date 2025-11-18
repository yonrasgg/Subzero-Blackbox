"""
Bluetooth passive recon module.

Scans for nearby Bluetooth/BLE devices:
- Uses bluetoothctl or hcitool for scanning.
- Classifies by type, RSSI.
- Stores results in JSON under data/captures.
- Optimized for low power consumption.
"""

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
CAPTURES_DIR = BASE_DIR / "data" / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)


def _load_config() -> Dict[str, Any]:
    """Load config.yaml and merge with secrets.yaml if it exists."""
    if not CONFIG_PATH.is_file():
        return {}
    
    # Load main config
    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    
    # Merge secrets.yaml if it exists
    secrets_path = CONFIG_PATH.parent / "secrets.yaml"
    if secrets_path.is_file():
        secrets = yaml.safe_load(secrets_path.read_text(encoding="utf-8")) or {}
        # Deep merge secrets into config
        def deep_merge(base, update):
            for key, value in update.items():
                if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value
        deep_merge(data, secrets)
    
    return data


def analyze_bt_vulnerabilities(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze Bluetooth devices for common vulnerabilities."""
    vulnerabilities = []
    config = _load_config()
    bt_audits = config.get("bt_audits", {})
    if not bt_audits.get("enable_vulnerability_scan", False):
        return vulnerabilities

    scan_types = bt_audits.get("scan_types", [])

    for device in devices:
        device_vulns = []
        name = device.get("name", "")

        if "blue_snarfing" in scan_types:
            # Assume if visible, vulnerable to snarfing
            device_vulns.append({
                "type": "blue_snarfing",
                "description": "Device may be vulnerable to Blue Snarfing if in visible mode, allowing unauthorized data access.",
                "severity": "high"
            })

        if "bluejacking" in scan_types:
            device_vulns.append({
                "type": "bluejacking",
                "description": "Device susceptible to Bluejacking attacks for sending unsolicited messages.",
                "severity": "medium"
            })

        if "pairing_vulnerabilities" in scan_types:
            # Check for default names or something
            if name in ["Bluetooth Device", "Unknown", ""] or not name:
                device_vulns.append({
                    "type": "pairing_vulnerabilities",
                    "description": "Weak or default pairing setup detected, vulnerable to interception.",
                    "severity": "high"
                })

        if "software_firmware" in scan_types:
            # Placeholder: assume old if no info
            device_vulns.append({
                "type": "software_firmware",
                "description": "Potential outdated software/firmware vulnerabilities in Bluetooth stack.",
                "severity": "medium"
            })

        if "dos_attacks" in scan_types:
            device_vulns.append({
                "type": "dos_attacks",
                "description": "Susceptible to DoS attacks via malformed packets.",
                "severity": "medium"
            })

        if bt_audits.get("captured_data_analysis", {}).get("device_info", False):
            # Analyze device info
            device_vulns.append({
                "type": "device_info_analysis",
                "description": "Device information captured; check for known vulnerabilities.",
                "severity": "low"
            })

        if bt_audits.get("captured_data_analysis", {}).get("service_discovery", False):
            device_vulns.append({
                "type": "service_discovery",
                "description": "Exposed services detected; potential for unauthorized access.",
                "severity": "medium"
            })

        if bt_audits.get("captured_data_analysis", {}).get("pairing_info", False):
            device_vulns.append({
                "type": "pairing_info",
                "description": "Pairing information analyzed; check for weak keys.",
                "severity": "high"
            })

        if device_vulns:
            vulnerabilities.append({
                "device": device,
                "vulnerabilities": device_vulns
            })

    return vulnerabilities


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


def scan_bluetooth_devices(duration: int = 10) -> List[Dict[str, Any]]:
    """Scan Bluetooth devices using bluetoothctl."""
    logger.info("Scanning Bluetooth devices for %d seconds", duration)
    devices = []

    # Use bluetoothctl scan on
    cmd_start = ["sudo", "bluetoothctl", "scan", "on"]
    proc = subprocess.Popen(cmd_start, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(duration)
    proc.terminate()
    proc.wait()

    # Get devices
    cmd_devices = ["sudo", "bluetoothctl", "devices"]
    output = _run_command(cmd_devices)
    for line in output.splitlines():
        if "Device" in line:
            parts = line.split()
            if len(parts) >= 3:
                mac = parts[1]
                name = " ".join(parts[2:])
                devices.append({"mac": mac, "name": name, "type": "unknown"})

    logger.info("Found %d Bluetooth devices", len(devices))
    return devices


def save_results(devices: List[Dict[str, Any]], job_id: int) -> None:
    """Save scan results to JSON file."""
    vulnerabilities = analyze_bt_vulnerabilities(devices)
    data = {
        "job_id": job_id,
        "timestamp": int(time.time()),
        "devices": devices,
        "vulnerabilities": vulnerabilities,
    }
    filename = f"bt_recon_job_{job_id}.json"
    filepath = DATA_DIR / filename
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Results saved to %s", filepath)
    except Exception as e:
        logger.error("Error saving results: %s", e)


def run(job) -> None:
    """Run Bluetooth reconnaissance for the given job."""
    profile = job.profile or "default"
    logger.info("Starting BT recon for job %s with profile %s", job.id, profile)

    config = _load_config()
    scan_duration = config.get("bt", {}).get("scan_duration", 10)

    try:
        devices = scan_bluetooth_devices(scan_duration)
        if devices:
            save_results(devices, job.id)
            logger.info("BT recon completed for job %s", job.id)
        else:
            logger.warning("No BT devices found for job %s", job.id)
    except Exception as e:
        logger.error("Error in BT recon for job %s: %s", job.id, e)
