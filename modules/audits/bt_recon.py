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
import re
from pathlib import Path
from typing import Dict, List, Any

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
CAPTURES_DIR = BASE_DIR / "data" / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"


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


def scan_bluetooth_devices(duration: int = 15) -> List[Dict[str, Any]]:
    """Scan Bluetooth devices using bluetoothctl."""
    logger.info("Scanning Bluetooth devices for %d seconds", duration)
    devices = {}

    # Start scanning
    cmd_start = ["sudo", "bluetoothctl", "scan", "on"]
    proc = subprocess.Popen(cmd_start, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            line = proc.stdout.readline()
            if not line:
                continue
            
            # Parse real-time output: [NEW] Device XX:XX:XX:XX:XX:XX Name
            # or [CHG] Device XX:XX:XX:XX:XX:XX RSSI: -80
            if "Device" in line:
                parts = line.split()
                try:
                    idx = parts.index("Device")
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1]
                        # Basic validation of MAC
                        if re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac, re.I):
                            if mac not in devices:
                                devices[mac] = {"mac": mac, "name": "Unknown", "rssi": None, "type": "unknown"}
                            
                            # Try to extract name if present
                            if len(parts) > idx + 2:
                                name_candidate = " ".join(parts[idx + 2:])
                                if "RSSI:" not in name_candidate:
                                    devices[mac]["name"] = name_candidate
                            
                            # Try to extract RSSI
                            if "RSSI:" in line:
                                rssi_idx = parts.index("RSSI:")
                                if rssi_idx + 1 < len(parts):
                                    devices[mac]["rssi"] = parts[rssi_idx + 1]
                except ValueError:
                    pass
    except Exception as e:
        logger.error(f"Error reading scan output: {e}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Get detailed list to fill in gaps
    cmd_devices = ["sudo", "bluetoothctl", "devices"]
    output = _run_command(cmd_devices)
    for line in output.splitlines():
        if "Device" in line:
            parts = line.split()
            if len(parts) >= 3:
                mac = parts[1]
                name = " ".join(parts[2:])
                if mac not in devices:
                    devices[mac] = {"mac": mac, "name": name, "rssi": None, "type": "unknown"}
                elif devices[mac]["name"] == "Unknown":
                    devices[mac]["name"] = name

    logger.info("Found %d Bluetooth devices", len(devices))
    return list(devices.values())


def get_device_info(mac: str) -> Dict[str, Any]:
    """Get detailed info about a device using bluetoothctl info."""
    cmd = ["sudo", "bluetoothctl", "info", mac]
    output = _run_command(cmd)
    info = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            info["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Alias:"):
            info["alias"] = line.split(":", 1)[1].strip()
        elif line.startswith("Class:"):
            info["class"] = line.split(":", 1)[1].strip()
        elif line.startswith("Icon:"):
            info["icon"] = line.split(":", 1)[1].strip()
        elif line.startswith("Paired:"):
            info["paired"] = line.split(":", 1)[1].strip()
        elif line.startswith("Trusted:"):
            info["trusted"] = line.split(":", 1)[1].strip()
        elif line.startswith("Blocked:"):
            info["blocked"] = line.split(":", 1)[1].strip()
        elif line.startswith("Connected:"):
            info["connected"] = line.split(":", 1)[1].strip()
        elif line.startswith("LegacyPairing:"):
            info["legacy_pairing"] = line.split(":", 1)[1].strip()
        elif line.startswith("UUID:"):
            if "uuids" not in info:
                info["uuids"] = []
            info["uuids"].append(line.split(":", 1)[1].strip())
    return info


def enumerate_services_sdp(mac: str) -> str:
    """Enumerate services using sdptool (Classic BT)."""
    # sdptool browse <MAC>
    cmd = ["sudo", "sdptool", "browse", mac]
    return _run_command(cmd, timeout=15)


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
        _mac = device.get("mac", "")
        
        # Check for known vulnerable MAC prefixes (OUI) - Placeholder
        # In a real scenario, we'd check against a database
        
        if "blue_snarfing" in scan_types:
            # Assume if visible and legacy pairing, potentially vulnerable
            if device.get("legacy_pairing") == "yes":
                device_vulns.append({
                    "type": "blue_snarfing",
                    "description": "Device supports Legacy Pairing, potentially vulnerable to Blue Snarfing.",
                    "severity": "high"
                })

        if "pairing_vulnerabilities" in scan_types:
            # Check for default names
            if name in ["Bluetooth Device", "Unknown", ""] or not name:
                device_vulns.append({
                    "type": "pairing_vulnerabilities",
                    "description": "Weak or default pairing setup detected (default name).",
                    "severity": "medium"
                })

        if "software_firmware" in scan_types:
            # Placeholder
            pass

        if device_vulns:
            vulnerabilities.append({
                "device": device,
                "vulnerabilities": device_vulns
            })

    return vulnerabilities


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
    scan_duration = config.get("bt", {}).get("scan_duration", 15)
    
    # Check if we should do extended recon (fingerprinting)
    # This could be a param in the job or part of the profile config
    # For now, let's assume if profile is 'bluetooth_audit', we do basic info gathering
    extended_recon = True 

    try:
        # Phase 1: Passive Scan
        devices = scan_bluetooth_devices(scan_duration)
        
        if extended_recon and devices:
            logger.info("Starting Phase 2: Fingerprinting for %d devices", len(devices))
            for device in devices:
                mac = device["mac"]
                # Get detailed info (bluetoothctl info)
                info = get_device_info(mac)
                device.update(info)
                
                # If we want to be more aggressive (Phase 2b), we could try SDP browsing
                # But sdptool often requires the device to be discoverable/connectable
                # We'll try it if it's not a BLE-only device (hard to tell without more info, but we can try)
                # Note: sdptool might hang or fail if device is not reachable
                # device["sdp_records"] = enumerate_services_sdp(mac)
        
        if devices:
            save_results(devices, job.id)
            logger.info("BT recon completed for job %s. Found %d devices.", job.id, len(devices))
        else:
            logger.warning("No BT devices found for job %s", job.id)
            
    except Exception as e:
        logger.error("Error in BT recon for job %s: %s", job.id, e)
