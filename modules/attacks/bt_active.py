"""
Bluetooth active module.

Performs active operations on Bluetooth devices (Phase 3 & 4):
- Reachability checks (l2ping).
- Service enumeration (SDP).
- GATT enumeration (BLE).
- Optimized for low resources; uses bluez tools.
"""

import json
import logging
import subprocess
import time
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
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


def scan_for_target(duration: int = 5) -> Optional[str]:
    """Quick scan to find a target if none provided."""
    logger.info("Scanning for a target for %d seconds...", duration)
    cmd_start = ["sudo", "bluetoothctl", "scan", "on"]
    proc = subprocess.Popen(cmd_start, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    target_mac = None
    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            line = proc.stdout.readline()
            if "Device" in line:
                parts = line.split()
                try:
                    idx = parts.index("Device")
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1]
                        if re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac, re.I):
                            target_mac = mac
                            break # Found one, stop
                except ValueError:
                    pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
            
    return target_mac


def check_reachability(mac: str) -> Dict[str, Any]:
    """Check device reachability using l2ping."""
    logger.info("Checking reachability for %s", mac)
    # l2ping -c 3 <MAC>
    cmd = ["sudo", "l2ping", "-c", "3", mac]
    output = _run_command(cmd, timeout=10)
    
    reachable = "received" in output and "0% loss" in output
    latency = "0"
    if reachable:
        # Extract avg latency: round-trip min/avg/max = 1.2/3.4/5.6 ms
        match = re.search(r"min/avg/max = [\d\.]+/([\d\.]+)/", output)
        if match:
            latency = match.group(1)
            
    return {
        "reachable": reachable,
        "latency_ms": latency,
        "output": output
    }


def enumerate_sdp_services(mac: str) -> str:
    """Enumerate SDP services (Classic BT)."""
    logger.info("Enumerating SDP services for %s", mac)
    cmd = ["sudo", "sdptool", "browse", mac]
    return _run_command(cmd, timeout=20)


def enumerate_gatt_services(mac: str) -> str:
    """Enumerate GATT services (BLE) using gatttool."""
    logger.info("Enumerating GATT services for %s", mac)
    # gatttool -b <MAC> --primary
    cmd = ["sudo", "gatttool", "-b", mac, "--primary"]
    return _run_command(cmd, timeout=15)


def save_results(data: Dict[str, Any], job_id: int) -> None:
    """Save active audit results to JSON file."""
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

    target_mac = job.params.get("target_mac")
    
    if not target_mac:
        logger.info("No target_mac provided, performing quick scan...")
        target_mac = scan_for_target()
        
    if not target_mac:
        logger.error("No target found for job %s", job.id)
        return

    logger.info("Targeting: %s", target_mac)
    
    results = {
        "job_id": job.id,
        "timestamp": int(time.time()),
        "target_mac": target_mac,
        "tests": {}
    }

    try:
        # 1. Reachability (Phase 3)
        reachability = check_reachability(target_mac)
        results["tests"]["reachability"] = reachability
        
        if reachability["reachable"]:
            # 2. SDP Enumeration (Classic)
            sdp_output = enumerate_sdp_services(target_mac)
            results["tests"]["sdp_services"] = sdp_output
            
            # 3. GATT Enumeration (BLE)
            # We try this regardless, as some devices are dual mode
            gatt_output = enumerate_gatt_services(target_mac)
            results["tests"]["gatt_services"] = gatt_output
            
            # 4. Vulnerability Check (Basic)
            vulns = []
            if "Keyboard" in sdp_output or "Human Interface Device" in sdp_output:
                vulns.append("Exposed HID Service (Potential Keystroke Injection)")
            
            if not gatt_output and not sdp_output:
                 vulns.append("Device reachable but no services enumerated (Stealthy or Auth required)")
                 
            results["vulnerabilities"] = vulns
            
        else:
            logger.warning("Target %s is not reachable via l2ping", target_mac)
            results["error"] = "Target unreachable"

        save_results(results, job.id)
        logger.info("BT active ops completed for job %s", job.id)
        
    except Exception as e:
        logger.error("Error in BT active ops for job %s: %s", job.id, e)
