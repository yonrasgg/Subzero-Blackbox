"""
Wi-Fi passive recon module.

Performs passive reconnaissance on Wi-Fi networks:
- Scans for visible access points using iwlist or nmcli.
- Captures beacons/probes if monitor mode is available.
- Stores results in JSON under data/captures.
- Optimized for low-resource devices (Pi Zero 2W).
"""

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any

import yaml

from worker.db import SessionLocal, AuditData, Vulnerability
from modules.cve_lookup import CVELookup

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


def analyze_vulnerabilities(networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze networks for common Wi-Fi vulnerabilities."""
    cve_lookup = CVELookup()
    vulnerabilities = []
    config = _load_config()
    wifi_audits = config.get("wifi_audits", {})
    if not wifi_audits.get("enable_vulnerability_scan", False):
        return vulnerabilities

    scan_types = wifi_audits.get("scan_types", [])

    for net in networks:
        net_vulns = []
        ssid = net.get("ssid", "")
        bssid = net.get("bssid", "")
        encrypted = net.get("encrypted", False)

        if "open_networks" in scan_types and not encrypted:
            net_vulns.append({
                "type": "open_network",
                "description": "Open Wi-Fi network without encryption, vulnerable to data interception.",
                "severity": "high"
            })

        if "outdated_protocols" in scan_types:
            # Assume if encrypted but not specified, it's WPA2 or something
            # iwlist may not give detailed encryption
            if encrypted and "WEP" in str(net):  # Placeholder, iwlist may show
                net_vulns.append({
                    "type": "outdated_protocol",
                    "description": "Uses outdated WEP encryption, easily cracked.",
                    "severity": "critical"
                })

        if "weak_passwords" in scan_types:
            # Check for default SSIDs
            default_ssids = ["NETGEAR", "TP-Link", "Linksys", "D-Link", "ASUS", "Belkin"]
            if ssid in default_ssids:
                net_vulns.append({
                    "type": "weak_password",
                    "description": "Default SSID detected, likely default password.",
                    "severity": "high"
                })

        if "manufacturer_mac" in wifi_audits.get("captured_data_analysis", {}):
            # Get vendor from MAC
            vendor = get_vendor_from_mac(bssid)
            if vendor:
                # Query CVEs for vendor
                cves = cve_lookup.query_opencve_cves(vendor=vendor.lower(), limit=5)
                if cves:
                    net_vulns.append({
                        "type": "manufacturer_vulnerability",
                        "description": f"Manufacturer {vendor} has known CVEs: {len(cves)} found.",
                        "cves": cves,
                        "severity": "medium"
                    })
        
        # Phase 1: OSINT (WiGLE)
        # If configured, query WiGLE for geolocation/info
        if config.get("hash_services", {}).get("wigle", {}).get("enabled", False):
            # This would be an API call to WiGLE
            # Placeholder for now as we don't want to block too long
            pass

        if "exposed_services" in wifi_audits.get("captured_data_analysis", {}):
            # If open network, try to scan for open ports (placeholder, requires IP)
            if not encrypted:
                # Assume gateway IP or something, but hard
                net_vulns.append({
                    "type": "exposed_services",
                    "description": "Open network may expose services; recommend active scan for ports.",
                    "severity": "medium"
                })

        if "captive_portals" in wifi_audits.get("captured_data_analysis", {}):
            # If open and common SSID, assume captive portal
            if not encrypted and ssid:
                net_vulns.append({
                    "type": "captive_portal",
                    "description": "Potential captive portal on open network, vulnerable to data extraction.",
                    "severity": "medium"
                })

        if net_vulns:
            vulnerabilities.append({
                "network": net,
                "vulnerabilities": net_vulns
            })

    return vulnerabilities


def get_vendor_from_mac(mac: str) -> str:
    """Get vendor from MAC address using OUI."""
    if not mac or len(mac) < 8:
        return ""
    oui = mac.replace(":", "").upper()[:6]
    oui_db = {
        "001A11": "Google",
        "0022F1": "Netgear",
        "001E8F": "Cisco",
        "000C42": "Routerboard.com",
        "001122": "TP-Link",
        "0000F8": "Cisco",
        # Add more as needed
    }
    return oui_db.get(oui, "Unknown")


def _run_command(cmd: List[str], timeout: int = 30) -> str:
    """Run a command and return stdout, handling errors."""
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


def scan_networks(interface: str = "wlan0") -> List[Dict[str, Any]]:
    """
    Scan Wi-Fi networks using airodump-ng (passive, monitor mode).
    Phase 1: Passive Recon.
    """
    logger.info("Scanning Wi-Fi networks on interface %s using airodump-ng", interface)
    
    # Ensure monitor mode (simple check, assuming profile switcher handled it or we do it here)
    # For now, assume interface is already in monitor mode or we use a helper
    # But airodump-ng needs monitor mode.
    # Let's try to use the 'wifi_audit' profile assumption that wlan1 is monitor or wlan0 is free.
    # Actually, let's use a temporary csv file.
    
    import tempfile
    import csv
    import os
    
    # Create temp file prefix
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        temp_prefix = tmp.name
    
    # Run airodump-ng for a short duration
    # sudo airodump-ng --write-interval 1 --output-format csv -w /tmp/recon interface
    cmd = [
        "sudo", "airodump-ng",
        "--write-interval", "1",
        "--output-format", "csv",
        "-w", temp_prefix,
        interface
    ]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(15) # Scan for 15 seconds
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            
        # Parse CSV
        csv_file = f"{temp_prefix}-01.csv"
        if not os.path.exists(csv_file):
            logger.error("No CSV output found from airodump-ng")
            return []
            
        networks = []
        with open(csv_file, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            section = "AP"
            for row in reader:
                if not row or len(row) < 2:
                    continue
                
                if row[0].strip() == "Station MAC":
                    section = "CLIENT"
                    continue
                    
                if section == "AP":
                    # BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
                    if len(row) < 14:
                        continue
                    bssid = row[0].strip()
                    if bssid == "BSSID":
                        continue  # Header
                    
                    channel = row[3].strip()
                    privacy = row[5].strip()
                    cipher = row[6].strip()
                    auth = row[7].strip()
                    power = row[8].strip()
                    essid = row[13].strip()
                    
                    networks.append({
                        "bssid": bssid,
                        "ssid": essid,
                        "channel": int(channel) if channel.isdigit() else 0,
                        "encrypted": "WEP" in privacy or "WPA" in privacy,
                        "encryption_type": f"{privacy}/{cipher}/{auth}",
                        "signal": int(power) if power.lstrip('-').isdigit() else -100,
                        "clients": [] # To be populated if we parse clients
                    })

        # Cleanup
        for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
            f = f"{temp_prefix}{ext}"
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(temp_prefix):
            os.remove(temp_prefix)
            
        logger.info("Found %d networks via airodump-ng", len(networks))
        return networks

    except Exception as e:
        logger.error("Error running airodump-ng: %s", e)
        return []

def save_results(networks: List[Dict[str, Any]], job_id: int) -> None:
    """Save scan results to database."""
    vulnerabilities = analyze_vulnerabilities(networks)
    
    with SessionLocal() as session:
        # Store audit data
        for net in networks:
            audit_data = AuditData(
                job_id=job_id,
                data_type="wifi_network",
                data=net
            )
            session.add(audit_data)
        
        # Store vulnerabilities
        for vuln_entry in vulnerabilities:
            for vuln in vuln_entry["vulnerabilities"]:
                vulnerability = Vulnerability(
                    job_id=job_id,
                    vuln_type="wifi",
                    severity=vuln["severity"],
                    description=vuln["description"],
                    details=vuln.get("cves", {})
                )
                session.add(vulnerability)
        
        session.commit()
    
    # Also save to JSON for backward compatibility
    data = {
        "job_id": job_id,
        "timestamp": int(time.time()),
        "networks": networks,
        "vulnerabilities": vulnerabilities,
    }
    filename = f"wifi_recon_job_{job_id}.json"
    filepath = CAPTURES_DIR / filename
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Results saved to %s", filepath)
    except Exception as e:
        logger.error("Error saving results: %s", e)


def run(job) -> None:
    """Run Wi-Fi reconnaissance for the given job."""
    profile = job.profile or "default"
    logger.info("Starting Wi-Fi recon for job %s with profile %s", job.id, profile)
    try:
        networks = scan_networks()
        if networks:
            save_results(networks, job.id)
            logger.info("Wi-Fi recon completed for job %s", job.id)
        else:
            logger.warning("No networks found for job %s", job.id)
    except Exception as e:
        logger.error("Error in Wi-Fi recon for job %s: %s", job.id, e)
REQUIRED_PROFILE = "wifi_audit"
