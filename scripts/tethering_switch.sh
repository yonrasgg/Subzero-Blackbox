#!/usr/bin/env bash
set -euo pipefail


# Dynamically discover BASE_DIR (works in ~/blackbox-dev and /opt/blackbox)
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$BASE_DIR/data/logs"
LOG_FILE="$LOG_DIR/tethering_switch.log"

mkdir -p "$LOG_DIR"

log() {
  local level="$1"; shift
  local msg="$*"
  printf '%s [%s] [tethering_switch] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" | tee -a "$LOG_FILE"
}

# 🔐 This script does NOT self-elevate.
# If not root, it makes no changes and exits with a clear error.
if [ "$(id -u)" -ne 0 ]; then
  log "ERROR" "tethering_switch.sh must be run as root. Called as UID=$(id -u)."
  exit 1
fi

MODE="${1:-}"

if [ -z "$MODE" ]; then
  log "ERROR" "Usage: $0 <wifi|bluetooth|usb|off|status>"
  exit 1
fi

# Adjustable variables for your environment
WIFI_IFACE="${WIFI_IFACE:-wlan0}"
WIFI_SSID="${WIFI_SSID:-CHANGE_ME_SSID}"
WIFI_PSK="${WIFI_PSK:-CHANGE_ME_PASSWORD}"

BT_MAC="${BT_MAC:-AA:BB:CC:DD:EE:FF}"   # Phone MAC for PAN (adjust)
BT_IFACE="${BT_IFACE:-bnep0}"           # Expected PAN interface (adjust if different)

USB_IFACE="${USB_IFACE:-usb0}"          # USB tethering interface (adjust if different)

wifi_enable() {
  log "INFO" "Turning on Wi-Fi radio with nmcli..."
  if ! nmcli radio wifi on; then
    log "ERROR" "Could not enable Wi-Fi radio with nmcli."
    return 1
  fi

  nmcli dev disconnect "$WIFI_IFACE" >/dev/null 2>&1 || true

  if [ "$WIFI_SSID" = "CHANGE_ME_SSID" ]; then
    log "WARNING" "WIFI_SSID not set. Adjust WIFI_SSID/WIFI_PSK in the environment or in tethering_switch.sh."
    return 0
  fi

  log "INFO" "Connecting to SSID '$WIFI_SSID' on interface $WIFI_IFACE..."
  if ! nmcli dev wifi connect "$WIFI_SSID" password "$WIFI_PSK" ifname "$WIFI_IFACE"; then
    log "ERROR" "Failed to connect to SSID '$WIFI_SSID' via $WIFI_IFACE."
    return 1
  fi

  log "INFO" "Wi-Fi connection active on $WIFI_IFACE (NetworkManager manages the default route)."
}

wifi_disable() {
  log "INFO" "Turning off Wi-Fi radio with nmcli..."
  if ! nmcli radio wifi off; then
    log "WARNING" "Could not turn off Wi-Fi radio with nmcli."
    return 1
  fi
}

bt_pan_enable() {
  log "INFO" "Enabling Bluetooth PAN (skeleton)."
  log "INFO" "Expected peer MAC: $BT_MAC, expected PAN interface: $BT_IFACE"

  # Integrate your real commands here (bluez, nmcli, etc.)
  log "WARNING" "Implement the real commands here to connect Bluetooth PAN."
  log "WARNING" "Example (for reference, NOT executed here):"
  log "WARNING" "  bt-network -c \"$BT_MAC\" nap"
  log "WARNING" "  ip link set \"$BT_IFACE\" up"
}

bt_pan_disable() {
  log "INFO" "Disabling Bluetooth PAN (skeleton)."
  log "WARNING" "Add commands here to close the PAN connection and bring down the interface if needed."
}

usb_enable() {
  log "INFO" "Enabling USB tethering on interface $USB_IFACE."
  if ! ip link set "$USB_IFACE" up; then
    log "ERROR" "Could not bring up USB interface $USB_IFACE."
    return 1
  fi
  # Assuming DHCP or static IP is handled by NetworkManager or systemd-networkd
  log "INFO" "USB tethering enabled on $USB_IFACE (ensure DHCP client is running)."
}

usb_disable() {
  log "INFO" "Disabling USB tethering on interface $USB_IFACE."
  if ! ip link set "$USB_IFACE" down; then
    log "WARNING" "Could not bring down USB interface $USB_IFACE."
    return 1
  fi
}

case "$MODE" in
  wifi)
    log "INFO" "Switching internet_via -> Wi-Fi tethering (REAL)."
    wifi_enable
    ;;

  bluetooth)
    log "INFO" "Switching internet_via -> Bluetooth PAN (REAL-ish, requires implementation)."
    bt_pan_enable
    ;;

  usb)
    log "INFO" "Switching internet_via -> USB tethering."
    usb_enable
    ;;

  off)
    log "INFO" "Disabling Wi-Fi and Bluetooth PAN."
    wifi_disable || true
    bt_pan_disable || true
    ;;

  status)
    log "INFO" "Tethering status requested."
    nmcli -t -f WIFI,STATE g 2>/dev/null | while IFS= read -r line; do
      log "INFO" "nmcli general: $line"
    done
    nmcli dev status 2>/dev/null | while IFS= read -r line; do
      log "INFO" "nmcli dev status: $line"
    done
    ;;

  *)
    log "ERROR" "Unknown mode '$MODE'. Expected: wifi|bluetooth|usb|off|status."
    exit 1
    ;;
esac
