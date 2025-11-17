#!/usr/bin/env bash
set -euo pipefail

# Descubrir BASE_DIR dinámicamente (sirve en ~/blackbox-dev y /opt/blackbox)
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$BASE_DIR/data/logs"
LOG_FILE="$LOG_DIR/tethering_switch.log"

mkdir -p "$LOG_DIR"

log() {
  local level="$1"; shift
  local msg="$*"
  printf '%s [%s] [tethering_switch] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" | tee -a "$LOG_FILE"
}

# 🔐 Este script NO se auto-eleva.
# Si no es root, no hace cambios y sale con error claro.
if [ "$(id -u)" -ne 0 ]; then
  log "ERROR" "tethering_switch.sh debe ejecutarse como root. Llamado como UID=$(id -u)."
  exit 1
fi

MODE="${1:-}"

if [ -z "$MODE" ]; then
  log "ERROR" "Usage: $0 <wifi|bluetooth|off|status>"
  exit 1
fi

# Variables ajustables para tu entorno
WIFI_IFACE="${WIFI_IFACE:-wlan0}"
WIFI_SSID="${WIFI_SSID:-CHANGE_ME_SSID}"
WIFI_PSK="${WIFI_PSK:-CHANGE_ME_PASSWORD}"

BT_MAC="${BT_MAC:-AA:BB:CC:DD:EE:FF}"   # MAC del teléfono para PAN (ajusta)
BT_IFACE="${BT_IFACE:-bnep0}"           # Interfaz PAN esperada (ajusta si difiere)

wifi_enable() {
  log "INFO" "Encendiendo radio Wi-Fi con nmcli..."
  if ! nmcli radio wifi on; then
    log "ERROR" "No se pudo habilitar la radio Wi-Fi con nmcli."
    return 1
  fi

  nmcli dev disconnect "$WIFI_IFACE" >/dev/null 2>&1 || true

  if [ "$WIFI_SSID" = "CHANGE_ME_SSID" ]; then
    log "WARNING" "WIFI_SSID no configurado. Ajusta WIFI_SSID/WIFI_PSK en el entorno o en tethering_switch.sh."
    return 0
  fi

  log "INFO" "Conectando a SSID '$WIFI_SSID' en interfaz $WIFI_IFACE..."
  if ! nmcli dev wifi connect "$WIFI_SSID" password "$WIFI_PSK" ifname "$WIFI_IFACE"; then
    log "ERROR" "Fallo al conectar al SSID '$WIFI_SSID' vía $WIFI_IFACE."
    return 1
  fi

  log "INFO" "Conexión Wi-Fi activa en $WIFI_IFACE (NetworkManager gestiona la ruta por defecto)."
}

wifi_disable() {
  log "INFO" "Desactivando radio Wi-Fi con nmcli..."
  if ! nmcli radio wifi off; then
    log "WARNING" "No se pudo desactivar la radio Wi-Fi con nmcli."
    return 1
  fi
}

bt_pan_enable() {
  log "INFO" "Activando Bluetooth PAN (esqueleto)."
  log "INFO" "MAC esperada del peer: $BT_MAC, interfaz PAN esperada: $BT_IFACE"

  # Aquí debes integrar tus comandos reales (bluez, nmcli, etc.)
  log "WARNING" "Implementar aquí los comandos reales para conectar el PAN Bluetooth."
  log "WARNING" "Ejemplo (a modo de referencia, NO se ejecuta aquí):"
  log "WARNING" "  bt-network -c \"$BT_MAC\" nap"
  log "WARNING" "  ip link set \"$BT_IFACE\" up"
}

bt_pan_disable() {
  log "INFO" "Desactivando Bluetooth PAN (esqueleto)."
  log "WARNING" "Agregar aquí comandos para cerrar la conexión PAN y bajar la interfaz si procede."
}

case "$MODE" in
  wifi)
    log "INFO" "Switching internet_via -> Wi-Fi tethering (REAL)."
    wifi_enable
    ;;

  bluetooth)
    log "INFO" "Switching internet_via -> Bluetooth PAN (REAL-ish, requiere implementación)."
    bt_pan_enable
    ;;

  off)
    log "INFO" "Deshabilitando Wi-Fi y Bluetooth PAN."
    wifi_disable || true
    bt_pan_disable || true
    ;;

  status)
    log "INFO" "Status de tethering solicitado."
    nmcli -t -f WIFI,STATE g 2>/dev/null | while IFS= read -r line; do
      log "INFO" "nmcli general: $line"
    done
    nmcli dev status 2>/dev/null | while IFS= read -r line; do
      log "INFO" "nmcli dev status: $line"
    done
    ;;

  *)
    log "ERROR" "Modo desconocido '$MODE'. Esperado: wifi|bluetooth|off|status."
    exit 1
    ;;
esac
