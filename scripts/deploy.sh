#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$HOME/Subzero-Blackbox"
DEST_DIR="/opt/blackbox"

echo "[INFO] Sincronizando código desde $SRC_DIR a $DEST_DIR ..."
sudo rsync -av \
  --delete \
  --exclude 'venv/' \
  --exclude '.git/' \
  --exclude '__pycache__/' \
  --exclude 'data/*.db*' \
  "$SRC_DIR/" "$DEST_DIR/"

echo "[INFO] Actualizando dependencias en venv de producción..."
cd "$DEST_DIR"
sudo ./venv/bin/pip install -r requirements.txt

echo "[INFO] Reiniciando servicios systemd..."
sudo systemctl restart blackbox-api.service
sudo systemctl restart blackbox-worker.service

echo "[OK] Despliegue completado."
