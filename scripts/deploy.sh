#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$HOME/Subzero-Blackbox"
DEST_DIR="/opt/blackbox"

echo "[INFO] Syncing code from $SRC_DIR to $DEST_DIR ..."
sudo rsync -av \
  --delete \
  --exclude 'venv/' \
  --exclude '.git/' \
  --exclude '__pycache__/' \
  --exclude 'data/*.db*' \
  "$SRC_DIR/" "$DEST_DIR/"

echo "[INFO] Updating dependencies in production venv..."
cd "$DEST_DIR"
sudo ./venv/bin/pip install -r requirements.txt

echo "[INFO] Restarting systemd services..."
sudo systemctl restart blackbox-api.service
sudo systemctl restart blackbox-worker.service

echo "[OK] Deployment completed."
