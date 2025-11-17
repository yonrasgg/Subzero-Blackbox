#!/bin/bash
# Script de deploy: desarrollo → producción

set -e

DEV_DIR="/home/rayden/blackbox-dev"
PROD_DIR="/opt/blackbox"

echo "🚀 Iniciando deploy a producción..."

# Verificar que estamos en branch main
cd "$DEV_DIR"
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "❌ Error: Debes estar en branch 'main' para hacer deploy"
    echo "   Branch actual: $BRANCH"
    exit 1
fi

# Verificar que no hay cambios sin commitear
if ! git diff-index --quiet HEAD --; then
    echo "❌ Error: Hay cambios sin commitear"
    exit 1
fi

# Copiar archivos a producción (excluyendo .git y venv)
echo "📦 Copiando archivos..."
rsync -av --delete \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='data/*.db' \
    --exclude='data/logs/*' \
    "$DEV_DIR/" "$PROD_DIR/"

# Reiniciar servicios si están corriendo
if systemctl is-active --quiet blackbox-api; then
    echo "🔄 Reiniciando servicio API..."
    sudo systemctl restart blackbox-api
fi

if systemctl is-active --quiet blackbox-worker; then
    echo "🔄 Reiniciando servicio Worker..."
    sudo systemctl restart blackbox-worker
fi

echo "✅ Deploy completado exitosamente"
