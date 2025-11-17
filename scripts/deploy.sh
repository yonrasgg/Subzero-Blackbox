
#!/bin/bash
# Deploy script: development → production


set -e


DEV_DIR="/home/rayden/blackbox-dev"
PROD_DIR="/opt/blackbox"

echo "🚀 Starting deploy to production..."


# Check that we are on the main branch
cd "$DEV_DIR"
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "❌ Error: You must be on the 'main' branch to deploy"
    echo "   Current branch: $BRANCH"
    exit 1
fi


# Check that there are no uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "❌ Error: There are uncommitted changes"
    exit 1
fi


# Copy files to production (excluding .git and venv)
echo "📦 Copying files..."
rsync -av --delete \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='data/*.db' \
    --exclude='data/logs/*' \
    "$DEV_DIR/" "$PROD_DIR/"


# Restart services if they are running
if systemctl is-active --quiet blackbox-api; then
    echo "🔄 Restarting API service..."
    sudo systemctl restart blackbox-api
fi

if systemctl is-active --quiet blackbox-worker; then
    echo "🔄 Restarting Worker service..."
    sudo systemctl restart blackbox-worker
fi

echo "✅ Deploy completed successfully"
