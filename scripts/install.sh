#!/usr/bin/env bash
set -euo pipefail

# Subzero-Blackbox Installation Script
# Cyber-security Swiss Army Knife for lowspec computing cards or boards
# Features: Wi-Fi/Bluetooth/USB Auditing + AI-Powered Analysis + Cyberpunk UI
# Author: Geovanny Alpizar S. (yonrasgg)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PROD_DIR="/opt/blackbox"
VENV_DIR="$PROD_DIR/venv"
DATA_DIR="$PROD_DIR/data"
CONFIG_DIR="$PROD_DIR/config"
SCRIPTS_DIR="$PROD_DIR/scripts"
EXAMPLES_DIR="$PROD_DIR/examples"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Get current user
CURRENT_USER=$(whoami)

# Functions
print_header() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}  🔐 Subzero-Blackbox Installation Script${NC}"
    echo -e "${CYAN}  🎯 Cyber-security Swiss Army Knife${NC}"
    echo -e "${CYAN}  ⚡ Wi-Fi/BT/USB Auditing + AI Analysis${NC}"
    echo -e "${CYAN}  🎮 Cyberpunk UI with AI Character Battles${NC}"
    echo -e "${CYAN}  Author: Geovanny Alpizar S. (yonrasgg)${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should NOT be run as root. Please run as regular user with sudo access."
        exit 1
    fi
}

check_raspberry_pi() {
    if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
        print_warning "This doesn't appear to be a Raspberry Pi. Installation may not work correctly."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

install_system_dependencies() {
    print_step "Installing system dependencies..."

    # Update package list
    sudo apt update

    # Install required packages
    sudo apt install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        libffi-dev \
        libssl-dev \
        rsync \
        curl \
        git \
        wireless-tools \
        iw \
        bluetooth \
        bluez-tools \
        aircrack-ng \
        usbutils \
        net-tools \
        sqlite3

    print_success "System dependencies installed"
}

create_directories() {
    print_step "Creating production directories..."

    # Create main directory
    sudo mkdir -p "$PROD_DIR"
    sudo chown -R "$CURRENT_USER:$CURRENT_USER" "$PROD_DIR"

    # Create subdirectories
    mkdir -p "$DATA_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$SCRIPTS_DIR"
    mkdir -p "$EXAMPLES_DIR"

    print_success "Directories created"
}

setup_virtual_environment() {
    print_step "Setting up Python virtual environment..."

    # Create virtual environment
    python3 -m venv "$VENV_DIR"

    # Activate and upgrade pip
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip

    print_success "Virtual environment created at $VENV_DIR"
}

install_python_dependencies() {
    print_step "Installing Python dependencies..."

    # Activate virtual environment
    source "$VENV_DIR/bin/activate"

    # Install requirements
    if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
        pip install -r "$PROJECT_ROOT/requirements.txt"
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found at $PROJECT_ROOT/requirements.txt"
        exit 1
    fi
}

download_ai_models() {
    print_step "Downloading AI models (this may take a few minutes)..."

    # Activate virtual environment
    source "$VENV_DIR/bin/activate"

    # Change to production directory
    cd "$PROD_DIR"

    # Download AI models by importing them
    echo "Downloading MiniLM-L6 model..."
    python3 -c "
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
print('✅ MiniLM-L6 model downloaded')
" 2>/dev/null || print_warning "MiniLM-L6 download failed - will download on first use"

    echo "Downloading ALBERT-tiny model..."
    python3 -c "
from transformers import pipeline
classifier = pipeline('text-classification', model='albert-base-v2')
print('✅ ALBERT-tiny model downloaded')
" 2>/dev/null || print_warning "ALBERT-tiny download failed - will download on first use"

    print_success "AI models download completed"
}

copy_project_files() {
    print_step "Copying project files to production directory..."

    # Copy files excluding development artifacts
    rsync -av \
        --exclude 'venv/' \
        --exclude '.git/' \
        --exclude '__pycache__/' \
        --exclude '*.pyc' \
        --exclude '.pytest_cache/' \
        --exclude 'data/*.db*' \
        --exclude 'config/secrets.yaml' \
        "$PROJECT_ROOT/" "$PROD_DIR/"

    print_success "Project files copied to $PROD_DIR"
}

initialize_database() {
    print_step "Initializing database..."

    # Activate virtual environment
    source "$VENV_DIR/bin/activate"

    # Initialize database
    cd "$PROD_DIR"
    python scripts/init_db.py

    print_success "Database initialized at $DATA_DIR/blackbox.db"
}

create_systemd_services() {
    print_step "Creating systemd services..."

    # Create API service
    cat > /tmp/blackbox-api.service << EOF
[Unit]
Description=Blackbox API (FastAPI + Uvicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$PROD_DIR

Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"

ExecStart=$VENV_DIR/bin/uvicorn api.main:app \\
  --host 0.0.0.0 \\
  --port 8010 \\
  --workers 1 \\
  --proxy-headers

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create Worker service
    cat > /tmp/blackbox-worker.service << EOF
[Unit]
Description=Blackbox Worker (Job queue processor)
After=network-online.target blackbox-api.service
Wants=network-online.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$PROD_DIR

Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"

ExecStart=$VENV_DIR/bin/python -m worker.engine

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Install services
    sudo mv /tmp/blackbox-api.service /etc/systemd/system/
    sudo mv /tmp/blackbox-worker.service /etc/systemd/system/

    # Reload systemd
    sudo systemctl daemon-reload

    print_success "Systemd services created"
}

create_config_files() {
    print_step "Creating configuration files..."

    if [ -f "$CONFIG_DIR/secrets.yaml" ]; then
        print_warning "$CONFIG_DIR/secrets.yaml already exists. Skipping creation to preserve keys."
    else
        # Create secrets.yaml template with new structure
        cat > "$CONFIG_DIR/secrets.yaml" << 'EOF'
# Subzero-Blackbox API Keys Configuration
# Please fill in your API keys below

# APIs section (required by modules)
apis:
  google_api_key: "your_google_gemini_api_key_here"
  onlinehashcrack_api_key: "your_onlinehashcrack_api_key_here"
  wigle_api_name: "your_wigle_username"
  wigle_api_token: "your_wigle_api_token"
  wpasec_api_key: "your_wpasec_api_key_here"

# Direct keys (for compatibility)
google_api_key: "your_google_gemini_api_key_here"
onlinehashcrack_api_key: "your_onlinehashcrack_api_key_here"
wigle_api_name: "your_wigle_username"
wigle_api_token: "your_wigle_api_token"
wpasec_api_key: "your_wpasec_api_key_here"
EOF

        print_warning "Created $CONFIG_DIR/secrets.yaml - You MUST edit this file with your API keys!"
    fi
}

start_services() {
    print_step "Starting services..."

    # Enable and start services
    sudo systemctl enable blackbox-api.service
    sudo systemctl enable blackbox-worker.service

    sudo systemctl start blackbox-api.service
    sudo systemctl start blackbox-worker.service

    # Wait a moment for services to start
    sleep 3

    print_success "Services started"
}

verify_installation() {
    print_step "Verifying installation..."

    # Check if services are running
    if sudo systemctl is-active --quiet blackbox-api.service; then
        print_success "API service is running"
    else
        print_error "API service failed to start"
        return 1
    fi

    if sudo systemctl is-active --quiet blackbox-worker.service; then
        print_success "Worker service is running"
    else
        print_error "Worker service failed to start"
        return 1
    fi

    # Test API health
    if curl -s http://127.0.0.1:8010/health > /dev/null; then
        print_success "API health check passed"
    else
        print_error "API health check failed"
        return 1
    fi

    # Test dialogue system
    if curl -s http://127.0.0.1:8010/api/ai/dialogue/stats > /dev/null; then
        print_success "AI dialogue system operational"
    else
        print_warning "AI dialogue system not responding (may be loading models)"
    fi

    # Check if AI models are available
    if [ -d "$HOME/.cache/huggingface" ] || [ -d "$PROD_DIR/.cache" ]; then
        print_success "AI models cache directory found"
    else
        print_warning "AI models not cached yet (will download on first use)"
    fi

    print_success "Installation verification completed"
}

show_post_installation_info() {
    echo
    echo -e "${CYAN}================================================${NC}"
    echo -e "${GREEN}  🎉 Installation Complete!${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo
    echo -e "${MAGENTA}🎮 NEW FEATURES INSTALLED:${NC}"
    echo -e "${CYAN}  • Cyberpunk Terminal UI with neon effects${NC}"
    echo -e "${CYAN}  • AI Character Dialogue System (English)${NC}"
    echo -e "${CYAN}  • Subzero ❄️ vs Rayden ⚡ personality battles${NC}"
    echo -e "${CYAN}  • 30 contextual dialogues for different scenarios${NC}"
    echo -e "${CYAN}  • Offline AI models (MiniLM-L6, ALBERT-tiny)${NC}"
    echo
    echo -e "${YELLOW}🔑 IMPORTANT: Configure your API keys${NC}"
    echo "Edit the following file with your API keys:"
    echo "  sudo nano $CONFIG_DIR/secrets.yaml"
    echo
    echo -e "${YELLOW}Required API Keys:${NC}"
    echo "• Google Gemini API: https://makersuite.google.com/app/apikey"
    echo "• OnlineHashCrack API: https://onlinehashcrack.com/"
    echo "• WiGLE API: https://wigle.net/"
    echo "• WPA Security API: https://wpa-sec.stanev.org/"
    echo
    echo -e "${YELLOW}🌐 Access your Blackbox:${NC}"
    echo "• Web UI: http://$(hostname -I | awk '{print $1}'):8010/ui/home"
    echo "• API Docs: http://$(hostname -I | awk '{print $1}'):8010/docs"
    echo "• Dialogue Demo: http://$(hostname -I | awk '{print $1}'):8010/api/ai/dialogue?context=boot"
    echo
    echo -e "${YELLOW}🎭 Try the AI Characters:${NC}"
    echo "• Subzero (❄️): Precise, methodical AI assistant"
    echo "• Rayden (⚡): Dynamic, sarcastic AI assistant"
    echo "• Watch them 'battle' during security audits!"
    echo
    echo -e "${YELLOW}⚙️ Service Management:${NC}"
    echo "• Check status: sudo systemctl status blackbox-api blackbox-worker"
    echo "• View logs: sudo journalctl -u blackbox-api -f"
    echo "• Restart: sudo systemctl restart blackbox-api blackbox-worker"
    echo
    echo -e "${GREEN}🚀 Enjoy your Cyberpunk Subzero-Blackbox!${NC}"
    echo -e "${CYAN}================================================${NC}"
}

main() {
    print_header

    check_root
    check_raspberry_pi

    echo "This script will install Subzero-Blackbox on your Raspberry Pi."
    echo "It will:"
    echo "• Install system dependencies (Python, Bluetooth, WiFi tools)"
    echo "• Create production environment at $PROD_DIR"
    echo "• Set up Python virtual environment with AI models"
    echo "• Download AI models (MiniLM-L6, ALBERT-tiny) for offline operation"
    echo "• Install Python dependencies (FastAPI, PyTorch, transformers)"
    echo "• Initialize database with 30 English dialogues"
    echo "• Create systemd services for auto-start"
    echo "• Set up cyberpunk UI with character battle arena"
    echo "• Start the services automatically"
    echo
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    install_system_dependencies
    create_directories
    setup_virtual_environment
    install_python_dependencies
    download_ai_models
    copy_project_files
    initialize_database
    create_systemd_services
    create_config_files
    start_services

    if verify_installation; then
        show_post_installation_info
    else
        print_error "Installation completed with errors. Please check the logs above."
        exit 1
    fi
}

# Run main function
main "$@"