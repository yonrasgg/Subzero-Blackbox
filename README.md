# 🔐 Subzero-Blackbox

**Cyber-security Swiss Army Knife for Raspberry Pi Zero 2W**

*Wi-Fi/Bluetooth/USB HID Auditing System with AI-Powered Analysis*

[![Author](https://img.shields.io/badge/Author-Geovanny%20Alpizar%20S.-blue)](https://github.com/yonrasgg)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12+-blue)](https://python.org)

---

## 📋 Table of Contents

- [🎯 Overview](#-overview)
- [🏗️ Architecture](#️-architecture)
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📚 Documentation](#-documentation)
- [🔧 API Reference](#-api-reference)
- [🛠️ Development](#️-development)
- [📋 TODOs & Roadmap](#-todos--roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**Subzero-Blackbox** is a comprehensive cybersecurity auditing platform designed specifically for the Raspberry Pi Zero 2W. It combines passive and active reconnaissance capabilities with AI-powered analysis to provide security professionals and researchers with a powerful, portable auditing toolkit.

### 🎯 Mission
To democratize cybersecurity auditing by providing an affordable, powerful, and intelligent auditing platform that can be deployed anywhere with just a Raspberry Pi Zero 2W.

### 🔑 Key Capabilities
- **Wi-Fi Auditing**: Passive network scanning, vulnerability assessment, rogue AP detection
- **Bluetooth Auditing**: Device discovery, pairing analysis, security assessment
- **USB HID Auditing**: Device impersonation detection, malware delivery prevention
- **AI-Powered Analysis**: Machine learning-driven vulnerability correlation and reporting
- **Real-time Monitoring**: Hardware stats, API usage tracking, system health
- **Offline Operation**: No internet required for core auditing functions

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web UI        │    │   FastAPI       │    │   Worker        │
│   (HTML/Jinja)  │◄──►│   Backend       │◄──►│   Engine        │
│                 │    │                 │    │                 │
│ - Dashboard     │    │ - REST API      │    │ - Job Queue     │
│ - Configuration │    │ - WebSocket     │    │ - Profile Mgmt  │
│ - Logs          │    │ - Auth          │    │ - Module Exec   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   SQLite DB     │
                    │                 │
                    │ - Jobs          │
                    │ - Audit Data    │
                    │ - Vulnerabilities│
                    │ - ML Training   │
                    └─────────────────┘
```

### 🏛️ Core Components

#### **1. Web Interface**
- **Framework**: HTML5 + Bulma CSS + Jinja2 Templates
- **Pages**: Dashboard, Configuration, Audits, Logs, Reports
- **Real-time**: Hardware monitoring, job status updates

#### **2. API Backend**
- **Framework**: FastAPI (ASGI)
- **Authentication**: HTTP Basic Auth
- **Endpoints**: RESTful API for all operations
- **Documentation**: Auto-generated OpenAPI/Swagger

#### **3. Worker Engine**
- **Architecture**: Producer-Consumer pattern
- **Job Types**: Wi-Fi recon, BT recon, USB HID audit, Hash cracking
- **Profile Management**: Dynamic system configuration switching
- **Error Handling**: Comprehensive logging and recovery

#### **4. Audit Modules**
- **Wi-Fi**: Passive scanning, vulnerability analysis, CVE correlation
- **Bluetooth**: Device enumeration, security assessment
- **USB HID**: Device impersonation detection, firmware analysis
- **Hash Operations**: Multi-service cracking integration

#### **5. Database Layer**
- **Engine**: SQLite with SQLAlchemy ORM
- **Tables**: Jobs, Runs, AuditData, Vulnerabilities, ProfileLogs
- **ML Integration**: Structured data for AI training

---

## ✨ Features

### 🔍 **Auditing Capabilities**

#### **Wi-Fi Auditing**
- ✅ Passive network scanning (iwlist/nmcli)
- ✅ Vulnerability assessment (WEP, WPA, open networks)
- ✅ Rogue AP detection
- ✅ Manufacturer MAC analysis
- ✅ Captive portal identification
- ✅ CVE correlation via multiple APIs

#### **Bluetooth Auditing**
- ✅ Device discovery and enumeration
- ✅ Pairing vulnerability analysis
- ✅ Service discovery assessment
- ✅ Bluejacking/BlueSnarfing detection
- ✅ DoS attack simulation

#### **USB HID Auditing**
- ✅ Keyboard emulation detection
- ✅ Network adapter spoofing prevention
- ✅ Malware delivery interception
- ✅ Firmware analysis
- ✅ Data exfiltration monitoring

### 🤖 **AI & Machine Learning**

#### **Current Implementation**
- 🔄 AI Assistant with personality (Rayden/Subzero)
- 🔄 API usage tracking for ML training
- 🔄 Structured audit data collection

#### **Planned Features**
- 📋 Intelligent vulnerability correlation
- 📋 Predictive threat analysis
- 📋 Automated report generation
- 📋 Behavioral pattern recognition

### 📊 **Monitoring & Analytics**

#### **Real-time Dashboard**
- 📈 Hardware statistics (CPU, RAM, Battery)
- 📈 Job queue status
- 📈 Active profile monitoring
- 📈 API usage metrics

#### **Comprehensive Logging**
- 📝 Job execution logs
- 📝 Vulnerability findings
- 📝 Audit data collection
- 📝 Profile change history
- 📝 System events

### 🔧 **System Management**

#### **Profile System**
- 🔄 Stealth Recon: Minimal footprint scanning
- 🔄 Aggressive Recon: Active testing and exploitation
- 🔄 Wi-Fi Audit: Wireless security assessment
- 🔄 Bluetooth Audit: BT security evaluation
- 🔄 USB Audit: HID device analysis

#### **Dual Tethering**
- 📡 Wi-Fi Hotspot mode
- 📡 Bluetooth PAN mode
- 📡 Automatic failover
- 📡 Internet connectivity management

---

## 🚀 Quick Start

### 📦 **Prerequisites**
- Raspberry Pi Zero 2W (or compatible)
- MicroSD card (32GB+ recommended)
- USB Wi-Fi adapter (optional, for extended range)
- Bluetooth adapter (optional, for BT auditing)

### 🛠️ **Installation**

#### **Automated Setup (Recommended)**
```bash
# Clone the repository
git clone https://github.com/yonrasgg/subzero-blackbox.git
cd subzero-blackbox

# Run installation script (installs everything automatically)
sudo ./scripts/install.sh
```

The installation script will:
- ✅ Install all required system dependencies
- ✅ Create production environment at `/opt/blackbox`
- ✅ Set up Python virtual environment
- ✅ Install Python dependencies
- ✅ Initialize the database
- ✅ Create systemd services for auto-start
- ✅ Configure API keys template
- ✅ Start the services automatically

After installation, you'll need to:
1. **Configure your API keys**: `sudo nano /opt/blackbox/config/secrets.yaml`
2. **Access the web interface**: `http://[YOUR_RPI_IP]:8010/ui/home`

#### **Manual Setup (Advanced Users Only)**
If you prefer manual installation or need custom configuration:

```bash
# Install system dependencies
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    sqlite3 wireless-tools iw bluetooth bluez-tools \
    usbutils net-tools curl git rsync

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Initialize database
python scripts/init_db.py

# Configure API keys
cp config/secrets.yaml.example config/secrets.yaml
# Edit with your API keys: nano config/secrets.yaml
```

### ⚙️ **Configuration**

#### **Basic Configuration** (`config/config.yaml`)
```yaml
environment: dev
raspi_id: subzero
ui:
  username: admin
  password: change-this

wifi_audits:
  enable_vulnerability_scan: true
  scan_types:
    - open_networks
    - weak_passwords
    - outdated_protocols

bt_audits:
  enable_vulnerability_scan: true
  scan_types:
    - bluejacking
    - pairing_vulnerabilities

usb_audits:
  enable_vulnerability_scan: true
  scan_types:
    - keyboard_emulation
    - malware_delivery
```

#### **API Keys** (`config/secrets.yaml` or `/opt/blackbox/config/secrets.yaml`)
```yaml
# Subzero-Blackbox API Keys Configuration
# Please fill in your API keys below

# Google Gemini AI API (for AI Assistant)
google_api_key: "your_google_gemini_api_key_here"

# OnlineHashCrack API (for hash cracking)
onlinehashcrack_api_key: "your_onlinehashcrack_api_key_here"

# WiGLE API (for wireless network database)
wigle_api_name: "your_wigle_username"
wigle_api_token: "your_wigle_api_token"

# WPA Security API (for WPA vulnerability analysis)
wpasec_api_key: "your_wpasec_api_key_here"
```

**Required API Keys:**
- **Google Gemini API**: Get from [Google AI Studio](https://makersuite.google.com/app/apikey)
- **OnlineHashCrack API**: Get from [OnlineHashCrack](https://onlinehashcrack.com/)
- **WiGLE API**: Get from [WiGLE](https://wigle.net/) (free account required)
- **WPA Security API**: Get from [WPA-Sec](https://wpa-sec.stanev.org/) (free API)

### ▶️ **Running the System**

#### **After Automated Installation**
The installation script automatically:
- Creates systemd services (`blackbox-api.service`, `blackbox-worker.service`)
- Enables auto-start on boot
- Starts services immediately

```bash
# Check service status
sudo systemctl status blackbox-api blackbox-worker

# View logs
sudo journalctl -u blackbox-api -f

# Access web interface
# URL: http://[YOUR_RPI_IP]:8010/ui/home
# Default credentials: admin / change-this
```

#### **Manual Startup (Development)**
```bash
# Activate virtual environment
source venv/bin/activate

# Start API server (development)
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Start worker engine (in another terminal)
python worker/engine.py

# Access at: http://localhost:8000
```

---

## 📚 Documentation

### 📖 **User Guides**

#### **Wi-Fi Auditing**
1. Navigate to "Audits Configuration"
2. Enable Wi-Fi vulnerability scanning
3. Select scan types (open networks, weak passwords, etc.)
4. Start Wi-Fi audit from dashboard
5. Review results in logs section

#### **Bluetooth Auditing**
1. Switch to Bluetooth audit profile
2. Configure BT scan parameters
3. Start BT audit job
4. Analyze discovered devices and vulnerabilities

#### **USB HID Auditing**
1. Connect USB devices to test
2. Configure HID audit parameters
3. Run USB audit
4. Monitor for impersonation attempts

### 🔧 **API Documentation**

#### **Core Endpoints**

##### **Health Check**
```http
GET /health
```
Returns system health status.

##### **Hardware Monitoring**
```http
GET /api/hardware
```
Returns real-time CPU, memory, and battery statistics.

##### **AI Assistant**
```http
GET /api/ai_assistant
```
Returns AI assistant status and messages.

##### **Job Management**
```http
POST /jobs
GET /jobs
GET /jobs/{id}
```

##### **Vulnerability Scanning**
```http
GET /api/cves
POST /api/parse_embedded
```

### 🗂️ **File Structure**
```
subzero-blackbox/
├── api/                    # FastAPI backend
│   ├── main.py            # Main API application
│   ├── schemas.py         # Pydantic models
│   └── templates/         # Jinja2 templates
├── worker/                # Worker engine
│   ├── engine.py          # Job processing engine
│   ├── db.py              # Database models
│   └── report_generator.py # Report generation
├── modules/               # Audit modules
│   ├── wifi_recon.py      # Wi-Fi reconnaissance
│   ├── bt_recon.py        # Bluetooth scanning
│   ├── usb_hid.py         # USB HID analysis
│   └── hash_ops.py        # Hash cracking
├── config/                # Configuration files
│   ├── config.yaml        # Main configuration
│   ├── profiles.yaml      # System profiles
│   └── secrets.yaml       # API keys (gitignored)
├── scripts/               # Utility scripts
│   ├── install.sh         # Installation script
│   ├── init_db.py         # Database initialization
│   └── profile_switcher.py # Profile management
├── data/                  # Runtime data
│   ├── blackbox.db        # SQLite database
│   ├── logs/              # System logs
│   └── captures/          # Packet captures
└── requirements.txt       # Python dependencies
```

---

## 🔧 API Reference

### 🌐 **REST API Endpoints**

#### **System Management**
- `GET /health` - Health check
- `GET /api/hardware` - Hardware statistics
- `GET /api/ai_assistant` - AI assistant status

#### **Job Management**
- `POST /jobs` - Create new job
- `GET /jobs` - List all jobs
- `GET /jobs/{id}` - Get job details

#### **Auditing APIs**
- `GET /api/cves` - Query CVE databases
- `POST /api/parse_embedded` - Parse embedded vulnerabilities

#### **Web Interface**
- `GET /ui/home` - Home page
- `GET /ui/dashboard` - Main dashboard
- `GET /ui/config` - Configuration page
- `GET /ui/audits_config` - Audit configuration
- `GET /ui/logs` - Activity logs
- `GET /ui/jobs/{id}` - Job details
- `GET /ui/jobs/{id}/report` - Job report

### 📊 **Data Models**

#### **Job**
```python
{
  "id": 1,
  "type": "wifi_recon",
  "profile": "wifi_audit",
  "status": "finished",
  "params": {"interface": "wlan0"},
  "created_at": "2025-11-17T10:00:00Z"
}
```

#### **Vulnerability**
```python
{
  "id": 1,
  "job_id": 1,
  "vuln_type": "wifi",
  "severity": "high",
  "description": "Open Wi-Fi network detected",
  "details": {"cves": ["CVE-2023-12345"]}
}
```

#### **AuditData**
```python
{
  "id": 1,
  "job_id": 1,
  "data_type": "wifi_network",
  "data": {
    "ssid": "OpenNetwork",
    "bssid": "00:11:22:33:44:55",
    "encrypted": false
  }
}
```

---

## 🛠️ Development

### 🏃 **Running in Development**

#### **API Server**
```bash
cd /home/pi/subzero-blackbox
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

#### **Worker Engine**
```bash
source venv/bin/activate
python worker/engine.py
```

#### **Database Management**
```bash
# Initialize/reset database
python scripts/init_db.py

# View database
sqlite3 data/blackbox.db
.schema
```

### 🧪 **Testing**

#### **API Testing**
```bash
# Health check
curl http://localhost:8000/health

# Hardware stats
curl http://localhost:8000/api/hardware

# API documentation
open http://localhost:8000/docs
```

#### **Module Testing**
```bash
# Test Wi-Fi scanning
python -c "from modules.wifi_recon import scan_networks; print(scan_networks())"

# Test BT scanning
python -c "from modules.bt_recon import scan_devices; print(scan_devices())"
```

### 🔍 **Debugging**

#### **Enable Debug Logging**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

#### **Database Inspection**
```bash
# Connect to database
sqlite3 data/blackbox.db

# View recent jobs
SELECT * FROM jobs ORDER BY created_at DESC LIMIT 5;

# View vulnerabilities
SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT 10;
```

---

## 📋 TODOs & Roadmap

### 🚀 **Phase 1: Core Auditing (Current)**
- ✅ Wi-Fi passive reconnaissance
- ✅ Bluetooth device discovery
- ✅ USB HID basic auditing
- ✅ Web UI with real-time monitoring
- ✅ Database integration
- ✅ Profile management system
- ✅ Basic vulnerability scanning

### 🚀 **Phase 2: Advanced Features (Next)**
- 🔄 **Active Wi-Fi Testing**
  - Deauthentication attacks
  - Evil twin AP creation
  - WPA handshake capture
  - Password cracking integration

- 🔄 **Bluetooth Exploitation**
  - BlueBorne vulnerability scanning
  - Pairing attack simulation
  - Device takeover capabilities

- 🔄 **USB HID Advanced**
  - Rubber Ducky script analysis
  - BadUSB firmware detection
  - Custom payload development

- 🔄 **AI/ML Integration**
  - Vulnerability pattern recognition
  - Automated report generation
  - Predictive threat analysis
  - Behavioral anomaly detection

### 🚀 **Phase 3: Enterprise Features (Future)**
- 📋 **Distributed Auditing**
  - Multi-device coordination
  - Mesh network support
  - Cloud synchronization

- 📋 **Advanced Reporting**
  - Executive summaries
  - Compliance reporting (PCI-DSS, HIPAA)
  - Historical trend analysis

- 📋 **Integration APIs**
  - SIEM integration
  - Ticketing system hooks
  - Alert management

- 📋 **Hardware Expansion**
  - GPS module integration
  - LTE/5G connectivity
  - Extended battery life
  - Environmental sensors

### 🔧 **Technical Debt & Improvements**
- 📋 **Performance Optimization**
  - Async job processing
  - Database query optimization
  - Memory usage optimization
  - Battery life improvements

- 📋 **Security Hardening**
  - Encrypted database storage
  - Secure API key management
  - Audit trail integrity
  - Network traffic encryption

- 📋 **Code Quality**
  - Comprehensive test suite
  - CI/CD pipeline
  - Code documentation
  - Type hints everywhere

### 🎯 **Immediate Next Steps**
1. **Complete Active Wi-Fi Testing** - Implement deauth and evil twin capabilities
2. **AI Model Training** - Start collecting data for ML model development
3. **Report Generation** - Create automated report templates
4. **API Key Management** - Improve secrets handling and rotation
5. **Performance Monitoring** - Add detailed performance metrics

---

## 🤝 Contributing

### 💡 **How to Contribute**

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Add tests if applicable**
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to the branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### 📝 **Development Guidelines**

#### **Code Style**
- Follow PEP 8 Python style guide
- Use type hints for all function parameters
- Add docstrings to all functions and classes
- Keep functions small and focused

#### **Commit Messages**
- Use conventional commits format
- Start with type: `feat:`, `fix:`, `docs:`, `refactor:`
- Keep first line under 50 characters
- Add detailed description if needed

#### **Testing**
- Write unit tests for new functionality
- Test on actual Raspberry Pi hardware
- Verify backward compatibility

### 🐛 **Reporting Issues**

When reporting bugs, please include:
- Raspberry Pi model and OS version
- Steps to reproduce the issue
- Expected vs actual behavior
- Relevant log output
- System configuration

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Geovanny Alpizar S.

Permission is granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

### 👨‍💻 **Author**
**Geovanny Alpizar S.** ([@yonrasgg](https://github.com/yonrasgg))
- Cybersecurity enthusiast and developer
- Raspberry Pi and embedded systems specialist
- Open source security tools contributor

### 🔬 **Inspiration**
- **Kali Linux** - For the comprehensive toolset approach
- **Wireshark** - For packet analysis inspiration
- **Aircrack-ng** - For Wi-Fi auditing methodology
- **Bettercap** - For network manipulation techniques

### 📚 **Resources**
- **OWASP** - Web application security guidelines
- **NIST** - Cybersecurity framework
- **MITRE ATT&CK** - Adversarial tactics knowledge base
- **CVE Details** - Vulnerability database

### 🤝 **Community**
Special thanks to the cybersecurity community for their invaluable contributions to open source security tools and knowledge sharing.

---

## 📞 Contact

**Geovanny Alpizar S.**
- **GitHub**: [@yonrasgg](https://github.com/yonrasgg)

---

*Built with ❤️ for the cybersecurity community on Raspberry Pi Zero 2W*
