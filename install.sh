#!/usr/bin/env bash
# ==============================================================================
# RootScan v1.0 Installation Script
# Automated environment, dependency, and security tool installer
# Supported: Kali Linux, Ubuntu, Debian
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
  ____             _   ____                  
 |  _ \ ___   ___ | |_/ ___|  ___ __ _ _ __  
 | |_) / _ \ / _ \| __\___ \ / __/ _` | '_ \ 
 |  _ < (_) | (_) | |_ ___) | (_| (_| | | | |
 |_| \_\___/ \___/ \__|____/ \___\\__,_|_| |_|
EOF
echo -e "${NC}"
echo -e "${GREEN}==> RootScan v1.0 Automated Installer <==${NC}\n"

# 1. Detect OS & Package Manager
echo -e "${BLUE}[*] Detecting Operating System...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$NAME
    echo -e "    Detected OS: ${YELLOW}$OS_NAME${NC}"
else
    echo -e "${RED}[!] Unable to detect OS from /etc/os-release.${NC}"
    exit 1
fi

# 2. Check Python version
echo -e "\n${BLUE}[*] Checking Python installation...${NC}"
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo -e "    Python version: ${YELLOW}$PY_VER${NC}"
else
    echo -e "${RED}[!] python3 is not installed. Please install Python 3.11+.${NC}"
    exit 1
fi

# 3. Install System Security Tools
echo -e "\n${BLUE}[*] Checking and installing system security tools...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    echo -e "    Updating apt package index..."
    sudo apt-get update -qq || true
    echo -e "    Installing standard tools (nmap, whatweb, git, curl)..."
    sudo apt-get install -y -qq nmap whatweb git curl python3-venv python3-pip || true
fi

# Check Go tools (Nuclei, httpx, dnsx, naabu)
if ! command -v nuclei >/dev/null 2>&1 || ! command -v httpx >/dev/null 2>&1; then
    echo -e "    Checking Go for ProjectDiscovery tools..."
    if command -v go >/dev/null 2>&1; then
        echo -e "    Installing nuclei & httpx via Go..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
    fi
fi

# 4. Create Python Virtual Environment
echo -e "\n${BLUE}[*] Setting up Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "    Created virtual environment in ${YELLOW}./venv${NC}"
else
    echo -e "    Virtual environment ${YELLOW}./venv${NC} already exists."
fi

# 5. Install Python Dependencies
echo -e "\n${BLUE}[*] Installing RootScan Python dependencies...${NC}"
./venv/bin/pip install --upgrade pip -q
./venv/bin/pip install -r requirements.txt -q

# 6. Initialize Environment Configuration
if [ ! -f ".env" ]; then
    echo -e "\n${BLUE}[*] Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "    ${YELLOW}Created .env - Remember to insert your NVIDIA_NIM_API_KEY!${NC}"
fi

# 7. Setup Directory Structures & DB
echo -e "\n${BLUE}[*] Initializing local database and storage directories...${NC}"
mkdir -p data/database data/scans

./venv/bin/python3 -c "from app.core.configuration import get_config; from app.database.repository import DatabaseRepository; config = get_config(); db = DatabaseRepository(config.database_path); print('    Database initialized at:', config.database_path)"

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}[✓] RootScan v1.0 installation completed successfully!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "To launch RootScan:"
echo -e "  ${YELLOW}chmod +x start.sh && ./start.sh${NC}\n"

